//! End-to-end tests: real `warden` binary supervising the real `rogue-agent`.
//! None of these depend on Landlock/seccomp being available.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const WARDEN: &str = env!("CARGO_BIN_EXE_warden");
const ROGUE: &str = env!("CARGO_BIN_EXE_rogue-agent");

struct Env {
    _tmp: tempfile::TempDir,
    ws: PathBuf,
    state: PathBuf,
    policy: PathBuf,
}

fn setup() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("ws");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(ws.join(".secrets")).unwrap();
    std::fs::write(ws.join("notes.txt"), "hello from the workspace\n").unwrap();
    std::fs::write(ws.join(".secrets/aws_credentials"), "canary\n").unwrap();
    let policy = tmp.path().join("policy.toml");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies/demo.toml");
    std::fs::copy(src, &policy).unwrap();
    Env {
        _tmp: tmp,
        ws,
        state,
        policy,
    }
}

impl Env {
    fn warden(&self) -> Command {
        let mut c = Command::new(WARDEN);
        c.arg("run")
            .arg("-p")
            .arg(&self.policy)
            .arg("-w")
            .arg(&self.ws)
            .arg("--state-dir")
            .arg(&self.state);
        c
    }
    fn run(&self, scenario: &str) -> Output {
        self.warden()
            .args(["--", ROGUE, scenario])
            .output()
            .unwrap()
    }
    fn log(&self) -> PathBuf {
        self.state.join("audit.jsonl")
    }
    fn events(&self) -> Vec<Value> {
        std::fs::read_to_string(self.log())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap()["event"].clone())
            .collect()
    }
    fn halt_event(&self) -> Value {
        self.events()
            .into_iter()
            .find(|e| e["kind"] == "halt")
            .expect("no halt event in audit log")
    }
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn full_demo_blocks_and_trips_on_shell() {
    let e = setup();
    let out = e.run("full");
    let (so, se) = (s(&out.stdout), s(&out.stderr));
    assert_eq!(out.status.code(), Some(99), "stdout:\n{so}\nstderr:\n{se}");
    assert!(
        so.contains("read notes.txt (in scope)") && so.contains("allowed"),
        "{so}"
    );
    for blocked in [
        "exec curl",
        "read ~/.ssh/id_rsa",
        "read ~/.aws/credentials",
        "read /etc/shadow",
        "write ../escape.txt",
        "delete notes.txt",
        "exec rm -rf .",
        "c2.evil.example/beacon",
        "cloud metadata 169.254.169.254",
        "pastebin.com",
    ] {
        let line = so
            .lines()
            .find(|l| l.contains(blocked))
            .unwrap_or_else(|| panic!("{blocked} missing:\n{so}"));
        assert!(line.contains("BLOCKED"), "{line}");
    }
    assert!(so.contains("403 Forbidden"), "{so}");
    assert!(
        !so.contains("still alive"),
        "agent survived the kill switch:\n{so}"
    );
    assert!(!e.ws.parent().unwrap().join("escape.txt").exists());
    assert!(e.ws.join("notes.txt").exists(), "notes.txt was deleted");
    assert!(
        !so.contains("NOT BLOCKED"),
        "a direct OS call got through the sandbox:\n{so}"
    );
    assert_eq!(e.halt_event()["tripwire"], "shell");
    let v = Command::new(WARDEN)
        .arg("verify-log")
        .arg(e.log())
        .output()
        .unwrap();
    assert!(v.status.success(), "{}", s(&v.stdout));
    assert_eq!(
        std::fs::read_to_string(e.ws.join("out/report.md")).unwrap(),
        "# summary\nall good\n"
    );
}

#[test]
fn deny_threshold_halts_agent() {
    let e = setup();
    let out = e.run("threshold");
    assert_eq!(out.status.code(), Some(99), "{}", s(&out.stderr));
    let h = e.halt_event();
    assert!(
        h["tripwire"] == "deny_threshold" || h["tripwire"] == "canary",
        "{h}"
    );
    assert!(!s(&out.stdout).contains("still alive"));
}

#[test]
fn secret_exfiltration_trips() {
    let e = setup();
    let out = e.run("exfil");
    assert_eq!(out.status.code(), Some(99), "{}", s(&out.stderr));
    assert_eq!(e.halt_event()["tripwire"], "secret_exfil");
    // The secret itself must not be written to the audit log.
    let raw = std::fs::read_to_string(e.log()).unwrap();
    assert!(!raw.contains("wJalrXUtnFEMI"), "secret leaked into the log");
}

#[test]
fn deleting_the_audit_log_trips() {
    let e = setup();
    let out = e.run("wipe");
    assert_eq!(out.status.code(), Some(99), "{}", s(&out.stderr));
    assert_eq!(e.halt_event()["tripwire"], "protected_path");
    assert!(!s(&out.stdout).contains("still alive"));
    let v = Command::new(WARDEN)
        .arg("verify-log")
        .arg(e.log())
        .output()
        .unwrap();
    assert!(v.status.success(), "{}", s(&v.stdout));
}

#[test]
fn honest_agent_exits_normally() {
    let e = setup();
    let out = e.run("honest");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}\n{}",
        s(&out.stdout),
        s(&out.stderr)
    );
    assert!(e.events().iter().all(|x| x["kind"] != "halt"));
}

#[cfg(windows)]
fn alive(pid: i32) -> bool {
    let o = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
        .unwrap();
    s(&o.stdout).contains(&format!("\"{pid}\""))
}

#[cfg(not(windows))]
fn alive(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(st) => !st
            .rsplit_once(')')
            .map(|x| x.1.trim_start().starts_with('Z'))
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Start the `escape` scenario and return (child, grandchild pid).
fn start_escape(e: &Env) -> (std::process::Child, i32) {
    let mut child = e
        .warden()
        .args(["--quiet", "--", ROGUE, "escape"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut r = BufReader::new(child.stdout.take().unwrap());
    let mut gpid = 0;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap() == 0 {
            break;
        }
        if let Some(p) = line
            .trim()
            .strip_prefix("[rogue] spawned detached grandchild pid ")
        {
            gpid = p.parse().unwrap();
        }
        if line.contains("ready") {
            break;
        }
    }
    assert!(gpid > 0, "grandchild never started");
    // Keep draining the pipe so nobody in the tree dies of a broken pipe
    // before the kill switch gets a chance to act.
    std::thread::spawn(move || std::io::copy(&mut r, &mut std::io::sink()));
    while !e.state.join("warden.json").exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    (child, gpid)
}

#[test]
fn kill_switch_terminates_whole_tree() {
    let e = setup();
    let (mut child, gpid) = start_escape(&e);
    assert!(alive(gpid));
    let k = Command::new(WARDEN)
        .args([
            "kill",
            "--reason",
            "operator pressed the big red button",
            "--state-dir",
        ])
        .arg(&e.state)
        .output()
        .unwrap();
    assert!(k.status.success(), "{}{}", s(&k.stdout), s(&k.stderr));
    assert_eq!(child.wait().unwrap().code(), Some(99));
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !alive(gpid),
        "detached grandchild {gpid} survived the kill switch"
    );
    let h = e.halt_event();
    assert_eq!(h["tripwire"], "manual");
    assert_eq!(h["reason"], "operator pressed the big red button");
}

#[test]
fn policy_tamper_trips() {
    let e = setup();
    let (mut child, gpid) = start_escape(&e);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&e.policy)
        .unwrap();
    writeln!(f, "# agent was here").unwrap();
    drop(f);
    assert_eq!(child.wait().unwrap().code(), Some(99));
    std::thread::sleep(Duration::from_millis(300));
    assert!(!alive(gpid));
    assert_eq!(e.halt_event()["tripwire"], "protected_path");
}

#[test]
fn verify_log_detects_tampering() {
    let e = setup();
    e.run("honest");
    let ok = Command::new(WARDEN)
        .arg("verify-log")
        .arg(e.log())
        .output()
        .unwrap();
    assert!(ok.status.success());
    let raw = std::fs::read_to_string(e.log()).unwrap();
    let tampered = raw.replacen("\"allow\"", "\"deny\"", 1);
    assert_ne!(raw, tampered);
    std::fs::write(e.log(), tampered).unwrap();
    let bad = Command::new(WARDEN)
        .arg("verify-log")
        .arg(e.log())
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
    assert!(s(&bad.stdout).contains("TAMPERED"));
}

#[test]
fn signed_log_roundtrip() {
    let e = setup();
    let key = e.state.parent().unwrap().join("log.key");
    let g = Command::new(WARDEN)
        .arg("keygen")
        .arg("--out")
        .arg(&key)
        .output()
        .unwrap();
    assert!(g.status.success());
    let out = e
        .warden()
        .arg("--sign-key")
        .arg(&key)
        .args(["--", ROGUE, "honest"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", s(&out.stderr));
    let mut pubp = key.clone().into_os_string();
    pubp.push(".pub");
    let v = Command::new(WARDEN)
        .arg("verify-log")
        .arg(e.log())
        .arg("--pubkey")
        .arg(&pubp)
        .output()
        .unwrap();
    assert!(v.status.success(), "{}", s(&v.stdout));
    assert!(s(&v.stdout).contains("signatures valid"));
}

#[test]
fn gateway_stdio_mcp() {
    let e = setup();
    let mut child = Command::new(WARDEN)
        .arg("gateway")
        .arg("-p")
        .arg(&e.policy)
        .arg("-w")
        .arg(&e.ws)
        .arg("--state-dir")
        .arg(&e.state)
        .arg("--quiet")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    {
        let mut i = child.stdin.take().unwrap();
        let reqs = [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"notes.txt"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec","arguments":{"program":"sh","args":["-c","id"]}}}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"read_file","params":{"path":"notes.txt"}}"#,
        ];
        for r in reqs {
            writeln!(i, "{r}").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(99));
    let resp: Vec<Value> = s(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(resp.len(), 5, "notification must not get a response");
    assert_eq!(resp[0]["result"]["serverInfo"]["name"], "agent-warden");
    assert_eq!(resp[1]["result"]["isError"], false);
    assert!(resp[1]["result"]["structuredContent"]["content"]
        .as_str()
        .unwrap()
        .contains("hello"));
    assert_eq!(resp[2]["result"]["isError"], true);
    assert_eq!(resp[3]["result"]["isError"], true);
    assert_eq!(resp[3]["result"]["_warden"]["code"], -32003);
    assert_eq!(
        resp[4]["error"]["code"], -32002,
        "halted session must refuse everything"
    );
}

#[test]
fn state_dir_inside_workspace_is_refused() {
    let e = setup();
    let out = Command::new(WARDEN)
        .arg("run")
        .arg("-p")
        .arg(&e.policy)
        .arg("-w")
        .arg(&e.ws)
        .arg("--state-dir")
        .arg(e.ws.join(".warden"))
        .args(["--", ROGUE, "honest"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(s(&out.stderr).contains("inside the workspace"));
}

#[test]
fn shipped_policies_check() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies");
    for p in ["strict.toml", "dev.toml", "demo.toml"] {
        let o = Command::new(WARDEN)
            .arg("check")
            .arg("-p")
            .arg(dir.join(p))
            .output()
            .unwrap();
        assert!(o.status.success(), "{p}: {}", s(&o.stderr));
    }
}
