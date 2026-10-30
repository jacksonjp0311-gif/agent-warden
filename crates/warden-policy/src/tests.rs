use super::*;
use std::net::Ipv4Addr;

fn setup(toml_src: &str) -> (tempfile::TempDir, CompiledPolicy) {
    let d = tempfile::tempdir().unwrap();
    let ws = d.path().join("ws");
    std::fs::create_dir(&ws).unwrap();
    std::fs::write(ws.join("notes.txt"), "hi").unwrap();
    let policy_file = d.path().join("policy.toml");
    std::fs::write(&policy_file, toml_src).unwrap();
    let p = Policy::load(&policy_file).unwrap();
    let c = CompiledPolicy::compile(
        p,
        &Context {
            workspace: ws,
            protected: vec![policy_file, d.path().join("state")],
        },
    )
    .unwrap();
    (d, c)
}

const BASIC: &str = r#"
[commands]
allow = [
  { program = "ls", args = ["-l", "-a", "*.txt"] },
  { program = "echo", args = ["*"], deny_args = ["*secret*"] },
  { program = "true" },
]
[files]
read = ["${WORKSPACE}/**"]
write = ["${WORKSPACE}/out/**"]
[network]
allow_domains = ["example.com", "*.github.com"]
allow_ports = [443]
[tripwires]
canary_paths = ["${WORKSPACE}/fake_creds.txt"]
"#;

#[test]
fn empty_policy_denies_everything() {
    let (d, c) = setup("");
    let ws = c.workspace().to_path_buf();
    assert!(c.check_read(Path::new("notes.txt"), &ws).is_err());
    assert!(c.check_write(Path::new("x"), &ws).is_err());
    assert!(c.check_command("ls", &[], &ws).is_err());
    assert!(c.check_destination("example.com", 443).is_err());
    drop(d);
}

#[test]
fn file_scopes() {
    let (_d, c) = setup(BASIC);
    let ws = c.workspace().to_path_buf();
    assert!(c.check_read(Path::new("notes.txt"), &ws).is_ok());
    assert!(
        c.check_read(&ws, &ws).is_ok(),
        "workspace root itself is readable"
    );
    assert!(c.check_write(Path::new("notes.txt"), &ws).is_err());
    assert!(c.check_write(Path::new("out/a.txt"), &ws).is_ok());
    assert!(c
        .check_read(Path::new("../../../../etc/passwd"), &ws)
        .is_err());
    assert!(matches!(
        c.check_read(Path::new("/etc/shadow"), &ws),
        Err(Verdict::Deny(_))
    ));
}

#[test]
fn default_deny_list_wins() {
    let (_d, c) = setup(BASIC);
    let ws = c.workspace().to_path_buf();
    std::fs::write(ws.join(".env"), "A=1").unwrap();
    let r = c.check_read(Path::new(".env"), &ws);
    assert!(
        matches!(r, Err(Verdict::Deny(ref m)) if m.contains("files.deny")),
        "{r:?}"
    );
}

#[test]
fn symlink_escape_is_denied() {
    let (_d, c) = setup(BASIC);
    let ws = c.workspace().to_path_buf();
    std::os::unix::fs::symlink("/etc", ws.join("etc_link")).unwrap();
    assert!(c.check_read(Path::new("etc_link/hostname"), &ws).is_err());
}

#[test]
fn protected_paths_trip() {
    let (d, c) = setup(BASIC);
    let ws = c.workspace().to_path_buf();
    let r = c.check_read(&d.path().join("policy.toml"), &ws);
    assert!(
        matches!(r, Err(Verdict::Trip(TripKind::ProtectedPath, _))),
        "{r:?}"
    );
    // via symlink inside the workspace
    std::os::unix::fs::symlink(d.path().join("policy.toml"), ws.join("p")).unwrap();
    let r = c.check_read(Path::new("p"), &ws);
    assert!(
        matches!(r, Err(Verdict::Trip(TripKind::ProtectedPath, _))),
        "{r:?}"
    );
}

#[test]
fn canary_trips() {
    let (_d, c) = setup(BASIC);
    let ws = c.workspace().to_path_buf();
    let r = c.check_read(Path::new("fake_creds.txt"), &ws);
    assert!(matches!(r, Err(Verdict::Trip(TripKind::Canary, _))));
}

#[test]
fn commands() {
    let (_d, c) = setup(BASIC);
    let ws = c.workspace().to_path_buf();
    assert!(c.check_command("ls", &["-l".into()], &ws).is_ok());
    assert!(c.check_command("ls", &["notes.txt".into()], &ws).is_ok());
    assert!(c.check_command("ls", &["/etc".into()], &ws).is_err());
    assert!(c.check_command("true", &[], &ws).is_ok());
    assert!(
        c.check_command("true", &["x".into()], &ws).is_err(),
        "no args allowed"
    );
    assert!(c.check_command("echo", &["my secret".into()], &ws).is_err());
    assert!(c.check_command("curl", &[], &ws).is_err());
}

#[test]
fn shells_and_tripwire_commands() {
    let (_d, c) = setup(BASIC);
    let ws = c.workspace().to_path_buf();
    for sh in ["sh", "bash", "/bin/sh", "zsh"] {
        let r = c.check_command(sh, &["-c".into(), "id".into()], &ws);
        assert!(
            matches!(r, Err(Verdict::Trip(TripKind::Shell, _))),
            "{sh}: {r:?}"
        );
    }
    let r = c.check_command("python3", &["-c".into(), "print(1)".into()], &ws);
    assert!(matches!(r, Err(Verdict::Trip(TripKind::Shell, _))), "{r:?}");
    let r = c.check_command("sudo", &["ls".into()], &ws);
    assert!(matches!(
        r,
        Err(Verdict::Trip(TripKind::ForbiddenCommand, _))
    ));
}

#[test]
fn command_args_touching_protected_paths_trip() {
    let (d, c) = setup(BASIC);
    let ws = c.workspace().to_path_buf();
    let pf = d.path().join("policy.toml").display().to_string();
    let r = c.check_command("echo", &[pf], &ws);
    assert!(
        matches!(r, Err(Verdict::Trip(TripKind::ProtectedPath, _))),
        "{r:?}"
    );
}

#[test]
fn domains_and_ports() {
    let (_d, c) = setup(BASIC);
    assert!(c.check_destination("example.com", 443).is_ok());
    assert!(c.check_destination("EXAMPLE.com.", 443).is_ok());
    assert!(c.check_destination("example.com", 80).is_err());
    assert!(c.check_destination("api.github.com", 443).is_ok());
    assert!(c.check_destination("github.com", 443).is_err());
    assert!(c.check_destination("evilgithub.com", 443).is_err());
    assert!(c.check_destination("example.com.evil.io", 443).is_err());
}

#[test]
fn forbidden_ips() {
    assert!(forbidden_ip(Ipv4Addr::new(169, 254, 169, 254).into()).is_some());
    assert!(forbidden_ip(Ipv4Addr::new(127, 0, 0, 1).into()).is_some());
    assert!(forbidden_ip(Ipv4Addr::new(10, 1, 2, 3).into()).is_some());
    assert!(forbidden_ip(Ipv4Addr::new(100, 100, 100, 200).into()).is_some());
    assert!(forbidden_ip("::ffff:169.254.169.254".parse().unwrap()).is_some());
    assert!(forbidden_ip("fd00:ec2::254".parse().unwrap()).is_some());
    assert!(forbidden_ip(Ipv4Addr::new(93, 184, 216, 34).into()).is_none());
    assert!(forbidden_ip("2606:2800:220:1::".parse().unwrap()).is_none());
}

#[test]
fn payload_checks() {
    let (_d, c) = setup(BASIC);
    assert!(c.check_payload(b"hello").is_ok());
    let r = c.check_payload(b"AKIAIOSFODNN7EXAMPLE");
    assert!(matches!(r, Err(Verdict::Trip(TripKind::SecretExfil, _))));
    let big = vec![b'a'; (1 << 20) + 1];
    assert!(matches!(c.check_payload(&big), Err(Verdict::Deny(_))));
}

#[test]
fn env_is_scrubbed() {
    let (_d, c) = setup(
        r#"
[env]
pass = ["PATH", "HOME", "GITHUB_TOKEN", "LANG"]
set = { AGENT = "1" }
"#,
    );
    let env = c.build_env(
        vec![
            ("PATH".to_string(), "/evil:/usr/bin".to_string()),
            ("HOME".to_string(), "/h".to_string()),
            ("GITHUB_TOKEN".to_string(), "x".to_string()),
            ("OPENAI_API_KEY".to_string(), "y".to_string()),
        ]
        .into_iter(),
    );
    assert_eq!(env.get("HOME").unwrap(), "/h");
    assert!(!env.contains_key("GITHUB_TOKEN"));
    assert!(!env.contains_key("OPENAI_API_KEY"));
    assert_eq!(env.get("PATH").unwrap(), "/usr/local/bin:/usr/bin:/bin");
    assert_eq!(env.get("AGENT").unwrap(), "1");
}

#[test]
fn unknown_fields_rejected() {
    assert!(Policy::from_toml("[files]\nreed = []").is_err());
}

#[test]
fn shipped_policies_parse() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies");
    let mut n = 0;
    for e in std::fs::read_dir(root).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "toml") {
            Policy::load(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            n += 1;
        }
    }
    assert!(n >= 2);
}
