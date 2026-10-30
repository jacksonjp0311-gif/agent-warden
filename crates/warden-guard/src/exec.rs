//! Running an allowed command on the agent's behalf.

use crate::sandbox::{self, SandboxSpec};
use serde::Serialize;
use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use warden_policy::CompiledPolicy;

#[derive(Debug, Clone, Serialize)]
pub struct ExecOutput {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
}

fn read_capped(
    mut r: impl Read + Send + 'static,
    cap: usize,
) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        let mut truncated = false;
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = cap.saturating_sub(out.len());
                    if n > room {
                        truncated = true;
                    }
                    out.extend_from_slice(&buf[..n.min(room)]);
                    // keep draining so the child never blocks on a full pipe
                }
            }
        }
        (out, truncated)
    })
}

/// Run `program` (already resolved and approved) with a scrubbed environment,
/// in its own process group, sandboxed with *no* network access, a timeout
/// and capped output.
pub fn run(
    policy: &CompiledPolicy,
    program: &Path,
    args: &[String],
    cwd: &Path,
    stdin: Option<&str>,
) -> std::io::Result<ExecOutput> {
    let pol = &policy.policy;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(policy.build_env(std::env::vars()))
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut spec = SandboxSpec::from_policy(policy);
    // Tools run by the gateway get no network at all; egress goes through
    // http_request or the proxy, which the agent itself has to use.
    spec.restrict_net = true;
    spec.connect_ports.clear();
    // The program itself must be readable/executable.
    spec.read_roots.push(program.to_path_buf());
    spec.read_roots.push(cwd.to_path_buf());
    sandbox::apply(&mut cmd, &spec);

    let mut child = cmd.spawn()?;
    if let (Some(input), Some(mut si)) = (stdin, child.stdin.take()) {
        let data = input.as_bytes().to_vec();
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = si.write_all(&data);
        });
    }
    let cap = pol.commands.max_output_bytes;
    let out = read_capped(child.stdout.take().unwrap(), cap);
    let err = read_capped(child.stderr.take().unwrap(), cap);
    let pgid = child.id() as i32;
    let deadline = Instant::now() + Duration::from_secs(pol.commands.timeout_secs.max(1));
    let mut timed_out = false;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // Reap anything the command left behind in its group.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    // A detached grandchild (setsid) could keep the pipes open forever;
    // bound how long we wait for them.
    let (o, t1) = join_bounded(out);
    let (e, t2) = join_bounded(err);
    Ok(ExecOutput {
        exit_code: status.code(),
        signal: status.signal(),
        stdout: String::from_utf8_lossy(&o).into_owned(),
        stderr: String::from_utf8_lossy(&e).into_owned(),
        truncated: t1 || t2,
        timed_out,
    })
}

fn join_bounded(h: std::thread::JoinHandle<(Vec<u8>, bool)>) -> (Vec<u8>, bool) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(h.join().unwrap_or_default());
    });
    rx.recv_timeout(Duration::from_secs(2)).unwrap_or_else(|_| {
        (
            b"[warden: output pipe held open by a detached process]".to_vec(),
            true,
        )
    })
}
