//! Session setup and the `warden run` supervisor loop.

use crate::gateway::Gateway;
use crate::sandbox::{self, SandboxSpec};
use crate::supervisor::{Counters, HaltInfo, KillTarget, Supervisor};
use serde_json::json;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use warden_audit::{AuditLog, Ed25519SigningKey as SigningKey};
use warden_policy::{CompiledPolicy, Context, Policy, TripKind};

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("policy: {0}")]
    Policy(#[from] warden_policy::PolicyError),
    #[error("audit log: {0}")]
    Audit(#[from] warden_audit::AuditError),
    #[error("{0}: {1}")]
    Io(String, std::io::Error),
    #[error("{0}")]
    Other(String),
}

fn io(ctx: impl Into<String>) -> impl FnOnce(std::io::Error) -> LaunchError {
    let c = ctx.into();
    move |e| LaunchError::Io(c, e)
}

/// Options shared by `run`, `gateway` and `proxy`.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub policy_path: PathBuf,
    pub workspace: PathBuf,
    pub state_dir: PathBuf,
    /// Defaults to `<state_dir>/audit.jsonl`.
    pub log_path: Option<PathBuf>,
    /// Hex ed25519 signing key file (also protected).
    pub key_path: Option<PathBuf>,
    pub verbose: bool,
}

/// Default state directory, deliberately outside any workspace.
pub fn default_state_dir() -> PathBuf {
    #[cfg(windows)]
    if let Some(x) = std::env::var_os("LOCALAPPDATA").filter(|x| !x.is_empty()) {
        return PathBuf::from(x).join("agent-warden").join("state");
    }
    if let Some(x) = std::env::var_os("XDG_STATE_HOME").filter(|x| !x.is_empty()) {
        return PathBuf::from(x).join("agent-warden");
    }
    let home = warden_policy::home_dir().unwrap_or_else(std::env::temp_dir);
    home.join(".local/state/agent-warden")
}

/// An opened session: policy compiled with its protected paths, audit log
/// open, supervisor ready.
pub struct Session {
    pub sup: Arc<Supervisor>,
    pub policy: Arc<CompiledPolicy>,
    pub state_dir: PathBuf,
    pub log_path: PathBuf,
    pub policy_path: PathBuf,
    pub policy_sha256: String,
    pub protected: Vec<PathBuf>,
}

fn canon(p: &Path) -> Result<PathBuf, LaunchError> {
    warden_policy::canonicalize(p).map_err(io(p.display().to_string()))
}

impl Session {
    pub fn open(o: &SessionOptions) -> Result<Session, LaunchError> {
        let policy_path = canon(&o.policy_path)?;
        let workspace = canon(&o.workspace)?;
        std::fs::create_dir_all(&o.state_dir).map_err(io(o.state_dir.display().to_string()))?;
        // On Windows the state dir inherits the per-user ACL of %LOCALAPPDATA%.
        #[cfg(unix)]
        std::fs::set_permissions(&o.state_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(io("state dir permissions"))?;
        let state_dir = canon(&o.state_dir)?;
        if state_dir.starts_with(&workspace) {
            return Err(LaunchError::Other(format!(
                "state dir {} is inside the workspace; the agent could tamper with it",
                state_dir.display()
            )));
        }
        let log_path = o
            .log_path
            .clone()
            .unwrap_or_else(|| state_dir.join("audit.jsonl"));
        let log_path = if log_path.is_absolute() {
            log_path
        } else {
            std::env::current_dir().map_err(io("cwd"))?.join(log_path)
        };
        let key = match &o.key_path {
            Some(k) => {
                let s = std::fs::read_to_string(k).map_err(io(k.display().to_string()))?;
                Some(warden_audit::parse_signing_key(s.trim())?)
            }
            None => None,
        };
        let raw = std::fs::read(&policy_path).map_err(io(policy_path.display().to_string()))?;
        let policy_sha256 = hex::encode(Sha256::digest(&raw));
        let policy = Policy::from_toml(&String::from_utf8_lossy(&raw))?;

        let mut protected = vec![
            policy_path.clone(),
            state_dir.clone(),
            log_path.clone(),
            warden_audit::head_path(&log_path),
        ];
        if let Ok(exe) = std::env::current_exe().and_then(|e| warden_policy::canonicalize(&e)) {
            protected.push(exe);
        }
        if let Some(k) = &o.key_path {
            protected.push(warden_policy::canonicalize(k).unwrap_or(k.clone()));
        }
        let compiled = Arc::new(CompiledPolicy::compile(
            policy,
            &Context {
                workspace,
                protected: protected.clone(),
            },
        )?);
        let log = open_log(&log_path, key)?;
        let sup = Supervisor::new(compiled.clone(), Some(log));
        sup.verbose.store(o.verbose, Ordering::Relaxed);
        Ok(Session {
            sup,
            policy: compiled,
            state_dir,
            log_path,
            policy_path,
            policy_sha256,
            protected,
        })
    }
}

fn open_log(path: &Path, key: Option<SigningKey>) -> Result<AuditLog, LaunchError> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(io(p.display().to_string()))?;
    }
    Ok(AuditLog::open(path, key)?)
}

/// Result of a supervised run.
#[derive(Debug)]
pub struct RunOutcome {
    pub exit_code: i32,
    pub halted: Option<HaltInfo>,
    pub counters: Counters,
}

/// Find `prog` the way `execvp` would (for granting Landlock execute).
fn is_pathish(prog: &str) -> bool {
    prog.contains('/') || (cfg!(windows) && prog.contains('\\'))
}

fn which(prog: &str) -> Option<PathBuf> {
    let exts: Vec<String> = if cfg!(windows) {
        let pe = std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.COM".into());
        std::iter::once(String::new())
            .chain(pe.split(';').filter(|e| !e.is_empty()).map(String::from))
            .collect()
    } else {
        vec![String::new()]
    };
    let try_one = |base: PathBuf| -> Option<PathBuf> {
        exts.iter()
            .map(|e| {
                let mut s = base.clone().into_os_string();
                s.push(e);
                PathBuf::from(s)
            })
            .find(|c| c.is_file())
            .and_then(|c| warden_policy::canonicalize(&c).ok())
    };
    if is_pathish(prog) {
        return try_one(PathBuf::from(prog));
    }
    std::env::var_os("PATH")
        .and_then(|p| std::env::split_paths(&p).find_map(|d| try_one(d.join(prog))))
}

/// Fingerprint of a file used to detect tampering while the agent runs.
/// (identity, length, mtime seconds, mtime nanos). Identity is the inode on
/// Unix and the creation time on Windows.
type Fingerprint = Option<(u64, u64, i64, i64)>;

#[cfg(unix)]
fn fingerprint(p: &Path) -> Fingerprint {
    std::fs::metadata(p)
        .ok()
        .map(|m| (m.ino(), m.len(), m.mtime(), m.mtime_nsec()))
}

#[cfg(windows)]
fn fingerprint(p: &Path) -> Fingerprint {
    std::fs::metadata(p).ok().map(|m| {
        let w = m.last_write_time() as i64; // 100ns ticks
        (m.creation_time(), m.len(), w / 10_000_000, w % 10_000_000)
    })
}

#[cfg(not(any(unix, windows)))]
fn fingerprint(p: &Path) -> Fingerprint {
    std::fs::metadata(p).ok().map(|m| (0, m.len(), 0, 0))
}

/// Launch `agent` under supervision and wait for it. Returns once the agent
/// exits or is killed.
pub fn run(o: &SessionOptions, agent: &[String]) -> Result<RunOutcome, LaunchError> {
    let s = Session::open(o)?;
    let sup = s.sup.clone();
    let pol = s.policy.clone();

    // Become a subreaper so orphaned grandchildren of the agent stay in our
    // tree and the kill switch can find them.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    }

    let proxy = warden_net::Proxy::start("127.0.0.1:0", pol.clone(), sup.clone())
        .map_err(io("start proxy"))?;
    let gw = Arc::new(Gateway::new(sup.clone()));
    #[cfg(unix)]
    let (socket, gw_env) = {
        let socket = s.state_dir.join("gateway.sock");
        gw.serve_unix(&socket).map_err(io("gateway socket"))?;
        let v = socket.display().to_string();
        (Some(socket), vec![("WARDEN_SOCKET", v)])
    };
    // No 0600 Unix socket on Windows: loopback TCP plus a per-session token
    // that only the agent receives (in its environment).
    #[cfg(not(unix))]
    let (socket, gw_env) = {
        let token = crate::gateway::new_token();
        let addr = gw
            .serve_tcp("127.0.0.1:0", token.clone())
            .map_err(io("gateway listener"))?;
        (
            None::<PathBuf>,
            vec![
                ("WARDEN_GATEWAY", format!("tcp://{addr}")),
                ("WARDEN_TOKEN", token),
            ],
        )
    };
    let gateway_desc = socket
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| gw_env[0].1.clone());

    let program = agent
        .first()
        .ok_or_else(|| LaunchError::Other("no agent command given".into()))?;
    let mut spec = SandboxSpec::from_policy(&pol);
    spec.connect_ports = vec![proxy.addr.port()];
    let resolved = which(program);
    if let Some(exe) = &resolved {
        spec.read_roots.push(exe.clone());
    }
    // A relative path is relative to where warden was started, not the workspace.
    let program_path: PathBuf = match (&resolved, is_pathish(program)) {
        (Some(p), true) => p.clone(),
        _ => PathBuf::from(program),
    };
    let layers = sandbox::describe(&spec);
    let exposed = spec.exposed(&s.protected);
    for l in &layers {
        eprintln!("warden: {l}");
    }
    for (p, r) in &exposed {
        eprintln!(
            "warden: WARNING protected path {} is under sandbox root {}; only the gateway guards it",
            p.display(),
            r.display()
        );
    }

    sup.log(json!({
        "kind": "session_start",
        "mode": "run",
        "policy": s.policy_path,
        "policy_sha256": s.policy_sha256,
        "workspace": pol.workspace(),
        "agent": agent,
        "proxy": proxy.url(),
        "socket": gateway_desc,
        "sandbox": layers,
        "warden_pid": std::process::id(),
    }));

    let proxy_url = proxy.url();
    let mut cmd = Command::new(&program_path);
    cmd.args(&agent[1..])
        .current_dir(pol.workspace())
        .env_clear()
        .envs(pol.build_env(std::env::vars()))
        .envs(gw_env.iter().map(|(k, v)| (*k, v.as_str())))
        .env("WARDEN_STATE_DIR", &s.state_dir)
        .env("WARDEN_PROXY", &proxy_url)
        .env("WARDEN_WORKSPACE", pol.workspace())
        .env("NO_PROXY", "")
        .env("no_proxy", "");
    for k in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        cmd.env(k, &proxy_url);
    }
    #[cfg(unix)]
    cmd.process_group(0);
    for n in sandbox::apply(&mut cmd, &spec) {
        eprintln!("warden: {n}");
        sup.log(json!({"kind": "sandbox_note", "note": n}));
    }

    // Signals -> manual kill.
    let sig = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    let sigs = [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGUSR1,
    ];
    #[cfg(not(unix))]
    let sigs = [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT];
    for s_ in sigs {
        signal_hook::flag::register(s_, sig.clone()).map_err(io("signal handler"))?;
    }

    let mut child = cmd.spawn().map_err(io(format!("spawn {program}")))?;
    let pid = child.id() as i32;
    #[cfg(unix)]
    let target = KillTarget::group(pid, std::process::id() as i32);
    // Windows: the agent and everything it starts live in a kill-on-close
    // Job Object. Assignment happens right after spawn; a process created in
    // that window (microseconds) would escape the job, but is still caught
    // by `taskkill /T` if the job is unavailable.
    #[cfg(windows)]
    let target = match crate::kill::Job::new().and_then(|j| j.assign(&child).map(|_| j)) {
        Ok(j) => KillTarget::Job {
            job: Arc::new(j),
            pid: pid as u32,
        },
        Err(e) => {
            eprintln!("warden: WARNING job object unavailable ({e}); falling back to taskkill");
            sup.log(
                json!({"kind": "sandbox_note", "note": format!("job object unavailable: {e}")}),
            );
            KillTarget::group(pid, pid)
        }
    };
    #[cfg(not(any(unix, windows)))]
    let target = KillTarget::group(pid, pid);
    sup.set_kill_target(target.clone());
    sup.log(json!({"kind": "agent_spawned", "pid": pid}));

    let state_file = s.state_dir.join("warden.json");
    let kill_file = s.state_dir.join("KILL");
    let _ = std::fs::remove_file(&kill_file);
    let info = json!({
        "warden_pid": std::process::id(),
        "agent_pid": pid,
        "agent_pgid": pid,
        "socket": gateway_desc,
        "proxy": proxy_url,
        "log": s.log_path,
        "started": SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    });
    std::fs::write(&state_file, serde_json::to_vec_pretty(&info).unwrap())
        .map_err(io("write state file"))?;

    // Watch the things an agent might tamper with outside the gateway.
    let exe = std::env::current_exe().ok();
    let watched: Vec<(String, PathBuf, Fingerprint)> = [
        Some(("policy file", s.policy_path.clone())),
        exe.map(|e| ("warden binary", e)),
    ]
    .into_iter()
    .flatten()
    .map(|(n, p)| (n.to_string(), p.clone(), fingerprint(&p)))
    .collect();
    let log_ino = fingerprint(&s.log_path).map(|f| f.0);

    let status = loop {
        if let Some(st) = child.try_wait().map_err(io("wait"))? {
            break st;
        }
        if kill_file.exists() {
            let why = std::fs::read_to_string(&kill_file).unwrap_or_default();
            let _ = std::fs::remove_file(&kill_file);
            let why = if why.trim().is_empty() {
                "warden kill".to_string()
            } else {
                why.trim().to_string()
            };
            sup.halt(TripKind::Manual, why);
        }
        if sig.swap(false, Ordering::SeqCst) {
            sup.halt(
                TripKind::Manual,
                "signal received by warden (SIGTERM/SIGINT/SIGUSR1/Ctrl-C)".into(),
            );
        }
        for (name, p, fp) in &watched {
            if fingerprint(p) != *fp {
                sup.halt(
                    TripKind::ProtectedPath,
                    format!("{name} {} was modified", p.display()),
                );
            }
        }
        if fingerprint(&s.log_path).map(|f| f.0) != log_ino {
            sup.halt(
                TripKind::ProtectedPath,
                "audit log was deleted or replaced".into(),
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    // Sweep stragglers (e.g. daemonized grandchildren) even on normal exit.
    #[cfg(unix)]
    let leftovers = {
        let l = crate::kill::descendants(std::process::id() as i32);
        if !l.is_empty() {
            target.kill(Duration::from_millis(500));
        }
        l.len()
    };
    #[cfg(windows)]
    let leftovers = match &target {
        KillTarget::Job { job, .. } => job.terminate(),
        _ => 0,
    };
    #[cfg(not(any(unix, windows)))]
    let leftovers = 0usize;
    proxy.stop();
    let halted = sup.halt_info();
    let signal = crate::exec::exit_signal(&status);
    let code = match (&halted, status.code(), signal) {
        (Some(_), _, _) => crate::HALT_EXIT_CODE,
        (None, Some(c), _) => c,
        (None, None, Some(sg)) => 128 + sg,
        _ => 1,
    };
    sup.log(json!({
        "kind": "session_end",
        "agent_exit_code": status.code(),
        "agent_signal": signal,
        "halted": halted,
        "counters": sup.counters(),
        "leftover_processes_killed": leftovers,
    }));
    if let Some(sock) = &socket {
        let _ = std::fs::remove_file(sock);
    }
    let _ = std::fs::remove_file(&state_file);
    Ok(RunOutcome {
        exit_code: code,
        halted,
        counters: sup.counters(),
    })
}

/// Serve the gateway on stdio (for harnesses that spawn warden as an MCP
/// server). If `kill_pgid` is set, that process group (Windows: that pid's
/// process tree) is killed on halt.
pub fn gateway_stdio(
    o: &SessionOptions,
    kill_pgid: Option<i32>,
) -> Result<RunOutcome, LaunchError> {
    let s = Session::open(o)?;
    s.sup.log(json!({
        "kind": "session_start",
        "mode": "gateway-stdio",
        "policy": s.policy_path,
        "policy_sha256": s.policy_sha256,
        "workspace": s.policy.workspace(),
    }));
    if let Some(p) = kill_pgid {
        s.sup.set_kill_target(KillTarget::group(p, p));
    }
    let gw = Gateway::new(s.sup.clone());
    let _ = gw.serve(std::io::stdin().lock(), std::io::stdout().lock());
    let halted = s.sup.halt_info();
    s.sup
        .log(json!({"kind": "session_end", "halted": halted, "counters": s.sup.counters()}));
    Ok(RunOutcome {
        exit_code: if halted.is_some() {
            crate::HALT_EXIT_CODE
        } else {
            0
        },
        halted,
        counters: s.sup.counters(),
    })
}
