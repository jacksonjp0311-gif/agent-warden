//! `warden`: run AI agents under a default-deny policy with a kill switch.

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use warden_guard::launch::{self, default_state_dir, SessionOptions};

#[derive(Parser)]
#[command(
    name = "warden",
    version,
    about = "Keep AI agents inside the lines: default-deny policy, tool gateway, egress proxy, tamper-evident log, kill switch"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Common {
    /// Policy file (TOML).
    #[arg(short, long)]
    policy: PathBuf,
    /// Workspace the agent works in (`${WORKSPACE}` in the policy).
    #[arg(short, long, default_value = ".")]
    workspace: PathBuf,
    /// State directory (socket, audit log, kill file). Must be outside the workspace.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Audit log path (default: <state-dir>/audit.jsonl).
    #[arg(long)]
    log: Option<PathBuf>,
    /// ed25519 signing key (hex) for the audit log; see `warden keygen`.
    #[arg(long)]
    sign_key: Option<PathBuf>,
    /// Don't echo every decision to stderr.
    #[arg(short, long)]
    quiet: bool,
}

impl Common {
    fn opts(&self) -> SessionOptions {
        SessionOptions {
            policy_path: self.policy.clone(),
            workspace: self.workspace.clone(),
            state_dir: self.state_dir.clone().unwrap_or_else(default_state_dir),
            log_path: self.log.clone(),
            key_path: self.sign_key.clone(),
            verbose: !self.quiet,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Launch an agent under supervision: `warden run -p policy.toml -- my-agent --flag`.
    Run {
        #[command(flatten)]
        common: Common,
        /// The agent command line.
        #[arg(last = true, required = true)]
        agent: Vec<String>,
    },
    /// Serve the tool-call gateway (JSON-RPC/MCP) on stdio or a Unix socket.
    Gateway {
        #[command(flatten)]
        common: Common,
        /// Listen on this Unix socket instead of stdio.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Kill this process group when a tripwire fires.
        #[arg(long)]
        kill_pgid: Option<i32>,
    },
    /// Run the egress proxy standalone.
    Proxy {
        #[command(flatten)]
        common: Common,
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
    },
    /// Verify an audit log's hash chain (and signatures).
    VerifyLog {
        log: PathBuf,
        /// Public key (hex, or a file containing it) to require valid signatures.
        #[arg(long)]
        pubkey: Option<String>,
        /// Don't require the `.head` sidecar (detects tail truncation).
        #[arg(long)]
        no_head: bool,
    },
    /// Generate an ed25519 key pair for signing audit logs.
    Keygen {
        /// Secret key output path; the public key goes to `<out>.pub`.
        #[arg(long)]
        out: PathBuf,
    },
    /// Kill switch: halt a running `warden run` session and its whole process tree.
    Kill {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long, default_value = "manual kill switch")]
        reason: String,
    },
    /// Validate and lint a policy.
    Check {
        #[arg(short, long)]
        policy: PathBuf,
        #[arg(short, long, default_value = ".")]
        workspace: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    match real_main(cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("warden: error: {e:#}");
            std::process::exit(2);
        }
    }
}

fn report(o: &launch::RunOutcome) {
    let c = &o.counters;
    eprintln!(
        "warden: session over: {} actions, {} allowed, {} denied, {} bytes out",
        c.actions, c.allowed, c.denied, c.bytes_out
    );
    if let Some(h) = &o.halted {
        eprintln!("warden: agent was HALTED ({}): {}", h.kind, h.reason);
    }
}

fn wait_halt(sup: &warden_guard::Supervisor) -> i32 {
    while !sup.is_halted() {
        std::thread::sleep(Duration::from_millis(100));
    }
    warden_guard::HALT_EXIT_CODE
}

fn real_main(cli: Cli) -> Result<i32> {
    match cli.cmd {
        Cmd::Run { common, agent } => {
            let out = launch::run(&common.opts(), &agent)?;
            report(&out);
            Ok(out.exit_code)
        }
        Cmd::Gateway {
            common,
            socket,
            kill_pgid,
        } => match socket {
            None => {
                let out = launch::gateway_stdio(&common.opts(), kill_pgid)?;
                Ok(out.exit_code)
            }
            Some(sock) => {
                let s = launch::Session::open(&common.opts())?;
                if let Some(p) = kill_pgid {
                    s.sup.set_kill_target(warden_guard::supervisor::KillTarget {
                        pgid: p,
                        tree_root: p,
                    });
                }
                s.sup.log(
                    serde_json::json!({"kind": "session_start", "mode": "gateway-socket",
                    "policy_sha256": s.policy_sha256, "socket": sock}),
                );
                let gw = std::sync::Arc::new(warden_guard::gateway::Gateway::new(s.sup.clone()));
                gw.serve_unix(&sock)?;
                eprintln!("warden: gateway listening on {}", sock.display());
                Ok(wait_halt(&s.sup))
            }
        },
        Cmd::Proxy { common, listen } => {
            let s = launch::Session::open(&common.opts())?;
            s.sup
                .log(serde_json::json!({"kind": "session_start", "mode": "proxy",
                "policy_sha256": s.policy_sha256, "listen": listen}));
            let p = warden_net::Proxy::start(&listen, s.policy.clone(), s.sup.clone())?;
            eprintln!("warden: proxy listening on {}", p.url());
            Ok(wait_halt(&s.sup))
        }
        Cmd::VerifyLog {
            log,
            pubkey,
            no_head,
        } => {
            let vk = match pubkey {
                None => None,
                Some(k) => {
                    let hex = if Path::new(&k).is_file() {
                        std::fs::read_to_string(&k)?.trim().to_string()
                    } else {
                        k
                    };
                    Some(warden_audit::parse_verifying_key(&hex)?)
                }
            };
            match warden_audit::verify(&log, vk.as_ref(), !no_head) {
                Ok(r) => {
                    println!(
                        "OK: {} records, chain intact, head {}{}{}",
                        r.records,
                        r.head_hash,
                        if r.signed {
                            ", all signatures valid"
                        } else {
                            ""
                        },
                        if r.head_file_checked {
                            ", head file matches"
                        } else {
                            ""
                        },
                    );
                    Ok(0)
                }
                Err(e) => {
                    println!("TAMPERED: {e}");
                    Ok(1)
                }
            }
        }
        Cmd::Keygen { out } => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let (sk, pk) = warden_audit::generate_key();
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&out)
                .with_context(|| format!("create {}", out.display()))?;
            writeln!(f, "{sk}")?;
            let mut pubp = out.clone().into_os_string();
            pubp.push(".pub");
            std::fs::write(&pubp, format!("{pk}\n"))?;
            println!(
                "secret key: {} (keep it outside the agent's reach)",
                out.display()
            );
            println!("public key: {} = {pk}", PathBuf::from(pubp).display());
            Ok(0)
        }
        Cmd::Kill { state_dir, reason } => {
            kill(&state_dir.unwrap_or_else(default_state_dir), &reason)
        }
        Cmd::Check { policy, workspace } => {
            let p = warden_policy::Policy::load(&policy)?;
            let lints = p.lint();
            let ws = workspace.canonicalize()?;
            let c = warden_policy::CompiledPolicy::compile(
                p,
                &warden_policy::Context {
                    workspace: ws,
                    protected: vec![policy.canonicalize()?],
                },
            )?;
            let pol = &c.policy;
            println!("policy OK: {}", policy.display());
            println!(
                "  commands allowed : {}",
                pol.commands
                    .allow
                    .iter()
                    .map(|r| r.program.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("  read scopes      : {}", pol.files.read.join(", "));
            println!("  write scopes     : {}", pol.files.write.join(", "));
            println!(
                "  domains          : {}",
                pol.network.allow_domains.join(", ")
            );
            println!("  ports            : {:?}", pol.network.allow_ports);
            println!(
                "  limits           : {}/min, {} total, {} bytes out, halt after {} denials in {}s",
                pol.limits.actions_per_minute,
                pol.limits.max_actions,
                pol.limits.max_bytes_out,
                pol.limits.deny_threshold,
                pol.limits.deny_window_secs
            );
            for l in &lints {
                println!("  lint: {l}");
            }
            Ok(0)
        }
    }
}

fn kill(state_dir: &Path, reason: &str) -> Result<i32> {
    let sf = state_dir.join("warden.json");
    let info: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&sf)
            .with_context(|| format!("no running session ({} missing)", sf.display()))?,
    )?;
    let wpid = info["warden_pid"].as_i64().unwrap_or(0) as i32;
    let apgid = info["agent_pgid"].as_i64().unwrap_or(0) as i32;
    if wpid <= 1 {
        bail!("bad state file");
    }
    std::fs::write(state_dir.join("KILL"), reason)?;
    unsafe { libc::kill(wpid, libc::SIGUSR1) };
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if !sf.exists() || unsafe { libc::kill(apgid, 0) } != 0 {
            println!("killed: agent process group {apgid} terminated by warden {wpid}");
            return Ok(0);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Warden did not respond (hung or itself compromised): hard kill.
    eprintln!("warden did not confirm; sending SIGKILL to process group {apgid}");
    if apgid > 1 {
        unsafe { libc::kill(-apgid, libc::SIGKILL) };
    }
    Ok(1)
}
