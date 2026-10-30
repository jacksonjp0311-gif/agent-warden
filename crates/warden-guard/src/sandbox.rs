//! Defense in depth for processes warden spawns (the agent itself and every
//! gateway `exec`). All layers are best effort: on kernels or platforms that
//! lack a feature, the process still runs and the gap is reported.
//!
//! Layers, applied in the child between `fork` and `exec`:
//! 1. `PR_SET_PDEATHSIG(SIGKILL)`: the child dies if warden dies.
//! 2. rlimits (CPU, file size, open files, address space, no core dumps).
//! 3. Landlock: filesystem access limited to the policy's scopes plus the
//!    system paths needed to run; TCP `connect` limited to given ports.
//! 4. seccomp-bpf: dangerous syscalls (ptrace, mount, bpf, kexec, module
//!    loading, namespace creation, ...) fail with EPERM.

use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use warden_policy::{expand, CompiledPolicy};

/// What the sandbox should allow.
#[derive(Debug, Clone, Default)]
pub struct SandboxSpec {
    pub read_roots: Vec<PathBuf>,
    pub write_roots: Vec<PathBuf>,
    /// TCP ports the process may connect to (only when `restrict_net`).
    pub connect_ports: Vec<u16>,
    pub restrict_net: bool,
    pub landlock: bool,
    pub seccomp: bool,
    pub block_udp: bool,
    pub rlimits: Vec<(Rlimit, u64)>,
}

#[derive(Debug, Clone, Copy)]
pub enum Rlimit {
    Cpu,
    Fsize,
    Nofile,
    As,
    Core,
}

impl Rlimit {
    #[allow(clippy::useless_conversion)]
    fn raw(self) -> libc::__rlimit_resource_t {
        (match self {
            Rlimit::Cpu => libc::RLIMIT_CPU,
            Rlimit::Fsize => libc::RLIMIT_FSIZE,
            Rlimit::Nofile => libc::RLIMIT_NOFILE,
            Rlimit::As => libc::RLIMIT_AS,
            Rlimit::Core => libc::RLIMIT_CORE,
        })
        .into()
    }
}

/// The literal directory prefix of a glob (`/ws/src/**/*.rs` -> `/ws/src`).
pub fn glob_root(pattern: &str) -> PathBuf {
    let mut out = PathBuf::from("/");
    for comp in Path::new(pattern).components().skip(1) {
        let s = comp.as_os_str().to_string_lossy();
        if s.contains(['*', '?', '[', '{']) {
            break;
        }
        out.push(comp);
    }
    out
}

impl SandboxSpec {
    /// Build a spec from the policy: file scopes become Landlock roots.
    pub fn from_policy(p: &CompiledPolicy) -> Self {
        let pol = &p.policy;
        let roots = |pats: &[String]| -> Vec<PathBuf> {
            pats.iter()
                .map(|x| glob_root(&expand(x, &p.vars)))
                .collect()
        };
        let mut read_roots = roots(&pol.files.read);
        read_roots.extend(roots(&pol.sandbox.landlock_extra_read));
        let mut write_roots = roots(&pol.files.write);
        write_roots.extend(roots(&pol.sandbox.landlock_extra_write));
        let s = &pol.sandbox;
        let mut rlimits = vec![];
        if let Some(v) = s.rlimit_cpu_secs {
            rlimits.push((Rlimit::Cpu, v));
        }
        if let Some(v) = s.rlimit_fsize_bytes {
            rlimits.push((Rlimit::Fsize, v));
        }
        if let Some(v) = s.rlimit_nofile {
            rlimits.push((Rlimit::Nofile, v));
        }
        if let Some(v) = s.rlimit_as_bytes {
            rlimits.push((Rlimit::As, v));
        }
        if s.no_core_dumps {
            rlimits.push((Rlimit::Core, 0));
        }
        Self {
            read_roots,
            write_roots,
            connect_ports: vec![],
            restrict_net: s.restrict_network,
            landlock: s.landlock,
            seccomp: s.seccomp,
            block_udp: s.block_udp,
            rlimits,
        }
    }

    /// Protected paths that Landlock cannot hide because they sit under a
    /// granted root (the gateway still refuses them; direct syscalls won't).
    pub fn exposed(&self, protected: &[PathBuf]) -> Vec<(PathBuf, PathBuf)> {
        let mut v = vec![];
        for p in protected {
            for r in self.read_roots.iter().chain(&self.write_roots) {
                if p.starts_with(r) {
                    v.push((p.clone(), r.clone()));
                }
            }
        }
        v
    }
}

/// Kernel Landlock ABI version, or None if unsupported/disabled.
pub fn landlock_abi() -> Option<i64> {
    #[cfg(target_os = "linux")]
    {
        const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
        let r = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<u8>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if r > 0 {
            return Some(r);
        }
    }
    None
}

/// Human-readable description of which layers will actually be active.
pub fn describe(spec: &SandboxSpec) -> Vec<String> {
    let mut v = vec![];
    let ll_compiled = cfg!(all(feature = "landlock", target_os = "linux"));
    let sc_compiled = cfg!(all(feature = "seccomp", target_os = "linux"));
    match (spec.landlock, ll_compiled, landlock_abi()) {
        (false, _, _) => v.push("landlock: disabled by policy".into()),
        (true, false, _) => v.push("landlock: NOT compiled in (feature `landlock` off)".into()),
        (true, true, None) => v.push("landlock: NOT available on this kernel".into()),
        (true, true, Some(abi)) => {
            let net = if !spec.restrict_net {
                "tcp unrestricted (policy)".to_string()
            } else if abi >= 4 {
                format!("tcp connect only to ports {:?}", spec.connect_ports)
            } else {
                "tcp NOT restricted (needs ABI >= 4)".to_string()
            };
            v.push(format!("landlock: ABI v{abi}, fs confined, {net}"));
        }
    }
    v.push(match (spec.seccomp, sc_compiled) {
        (false, _) => "seccomp: disabled by policy".into(),
        (true, false) => "seccomp: NOT compiled in (feature `seccomp` off)".into(),
        (true, true) => format!(
            "seccomp: dangerous-syscall blocklist{}",
            if spec.block_udp {
                " + UDP/raw sockets blocked"
            } else {
                ""
            }
        ),
    });
    if !spec.rlimits.is_empty() {
        v.push(format!("rlimits: {:?}", spec.rlimits));
    }
    v
}

#[cfg(all(feature = "landlock", target_os = "linux"))]
fn build_landlock(spec: &SandboxSpec) -> io::Result<landlock::RulesetCreated> {
    use landlock::{
        path_beneath_rules, Access, AccessFs, AccessNet, NetPort, Ruleset, RulesetAttr,
        RulesetCreatedAttr, ABI,
    };
    // V6 is the newest ABI whose rights we fully understand; newer handled
    // rights (e.g. unix-socket scoping) would break the gateway socket.
    let abi = ABI::V6;
    let e = |x: landlock::RulesetError| io::Error::other(x.to_string());
    let mut rs = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(e)?;
    if spec.restrict_net {
        rs = rs
            .handle_access(AccessNet::ConnectTcp | AccessNet::BindTcp)
            .map_err(e)?;
    }
    let mut created = rs
        .create()
        .map_err(e)?
        .add_rules(path_beneath_rules(
            &spec.read_roots,
            AccessFs::from_read(abi),
        ))
        .map_err(e)?
        .add_rules(path_beneath_rules(
            &spec.write_roots,
            AccessFs::from_all(abi),
        ))
        .map_err(e)?;
    if spec.restrict_net {
        for &p in &spec.connect_ports {
            created = created
                .add_rule(NetPort::new(p, AccessNet::ConnectTcp))
                .map_err(e)?;
        }
    }
    Ok(created)
}

#[cfg(all(feature = "seccomp", target_os = "linux"))]
#[allow(clippy::unnecessary_cast)] // c_long is i32 on 32-bit targets
fn build_seccomp(spec: &SandboxSpec) -> io::Result<seccompiler::BpfProgram> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp as Op, SeccompCondition as Cond,
        SeccompFilter, SeccompRule,
    };
    use std::collections::BTreeMap;
    let e = |x: seccompiler::BackendError| io::Error::other(x.to_string());
    let deny: &[libc::c_long] = &[
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_userfaultfd,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_acct,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_fanotify_init,
        libc::SYS_quotactl,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        // clone3 takes its flags via a pointer we cannot inspect; ENOSYS-like
        // EPERM makes libc fall back to clone(2), which we do filter below.
        libc::SYS_clone3,
    ];
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
        deny.iter().map(|&s| (s as i64, vec![])).collect();
    // clone(2) with CLONE_NEWUSER (user namespaces = privilege games).
    rules.insert(
        libc::SYS_clone as i64,
        vec![SeccompRule::new(vec![Cond::new(
            0,
            Len::Qword,
            Op::MaskedEq(libc::CLONE_NEWUSER as u64),
            libc::CLONE_NEWUSER as u64,
        )
        .map_err(e)?])
        .map_err(e)?],
    );
    if spec.block_udp {
        let mut v = vec![];
        for dom in [libc::AF_INET, libc::AF_INET6] {
            for ty in [libc::SOCK_DGRAM, libc::SOCK_RAW] {
                v.push(
                    SeccompRule::new(vec![
                        Cond::new(0, Len::Dword, Op::Eq, dom as u64).map_err(e)?,
                        Cond::new(1, Len::Dword, Op::MaskedEq(0xf), ty as u64).map_err(e)?,
                    ])
                    .map_err(e)?,
                );
            }
        }
        rules.insert(libc::SYS_socket as i64, v);
    }
    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| io::Error::other("unsupported arch for seccomp"))?;
    let f = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(e)?;
    f.try_into().map_err(e)
}

/// Install the sandbox into `cmd` (applied in the child before `exec`).
/// Returns notes about layers that could not be prepared.
pub fn apply(cmd: &mut Command, spec: &SandboxSpec) -> Vec<String> {
    #[allow(unused_mut)]
    let mut notes = vec![];

    #[cfg(all(feature = "landlock", target_os = "linux"))]
    let ll = if spec.landlock {
        match build_landlock(spec) {
            Ok(r) => Some(std::sync::Mutex::new(Some(r))),
            Err(e) => {
                notes.push(format!("landlock setup failed: {e}"));
                None
            }
        }
    } else {
        None
    };
    #[cfg(all(feature = "seccomp", target_os = "linux"))]
    let sc = if spec.seccomp {
        match build_seccomp(spec) {
            Ok(p) => Some(p),
            Err(e) => {
                notes.push(format!("seccomp setup failed: {e}"));
                None
            }
        }
    } else {
        None
    };
    let rlimits: Vec<(libc::__rlimit_resource_t, u64)> =
        spec.rlimits.iter().map(|(r, v)| (r.raw(), *v)).collect();

    // SAFETY: the closure only performs raw syscalls (prctl, setrlimit,
    // landlock_restrict_self, seccomp) on data prepared before fork. It takes
    // a Mutex that no other thread can hold (it was created for this spawn).
    unsafe {
        cmd.pre_exec(move || {
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            for &(res, v) in &rlimits {
                let lim = libc::rlimit {
                    rlim_cur: v as libc::rlim_t,
                    rlim_max: v as libc::rlim_t,
                };
                if libc::setrlimit(res, &lim) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            #[cfg(all(feature = "landlock", target_os = "linux"))]
            if let Some(m) = &ll {
                if let Some(r) = m.lock().ok().and_then(|mut g| g.take()) {
                    r.restrict_self()
                        .map_err(|e| io::Error::other(e.to_string()))?;
                }
            }
            #[cfg(all(feature = "seccomp", target_os = "linux"))]
            if let Some(p) = &sc {
                seccompiler::apply_filter(p).map_err(|e| io::Error::other(e.to_string()))?;
            }
            Ok(())
        });
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_roots() {
        assert_eq!(glob_root("/ws/src/**/*.rs"), PathBuf::from("/ws/src"));
        assert_eq!(glob_root("/ws/**"), PathBuf::from("/ws"));
        assert_eq!(glob_root("/etc/hosts"), PathBuf::from("/etc/hosts"));
        assert_eq!(glob_root("/*"), PathBuf::from("/"));
    }

    #[cfg(all(feature = "landlock", target_os = "linux"))]
    #[test]
    fn landlock_blocks_reads_outside_roots() {
        if landlock_abi().is_none() {
            eprintln!("landlock unavailable; skipping");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("ok.txt"), "ok").unwrap();
        let secret = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(secret.path(), "secret").unwrap();
        let spec = SandboxSpec {
            read_roots: vec![
                d.path().into(),
                "/usr".into(),
                "/lib".into(),
                "/lib64".into(),
                "/bin".into(),
                "/etc/ld.so.cache".into(),
            ],
            landlock: true,
            ..Default::default()
        };
        let run = |p: &Path| {
            let mut c = Command::new("/bin/cat");
            c.arg(p)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            apply(&mut c, &spec);
            c.status().unwrap().success()
        };
        assert!(run(&d.path().join("ok.txt")));
        assert!(
            !run(secret.path()),
            "landlock should block reads outside roots"
        );
    }

    #[cfg(all(feature = "seccomp", target_os = "linux"))]
    #[test]
    fn seccomp_blocks_unshare() {
        let spec = SandboxSpec {
            seccomp: true,
            ..Default::default()
        };
        if !Path::new("/usr/bin/unshare").exists() {
            return;
        }
        let mut c = Command::new("/usr/bin/unshare");
        c.args(["--user", "true"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        apply(&mut c, &spec);
        assert!(!c.status().unwrap().success());
    }
}
