//! # warden-policy
//!
//! Default-deny policy engine for `agent-warden`. A [`Policy`] is parsed from
//! TOML and compiled into a [`CompiledPolicy`] which answers questions like
//! "may the agent run `git status` here?" or "may it write this path?".
//!
//! Every check returns a [`Verdict`]. Anything not explicitly allowed is
//! denied, and some denials are *tripwires* that halt the agent outright.

pub mod model;
pub mod paths;
pub mod secrets;

pub use model::*;
pub use paths::{
    canonicalize, expand, home_dir, lexical_normalize, resolve, simplify, slashed, Vars,
};
pub use secrets::SecretScanner;

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("reading policy {0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("parsing policy: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid glob `{0}`: {1}")]
    Glob(String, globset::Error),
    #[error("invalid secret regex: {0}")]
    Regex(#[from] regex::Error),
    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// Kinds of tripwire. Hitting one halts the agent immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripKind {
    /// Touched the policy, the warden binary, the audit log or state dir.
    ProtectedPath,
    /// Touched a honeypot path.
    Canary,
    /// Tried to spawn a shell / inline interpreter while shells are denied.
    Shell,
    /// Tried to run a program on the tripwire list (sudo, kill, iptables ...).
    ForbiddenCommand,
    /// Tried to send something that looks like a credential.
    SecretExfil,
    /// Exhausted an action / byte budget.
    Budget,
    /// Too many denials in the configured window.
    DenyThreshold,
    /// Operator pressed the kill switch.
    Manual,
}

impl std::fmt::Display for TripKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json_like(self);
        f.write_str(s)
    }
}

fn serde_json_like(k: &TripKind) -> &'static str {
    match k {
        TripKind::ProtectedPath => "protected_path",
        TripKind::Canary => "canary",
        TripKind::Shell => "shell",
        TripKind::ForbiddenCommand => "forbidden_command",
        TripKind::SecretExfil => "secret_exfil",
        TripKind::Budget => "budget",
        TripKind::DenyThreshold => "deny_threshold",
        TripKind::Manual => "manual",
    }
}

/// Result of a policy check that did not simply allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Deny(String),
    Trip(TripKind, String),
}

impl Verdict {
    pub fn reason(&self) -> &str {
        match self {
            Verdict::Deny(r) | Verdict::Trip(_, r) => r,
        }
    }
}

pub type Check<T> = Result<T, Verdict>;

/// Runtime context needed to compile a policy.
#[derive(Debug, Clone)]
pub struct Context {
    /// Directory the agent works in; `${WORKSPACE}` in patterns.
    pub workspace: PathBuf,
    /// Paths that must never be touched (policy file, warden exe, logs...).
    /// Directories protect everything below them.
    pub protected: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    resolved: Option<PathBuf>,
    program: String,
    args: Option<GlobSet>,
    deny_args: GlobSet,
    max_args: Option<usize>,
}

/// A policy compiled for fast, repeated checks.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub policy: Policy,
    pub vars: Vars,
    read: GlobSet,
    write: GlobSet,
    deny: GlobSet,
    protect: GlobSet,
    canary: GlobSet,
    scrub: GlobSet,
    rules: Vec<CompiledRule>,
    trip_cmds: HashSet<String>,
    scanner: SecretScanner,
    protected_roots: Vec<PathBuf>,
}

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "mksh",
    "fish",
    "csh",
    "tcsh",
    "ash",
    "busybox",
    "pwsh",
    "powershell",
    "rbash",
    "yash",
    "elvish",
    "nu",
    "xonsh",
    // Windows command interpreters / script hosts.
    "cmd",
    "wscript",
    "cscript",
    "mshta",
];
const INLINE_INTERPRETERS: &[&str] = &[
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "node",
    "nodejs",
    "php",
    "lua",
    "deno",
    "bun",
    "osascript",
    "awk",
    "gawk",
];

/// True if `name` (a basename) is a shell.
pub fn is_shell(name: &str) -> bool {
    SHELLS.contains(&name)
}

fn is_inline_interpreter(name: &str) -> bool {
    // python3.12 -> python3
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INLINE_INTERPRETERS.contains(&name) || INLINE_INTERPRETERS.contains(&base)
}

fn glob(p: &str) -> Result<Glob, PolicyError> {
    // On Windows, paths are matched `/`-separated (globset normalises the
    // candidate) and case-insensitively; a `\` in a pattern is a separator,
    // not an escape.
    let pat = if cfg!(windows) {
        p.replace('\\', "/")
    } else {
        p.to_string()
    };
    GlobBuilder::new(&pat)
        .literal_separator(true)
        .backslash_escape(!cfg!(windows))
        .case_insensitive(cfg!(windows))
        .build()
        .map_err(|e| PolicyError::Glob(p.to_string(), e))
}

/// Executable extensions Windows runs directly. Batch files (`.bat`/`.cmd`)
/// are deliberately absent: they execute through `cmd.exe`, i.e. a shell.
#[cfg(windows)]
const WIN_EXE_EXT: &[&str] = &["exe", "com"];

/// The comparable name of a program: its basename, and on Windows lower-cased
/// with any executable/script extension removed (`BASH.EXE` -> `bash`).
pub fn prog_name(p: &Path) -> String {
    let n = p
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    if cfg!(windows) {
        let l = n.to_ascii_lowercase();
        for ext in [".exe", ".com", ".bat", ".cmd"] {
            if let Some(stem) = l.strip_suffix(ext) {
                return stem.to_string();
            }
        }
        l
    } else {
        n
    }
}

/// Windows batch scripts run through `cmd.exe`, so they count as shells.
fn is_batch(p: &Path) -> bool {
    cfg!(windows)
        && p.extension()
            .map(|e| {
                let e = e.to_string_lossy().to_ascii_lowercase();
                e == "bat" || e == "cmd"
            })
            .unwrap_or(false)
}

fn path_set<'a>(
    pats: impl IntoIterator<Item = &'a String>,
    vars: &Vars,
) -> Result<GlobSet, PolicyError> {
    let mut b = GlobSetBuilder::new();
    for p in pats {
        let e = expand(p, vars);
        b.add(glob(&e)?);
        if let Some(base) = e.strip_suffix("/**") {
            if !base.is_empty() {
                b.add(glob(base)?);
            }
        }
    }
    b.build().map_err(|e| PolicyError::Glob("<set>".into(), e))
}

fn arg_set(pats: &[String]) -> Result<GlobSet, PolicyError> {
    let mut b = GlobSetBuilder::new();
    for p in pats {
        b.add(
            GlobBuilder::new(p)
                .literal_separator(false)
                .build()
                .map_err(|e| PolicyError::Glob(p.clone(), e))?,
        );
    }
    b.build().map_err(|e| PolicyError::Glob("<set>".into(), e))
}

impl Policy {
    pub fn from_toml(s: &str) -> Result<Self, PolicyError> {
        Ok(toml::from_str(s)?)
    }

    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let s = std::fs::read_to_string(path).map_err(|e| PolicyError::Io(path.into(), e))?;
        Self::from_toml(&s)
    }

    /// Human-readable warnings about risky but valid settings.
    pub fn lint(&self) -> Vec<String> {
        let mut w = vec![];
        if self.network.allow_domains.iter().any(|d| d == "*") {
            w.push("network.allow_domains contains \"*\": any domain is reachable".into());
        }
        if !self.commands.deny_shells {
            w.push("commands.deny_shells = false: an allowed shell can run anything".into());
        }
        for r in &self.commands.allow {
            let base = prog_name(Path::new(&r.program));
            if is_shell(&base) || is_batch(Path::new(&r.program)) {
                w.push(format!("command `{}` is a shell", r.program));
            }
            if r.args
                .as_ref()
                .is_some_and(|a| a.iter().any(|p| p == "*" || p == "**"))
            {
                w.push(format!("command `{}` accepts any argument", r.program));
            }
        }
        if !self.network.block_private_ips {
            w.push("network.block_private_ips = false: cloud metadata endpoints reachable".into());
        }
        if self.limits.deny_threshold == 0 {
            w.push("limits.deny_threshold = 0: repeated probing never halts the agent".into());
        }
        if self.files.write.iter().any(|p| p == "/**" || p == "**") {
            w.push("files.write allows the whole filesystem".into());
        }
        w
    }
}

impl CompiledPolicy {
    pub fn compile(policy: Policy, ctx: &Context) -> Result<Self, PolicyError> {
        let vars = Vars::new(&ctx.workspace);
        let read = path_set(&policy.files.read, &vars)?;
        let write = path_set(&policy.files.write, &vars)?;
        let deny = path_set(&policy.files.deny, &vars)?;
        let canary = path_set(&policy.tripwires.canary_paths, &vars)?;

        let mut protected_roots = vec![];
        let mut prot_pats: Vec<String> = policy.tripwires.protect_paths.clone();
        for p in &ctx.protected {
            let canon = resolve(p, &vars.workspace);
            let esc = globset::escape(&slashed(&canon));
            prot_pats.push(esc.clone());
            if canon.is_dir() {
                prot_pats.push(format!("{esc}/**"));
            }
            protected_roots.push(canon);
        }
        let protect = path_set(&prot_pats, &vars)?;

        let mut sb = GlobSetBuilder::new();
        for p in &policy.env.scrub {
            sb.add(
                GlobBuilder::new(p)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| PolicyError::Glob(p.clone(), e))?,
            );
        }
        let scrub = sb
            .build()
            .map_err(|e| PolicyError::Glob("<scrub>".into(), e))?;

        let mut rules = vec![];
        for r in &policy.commands.allow {
            if r.program.trim().is_empty() {
                return Err(PolicyError::Invalid("empty command program".into()));
            }
            rules.push(CompiledRule {
                resolved: resolve_program(
                    &r.program,
                    &policy.commands.search_path,
                    &vars.workspace,
                ),
                program: r.program.clone(),
                args: r.args.as_deref().map(arg_set).transpose()?,
                deny_args: arg_set(&r.deny_args)?,
                max_args: r.max_args,
            });
        }
        let trip_cmds = policy.tripwires.commands.iter().cloned().collect();
        let scanner = SecretScanner::new(&policy.network.extra_secret_patterns)?;
        Ok(Self {
            policy,
            vars,
            read,
            write,
            deny,
            protect,
            canary,
            scrub,
            rules,
            trip_cmds,
            scanner,
            protected_roots,
        })
    }

    pub fn workspace(&self) -> &Path {
        &self.vars.workspace
    }

    pub fn protected_roots(&self) -> &[PathBuf] {
        &self.protected_roots
    }

    /// Tripwire check only (protected + canary), on lexical and resolved forms.
    fn trip_path(&self, lex: &Path, res: &Path) -> Check<()> {
        for p in [lex, res] {
            if self.protect.is_match(p) {
                return Err(Verdict::Trip(
                    TripKind::ProtectedPath,
                    format!(
                        "{} is protected (warden policy/binary/log/state)",
                        p.display()
                    ),
                ));
            }
            if self.canary.is_match(p) {
                return Err(Verdict::Trip(
                    TripKind::Canary,
                    format!("{} is a canary (honeypot) path", p.display()),
                ));
            }
        }
        Ok(())
    }

    /// Check a filesystem access. Returns the resolved path to operate on.
    pub fn check_path(&self, path: &Path, base: &Path, write: bool) -> Check<PathBuf> {
        let lex = lexical_normalize(path, base);
        let res = resolve(path, base);
        self.trip_path(&lex, &res)?;
        if self.deny.is_match(&lex) || self.deny.is_match(&res) {
            return Err(Verdict::Deny(format!(
                "{} matches files.deny",
                res.display()
            )));
        }
        let ok = if write {
            self.write.is_match(&res)
        } else {
            self.read.is_match(&res) || self.write.is_match(&res)
        };
        if ok {
            Ok(res)
        } else {
            Err(Verdict::Deny(format!(
                "{} is outside the {} scope",
                res.display(),
                if write { "write" } else { "read" }
            )))
        }
    }

    pub fn check_read(&self, path: &Path, base: &Path) -> Check<PathBuf> {
        self.check_path(path, base, false)
    }

    pub fn check_write(&self, path: &Path, base: &Path) -> Check<PathBuf> {
        self.check_path(path, base, true)
    }

    /// Check a command. Returns the absolute program path that must be executed.
    pub fn check_command(&self, program: &str, args: &[String], cwd: &Path) -> Check<PathBuf> {
        let c = &self.policy.commands;
        let req_base = prog_name(Path::new(program));

        // Tripwire commands are checked by requested name first: even trying
        // to run `sudo` is suspicious, whether or not it exists.
        if self.trip_cmds.contains(&req_base) {
            return Err(Verdict::Trip(
                TripKind::ForbiddenCommand,
                format!("attempted to run tripwire command `{req_base}`"),
            ));
        }
        let shellish = |name: &str| {
            is_shell(name)
                || (is_inline_interpreter(name)
                    && args.iter().any(|a| {
                        matches!(
                            a.as_str(),
                            "-c" | "-e" | "-E" | "--eval" | "-r" | "--command"
                        ) || (name.contains("awk") && !a.starts_with('-'))
                    }))
        };
        if c.deny_shells && (shellish(&req_base) || is_batch(Path::new(program))) {
            return Err(self.shell_verdict(&req_base));
        }

        let Some(resolved) = resolve_program(program, &c.search_path, cwd) else {
            return Err(Verdict::Deny(format!(
                "program `{program}` not found on the policy search path"
            )));
        };
        let res_base = prog_name(&resolved);
        if self.trip_cmds.contains(&res_base) {
            return Err(Verdict::Trip(
                TripKind::ForbiddenCommand,
                format!("`{program}` resolves to tripwire command `{res_base}`"),
            ));
        }
        if c.deny_shells && (shellish(&res_base) || is_batch(&resolved)) {
            return Err(self.shell_verdict(&res_base));
        }
        // The program itself or any path-like argument touching protected paths.
        self.trip_path(&resolved, &resolved)?;
        for a in args {
            let cand = a.rsplit('=').next().unwrap_or(a);
            let win_path = cfg!(windows) && (cand.contains('\\') || cand.contains(':'));
            if cand.contains('/') || cand.starts_with('.') || cand.starts_with('~') || win_path {
                let p = PathBuf::from(expand(cand, &self.vars));
                self.trip_path(&lexical_normalize(&p, cwd), &resolve(&p, cwd))?;
            }
        }

        let Some(rule) = self
            .rules
            .iter()
            .find(|r| r.resolved.as_deref() == Some(resolved.as_path()))
        else {
            return Err(Verdict::Deny(format!(
                "program `{}` is not in commands.allow",
                resolved.display()
            )));
        };
        if let Some(max) = rule.max_args {
            if args.len() > max {
                return Err(Verdict::Deny(format!(
                    "`{}` allows at most {max} arguments",
                    rule.program
                )));
            }
        }
        for a in args {
            if rule.deny_args.is_match(a) {
                return Err(Verdict::Deny(format!(
                    "argument `{a}` is denied for `{}`",
                    rule.program
                )));
            }
            match &rule.args {
                None => {
                    return Err(Verdict::Deny(format!(
                        "`{}` takes no arguments",
                        rule.program
                    )))
                }
                Some(set) if !set.is_match(a) => {
                    return Err(Verdict::Deny(format!(
                        "argument `{a}` not allowed for `{}`",
                        rule.program
                    )))
                }
                _ => {}
            }
        }
        Ok(resolved)
    }

    fn shell_verdict(&self, name: &str) -> Verdict {
        let msg = format!("shell / inline interpreter `{name}` is not allowed");
        if self.policy.tripwires.halt_on_shell {
            Verdict::Trip(TripKind::Shell, msg)
        } else {
            Verdict::Deny(msg)
        }
    }

    /// Check a network destination by name and port (IP checks happen after
    /// DNS resolution, see [`forbidden_ip`]).
    pub fn check_destination(&self, host: &str, port: u16) -> Check<()> {
        let n = &self.policy.network;
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if !n.allow_ports.contains(&port) {
            return Err(Verdict::Deny(format!(
                "port {port} is not in network.allow_ports"
            )));
        }
        let ok = n.allow_domains.iter().any(|d| {
            let d = d.to_ascii_lowercase();
            if d == "*" {
                true
            } else if let Some(sfx) = d.strip_prefix("*.") {
                host.ends_with(&format!(".{sfx}"))
            } else {
                d == host
            }
        });
        if !ok {
            return Err(Verdict::Deny(format!(
                "host `{host}` is not in network.allow_domains"
            )));
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            self.check_ip(ip)?;
        }
        Ok(())
    }

    pub fn check_ip(&self, ip: IpAddr) -> Check<()> {
        if self.policy.network.block_private_ips {
            if let Some(why) = forbidden_ip(ip) {
                return Err(Verdict::Deny(format!("{ip} is a {why} address")));
            }
        }
        Ok(())
    }

    pub fn check_method(&self, method: &str) -> Check<()> {
        if self
            .policy
            .network
            .allow_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
        {
            Ok(())
        } else {
            Err(Verdict::Deny(format!("HTTP method {method} not allowed")))
        }
    }

    /// Exfiltration heuristics for an outbound payload.
    pub fn check_payload(&self, data: &[u8]) -> Check<()> {
        let n = &self.policy.network;
        if data.len() as u64 > n.max_request_bytes {
            return Err(Verdict::Deny(format!(
                "payload of {} bytes exceeds network.max_request_bytes ({})",
                data.len(),
                n.max_request_bytes
            )));
        }
        if n.detect_secrets {
            if let Some(name) = self.scanner.scan(data) {
                let msg = format!("outbound payload contains a secret ({name})");
                return Err(if self.policy.tripwires.halt_on_secret {
                    Verdict::Trip(TripKind::SecretExfil, msg)
                } else {
                    Verdict::Deny(msg)
                });
            }
        }
        Ok(())
    }

    pub fn scanner(&self) -> &SecretScanner {
        &self.scanner
    }

    /// Build the scrubbed environment for a child process.
    pub fn build_env(
        &self,
        from: impl Iterator<Item = (String, String)>,
    ) -> BTreeMap<String, String> {
        // Windows variable names are case-insensitive (`Path` == `PATH`).
        let norm = |k: &str| {
            if cfg!(windows) {
                k.to_ascii_uppercase()
            } else {
                k.to_string()
            }
        };
        let pass: HashSet<String> = self.policy.env.pass.iter().map(|s| norm(s)).collect();
        let mut out: BTreeMap<String, String> = from
            .filter(|(k, _)| pass.contains(&norm(k)) && !self.scrub.is_match(k))
            .collect();
        let sep = if cfg!(windows) { ";" } else { ":" };
        for (k, v) in out.iter_mut() {
            if norm(k) == "PATH" {
                // Never let the inherited PATH widen what bare names resolve to.
                *v = self.policy.commands.search_path.join(sep);
            }
        }
        for (k, v) in &self.policy.env.set {
            out.insert(k.clone(), v.clone());
        }
        out
    }

    /// Would this variable name be scrubbed?
    pub fn is_scrubbed(&self, name: &str) -> bool {
        self.scrub.is_match(name)
    }
}

/// Resolve a program to a canonical absolute path. Bare names are looked up
/// only in `search_path` (never the agent's PATH).
pub fn resolve_program(program: &str, search_path: &[String], cwd: &Path) -> Option<PathBuf> {
    if program.is_empty() {
        return None;
    }
    let is_pathish = program.contains('/') || (cfg!(windows) && program.contains('\\'));
    if is_pathish {
        return candidates(&resolve(Path::new(program), cwd))
            .into_iter()
            .find(|p| is_exec(p));
    }
    search_path
        .iter()
        .flat_map(|d| candidates(&Path::new(d).join(program)))
        .find(|p| is_exec(p))
        .and_then(|p| canonicalize(&p).ok())
}

#[cfg(unix)]
fn is_exec(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_exec(p: &Path) -> bool {
    #[cfg(windows)]
    {
        let ext_ok = p
            .extension()
            .map(|e| {
                WIN_EXE_EXT
                    .iter()
                    .any(|x| e.to_string_lossy().eq_ignore_ascii_case(x))
            })
            .unwrap_or(false);
        if !ext_ok {
            return false;
        }
    }
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// Paths to try for `p`: itself, and on Windows with `.exe`/`.com` appended.
fn candidates(p: &Path) -> Vec<PathBuf> {
    #[allow(unused_mut)]
    let mut v = vec![p.to_path_buf()];
    #[cfg(windows)]
    for ext in WIN_EXE_EXT {
        let mut s = p.as_os_str().to_os_string();
        s.push(".");
        s.push(ext);
        v.push(PathBuf::from(s));
    }
    v
}

/// Classify IPs agents must never reach: loopback, private, link-local
/// (includes 169.254.169.254 cloud metadata), CGNAT, multicast, etc.
pub fn forbidden_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_private() {
                Some("private (RFC1918)")
            } else if v4.is_link_local() {
                Some("link-local / cloud-metadata")
            } else if o[0] == 100 && (64..128).contains(&o[1]) {
                Some("carrier-grade NAT")
            } else if v4.is_unspecified() || o[0] == 0 {
                Some("unspecified")
            } else if v4.is_multicast() || o[0] >= 240 {
                Some("multicast/reserved")
            } else if v4.is_broadcast() {
                Some("broadcast")
            } else if o[0] == 192 && o[1] == 0 && o[2] == 0 {
                Some("IETF protocol assignment")
            } else if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                Some("benchmarking")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return forbidden_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            if v6.is_loopback() {
                Some("loopback")
            } else if v6.is_unspecified() {
                Some("unspecified")
            } else if (s[0] & 0xfe00) == 0xfc00 {
                Some("unique-local (ULA)")
            } else if (s[0] & 0xffc0) == 0xfe80 {
                Some("link-local")
            } else if v6.is_multicast() {
                Some("multicast")
            } else if s[0] == 0xfd00 && s[1] == 0x0ec2 {
                Some("cloud-metadata")
            } else if s[0] == 0x64 && s[1] == 0xff9b {
                Some("NAT64")
            } else if s[0] == 0x2002 {
                Some("6to4")
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests;
