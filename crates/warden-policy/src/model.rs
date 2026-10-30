//! Serde model of a policy file. Every section is optional; anything not
//! explicitly allowed is denied.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub meta: Meta,
    #[serde(default)]
    pub commands: Commands,
    #[serde(default)]
    pub files: Files,
    #[serde(default)]
    pub network: Network,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub tripwires: Tripwires,
    #[serde(default)]
    pub env: EnvPolicy,
    #[serde(default)]
    pub sandbox: Sandbox,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commands {
    /// Allowed programs. Empty = no command execution at all.
    #[serde(default)]
    pub allow: Vec<CommandRule>,
    /// Directories used to resolve bare program names. Agents cannot change it.
    #[serde(default = "default_search_path")]
    pub search_path: Vec<String>,
    /// Refuse (and trip on) shells and interpreters running inline code.
    #[serde(default = "yes")]
    pub deny_shells: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_max_output")]
    pub max_output_bytes: usize,
}

impl Default for Commands {
    fn default() -> Self {
        Self {
            allow: vec![],
            search_path: default_search_path(),
            deny_shells: true,
            timeout_secs: default_timeout(),
            max_output_bytes: default_max_output(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRule {
    /// Bare name (resolved through `search_path`) or absolute path.
    pub program: String,
    /// Glob patterns; every argument must match at least one. Absent = no
    /// arguments allowed. `["*"]` = any arguments.
    #[serde(default)]
    pub args: Option<Vec<String>>,
    /// Glob patterns; any argument matching one of these is refused.
    #[serde(default)]
    pub deny_args: Vec<String>,
    #[serde(default)]
    pub max_args: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Files {
    /// Glob patterns of readable paths. `${WORKSPACE}`, `${HOME}`, `${TMPDIR}` and `~/` expand.
    #[serde(default)]
    pub read: Vec<String>,
    /// Glob patterns of writable paths (also readable).
    #[serde(default)]
    pub write: Vec<String>,
    /// Glob patterns that are always refused, even if matched above.
    #[serde(default = "default_file_deny")]
    pub deny: Vec<String>,
    #[serde(default = "default_max_read")]
    pub max_read_bytes: u64,
}

impl Default for Files {
    fn default() -> Self {
        Self {
            read: vec![],
            write: vec![],
            deny: default_file_deny(),
            max_read_bytes: default_max_read(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Exact hostnames or `*.suffix` wildcards. Empty = no egress.
    #[serde(default)]
    pub allow_domains: Vec<String>,
    #[serde(default = "default_ports")]
    pub allow_ports: Vec<u16>,
    /// Refuse loopback, RFC1918, link-local (cloud metadata), CGNAT, ULA, etc.
    #[serde(default = "yes")]
    pub block_private_ips: bool,
    #[serde(default = "default_methods")]
    pub allow_methods: Vec<String>,
    /// Max size of a single outbound request body.
    #[serde(default = "default_max_request")]
    pub max_request_bytes: u64,
    #[serde(default = "yes")]
    pub detect_secrets: bool,
    /// Extra regexes treated as secrets (in addition to the built-ins).
    #[serde(default)]
    pub extra_secret_patterns: Vec<String>,
    /// Per-connection cap on client->server bytes through a CONNECT tunnel
    /// (TLS payloads cannot be inspected, so size is the only signal).
    #[serde(default = "default_tunnel_bytes")]
    pub max_tunnel_bytes_out: u64,
    /// Max response body returned to the agent by the gateway `http_request`.
    #[serde(default = "default_max_response")]
    pub max_response_bytes: u64,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            allow_domains: vec![],
            allow_ports: default_ports(),
            block_private_ips: true,
            allow_methods: default_methods(),
            max_request_bytes: default_max_request(),
            detect_secrets: true,
            extra_secret_patterns: vec![],
            max_tunnel_bytes_out: default_tunnel_bytes(),
            max_response_bytes: default_max_response(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_apm")]
    pub actions_per_minute: u32,
    #[serde(default = "default_max_actions")]
    pub max_actions: u64,
    /// Total bytes the agent may send over the network (gateway + proxy).
    #[serde(default = "default_bytes_out")]
    pub max_bytes_out: u64,
    #[serde(default = "default_write_bytes")]
    pub max_file_write_bytes: u64,
    /// Halt after this many denials inside `deny_window_secs`. 0 = never.
    #[serde(default = "default_deny_threshold")]
    pub deny_threshold: u32,
    #[serde(default = "default_deny_window")]
    pub deny_window_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            actions_per_minute: default_apm(),
            max_actions: default_max_actions(),
            max_bytes_out: default_bytes_out(),
            max_file_write_bytes: default_write_bytes(),
            deny_threshold: default_deny_threshold(),
            deny_window_secs: default_deny_window(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tripwires {
    /// Extra protected paths (the policy file, warden binary, audit log and
    /// state dir are always protected). Touching one halts the agent.
    #[serde(default)]
    pub protect_paths: Vec<String>,
    /// Honeypot paths (e.g. fake credentials). Reading one halts the agent.
    #[serde(default = "default_canaries")]
    pub canary_paths: Vec<String>,
    /// Programs whose mere attempted execution halts the agent.
    #[serde(default = "default_trip_commands")]
    pub commands: Vec<String>,
    #[serde(default = "yes")]
    pub halt_on_shell: bool,
    #[serde(default = "yes")]
    pub halt_on_secret: bool,
    #[serde(default = "yes")]
    pub halt_on_budget: bool,
}

impl Default for Tripwires {
    fn default() -> Self {
        Self {
            protect_paths: vec![],
            canary_paths: default_canaries(),
            commands: default_trip_commands(),
            halt_on_shell: true,
            halt_on_secret: true,
            halt_on_budget: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvPolicy {
    /// Variables copied from warden's environment. Everything else is dropped.
    #[serde(default = "default_env_pass")]
    pub pass: Vec<String>,
    /// Variables set explicitly (applied after `pass`, never scrubbed).
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    /// Glob patterns of variable names removed even if listed in `pass`.
    #[serde(default = "default_scrub")]
    pub scrub: Vec<String>,
}

impl Default for EnvPolicy {
    fn default() -> Self {
        Self {
            pass: default_env_pass(),
            set: BTreeMap::new(),
            scrub: default_scrub(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    /// Linux Landlock filesystem confinement (best effort; needs kernel >= 5.13).
    #[serde(default = "yes")]
    pub landlock: bool,
    /// Read/execute-only system paths the agent needs to run at all.
    #[serde(default = "default_ll_read")]
    pub landlock_extra_read: Vec<String>,
    #[serde(default = "default_ll_write")]
    pub landlock_extra_write: Vec<String>,
    /// Landlock TCP rules: the agent may only `connect()` to the egress
    /// proxy port (kernel >= 6.7).
    #[serde(default = "yes")]
    pub restrict_network: bool,
    /// seccomp-bpf blocklist of dangerous syscalls (ptrace, mount, bpf, ...).
    #[serde(default = "yes")]
    pub seccomp: bool,
    /// Also block UDP and raw sockets for IPv4/IPv6 via seccomp (kills DNS
    /// exfiltration, but also breaks local DNS resolution).
    #[serde(default)]
    pub block_udp: bool,
    #[serde(default)]
    pub rlimit_cpu_secs: Option<u64>,
    #[serde(default)]
    pub rlimit_fsize_bytes: Option<u64>,
    #[serde(default)]
    pub rlimit_nofile: Option<u64>,
    #[serde(default)]
    pub rlimit_as_bytes: Option<u64>,
    #[serde(default = "yes")]
    pub no_core_dumps: bool,
}

impl Default for Sandbox {
    fn default() -> Self {
        Self {
            landlock: true,
            landlock_extra_read: default_ll_read(),
            landlock_extra_write: default_ll_write(),
            restrict_network: true,
            seccomp: true,
            block_udp: false,
            rlimit_cpu_secs: None,
            rlimit_fsize_bytes: None,
            rlimit_nofile: None,
            rlimit_as_bytes: None,
            no_core_dumps: true,
        }
    }
}

fn yes() -> bool {
    true
}
fn default_search_path() -> Vec<String> {
    ["/usr/local/bin", "/usr/bin", "/bin"]
        .map(String::from)
        .to_vec()
}
fn default_timeout() -> u64 {
    30
}
fn default_max_output() -> usize {
    1 << 20
}
fn default_file_deny() -> Vec<String> {
    [
        "**/.ssh/**",
        "**/.gnupg/**",
        "**/.aws/**",
        "**/.config/gh/**",
        "**/.docker/config.json",
        "**/.netrc",
        "**/.git-credentials",
        "**/.env",
        "**/.env.*",
        "/etc/shadow",
        "/etc/sudoers",
        "/proc/*/environ",
        "/proc/*/mem",
    ]
    .map(String::from)
    .to_vec()
}
fn default_max_read() -> u64 {
    10 << 20
}
fn default_ports() -> Vec<u16> {
    vec![443]
}
fn default_methods() -> Vec<String> {
    ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        .map(String::from)
        .to_vec()
}
fn default_max_request() -> u64 {
    1 << 20
}
fn default_tunnel_bytes() -> u64 {
    16 << 20
}
fn default_max_response() -> u64 {
    8 << 20
}
fn default_apm() -> u32 {
    120
}
fn default_max_actions() -> u64 {
    5000
}
fn default_bytes_out() -> u64 {
    20 << 20
}
fn default_write_bytes() -> u64 {
    100 << 20
}
fn default_deny_threshold() -> u32 {
    10
}
fn default_deny_window() -> u64 {
    60
}
fn default_canaries() -> Vec<String> {
    vec![]
}
fn default_trip_commands() -> Vec<String> {
    [
        "sudo",
        "su",
        "doas",
        "pkexec",
        "kill",
        "pkill",
        "killall",
        "chattr",
        "iptables",
        "ip6tables",
        "nft",
        "mount",
        "umount",
        "nsenter",
        "unshare",
        "setcap",
        "chroot",
        "insmod",
        "modprobe",
        "systemctl",
        "crontab",
        "at",
    ]
    .map(String::from)
    .to_vec()
}
fn default_env_pass() -> Vec<String> {
    ["PATH", "HOME", "LANG", "LC_ALL", "TERM", "TZ", "USER"]
        .map(String::from)
        .to_vec()
}
fn default_scrub() -> Vec<String> {
    [
        "*TOKEN*",
        "*SECRET*",
        "*PASSWORD*",
        "*PASSWD*",
        "*_KEY",
        "*API_KEY*",
        "*APIKEY*",
        "*CREDENTIAL*",
        "*PRIVATE*",
        "AWS_*",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "SSH_AUTH_SOCK",
        "*SESSION*",
        "*COOKIE*",
    ]
    .map(String::from)
    .to_vec()
}
fn default_ll_read() -> Vec<String> {
    [
        "/usr",
        "/lib",
        "/lib64",
        "/bin",
        "/sbin",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/ssl",
        "/etc/ca-certificates",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/localtime",
        "/etc/passwd",
        "/etc/group",
        "/dev/urandom",
        "/dev/random",
        "/dev/null",
        "/proc/self",
    ]
    .map(String::from)
    .to_vec()
}
fn default_ll_write() -> Vec<String> {
    ["/dev/null", "/dev/tty"].map(String::from).to_vec()
}
