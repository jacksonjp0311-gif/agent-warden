# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## 0.1.0 - 2026-10-30

First public release.

### Added

- **Policy engine** (`warden-policy`): default-deny TOML policies for commands
  (per-argument globs), file read and write scopes, an always-deny list for
  well-known secrets, domain, port and method allowlists, rate limits, and
  action and byte budgets. `~/` is expanded, so `~/.ssh/**` means the real
  home directory on every platform. Unknown fields are rejected.
- **Tool gateway** (`warden-guard`): MCP-compatible JSON-RPC 2.0 over a Unix
  socket, stdio, or (Windows) a loopback TCP socket that requires a 256-bit
  per-session token. Tools: `exec`, `read_file`, `write_file`, `delete_file`,
  `list_dir`, `http_request`.
- **Command guard**: no shells or inline interpreters (tripwire), programs
  resolved from the policy's search path, scrubbed environment, timeouts,
  output caps.
- **Network guard** (`warden-net`): HTTP/CONNECT egress proxy with domain and
  port allowlists, private and metadata IP blocking after DNS resolution with
  address pinning, and secret-pattern detection in outbound requests.
- **Tamper-evident audit log** (`warden-audit`): SHA-256 hash chain, `.head`
  sidecar against truncation, optional ed25519 signatures, `warden verify-log`.
- **Tripwires and kill switch**: deny threshold, budgets, protected and canary
  paths, shells, forbidden commands, secret exfiltration, and on-disk changes to
  the policy, binary or log. `warden kill` takes down the whole process tree.
- **Linux kernel sandbox** (default feature): Landlock (filesystem scopes, TCP
  connect only to the proxy), seccomp blocklist, rlimits, `PR_SET_PDEATHSIG`,
  child subreaper.
- **Windows support**: native build; Job Object kill switch with
  kill-on-close (breakaway refused), token-authenticated TCP gateway,
  `%LOCALAPPDATA%` state directory. No kernel sandbox; this is reported at
  startup and in the audit log.
- `rogue-agent` demo with `full`, `threshold`, `exfil`, `wipe`, `escape` and
  `honest` scenarios, plus `demo/run-demo.sh`.
- Shipped policies: `strict.toml`, `dev.toml`, `demo.toml`.
- `evidence/` with test, demo, audit-log and tamper-detection output from
  Linux and Windows runs.
- README sections: Who this is for, Platform support, Trust boundary.

