# Contributing to agent-warden

Thanks for helping keep agents on a leash.

## Ground rules

* **Default deny is the invariant.** A change must never make an empty or
  partial policy allow more than before. New policy fields need safe defaults
  and must reject unknown keys (`deny_unknown_fields`).
* **Fail closed.** If warden cannot check, log, or enforce something, it
  refuses or halts. It never proceeds silently.
* **Every guard gets a test that proves it blocks.** Add a unit test next to
  the check, and an integration test in `crates/warden-cli/tests/` (or a new
  `rogue-agent` scenario) when behaviour is user-visible.
* **Be honest in docs.** If a feature has a gap, document it in the README
  threat model.

## Workflow

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace
./demo/run-demo.sh
```

Open a pull request against `main`. CI runs on pull requests and pushes
only. Please do **not** add `schedule:` triggers or large build matrices,
because Actions minutes are limited.

## Reporting security issues

Do **not** open a public issue for a bypass. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are dual-licensed under
MIT OR Apache-2.0, as described in the README, without additional terms.
