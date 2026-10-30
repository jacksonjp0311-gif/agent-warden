//! # warden-guard
//!
//! The enforcement core of agent-warden:
//!
//! * [`Supervisor`]: shared state for one agent session. Every action, from
//!   the gateway or the egress proxy, goes through it: rate limits, budgets,
//!   denial counting, tripwires, audit logging and the kill switch.
//! * [`gateway`]: JSON-RPC (MCP-style) tool-call server over stdio or a Unix
//!   socket exposing `exec`, `read_file`, `write_file`, `list_dir` and
//!   `http_request`.
//! * [`exec`]: runs allowed commands with a scrubbed environment, timeout,
//!   output caps and the sandbox.
//! * [`sandbox`]: defense in depth on Linux: Landlock, seccomp, rlimits,
//!   `PR_SET_PDEATHSIG`. Every layer degrades gracefully when unavailable.
//! * [`launch`]: spawns and watches the agent process group.
//! * [`kill`]: process-tree termination.

pub mod exec;
pub mod gateway;
pub mod kill;
pub mod launch;
pub mod sandbox;
pub mod supervisor;

pub use supervisor::{HaltInfo, Supervisor};

/// Exit code used by `warden run` / `warden gateway` when the agent was halted.
pub const HALT_EXIT_CODE: i32 = 99;
