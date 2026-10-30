//! Shared enforcement state for one agent session.

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use warden_audit::AuditLog;
use warden_net::{Egress, Monitor};
use warden_policy::{Check, CompiledPolicy, TripKind, Verdict};

/// Why and when the session was halted.
#[derive(Debug, Clone, Serialize)]
pub struct HaltInfo {
    pub kind: TripKind,
    pub reason: String,
}

pub use crate::kill::KillTarget;

#[derive(Debug, Default, Clone, Serialize)]
pub struct Counters {
    pub actions: u64,
    pub allowed: u64,
    pub denied: u64,
    pub bytes_out: u64,
    pub file_bytes_written: u64,
}

struct State {
    counters: Counters,
    recent_actions: VecDeque<Instant>,
    recent_denials: VecDeque<Instant>,
}

type HaltHook = Box<dyn Fn(&HaltInfo) + Send + Sync>;

pub struct Supervisor {
    policy: Arc<CompiledPolicy>,
    log: Mutex<Option<AuditLog>>,
    state: Mutex<State>,
    halted: AtomicBool,
    halt: Mutex<Option<HaltInfo>>,
    target: Mutex<Option<KillTarget>>,
    hooks: Mutex<Vec<HaltHook>>,
    /// Echo decisions to stderr (for demos / operators).
    pub verbose: AtomicBool,
}

fn verdict_json(o: &Result<(), Verdict>) -> (&'static str, Option<&str>, Option<String>) {
    match o {
        Ok(()) => ("allow", None, None),
        Err(Verdict::Deny(r)) => ("deny", Some(r.as_str()), None),
        Err(Verdict::Trip(k, r)) => ("trip", Some(r.as_str()), Some(k.to_string())),
    }
}

impl Supervisor {
    pub fn new(policy: Arc<CompiledPolicy>, log: Option<AuditLog>) -> Arc<Self> {
        Arc::new(Self {
            policy,
            log: Mutex::new(log),
            state: Mutex::new(State {
                counters: Counters::default(),
                recent_actions: VecDeque::new(),
                recent_denials: VecDeque::new(),
            }),
            halted: AtomicBool::new(false),
            halt: Mutex::new(None),
            target: Mutex::new(None),
            hooks: Mutex::new(vec![]),
            verbose: AtomicBool::new(false),
        })
    }

    pub fn policy(&self) -> &Arc<CompiledPolicy> {
        &self.policy
    }

    pub fn counters(&self) -> Counters {
        self.state.lock().unwrap().counters.clone()
    }

    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst)
    }

    pub fn halt_info(&self) -> Option<HaltInfo> {
        self.halt.lock().unwrap().clone()
    }

    /// Register the agent process to kill when halting. If the session is
    /// already halted, the kill happens immediately.
    pub fn set_kill_target(&self, t: KillTarget) {
        *self.target.lock().unwrap() = Some(t.clone());
        if self.is_halted() {
            t.kill(Duration::from_millis(1500));
        }
    }

    pub fn on_halt(&self, f: impl Fn(&HaltInfo) + Send + Sync + 'static) {
        self.hooks.lock().unwrap().push(Box::new(f));
    }

    /// Append an event to the audit log. Failure to log is fatal: an
    /// unlogged agent is an unsupervised agent, so we halt.
    pub fn log(&self, event: Value) {
        let failed = {
            let mut g = self.log.lock().unwrap();
            match g.as_mut() {
                Some(l) => l.append(event).err(),
                None => None,
            }
        };
        if let Some(e) = failed {
            eprintln!("warden: AUDIT LOG WRITE FAILED: {e}");
            // Detach the broken log so halt() does not recurse on it.
            *self.log.lock().unwrap() = None;
            self.halt(
                TripKind::ProtectedPath,
                format!("audit log write failed: {e}"),
            );
        }
    }

    /// Pre-flight checks that apply to every action: halted, rate, budget.
    fn admit(&self) -> Check<()> {
        if self.is_halted() {
            return Err(Verdict::Deny("agent halted by warden".into()));
        }
        let l = &self.policy.policy.limits;
        let mut s = self.state.lock().unwrap();
        let now = Instant::now();
        while s
            .recent_actions
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            s.recent_actions.pop_front();
        }
        s.counters.actions += 1;
        if s.counters.actions > l.max_actions {
            let msg = format!("action budget exhausted ({} actions)", l.max_actions);
            return Err(self.budget_verdict(msg));
        }
        if l.actions_per_minute > 0 && s.recent_actions.len() as u32 >= l.actions_per_minute {
            return Err(Verdict::Deny(format!(
                "rate limit: more than {} actions per minute",
                l.actions_per_minute
            )));
        }
        s.recent_actions.push_back(now);
        Ok(())
    }

    fn budget_verdict(&self, msg: String) -> Verdict {
        if self.policy.policy.tripwires.halt_on_budget {
            Verdict::Trip(TripKind::Budget, msg)
        } else {
            Verdict::Deny(msg)
        }
    }

    /// Log a decision and react to it (count denials, fire tripwires).
    fn settle(&self, source: &str, method: &str, details: Value, o: &Result<(), Verdict>) {
        let (decision, reason, trip) = verdict_json(o);
        if self.verbose.load(Ordering::Relaxed) {
            match reason {
                None => eprintln!("warden: ALLOW {method} {}", compact(&details)),
                Some(r) => eprintln!(
                    "warden: {} {method} {} -- {r}",
                    if trip.is_some() { "TRIP " } else { "DENY " },
                    compact(&details)
                ),
            }
        }
        self.log(json!({
            "kind": "action",
            "source": source,
            "method": method,
            "params": details,
            "decision": decision,
            "reason": reason,
            "tripwire": trip,
        }));
        match o {
            Ok(()) => self.state.lock().unwrap().counters.allowed += 1,
            Err(Verdict::Trip(k, r)) => {
                self.state.lock().unwrap().counters.denied += 1;
                self.halt(*k, r.clone());
            }
            Err(Verdict::Deny(_)) => {
                if self.is_halted() {
                    return;
                }
                let l = &self.policy.policy.limits;
                let over = {
                    let mut s = self.state.lock().unwrap();
                    s.counters.denied += 1;
                    let now = Instant::now();
                    let win = Duration::from_secs(l.deny_window_secs.max(1));
                    while s
                        .recent_denials
                        .front()
                        .is_some_and(|t| now.duration_since(*t) > win)
                    {
                        s.recent_denials.pop_front();
                    }
                    s.recent_denials.push_back(now);
                    l.deny_threshold > 0 && s.recent_denials.len() as u32 >= l.deny_threshold
                };
                if over {
                    self.halt(
                        TripKind::DenyThreshold,
                        format!(
                            "{} denials within {}s",
                            l.deny_threshold, l.deny_window_secs
                        ),
                    );
                }
            }
        }
    }

    /// Gate one gateway action: admission, the policy `check`, logging and
    /// reaction. The returned value is what the caller may act on.
    pub fn gate<T>(
        &self,
        method: &str,
        details: Value,
        check: impl FnOnce() -> Check<T>,
    ) -> Check<T> {
        let out = self.admit().and_then(|_| check());
        let o = out.as_ref().map(|_| ()).map_err(Clone::clone);
        self.settle("gateway", method, details, &o);
        out
    }

    /// Account bytes written to files. Returns false if over budget.
    pub fn file_bytes(&self, n: u64) -> Check<()> {
        let l = &self.policy.policy.limits;
        let mut s = self.state.lock().unwrap();
        if s.counters.file_bytes_written + n > l.max_file_write_bytes {
            drop(s);
            let v = self.budget_verdict(format!(
                "file write budget exhausted ({} bytes)",
                l.max_file_write_bytes
            ));
            return Err(v);
        }
        s.counters.file_bytes_written += n;
        Ok(())
    }

    /// Record a post-hoc verdict (e.g. budget hit after the gate passed).
    pub fn late_verdict(&self, method: &str, details: Value, v: &Verdict) {
        self.settle("gateway", method, details, &Err(v.clone()));
    }

    /// Halt the session: log it, run hooks, kill the agent process tree.
    /// Idempotent: only the first call has an effect.
    pub fn halt(&self, kind: TripKind, reason: String) {
        if self.halted.swap(true, Ordering::SeqCst) {
            return;
        }
        let info = HaltInfo { kind, reason };
        *self.halt.lock().unwrap() = Some(info.clone());
        eprintln!("warden: *** HALT ({}) {} ***", info.kind, info.reason);
        let counters = self.counters();
        self.log(json!({
            "kind": "halt",
            "tripwire": info.kind,
            "reason": info.reason,
            "counters": counters,
        }));
        for h in self.hooks.lock().unwrap().iter() {
            h(&info);
        }
        let target = self.target.lock().unwrap().clone();
        if let Some(t) = target {
            let n = t.kill(Duration::from_millis(1500));
            self.log(json!({"kind": "killed", "pgid": t.pid(), "processes": n}));
        }
    }
}

fn compact(v: &Value) -> String {
    let s = v.to_string();
    if s.len() > 160 {
        format!(
            "{}…",
            &s[..s.char_indices().nth(157).map(|x| x.0).unwrap_or(s.len())]
        )
    } else {
        s
    }
}

impl Monitor for Supervisor {
    fn record(&self, ev: &Egress, outcome: &Result<(), Verdict>) -> Result<(), Verdict> {
        let o = self.admit().and(outcome.clone());
        let details = serde_json::to_value(ev).unwrap_or(Value::Null);
        let method = if ev.via == "gateway-http" {
            "http_request"
        } else {
            "egress"
        };
        let source = if ev.via == "gateway-http" {
            "gateway"
        } else {
            "proxy"
        };
        self.settle(source, method, details, &o);
        o
    }

    fn bytes_out(&self, n: u64) -> bool {
        let max = self.policy.policy.limits.max_bytes_out;
        let over = {
            let mut s = self.state.lock().unwrap();
            s.counters.bytes_out += n;
            s.counters.bytes_out > max
        };
        if over {
            let v = self.budget_verdict(format!("network byte budget exhausted ({max} bytes)"));
            self.settle("proxy", "egress_bytes", json!({"bytes": n}), &Err(v));
            return false;
        }
        true
    }

    fn halted(&self) -> bool {
        self.is_halted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_policy::{Context, Policy};

    fn sup(toml: &str) -> (tempfile::TempDir, Arc<Supervisor>) {
        let d = tempfile::tempdir().unwrap();
        let p = CompiledPolicy::compile(
            Policy::from_toml(toml).unwrap(),
            &Context {
                workspace: d.path().into(),
                protected: vec![],
            },
        )
        .unwrap();
        let log = AuditLog::open(&d.path().join("a.jsonl"), None).unwrap();
        (d, Supervisor::new(Arc::new(p), Some(log)))
    }

    #[test]
    fn deny_threshold_halts() {
        let (d, s) = sup("[limits]\ndeny_threshold = 3\n");
        for _ in 0..2 {
            let _ = s.gate::<()>("x", json!({}), || Err(Verdict::Deny("no".into())));
            assert!(!s.is_halted());
        }
        let _ = s.gate::<()>("x", json!({}), || Err(Verdict::Deny("no".into())));
        assert!(s.is_halted());
        assert_eq!(s.halt_info().unwrap().kind, TripKind::DenyThreshold);
        // everything is refused afterwards, even things that would pass
        assert!(s.gate("x", json!({}), || Ok(())).is_err());
        let rep = warden_audit::verify(&d.path().join("a.jsonl"), None, true).unwrap();
        assert!(rep.records >= 5);
    }

    #[test]
    fn budget_halts() {
        let (_d, s) = sup("[limits]\nmax_actions = 2\n");
        assert!(s.gate("x", json!({}), || Ok(())).is_ok());
        assert!(s.gate("x", json!({}), || Ok(())).is_ok());
        assert!(s.gate("x", json!({}), || Ok(())).is_err());
        assert_eq!(s.halt_info().unwrap().kind, TripKind::Budget);
    }

    #[test]
    fn rate_limit_denies() {
        let (_d, s) = sup("[limits]\nactions_per_minute = 2\ndeny_threshold = 0\n");
        assert!(s.gate("x", json!({}), || Ok(())).is_ok());
        assert!(s.gate("x", json!({}), || Ok(())).is_ok());
        let r = s.gate("x", json!({}), || Ok(()));
        assert!(matches!(r, Err(Verdict::Deny(m)) if m.contains("rate limit")));
        assert!(!s.is_halted());
    }

    #[test]
    fn tripwire_halts_and_runs_hooks() {
        let (_d, s) = sup("");
        let fired = Arc::new(AtomicBool::new(false));
        let f2 = fired.clone();
        s.on_halt(move |_| f2.store(true, Ordering::SeqCst));
        let _ = s.gate::<()>("exec", json!({}), || {
            Err(Verdict::Trip(TripKind::Shell, "bash".into()))
        });
        assert!(s.is_halted());
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn byte_budget() {
        let (_d, s) = sup("[limits]\nmax_bytes_out = 100\n");
        assert!(s.bytes_out(60));
        assert!(!s.bytes_out(60));
        assert!(s.is_halted());
    }
}
