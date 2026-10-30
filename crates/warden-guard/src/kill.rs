//! Process-tree termination. Killing only the process group is not enough:
//! a child can `setsid()` its way out. We also walk `/proc` and signal every
//! descendant of the given root.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Map of pid -> parent pid, read from `/proc/*/stat`.
fn ppid_map() -> HashMap<i32, i32> {
    let mut m = HashMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return m;
    };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            // comm may contain spaces/parens; ppid is the 2nd field after the last ')'
            if let Some(rest) = stat.rsplit_once(')').map(|x| x.1) {
                if let Some(ppid) = rest.split_whitespace().nth(1).and_then(|s| s.parse().ok()) {
                    m.insert(pid, ppid);
                }
            }
        }
    }
    m
}

/// All descendants of `root` (not including `root`).
pub fn descendants(root: i32) -> Vec<i32> {
    let m = ppid_map();
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for (&pid, &pp) in &m {
        children.entry(pp).or_default().push(pid);
    }
    let mut out = vec![];
    let mut seen = HashSet::new();
    let mut stack = vec![root];
    while let Some(p) = stack.pop() {
        for &c in children.get(&p).map(|v| v.as_slice()).unwrap_or(&[]) {
            if seen.insert(c) {
                out.push(c);
                stack.push(c);
            }
        }
    }
    out
}

fn alive(pid: i32) -> bool {
    // A zombie still "exists" for kill(0); check the state field too.
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => !s
            .rsplit_once(')')
            .map(|x| x.1.trim_start().starts_with('Z'))
            .unwrap_or(false),
        Err(_) => true,
    }
}

/// SIGTERM the process group `pgid` and the process tree under `tree_root`
/// (excluding `tree_root` itself unless it is `pgid`), wait up to `grace`, then
/// SIGKILL whatever is left. Returns the number of processes signalled.
pub fn kill_tree(pgid: i32, tree_root: i32, grace: Duration) -> usize {
    let mut targets: Vec<i32> = descendants(tree_root);
    if pgid > 0 && !targets.contains(&pgid) {
        targets.push(pgid);
    }
    let me = std::process::id() as i32;
    targets.retain(|&p| p != me && p > 1);
    unsafe {
        if pgid > 1 {
            libc::kill(-pgid, libc::SIGTERM);
        }
        for &p in &targets {
            libc::kill(p, libc::SIGTERM);
        }
    }
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline && targets.iter().any(|&p| alive(p)) {
        std::thread::sleep(Duration::from_millis(20));
    }
    // Re-scan: something may have forked during the grace period.
    let mut late = descendants(tree_root);
    late.retain(|&p| p != me && p > 1);
    unsafe {
        if pgid > 1 {
            libc::kill(-pgid, libc::SIGKILL);
        }
        for &p in targets.iter().chain(late.iter()) {
            libc::kill(p, libc::SIGKILL);
        }
    }
    targets.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    #[test]
    fn kills_group_and_escaped_children() {
        // A parent in its own group whose child escapes with setsid.
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "setsid sleep 30 & sleep 30"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        std::thread::sleep(Duration::from_millis(200));
        let before = descendants(pid);
        assert!(!before.is_empty(), "expected sleeping children");
        kill_tree(pid, pid, Duration::from_millis(500));
        let _ = child.wait();
        std::thread::sleep(Duration::from_millis(100));
        for p in before {
            assert!(!alive(p), "pid {p} survived");
        }
    }
}
