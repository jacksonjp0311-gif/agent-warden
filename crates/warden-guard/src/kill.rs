//! Process-tree termination.
//!
//! * Unix: killing only the process group is not enough, a child can
//!   `setsid()` its way out, so we also walk `/proc` and signal every
//!   descendant of the given root.
//! * Windows: the agent is placed in a Job Object created with
//!   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Every process it starts (detached
//!   or not) inherits the job, and `TerminateJobObject` ends them all. If
//!   warden itself dies, the job handle closes and the kernel kills the tree.

use std::time::Duration;

#[cfg(windows)]
pub use win::Job;

/// Where to deliver the kill.
#[derive(Debug, Clone)]
pub enum KillTarget {
    /// Unix: the agent's process group (also its pid) and the root of the
    /// process tree to sweep (warden itself when it is a child subreaper,
    /// otherwise the agent pid). On Windows `pgid` is a pid whose tree is
    /// ended with `taskkill /T /F`.
    Group { pgid: i32, tree_root: i32 },
    /// Windows: a Job Object holding the agent and all its descendants.
    #[cfg(windows)]
    Job { job: std::sync::Arc<Job>, pid: u32 },
}

impl KillTarget {
    /// A process group target (see [`KillTarget::Group`]).
    pub fn group(pgid: i32, tree_root: i32) -> Self {
        KillTarget::Group { pgid, tree_root }
    }

    /// Pid used in logs.
    pub fn pid(&self) -> i64 {
        match self {
            KillTarget::Group { pgid, .. } => *pgid as i64,
            #[cfg(windows)]
            KillTarget::Job { pid, .. } => *pid as i64,
        }
    }

    /// Kill everything this target covers. Returns the number of processes
    /// signalled / terminated (best effort).
    pub fn kill(&self, grace: Duration) -> usize {
        match self {
            #[cfg(unix)]
            KillTarget::Group { pgid, tree_root } => kill_tree(*pgid, *tree_root, grace),
            #[cfg(not(unix))]
            KillTarget::Group { pgid, .. } => {
                let _ = grace;
                taskkill_tree(*pgid as u32)
            }
            #[cfg(windows)]
            KillTarget::Job { job, .. } => {
                let _ = grace;
                job.terminate()
            }
        }
    }
}

/// End a process and its children with `taskkill /T /F` (Windows fallback
/// when no job is available).
#[cfg(not(unix))]
pub fn taskkill_tree(pid: u32) -> usize {
    let ok = std::process::Command::new("taskkill")
        .args(["/T", "/F", "/PID", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    usize::from(ok)
}

#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
mod unix {
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
                    if let Some(ppid) = rest.split_whitespace().nth(1).and_then(|s| s.parse().ok())
                    {
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

    /// Is `pid` running (and not a zombie)?
    pub fn alive(pid: i32) -> bool {
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
}

#[cfg(windows)]
mod win {
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// An owned Job Object. Dropping it kills every process still in it.
    #[derive(Debug)]
    pub struct Job(HANDLE);

    // The handle is an opaque kernel object reference, usable from any thread.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    impl Job {
        pub fn new() -> io::Result<Job> {
            unsafe {
                let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if h == 0 {
                    return Err(io::Error::last_os_error());
                }
                let job = Job(h);
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let ok = SetInformationJobObject(
                    h,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                if ok == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(job)
            }
        }

        /// Put a freshly spawned child (and so all its future descendants)
        /// into the job.
        pub fn assign(&self, child: &std::process::Child) -> io::Result<()> {
            let ok = unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle() as HANDLE) };
            if ok == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        /// Number of processes currently in the job.
        pub fn active(&self) -> usize {
            unsafe {
                let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
                let ok = QueryInformationJobObject(
                    self.0,
                    JobObjectBasicAccountingInformation,
                    &mut info as *mut _ as *mut core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                );
                if ok == 0 {
                    0
                } else {
                    info.ActiveProcesses as usize
                }
            }
        }

        /// Terminate every process in the job. Returns how many there were.
        pub fn terminate(&self) -> usize {
            let n = self.active();
            unsafe {
                TerminateJobObject(self.0, 1);
            }
            n
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(all(test, unix))]
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

#[cfg(all(test, windows))]
mod win_tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn job_kills_tree() {
        let job = std::sync::Arc::new(Job::new().unwrap());
        // ping -n 30 waits ~30s; a nested one simulates a grandchild.
        let mut child = Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        job.assign(&child).unwrap();
        assert!(job.active() >= 1);
        let t = KillTarget::Job {
            job: job.clone(),
            pid: child.id(),
        };
        assert!(t.kill(Duration::from_millis(100)) >= 1);
        let st = child.wait().unwrap();
        assert!(!st.success());
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(job.active(), 0);
    }
}
