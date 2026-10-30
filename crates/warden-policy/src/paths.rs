//! Path normalisation used before any policy check, so `..`, `.` and
//! symlinks cannot be used to escape a scope.

use std::path::{Component, Path, PathBuf};

/// Lexically normalise `path` (joined onto `base` if relative): removes `.`
/// and resolves `..` without touching the filesystem.
pub fn lexical_normalize(path: &Path, base: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut out = PathBuf::from("/");
    for c in joined.components() {
        match c {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(p) => out.push(p),
        }
    }
    out
}

/// Resolve symlinks for the longest existing prefix of `path`, then append the
/// non-existent remainder. The result is what the kernel would actually touch.
pub fn resolve(path: &Path, base: &Path) -> PathBuf {
    let lex = lexical_normalize(path, base);
    let mut existing = lex.clone();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(canon) = std::fs::canonicalize(&existing) {
            let mut out = canon;
            for r in rest.iter().rev() {
                out.push(r);
            }
            // A dangling remainder could still contain `..` only if it was in
            // the input, which lexical normalisation already removed.
            return out;
        }
        match (
            existing.file_name().map(|s| s.to_os_string()),
            existing.parent(),
        ) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                existing = parent.to_path_buf();
            }
            _ => return lex,
        }
    }
}

/// Expand `${WORKSPACE}`, `${HOME}`, `${TMPDIR}` and a leading `~/`.
pub fn expand(pattern: &str, vars: &Vars) -> String {
    let mut s = pattern.to_string();
    if let Some(rest) = s.strip_prefix("~/") {
        s = format!("{}/{}", vars.home.display(), rest);
    }
    s.replace("${WORKSPACE}", &vars.workspace.display().to_string())
        .replace("${HOME}", &vars.home.display().to_string())
        .replace("${TMPDIR}", &vars.tmpdir.display().to_string())
}

/// Values substituted into policy patterns.
#[derive(Debug, Clone)]
pub struct Vars {
    pub workspace: PathBuf,
    pub home: PathBuf,
    pub tmpdir: PathBuf,
}

impl Vars {
    pub fn new(workspace: &Path) -> Self {
        let canon = |p: PathBuf| std::fs::canonicalize(&p).unwrap_or(p);
        Self {
            workspace: canon(workspace.to_path_buf()),
            home: canon(PathBuf::from(
                std::env::var("HOME").unwrap_or_else(|_| "/nonexistent".into()),
            )),
            tmpdir: canon(std::env::temp_dir()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotdot_cannot_escape_lexically() {
        let p = lexical_normalize(Path::new("a/../../../etc/passwd"), Path::new("/ws"));
        assert_eq!(p, PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn symlink_is_resolved() {
        let d = tempfile::tempdir().unwrap();
        let ws = d.path().join("ws");
        std::fs::create_dir(&ws).unwrap();
        std::os::unix::fs::symlink("/etc", ws.join("link")).unwrap();
        let r = resolve(Path::new("link/hostname"), &ws);
        assert!(r.starts_with("/etc"), "{r:?}");
    }

    #[test]
    fn nonexistent_tail_kept() {
        let d = tempfile::tempdir().unwrap();
        let r = resolve(Path::new("new/dir/file.txt"), d.path());
        assert!(r.ends_with("new/dir/file.txt"));
        assert!(r.starts_with(std::fs::canonicalize(d.path()).unwrap()));
    }
}
