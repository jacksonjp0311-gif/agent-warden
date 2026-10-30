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
    // Simplify first: in verbatim (`\\?\`) form `..` is not a component.
    let mut out = PathBuf::new();
    for c in simplify(joined).components() {
        match c {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(std::path::MAIN_SEPARATOR_STR),
            Component::CurDir => {}
            Component::ParentDir => {
                // `pop` never removes the root (or a Windows drive prefix).
                out.pop();
            }
            Component::Normal(p) => out.push(p),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(std::path::MAIN_SEPARATOR_STR);
    }
    simplify(out)
}

/// On Windows, turn verbatim paths (`\\?\C:\x`, as returned by
/// `canonicalize`) into their ordinary form (`C:\x`) so they compare and
/// glob-match like user-written paths. A no-op elsewhere.
pub fn simplify(p: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let s = p.as_os_str().to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            let b = rest.as_bytes();
            if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
                return PathBuf::from(rest);
            }
        }
    }
    p
}

/// Canonicalize (resolving symlinks), in the simplified form.
pub fn canonicalize(p: &Path) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(p).map(simplify)
}

/// A path rendered for glob patterns and matching: always `/`-separated.
pub fn slashed(p: &Path) -> String {
    let s = p.display().to_string();
    if cfg!(windows) {
        s.replace('\\', "/")
    } else {
        s
    }
}

/// Resolve symlinks for the longest existing prefix of `path`, then append the
/// non-existent remainder. The result is what the kernel would actually touch.
pub fn resolve(path: &Path, base: &Path) -> PathBuf {
    // `~/x` means the home directory, as an agent (or a human) would expect;
    // otherwise it would silently become `<workspace>/~/x`.
    let tilde;
    let path = match path.to_str().and_then(|s| {
        s.strip_prefix("~/")
            .or_else(|| s.strip_prefix("~\\").filter(|_| cfg!(windows)))
    }) {
        Some(rest) => match home_dir() {
            Some(h) => {
                tilde = h.join(rest);
                tilde.as_path()
            }
            None => path,
        },
        None => path,
    };
    let lex = lexical_normalize(path, base);
    let mut existing = lex.clone();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(canon) = canonicalize(&existing) {
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
        s = format!("{}/{}", slashed(&vars.home), rest);
    }
    s.replace("${WORKSPACE}", &slashed(&vars.workspace))
        .replace("${HOME}", &slashed(&vars.home))
        .replace("${TMPDIR}", &slashed(&vars.tmpdir))
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
        let canon = |p: PathBuf| canonicalize(&p).unwrap_or(p);
        Self {
            workspace: canon(workspace.to_path_buf()),
            home: canon(home_dir().unwrap_or_else(|| PathBuf::from("/nonexistent"))),
            tmpdir: canon(std::env::temp_dir()),
        }
    }
}

/// The user's home directory (`$HOME`, or `%USERPROFILE%` on Windows).
pub fn home_dir() -> Option<PathBuf> {
    let keys: &[&str] = if cfg!(windows) {
        &["USERPROFILE", "HOME"]
    } else {
        &["HOME"]
    };
    keys.iter()
        .filter_map(std::env::var_os)
        .find(|v| !v.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn dotdot_cannot_escape_lexically() {
        let p = lexical_normalize(Path::new("a/../../../etc/passwd"), Path::new("/ws"));
        assert_eq!(p, PathBuf::from("/etc/passwd"));
    }

    #[cfg(windows)]
    #[test]
    fn dotdot_cannot_escape_drive() {
        let p = lexical_normalize(
            Path::new(r"a\..\..\..\Windows\win.ini"),
            Path::new(r"C:\ws"),
        );
        assert_eq!(p, PathBuf::from(r"C:\Windows\win.ini"));
        assert_eq!(
            simplify(PathBuf::from(r"\\?\C:\x\y")),
            PathBuf::from(r"C:\x\y")
        );
        assert_eq!(slashed(Path::new(r"C:\x\y")), "C:/x/y");
    }

    #[cfg(unix)]
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
        assert!(r.ends_with(Path::new("new").join("dir").join("file.txt")));
        assert!(r.starts_with(canonicalize(d.path()).unwrap()));
    }
}
