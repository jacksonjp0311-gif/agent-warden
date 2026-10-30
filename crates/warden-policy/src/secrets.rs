//! Secret / credential pattern detection for data-exfiltration heuristics.

use regex::bytes::RegexSet;

/// (name, regex) pairs for common credential formats.
pub const BUILTIN_PATTERNS: &[(&str, &str)] = &[
    ("aws-access-key-id", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    (
        "aws-secret-key",
        r"(?i)aws.{0,20}secret.{0,20}[=:]\s*['\x22]?[A-Za-z0-9/+=]{40}",
    ),
    (
        "github-token",
        r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b",
    ),
    ("github-fine-grained", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    ("openai-key", r"\bsk-(proj-)?[A-Za-z0-9_\-]{32,}\b"),
    ("anthropic-key", r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b"),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("stripe-key", r"\b(sk|rk)_live_[0-9A-Za-z]{20,}\b"),
    ("private-key", r"-----BEGIN ([A-Z]+ )?PRIVATE KEY-----"),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    ),
];

/// Compiled scanner.
#[derive(Debug, Clone)]
pub struct SecretScanner {
    names: Vec<String>,
    set: RegexSet,
}

impl SecretScanner {
    pub fn new(extra: &[String]) -> Result<Self, regex::Error> {
        let mut names: Vec<String> = BUILTIN_PATTERNS
            .iter()
            .map(|(n, _)| n.to_string())
            .collect();
        let mut pats: Vec<String> = BUILTIN_PATTERNS
            .iter()
            .map(|(_, p)| p.to_string())
            .collect();
        for (i, p) in extra.iter().enumerate() {
            names.push(format!("custom-{i}"));
            pats.push(p.clone());
        }
        Ok(Self {
            names,
            set: RegexSet::new(&pats)?,
        })
    }

    /// Returns the name of the first matching pattern, if any.
    pub fn scan(&self, data: &[u8]) -> Option<&str> {
        self.set
            .matches(data)
            .iter()
            .next()
            .map(|i| self.names[i].as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_keys() {
        let s = SecretScanner::new(&[]).unwrap();
        assert_eq!(
            s.scan(b"key=AKIAIOSFODNN7EXAMPLE"),
            Some("aws-access-key-id")
        );
        assert_eq!(
            s.scan(b"token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"),
            Some("github-token")
        );
        assert_eq!(
            s.scan(b"-----BEGIN OPENSSH PRIVATE KEY-----"),
            Some("private-key")
        );
        assert_eq!(s.scan(b"hello world, nothing to see"), None);
    }

    #[test]
    fn custom_patterns() {
        let s = SecretScanner::new(&["CORP-[0-9]{6}".into()]).unwrap();
        assert_eq!(s.scan(b"id CORP-123456"), Some("custom-0"));
    }
}
