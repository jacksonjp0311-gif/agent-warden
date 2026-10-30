//! # warden-audit
//!
//! Append-only JSONL audit log. Each line is a [`Record`] whose `hash` is
//! `SHA-256(prev_hash ‖ seq ‖ ts ‖ canonical_json(event))`, so editing,
//! inserting, reordering or deleting any line breaks the chain. A sidecar
//! `<log>.head` file pins the latest `(seq, hash)` so tail truncation is
//! detected too. Optionally every hash is signed with ed25519, so someone
//! without the signing key cannot rebuild a valid chain after tampering.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
pub use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub seq: u64,
    pub ts: String,
    pub event: Value,
    pub prev: String,
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Head {
    pub seq: u64,
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("existing log failed verification, refusing to append: {0}")]
    Corrupt(VerifyError),
    #[error("bad key: {0}")]
    Key(String),
}

/// A verification failure, pointing at the first bad line (1-based).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("line {line}: {msg}")]
pub struct VerifyError {
    pub line: usize,
    pub msg: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VerifyReport {
    pub records: u64,
    pub head_hash: String,
    pub signed: bool,
    pub head_file_checked: bool,
}

/// Deterministic JSON: object keys sorted recursively, no whitespace.
pub fn canonical_json(v: &Value) -> String {
    fn canon(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<_> = m.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), canon(&m[k]));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(canon).collect()),
            other => other.clone(),
        }
    }
    // serde_json::Map is a BTreeMap unless `preserve_order` is enabled; the
    // explicit sort above keeps this correct either way.
    serde_json::to_string(&canon(v)).expect("serialising a Value cannot fail")
}

pub fn compute_hash(prev: &str, seq: u64, ts: &str, event: &Value) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(seq.to_string().as_bytes());
    h.update(b"\n");
    h.update(ts.as_bytes());
    h.update(b"\n");
    h.update(canonical_json(event).as_bytes());
    hex::encode(h.finalize())
}

pub fn head_path(log: &Path) -> PathBuf {
    let mut s = log.as_os_str().to_os_string();
    s.push(".head");
    PathBuf::from(s)
}

/// Generate a new signing key; returns (secret_hex, public_hex).
pub fn generate_key() -> (String, String) {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    (
        hex::encode(sk.to_bytes()),
        hex::encode(sk.verifying_key().to_bytes()),
    )
}

pub fn parse_signing_key(hex_str: &str) -> Result<SigningKey, AuditError> {
    let b = hex::decode(hex_str.trim()).map_err(|e| AuditError::Key(e.to_string()))?;
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| AuditError::Key("signing key must be 32 bytes hex".into()))?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey, AuditError> {
    let b = hex::decode(hex_str.trim()).map_err(|e| AuditError::Key(e.to_string()))?;
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| AuditError::Key("public key must be 32 bytes hex".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| AuditError::Key(e.to_string()))
}

fn sign(key: &SigningKey, hash: &str) -> String {
    hex::encode(key.sign(hash.as_bytes()).to_bytes())
}

fn check_sig(vk: &VerifyingKey, hash: &str, sig: Option<&str>) -> Result<(), String> {
    let sig = sig.ok_or("record is not signed")?;
    let b = hex::decode(sig).map_err(|e| format!("bad signature hex: {e}"))?;
    let arr: [u8; 64] = b.try_into().map_err(|_| "signature must be 64 bytes")?;
    vk.verify(hash.as_bytes(), &Signature::from_bytes(&arr))
        .map_err(|_| "signature does not verify".to_string())
}

/// An open, append-only audit log.
pub struct AuditLog {
    file: File,
    path: PathBuf,
    seq: u64,
    prev: String,
    key: Option<SigningKey>,
}

impl AuditLog {
    /// Open (or create) a log. An existing log is fully verified first; a
    /// tampered log is never appended to.
    pub fn open(path: &Path, key: Option<SigningKey>) -> Result<Self, AuditError> {
        let (seq, prev) = if path.exists() && std::fs::metadata(path)?.len() > 0 {
            let vk = key.as_ref().map(|k| k.verifying_key());
            let rep = verify(path, vk.as_ref(), true).map_err(AuditError::Corrupt)?;
            (rep.records, rep.head_hash)
        } else {
            (0, GENESIS.to_string())
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            seq,
            prev,
            key,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> u64 {
        self.seq
    }

    pub fn is_empty(&self) -> bool {
        self.seq == 0
    }

    /// Append an event; it is flushed and fsync'd before returning.
    pub fn append(&mut self, event: Value) -> Result<Record, AuditError> {
        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        let hash = compute_hash(&self.prev, self.seq, &ts, &event);
        let sig = self.key.as_ref().map(|k| sign(k, &hash));
        let rec = Record {
            seq: self.seq,
            ts,
            event,
            prev: self.prev.clone(),
            hash: hash.clone(),
            sig: sig.clone(),
        };
        let mut line = serde_json::to_string(&rec)?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()?;
        self.seq += 1;
        self.prev = hash.clone();
        let head = Head {
            seq: rec.seq,
            hash,
            sig,
        };
        let hp = head_path(&self.path);
        let tmp = hp.with_extension("head.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&head)?)?;
        std::fs::rename(&tmp, &hp)?;
        Ok(rec)
    }
}

/// Verify a log end to end. With `pubkey`, every record must carry a valid
/// signature. With `check_head`, the `.head` sidecar (if present) must match
/// the final record, which detects truncation of the tail.
pub fn verify(
    path: &Path,
    pubkey: Option<&VerifyingKey>,
    check_head: bool,
) -> Result<VerifyReport, VerifyError> {
    let err = |line: usize, msg: String| VerifyError { line, msg };
    let f = File::open(path).map_err(|e| err(0, format!("cannot open log: {e}")))?;
    let mut prev = GENESIS.to_string();
    let mut n: u64 = 0;
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let lineno = i + 1;
        let line = line.map_err(|e| err(lineno, format!("read error: {e}")))?;
        if line.trim().is_empty() {
            return Err(err(lineno, "blank line inserted".into()));
        }
        let rec: Record =
            serde_json::from_str(&line).map_err(|e| err(lineno, format!("not a record: {e}")))?;
        if rec.seq != n {
            return Err(err(
                lineno,
                format!(
                    "sequence {} where {} expected (line deleted or reordered)",
                    rec.seq, n
                ),
            ));
        }
        if rec.prev != prev {
            return Err(err(
                lineno,
                "prev hash does not match previous record".into(),
            ));
        }
        let h = compute_hash(&rec.prev, rec.seq, &rec.ts, &rec.event);
        if h != rec.hash {
            return Err(err(
                lineno,
                "content hash mismatch (record was edited)".into(),
            ));
        }
        if let Some(vk) = pubkey {
            check_sig(vk, &rec.hash, rec.sig.as_deref()).map_err(|m| err(lineno, m))?;
        }
        prev = rec.hash;
        n += 1;
    }
    let mut head_checked = false;
    if check_head {
        let hp = head_path(path);
        if hp.exists() {
            let raw = std::fs::read(&hp).map_err(|e| err(0, format!("head file: {e}")))?;
            let head: Head =
                serde_json::from_slice(&raw).map_err(|e| err(0, format!("head file: {e}")))?;
            if n == 0 || head.seq != n - 1 || head.hash != prev {
                return Err(err(
                    n as usize,
                    format!(
                        "log ends at record {} but head file pins record {} (tail truncated or head forged)",
                        n as i64 - 1,
                        head.seq
                    ),
                ));
            }
            if let Some(vk) = pubkey {
                check_sig(vk, &head.hash, head.sig.as_deref())
                    .map_err(|m| err(0, format!("head file: {m}")))?;
            }
            head_checked = true;
        } else if n > 0 {
            return Err(err(0, "head file missing (deleted?)".into()));
        }
    }
    Ok(VerifyReport {
        records: n,
        head_hash: prev,
        signed: pubkey.is_some(),
        head_file_checked: head_checked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write_log(n: usize, key: Option<SigningKey>) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("audit.jsonl");
        let mut log = AuditLog::open(&p, key).unwrap();
        for i in 0..n {
            log.append(json!({"kind": "test", "i": i, "z": {"b": 1, "a": 2}}))
                .unwrap();
        }
        (d, p)
    }

    fn lines(p: &Path) -> Vec<String> {
        std::fs::read_to_string(p)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    fn put(p: &Path, l: &[String]) {
        std::fs::write(p, l.join("\n") + "\n").unwrap();
    }

    #[test]
    fn intact_log_verifies() {
        let (_d, p) = write_log(5, None);
        let r = verify(&p, None, true).unwrap();
        assert_eq!(r.records, 5);
        assert!(r.head_file_checked);
    }

    #[test]
    fn canonical_json_is_order_independent() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":3}}"#).unwrap();
        assert_eq!(canonical_json(&a), r#"{"a":{"x":3,"y":2},"b":1}"#);
    }

    #[test]
    fn edit_is_detected() {
        let (_d, p) = write_log(5, None);
        let mut l = lines(&p);
        l[2] = l[2].replace("\"i\":2", "\"i\":99");
        put(&p, &l);
        let e = verify(&p, None, true).unwrap_err();
        assert_eq!(e.line, 3);
        assert!(e.msg.contains("edited"));
    }

    #[test]
    fn deletion_is_detected() {
        let (_d, p) = write_log(5, None);
        let mut l = lines(&p);
        l.remove(1);
        put(&p, &l);
        let e = verify(&p, None, true).unwrap_err();
        assert_eq!(e.line, 2);
    }

    #[test]
    fn truncation_is_detected_via_head() {
        let (_d, p) = write_log(5, None);
        let mut l = lines(&p);
        l.truncate(3);
        put(&p, &l);
        let e = verify(&p, None, true).unwrap_err();
        assert!(e.msg.contains("truncated"), "{e}");
        // without the head check the shortened chain is self-consistent
        assert!(verify(&p, None, false).is_ok());
    }

    #[test]
    fn deleting_head_is_detected() {
        let (_d, p) = write_log(2, None);
        std::fs::remove_file(head_path(&p)).unwrap();
        assert!(verify(&p, None, true).is_err());
    }

    #[test]
    fn rehash_without_key_fails_signature_check() {
        let (sk_hex, pk_hex) = generate_key();
        let sk = parse_signing_key(&sk_hex).unwrap();
        let pk = parse_verifying_key(&pk_hex).unwrap();
        let (_d, p) = write_log(3, Some(sk));
        assert!(verify(&p, Some(&pk), true).unwrap().signed);

        // attacker edits record 1 and recomputes every hash (no key)
        let mut recs: Vec<Record> = lines(&p)
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        recs[1].event = json!({"kind": "innocent"});
        let mut prev = GENESIS.to_string();
        for r in recs.iter_mut() {
            r.prev = prev.clone();
            r.hash = compute_hash(&r.prev, r.seq, &r.ts, &r.event);
            prev = r.hash.clone();
        }
        let l: Vec<String> = recs
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect();
        put(&p, &l);
        let head = Head {
            seq: 2,
            hash: prev,
            sig: recs[2].sig.clone(),
        };
        std::fs::write(head_path(&p), serde_json::to_vec(&head).unwrap()).unwrap();

        assert!(
            verify(&p, None, true).is_ok(),
            "unsigned chain is self-consistent"
        );
        let e = verify(&p, Some(&pk), true).unwrap_err();
        assert!(e.msg.contains("signature"), "{e}");
    }

    #[test]
    fn reopen_continues_chain_and_refuses_corrupt() {
        let (_d, p) = write_log(2, None);
        let mut log = AuditLog::open(&p, None).unwrap();
        assert_eq!(log.len(), 2);
        log.append(json!({"kind": "more"})).unwrap();
        assert_eq!(verify(&p, None, true).unwrap().records, 3);
        let mut l = lines(&p);
        l[0] = l[0].replace("test", "tset");
        put(&p, &l);
        assert!(matches!(
            AuditLog::open(&p, None),
            Err(AuditError::Corrupt(_))
        ));
    }
}
