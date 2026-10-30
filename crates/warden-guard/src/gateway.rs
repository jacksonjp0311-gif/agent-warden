//! Tool-call gateway: newline-delimited JSON-RPC 2.0, MCP-compatible.
//!
//! The agent never touches the filesystem, processes or network "for real"
//! through warden; it asks, and the gateway checks every request against the
//! policy, logs the decision and only then acts.
//!
//! Methods:
//! * MCP: `initialize`, `tools/list`, `tools/call` (`{name, arguments}`),
//!   `notifications/*` (ignored), `ping`.
//! * Direct: `exec`, `read_file`, `write_file`, `delete_file`, `list_dir`,
//!   `http_request`, `status`.
//!
//! Transports: stdio, a Unix socket (mode 0600, Unix), or loopback TCP with a
//! per-session token as the first line (Windows, see [`Gateway::serve_tcp`]).
//!
//! Error codes: `-32001` denied by policy, `-32002` session halted,
//! `-32003` tripwire fired (session halted), `-32601` unknown method,
//! `-32602` bad params, `-32000` internal/transport error.

use crate::exec;
use crate::supervisor::Supervisor;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use warden_policy::Verdict;

pub const DENIED: i64 = -32001;
pub const HALTED: i64 = -32002;
pub const TRIPPED: i64 = -32003;
pub const NO_METHOD: i64 = -32601;
pub const BAD_PARAMS: i64 = -32602;
pub const INTERNAL: i64 = -32000;

/// Maximum size of one request line.
const MAX_LINE: u64 = 32 * 1024 * 1024;

#[derive(Debug)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    fn new(code: i64, m: impl Into<String>) -> Self {
        Self {
            code,
            message: m.into(),
        }
    }
    fn params(e: impl std::fmt::Display) -> Self {
        Self::new(BAD_PARAMS, format!("invalid params: {e}"))
    }
}

pub struct Gateway {
    sup: Arc<Supervisor>,
}

#[derive(Deserialize)]
struct ExecParams {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    cwd: Option<String>,
    stdin: Option<String>,
}

#[derive(Deserialize)]
struct ReadParams {
    path: String,
    max_bytes: Option<u64>,
}

#[derive(Deserialize)]
struct WriteParams {
    path: String,
    content: String,
    #[serde(default)]
    append: bool,
}

#[derive(Deserialize)]
struct ListParams {
    #[serde(default = "dot")]
    path: String,
}

#[derive(Deserialize)]
struct DeleteParams {
    path: String,
}

fn dot() -> String {
    ".".into()
}

fn tools() -> Value {
    json!([
        {
            "name": "exec",
            "description": "Run an allowed program (no shell). Arguments are passed verbatim.",
            "inputSchema": {"type": "object", "required": ["program"], "properties": {
                "program": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}},
                "cwd": {"type": "string"},
                "stdin": {"type": "string"}
            }}
        },
        {
            "name": "read_file",
            "description": "Read a file inside the policy's read scope.",
            "inputSchema": {"type": "object", "required": ["path"], "properties": {
                "path": {"type": "string"}, "max_bytes": {"type": "integer"}
            }}
        },
        {
            "name": "write_file",
            "description": "Write (or append to) a file inside the policy's write scope.",
            "inputSchema": {"type": "object", "required": ["path", "content"], "properties": {
                "path": {"type": "string"}, "content": {"type": "string"}, "append": {"type": "boolean"}
            }}
        },
        {
            "name": "delete_file",
            "description": "Delete one file (not a directory) inside the policy's write scope.",
            "inputSchema": {"type": "object", "required": ["path"], "properties": {
                "path": {"type": "string"}
            }}
        },
        {
            "name": "list_dir",
            "description": "List a directory inside the policy's read scope.",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
        },
        {
            "name": "http_request",
            "description": "Make an HTTP(S) request to an allowlisted domain.",
            "inputSchema": {"type": "object", "required": ["url"], "properties": {
                "method": {"type": "string"}, "url": {"type": "string"},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "body": {"type": "string"}
            }}
        }
    ])
}

impl Gateway {
    pub fn new(sup: Arc<Supervisor>) -> Self {
        Self { sup }
    }

    fn verdict(&self, v: Verdict) -> RpcError {
        match v {
            Verdict::Trip(k, r) => {
                RpcError::new(TRIPPED, format!("tripwire {k}: {r}; session halted"))
            }
            Verdict::Deny(r) if self.sup.is_halted() => {
                RpcError::new(HALTED, format!("denied: {r}"))
            }
            Verdict::Deny(r) => RpcError::new(DENIED, format!("denied: {r}")),
        }
    }

    fn ws(&self) -> PathBuf {
        self.sup.policy().workspace().to_path_buf()
    }

    /// Execute one tool. `Ok` is the tool's structured result.
    pub fn call_tool(&self, name: &str, args: Value) -> Result<Value, RpcError> {
        if self.sup.is_halted() {
            let why = self
                .sup
                .halt_info()
                .map(|h| format!("{}: {}", h.kind, h.reason))
                .unwrap_or_default();
            return Err(RpcError::new(HALTED, format!("session halted ({why})")));
        }
        let pol = self.sup.policy().clone();
        let ws = self.ws();
        match name {
            "exec" => {
                let p: ExecParams = serde_json::from_value(args).map_err(RpcError::params)?;
                let details = json!({"program": p.program, "args": p.args, "cwd": p.cwd});
                let (prog, cwd) = self
                    .sup
                    .gate("exec", details, || {
                        let cwd =
                            pol.check_read(Path::new(p.cwd.as_deref().unwrap_or(".")), &ws)?;
                        let prog = pol.check_command(&p.program, &p.args, &cwd)?;
                        Ok((prog, cwd))
                    })
                    .map_err(|v| self.verdict(v))?;
                let out = exec::run(&pol, &prog, &p.args, &cwd, p.stdin.as_deref())
                    .map_err(|e| RpcError::new(INTERNAL, format!("spawn failed: {e}")))?;
                Ok(serde_json::to_value(out).unwrap())
            }
            "read_file" => {
                let p: ReadParams = serde_json::from_value(args).map_err(RpcError::params)?;
                let path = self
                    .sup
                    .gate("read_file", json!({"path": p.path}), || {
                        pol.check_read(Path::new(&p.path), &ws)
                    })
                    .map_err(|v| self.verdict(v))?;
                let cap = p
                    .max_bytes
                    .unwrap_or(u64::MAX)
                    .min(pol.policy.files.max_read_bytes);
                let f = std::fs::File::open(&path)
                    .map_err(|e| RpcError::new(INTERNAL, format!("{}: {e}", path.display())))?;
                let total = f.metadata().map(|m| m.len()).unwrap_or(0);
                let mut buf = vec![];
                f.take(cap)
                    .read_to_end(&mut buf)
                    .map_err(|e| RpcError::new(INTERNAL, e.to_string()))?;
                Ok(json!({
                    "path": path,
                    "content": String::from_utf8_lossy(&buf),
                    "bytes": buf.len(),
                    "truncated": total > buf.len() as u64,
                }))
            }
            "write_file" => {
                let p: WriteParams = serde_json::from_value(args).map_err(RpcError::params)?;
                let sha = hex::encode(Sha256::digest(p.content.as_bytes()));
                let n = p.content.len() as u64;
                // Content is not logged, only its size and hash.
                let details =
                    json!({"path": p.path, "bytes": n, "sha256": sha, "append": p.append});
                let path = self
                    .sup
                    .gate("write_file", details.clone(), || {
                        let path = pol.check_write(Path::new(&p.path), &ws)?;
                        self.sup.file_bytes(n)?;
                        Ok(path)
                    })
                    .map_err(|v| self.verdict(v))?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| RpcError::new(INTERNAL, e.to_string()))?;
                }
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .append(p.append)
                    .truncate(!p.append)
                    .open(&path)
                    .map_err(|e| RpcError::new(INTERNAL, format!("{}: {e}", path.display())))?;
                f.write_all(p.content.as_bytes())
                    .map_err(|e| RpcError::new(INTERNAL, e.to_string()))?;
                Ok(json!({"path": path, "bytes": n, "sha256": sha}))
            }
            "delete_file" => {
                let p: DeleteParams = serde_json::from_value(args).map_err(RpcError::params)?;
                let path = self
                    .sup
                    .gate("delete_file", json!({"path": p.path}), || {
                        pol.check_write(Path::new(&p.path), &ws)
                    })
                    .map_err(|v| self.verdict(v))?;
                let md = std::fs::symlink_metadata(&path)
                    .map_err(|e| RpcError::new(INTERNAL, format!("{}: {e}", path.display())))?;
                if md.is_dir() {
                    return Err(RpcError::new(
                        DENIED,
                        format!("denied: {} is a directory", path.display()),
                    ));
                }
                std::fs::remove_file(&path)
                    .map_err(|e| RpcError::new(INTERNAL, format!("{}: {e}", path.display())))?;
                Ok(json!({"path": path, "deleted": true}))
            }
            "list_dir" => {
                let p: ListParams = serde_json::from_value(args).map_err(RpcError::params)?;
                let path = self
                    .sup
                    .gate("list_dir", json!({"path": p.path}), || {
                        pol.check_read(Path::new(&p.path), &ws)
                    })
                    .map_err(|v| self.verdict(v))?;
                let mut entries = vec![];
                for e in std::fs::read_dir(&path)
                    .map_err(|e| RpcError::new(INTERNAL, format!("{}: {e}", path.display())))?
                    .flatten()
                {
                    let ft = e.file_type().ok();
                    entries.push(json!({
                        "name": e.file_name().to_string_lossy(),
                        "dir": ft.map(|t| t.is_dir()).unwrap_or(false),
                    }));
                }
                Ok(json!({"path": path, "entries": entries}))
            }
            "http_request" => {
                let req: warden_net::HttpRequest =
                    serde_json::from_value(args).map_err(RpcError::params)?;
                match warden_net::fetch(&pol, self.sup.as_ref(), &req) {
                    Ok(r) => Ok(serde_json::to_value(r).unwrap()),
                    Err(warden_net::FetchError::Policy(v)) => Err(self.verdict(v)),
                    Err(warden_net::FetchError::Transport(e)) => {
                        Err(RpcError::new(INTERNAL, format!("transport: {e}")))
                    }
                }
            }
            other => Err(RpcError::new(NO_METHOD, format!("unknown tool `{other}`"))),
        }
    }

    /// Handle one JSON-RPC message; returns the response (None for notifications).
    pub fn handle(&self, msg: &Value) -> Option<Value> {
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(json!({}));
        // Notifications (no id, e.g. notifications/initialized) get no reply.
        id.as_ref()?;
        let res: Result<Value, RpcError> = match method {
            "initialize" => Ok(json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "agent-warden", "version": env!("CARGO_PKG_VERSION")},
                "capabilities": {"tools": {}},
                "instructions": "All actions are policy-checked and audited. Denied actions count toward an automatic kill switch."
            })),
            "ping" => Ok(json!({})),
            "status" => Ok(json!({
                "halted": self.sup.halt_info(),
                "counters": self.sup.counters(),
            })),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                // MCP: tool failures are results with isError, not protocol errors.
                Ok(match self.call_tool(&name, args) {
                    Ok(v) => json!({
                        "content": [{"type": "text", "text": v.to_string()}],
                        "structuredContent": v,
                        "isError": false
                    }),
                    Err(e) => json!({
                        "content": [{"type": "text", "text": e.message}],
                        "isError": true,
                        "_warden": {"code": e.code}
                    }),
                })
            }
            m @ ("exec" | "read_file" | "write_file" | "delete_file" | "list_dir"
            | "http_request") => self.call_tool(m, params),
            other => Err(RpcError::new(
                NO_METHOD,
                format!("method not found: {other}"),
            )),
        };
        Some(match res {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err(e) => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": e.code, "message": e.message}})
            }
        })
    }

    /// Serve newline-delimited JSON-RPC on a byte stream until EOF.
    pub fn serve(&self, input: impl Read, mut output: impl Write) -> std::io::Result<()> {
        let mut r = BufReader::new(input);
        loop {
            let mut line = Vec::new();
            let n = (&mut r).take(MAX_LINE).read_until(b'\n', &mut line)?;
            if n == 0 {
                return Ok(());
            }
            if line.trim_ascii().is_empty() {
                continue;
            }
            let resp = match serde_json::from_slice::<Value>(&line) {
                Ok(msg) => self.handle(&msg),
                Err(e) => Some(json!({"jsonrpc": "2.0", "id": null,
                    "error": {"code": -32700, "message": format!("parse error: {e}")}})),
            };
            if let Some(resp) = resp {
                writeln!(output, "{resp}")?;
                output.flush()?;
            }
        }
    }

    /// Listen on loopback TCP; one thread per connection. Every connection
    /// must first send `{"method":"warden/auth","params":{"token":"..."}}`
    /// with the session token, otherwise it is closed. Returns the bound
    /// address. Used on Windows, where there is no 0600 Unix socket.
    pub fn serve_tcp(
        self: &Arc<Self>,
        addr: &str,
        token: String,
    ) -> std::io::Result<std::net::SocketAddr> {
        let l = std::net::TcpListener::bind(addr)?;
        let local = l.local_addr()?;
        let me = self.clone();
        let token = Arc::new(token);
        std::thread::Builder::new()
            .name("warden-gateway".into())
            .spawn(move || {
                for c in l.incoming().flatten() {
                    let g = me.clone();
                    let token = token.clone();
                    std::thread::spawn(move || {
                        let _ = c.set_nodelay(true);
                        let Ok(mut w) = c.try_clone() else { return };
                        let mut r = BufReader::new(c);
                        let mut line = Vec::new();
                        if (&mut r).take(4096).read_until(b'\n', &mut line).is_err() {
                            return;
                        }
                        let given = serde_json::from_slice::<Value>(&line)
                            .ok()
                            .filter(|m| m.get("method").and_then(Value::as_str) == Some("warden/auth"))
                            .and_then(|m| m.pointer("/params/token")?.as_str().map(String::from))
                            .unwrap_or_default();
                        if !ct_eq(given.as_bytes(), token.as_bytes()) {
                            g.sup.log(json!({"kind": "gateway_auth_failed"}));
                            let _ = writeln!(
                                w,
                                "{}",
                                json!({"jsonrpc": "2.0", "id": null,
                                    "error": {"code": DENIED, "message": "denied: bad or missing gateway token"}})
                            );
                            return;
                        }
                        let _ = writeln!(w, "{}", json!({"jsonrpc": "2.0", "id": null, "result": {"auth": "ok"}}));
                        let _ = g.serve(r, w);
                    });
                }
            })?;
        Ok(local)
    }

    /// Listen on a Unix socket (mode 0600); one thread per connection.
    #[cfg(unix)]
    pub fn serve_unix(self: &Arc<Self>, path: &Path) -> std::io::Result<()> {
        let _ = std::fs::remove_file(path);
        let l = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let me = self.clone();
        std::thread::Builder::new()
            .name("warden-gateway".into())
            .spawn(move || {
                for c in l.incoming().flatten() {
                    let g = me.clone();
                    std::thread::spawn(move || {
                        if let Ok(w) = c.try_clone() {
                            let _ = g.serve(c, w);
                        }
                    });
                }
            })?;
        Ok(())
    }
}

/// Constant-time byte comparison (length is not secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A fresh random session token (hex, 256 bits).
pub fn new_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use warden_audit::AuditLog;
    use warden_policy::{CompiledPolicy, Context, Policy};

    fn gw() -> (tempfile::TempDir, Arc<Gateway>, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let ws = warden_policy::canonicalize(d.path()).unwrap().join("ws");
        std::fs::create_dir_all(ws.join("out")).unwrap();
        let p = CompiledPolicy::compile(
            Policy::from_toml(
                "[files]\nread = [\"${WORKSPACE}/**\"]\nwrite = [\"${WORKSPACE}/out/**\"]\n",
            )
            .unwrap(),
            &Context {
                workspace: ws.clone(),
                protected: vec![],
            },
        )
        .unwrap();
        let log = AuditLog::open(&d.path().join("a.jsonl"), None).unwrap();
        let sup = Supervisor::new(Arc::new(p), Some(log));
        (d, Arc::new(Gateway::new(sup)), ws)
    }

    #[test]
    fn delete_file_respects_write_scope() {
        let (_d, g, ws) = gw();
        std::fs::write(ws.join("keep.txt"), "x").unwrap();
        std::fs::write(ws.join("out/tmp.txt"), "x").unwrap();
        let e = g
            .call_tool("delete_file", json!({"path": "keep.txt"}))
            .unwrap_err();
        assert_eq!(e.code, DENIED);
        assert!(ws.join("keep.txt").exists());
        g.call_tool("delete_file", json!({"path": "out/tmp.txt"}))
            .unwrap();
        assert!(!ws.join("out/tmp.txt").exists());
        let e = g
            .call_tool("delete_file", json!({"path": "out"}))
            .unwrap_err();
        assert_eq!(e.code, DENIED, "directories are never deleted");
    }

    fn roundtrip(addr: std::net::SocketAddr, first: &str) -> (String, String) {
        let s = TcpStream::connect(addr).unwrap();
        let mut w = s.try_clone().unwrap();
        let mut r = BufReader::new(s);
        writeln!(w, "{first}").unwrap();
        writeln!(w, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
        let (mut a, mut b) = (String::new(), String::new());
        let _ = r.read_line(&mut a);
        let _ = r.read_line(&mut b);
        (a, b)
    }

    #[test]
    fn tcp_gateway_requires_token() {
        let (_d, g, _ws) = gw();
        let tok = new_token();
        assert_eq!(tok.len(), 64);
        let addr = g.serve_tcp("127.0.0.1:0", tok.clone()).unwrap();
        let (a, b) = roundtrip(
            addr,
            r#"{"method":"warden/auth","params":{"token":"nope"}}"#,
        );
        assert!(a.contains("bad or missing gateway token"), "{a}");
        assert!(b.is_empty(), "connection must be closed: {b}");
        let (a, b) = roundtrip(addr, r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
        assert!(a.contains("bad or missing"), "{a}");
        assert!(b.is_empty());
        let good = json!({"method": "warden/auth", "params": {"token": tok}}).to_string();
        let (a, b) = roundtrip(addr, &good);
        assert!(a.contains("\"auth\":\"ok\""), "{a}");
        assert!(b.contains("\"result\":{}"), "{b}");
    }
}
