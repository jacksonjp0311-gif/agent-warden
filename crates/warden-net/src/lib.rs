//! # warden-net
//!
//! Network guard. Two ways out for an agent, both policy-checked:
//!
//! * [`Proxy`]: an HTTP forward proxy that also supports `CONNECT` for
//!   HTTPS. Enforces the domain/port allowlist, refuses private and cloud
//!   metadata IPs *after* DNS resolution (and pins the checked address so a
//!   second lookup cannot be rebound), caps payload sizes, and scans plain
//!   HTTP requests for credentials.
//! * [`fetch`]: a checked HTTP client used by the gateway's `http_request`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use warden_policy::{CompiledPolicy, Verdict};

/// Description of one egress attempt, handed to the [`Monitor`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Egress {
    /// "proxy-http", "proxy-connect" or "gateway-http".
    pub via: String,
    pub method: String,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub bytes: u64,
}

/// Hooks into the supervisor: logging, rate limiting, budgets and halting.
pub trait Monitor: Send + Sync {
    /// Called once per attempt with the policy outcome. Returning `Err`
    /// refuses an otherwise-allowed attempt (rate limit, halt, budget).
    fn record(&self, ev: &Egress, outcome: &Result<(), Verdict>) -> Result<(), Verdict>;
    /// Account outbound bytes. Returning `false` aborts the connection.
    fn bytes_out(&self, n: u64) -> bool;
    /// True once the supervisor has halted.
    fn halted(&self) -> bool;
}

/// A monitor that allows everything the policy allows and logs nothing.
pub struct NullMonitor;

impl Monitor for NullMonitor {
    fn record(&self, _: &Egress, o: &Result<(), Verdict>) -> Result<(), Verdict> {
        o.clone()
    }
    fn bytes_out(&self, _: u64) -> bool {
        true
    }
    fn halted(&self) -> bool {
        false
    }
}

/// Resolve `host:port` and refuse if *any* address is forbidden.
pub fn resolve_checked(
    policy: &CompiledPolicy,
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, Verdict> {
    let host_clean = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<SocketAddr> = if let Ok(ip) = host_clean.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        (host_clean, port)
            .to_socket_addrs()
            .map_err(|e| Verdict::Deny(format!("DNS resolution of {host_clean} failed: {e}")))?
            .collect()
    };
    if addrs.is_empty() {
        return Err(Verdict::Deny(format!(
            "{host_clean} resolved to no addresses"
        )));
    }
    for a in &addrs {
        policy
            .check_ip(a.ip())
            .map_err(|v| Verdict::Deny(format!("{host_clean} -> {}", v.reason())))?;
    }
    Ok(addrs)
}

fn connect_any(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last = io::Error::other("no address");
    for a in addrs {
        match TcpStream::connect_timeout(a, Duration::from_secs(10)) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Splits `host[:port]` (IPv6 in brackets) with a default port.
pub fn split_host_port(s: &str, default: u16) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default,
            None => return None,
        };
        return Some((h.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h.to_string(), p.parse().ok()?)),
        Some(_) => None,
        None => Some((s.to_string(), default)),
    }
}

/// Parsed absolute URL (`http[s]://host[:port]/path`).
#[derive(Debug, Clone, PartialEq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_url(u: &str) -> Option<Url> {
    let (scheme, rest) = u.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.contains('@') || authority.is_empty() {
        return None; // userinfo is refused: classic allowlist-confusion trick
    }
    let (host, port) = split_host_port(authority, default)?;
    let path = if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    };
    Some(Url {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
        path,
    })
}

// ---------------------------------------------------------------- proxy ---

/// Handle to a running proxy.
pub struct Proxy {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Proxy {
    /// Bind `listen` (use port 0 for ephemeral) and serve in background threads.
    pub fn start(
        listen: &str,
        policy: Arc<CompiledPolicy>,
        monitor: Arc<dyn Monitor>,
    ) -> io::Result<Proxy> {
        let listener = TcpListener::bind(listen)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let active = Arc::new(AtomicUsize::new(0));
        std::thread::Builder::new()
            .name("warden-proxy".into())
            .spawn(move || {
                for conn in listener.incoming() {
                    if stop2.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(conn) = conn else { continue };
                    if active.load(Ordering::SeqCst) >= 128 {
                        let _ = deny_response(&conn, 503, "too many connections");
                        continue;
                    }
                    let (p, m, a) = (policy.clone(), monitor.clone(), active.clone());
                    a.fetch_add(1, Ordering::SeqCst);
                    std::thread::spawn(move || {
                        let _ = handle(conn, &p, m.as_ref());
                        a.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            })?;
        Ok(Proxy { addr, stop })
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop();
    }
}

fn deny_response(mut s: &TcpStream, code: u16, reason: &str) -> io::Result<()> {
    let text = match code {
        403 => "Forbidden",
        400 => "Bad Request",
        411 => "Length Required",
        413 => "Payload Too Large",
        502 => "Bad Gateway",
        _ => "Service Unavailable",
    };
    let body = format!("agent-warden: {reason}\n");
    let clean: String = reason.chars().filter(|c| !c.is_control()).collect();
    write!(
        s,
        "HTTP/1.1 {code} {text}\r\nX-Warden-Reason: {clean}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    s.flush()
}

const MAX_HEAD: usize = 64 * 1024;

fn read_head<R: BufRead>(r: &mut R) -> io::Result<Vec<String>> {
    let mut lines = vec![];
    let mut total = 0;
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in head"));
        }
        total += n;
        if total > MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"));
        }
        let l = line.trim_end_matches(['\r', '\n']).to_string();
        if l.is_empty() {
            return Ok(lines);
        }
        lines.push(l);
    }
}

fn handle(client: TcpStream, policy: &CompiledPolicy, mon: &dyn Monitor) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(client.try_clone()?);
    let head = read_head(&mut reader)?;
    let Some(reqline) = head.first() else {
        return deny_response(&client, 400, "empty request");
    };
    let parts: Vec<&str> = reqline.split_whitespace().collect();
    if parts.len() != 3 {
        return deny_response(&client, 400, "malformed request line");
    }
    let (method, target) = (parts[0].to_ascii_uppercase(), parts[1]);
    if mon.halted() {
        return deny_response(&client, 403, "agent halted by warden");
    }
    if method == "CONNECT" {
        handle_connect(client, reader, target, policy, mon)
    } else {
        handle_http(client, reader, &method, target, &head[1..], policy, mon)
    }
}

fn handle_connect(
    client: TcpStream,
    mut reader: BufReader<TcpStream>,
    target: &str,
    policy: &CompiledPolicy,
    mon: &dyn Monitor,
) -> io::Result<()> {
    let Some((host, port)) = split_host_port(target, 443) else {
        return deny_response(&client, 400, "bad CONNECT target");
    };
    let ev = Egress {
        via: "proxy-connect".into(),
        method: "CONNECT".into(),
        host: host.clone(),
        port,
        path: None,
        bytes: 0,
    };
    let checked = policy
        .check_destination(&host, port)
        .and_then(|_| resolve_checked(policy, &host, port));
    let outcome = checked.as_ref().map(|_| ()).map_err(Clone::clone);
    if let Err(v) = mon.record(&ev, &outcome) {
        return deny_response(&client, 403, v.reason());
    }
    let addrs = checked.expect("record() passes through denials");
    let upstream = match connect_any(&addrs) {
        Ok(u) => u,
        Err(e) => return deny_response(&client, 502, &format!("connect failed: {e}")),
    };
    (&client).write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    // Anything the client pipelined after the CONNECT head.
    let leftover = reader.buffer().to_vec();
    reader.consume(leftover.len());
    client.set_read_timeout(Some(Duration::from_secs(300)))?;
    upstream.set_read_timeout(Some(Duration::from_secs(300)))?;
    tunnel(
        client,
        upstream,
        leftover,
        policy.policy.network.max_tunnel_bytes_out,
        mon,
    );
    Ok(())
}

fn tunnel(client: TcpStream, upstream: TcpStream, leftover: Vec<u8>, cap: u64, mon: &dyn Monitor) {
    let (mut c_r, mut u_w) = (client.try_clone().unwrap(), upstream.try_clone().unwrap());
    let (mut u_r, mut c_w) = (upstream, client);
    std::thread::scope(|s| {
        s.spawn(|| {
            let mut sent: u64 = 0;
            let mut buf = [0u8; 16 * 1024];
            let mut forward = |data: &[u8], sent: &mut u64| -> bool {
                *sent += data.len() as u64;
                *sent <= cap
                    && mon.bytes_out(data.len() as u64)
                    && !mon.halted()
                    && u_w.write_all(data).is_ok()
            };
            let mut ok = leftover.is_empty() || forward(&leftover, &mut sent);
            while ok {
                match c_r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => ok = forward(&buf[..n], &mut sent),
                }
            }
            let _ = u_w.shutdown(Shutdown::Both);
            let _ = c_r.shutdown(Shutdown::Both);
        });
        let _ = io::copy(&mut u_r, &mut c_w);
        let _ = c_w.shutdown(Shutdown::Both);
    });
}

fn handle_http(
    client: TcpStream,
    mut reader: BufReader<TcpStream>,
    method: &str,
    target: &str,
    headers: &[String],
    policy: &CompiledPolicy,
    mon: &dyn Monitor,
) -> io::Result<()> {
    let Some(url) = parse_url(target) else {
        return deny_response(&client, 400, "proxy requests need an absolute http:// URL");
    };
    if url.scheme != "http" {
        return deny_response(&client, 400, "use CONNECT for https");
    }
    let mut content_length: u64 = 0;
    let mut fwd_headers = vec![];
    for h in headers {
        let Some((k, v)) = h.split_once(':') else {
            return deny_response(&client, 400, "malformed header");
        };
        let kl = k.trim().to_ascii_lowercase();
        match kl.as_str() {
            "content-length" => {
                content_length = match v.trim().parse() {
                    Ok(n) => n,
                    Err(_) => return deny_response(&client, 400, "bad content-length"),
                }
            }
            "transfer-encoding" => {
                return deny_response(&client, 411, "chunked request bodies are not supported")
            }
            "connection"
            | "proxy-connection"
            | "proxy-authorization"
            | "keep-alive"
            | "upgrade" => {}
            _ => fwd_headers.push(format!("{}:{}", k.trim(), v)),
        }
    }
    let max = policy.policy.network.max_request_bytes;
    let mut ev = Egress {
        via: "proxy-http".into(),
        method: method.to_string(),
        host: url.host.clone(),
        port: url.port,
        path: Some(url.path.clone()),
        bytes: content_length,
    };
    let mut body = vec![];
    let outcome: Result<Vec<SocketAddr>, Verdict> = (|| {
        policy.check_method(method)?;
        policy.check_destination(&url.host, url.port)?;
        if content_length > max {
            return Err(Verdict::Deny(format!(
                "request body {content_length} bytes exceeds network.max_request_bytes ({max})"
            )));
        }
        (&mut reader)
            .take(content_length)
            .read_to_end(&mut body)
            .map_err(|e| Verdict::Deny(format!("reading body: {e}")))?;
        // Scan URL, headers and body: secrets also leak via query strings.
        let mut scan = Vec::with_capacity(body.len() + 512);
        scan.extend_from_slice(target.as_bytes());
        scan.push(b'\n');
        for h in &fwd_headers {
            scan.extend_from_slice(h.as_bytes());
            scan.push(b'\n');
        }
        scan.extend_from_slice(&body);
        policy.check_payload(&scan)?;
        resolve_checked(policy, &url.host, url.port)
    })();
    ev.bytes = body.len() as u64;
    let o = outcome.as_ref().map(|_| ()).map_err(Clone::clone);
    if let Err(v) = mon.record(&ev, &o) {
        let code = if v.reason().contains("exceeds") {
            413
        } else {
            403
        };
        return deny_response(&client, code, v.reason());
    }
    let addrs = outcome.expect("record() passes through denials");
    let total =
        (url.path.len() + fwd_headers.iter().map(|h| h.len()).sum::<usize>() + body.len()) as u64;
    if !mon.bytes_out(total) {
        return deny_response(&client, 403, "network byte budget exhausted");
    }
    let mut upstream = match connect_any(&addrs) {
        Ok(u) => u,
        Err(e) => return deny_response(&client, 502, &format!("connect failed: {e}")),
    };
    upstream.set_read_timeout(Some(Duration::from_secs(60)))?;
    let mut req = format!("{method} {} HTTP/1.1\r\n", url.path);
    for h in &fwd_headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    if !body.is_empty() || content_length > 0 {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("Connection: close\r\n\r\n");
    upstream.write_all(req.as_bytes())?;
    upstream.write_all(&body)?;
    let mut c = client;
    io::copy(&mut upstream, &mut c)?;
    Ok(())
}

// ---------------------------------------------------------- http client ---

/// Gateway `http_request` parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpRequest {
    #[serde(default = "get")]
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
}

fn get() -> String {
    "GET".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub truncated: bool,
}

/// Errors from [`fetch`]: a policy verdict, or a transport failure after the
/// request was allowed.
#[derive(Debug)]
pub enum FetchError {
    Policy(Verdict),
    Transport(String),
}

struct PinnedResolver {
    addrs: Vec<SocketAddr>,
}

impl ureq::Resolver for PinnedResolver {
    fn resolve(&self, _netloc: &str) -> io::Result<Vec<SocketAddr>> {
        Ok(self.addrs.clone())
    }
}

/// Policy-check and perform an HTTP(S) request on behalf of the agent.
pub fn fetch(
    policy: &CompiledPolicy,
    mon: &dyn Monitor,
    req: &HttpRequest,
) -> Result<HttpResponse, FetchError> {
    let method = req.method.to_ascii_uppercase();
    let body = req.body.clone().unwrap_or_default();
    let url = parse_url(&req.url);
    let ev = Egress {
        via: "gateway-http".into(),
        method: method.clone(),
        host: url.as_ref().map(|u| u.host.clone()).unwrap_or_default(),
        port: url.as_ref().map(|u| u.port).unwrap_or(0),
        path: url.as_ref().map(|u| u.path.clone()),
        bytes: body.len() as u64,
    };
    let outcome: Result<Vec<SocketAddr>, Verdict> = (|| {
        let u = url
            .clone()
            .ok_or_else(|| Verdict::Deny(format!("unsupported or malformed URL `{}`", req.url)))?;
        policy.check_method(&method)?;
        policy.check_destination(&u.host, u.port)?;
        let mut scan = req.url.clone().into_bytes();
        scan.push(b'\n');
        for (k, v) in &req.headers {
            scan.extend_from_slice(format!("{k}: {v}\n").as_bytes());
        }
        scan.extend_from_slice(body.as_bytes());
        policy.check_payload(&scan)?;
        resolve_checked(policy, &u.host, u.port)
    })();
    let o = outcome.as_ref().map(|_| ()).map_err(Clone::clone);
    mon.record(&ev, &o).map_err(FetchError::Policy)?;
    let addrs = outcome.map_err(FetchError::Policy)?;
    if !mon.bytes_out((req.url.len() + body.len()) as u64) {
        return Err(FetchError::Policy(Verdict::Deny(
            "network byte budget exhausted".into(),
        )));
    }
    let agent = ureq::AgentBuilder::new()
        .resolver(PinnedResolver { addrs })
        .redirects(0)
        .timeout(Duration::from_secs(30))
        .build();
    let mut r = agent.request(&method, &req.url);
    for (k, v) in &req.headers {
        r = r.set(k, v);
    }
    let resp = if body.is_empty() {
        r.call()
    } else {
        r.send_string(&body)
    };
    let resp = match resp {
        Ok(r) | Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(FetchError::Transport(e.to_string())),
    };
    let status = resp.status();
    let mut headers = BTreeMap::new();
    for n in resp.headers_names() {
        if let Some(v) = resp.header(&n) {
            headers.insert(n, v.to_string());
        }
    }
    let cap = policy.policy.network.max_response_bytes;
    let mut buf = vec![];
    resp.into_reader()
        .take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| FetchError::Transport(e.to_string()))?;
    let truncated = buf.len() as u64 > cap;
    buf.truncate(cap as usize);
    Ok(HttpResponse {
        status,
        headers,
        body: String::from_utf8_lossy(&buf).into_owned(),
        truncated,
    })
}

#[cfg(test)]
mod tests;
