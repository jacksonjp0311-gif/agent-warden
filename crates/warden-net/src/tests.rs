use super::*;
use std::sync::Mutex;
use warden_policy::{Context, Policy, TripKind};

fn policy(extra: &str) -> Arc<CompiledPolicy> {
    let d = tempfile::tempdir().unwrap();
    let p = Policy::from_toml(extra).unwrap();
    Arc::new(
        CompiledPolicy::compile(
            p,
            &Context {
                workspace: d.path().to_path_buf(),
                protected: vec![],
            },
        )
        .unwrap(),
    )
}

#[derive(Default)]
struct Rec {
    events: Mutex<Vec<(Egress, Result<(), Verdict>)>>,
}
impl Monitor for Rec {
    fn record(&self, ev: &Egress, o: &Result<(), Verdict>) -> Result<(), Verdict> {
        self.events.lock().unwrap().push((ev.clone(), o.clone()));
        o.clone()
    }
    fn bytes_out(&self, _: u64) -> bool {
        true
    }
    fn halted(&self) -> bool {
        false
    }
}

/// Tiny HTTP server on loopback that answers every request with its body.
fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { continue };
            std::thread::spawn(move || {
                let mut r = BufReader::new(c.try_clone().unwrap());
                let head = read_head(&mut r).unwrap_or_default();
                let len: usize = head
                    .iter()
                    .find_map(|h| {
                        h.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                let mut c = c;
                let reply = format!(
                    "{}|{}",
                    head.first().cloned().unwrap_or_default(),
                    String::from_utf8_lossy(&body)
                );
                write!(
                    c,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                )
                .unwrap();
            });
        }
    });
    a
}

fn raw(proxy: &Proxy, req: &str) -> String {
    let mut s = TcpStream::connect(proxy.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn url_parsing() {
    let u = parse_url("https://Example.com:8443/a?b").unwrap();
    assert_eq!(
        (u.host.as_str(), u.port, u.path.as_str()),
        ("example.com", 8443, "/a?b")
    );
    assert_eq!(parse_url("http://example.com").unwrap().path, "/");
    assert_eq!(parse_url("http://[::1]:81/x").unwrap().host, "::1");
    assert!(parse_url("http://good.com@evil.com/").is_none());
    assert!(parse_url("ftp://x/").is_none());
    assert_eq!(split_host_port("a.com:443", 1), Some(("a.com".into(), 443)));
    assert_eq!(split_host_port("a.com", 1), Some(("a.com".into(), 1)));
}

#[test]
fn metadata_ip_blocked_even_if_allowlisted() {
    let p = policy("[network]\nallow_domains=[\"169.254.169.254\"]\nallow_ports=[80]");
    let r = resolve_checked(&p, "169.254.169.254", 80);
    assert!(r.is_err());
    let r = p.check_destination("169.254.169.254", 80);
    assert!(r.is_err());
}

#[test]
fn proxy_forwards_allowed_and_blocks_others() {
    let up = echo_server();
    let p = policy(
        "[network]\nallow_domains=[\"127.0.0.1\"]\nallow_ports=[1,2]\nblock_private_ips=false",
    );
    // rebuild with the dynamic port allowed
    let mut pol = p.policy.clone();
    pol.network.allow_ports = vec![up.port()];
    let p = Arc::new(
        CompiledPolicy::compile(
            pol,
            &Context {
                workspace: "/".into(),
                protected: vec![],
            },
        )
        .unwrap(),
    );
    let mon = Arc::new(Rec::default());
    let proxy = Proxy::start("127.0.0.1:0", p, mon.clone()).unwrap();

    let ok = raw(
        &proxy,
        &format!(
            "POST http://127.0.0.1:{}/hello HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nworld",
            up.port()
        ),
    );
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    assert!(ok.contains("POST /hello HTTP/1.1|world"), "{ok}");

    let denied = raw(
        &proxy,
        &format!(
            "GET http://evil.example:{}/ HTTP/1.1\r\nHost: evil.example\r\n\r\n",
            up.port()
        ),
    );
    assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");
    assert!(denied.contains("not in network.allow_domains"));

    let secret = raw(
        &proxy,
        &format!(
            "POST http://127.0.0.1:{}/x HTTP/1.1\r\nContent-Length: 20\r\n\r\nAKIAIOSFODNN7EXAMPLE",
            up.port()
        ),
    );
    assert!(secret.starts_with("HTTP/1.1 403"), "{secret}");

    // CONNECT tunnel to the allowed upstream, then speak HTTP through it
    let mut s = TcpStream::connect(proxy.addr).unwrap();
    write!(s, "CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", up.port()).unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let head = read_head(&mut r).unwrap();
    assert!(head[0].contains("200"), "{head:?}");
    write!(s, "GET /t HTTP/1.1\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = r.read_to_string(&mut out);
    assert!(out.contains("GET /t HTTP/1.1|"), "{out}");

    let c = raw(&proxy, "CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n");
    assert!(c.starts_with("HTTP/1.1 403"), "{c}");

    let ev = mon.events.lock().unwrap();
    let trips = ev
        .iter()
        .filter(|(_, o)| matches!(o, Err(Verdict::Trip(TripKind::SecretExfil, _))))
        .count();
    assert_eq!(trips, 1);
    assert_eq!(ev.iter().filter(|(_, o)| o.is_ok()).count(), 2);
}

#[test]
fn oversized_body_rejected() {
    let p = policy(
        "[network]\nallow_domains=[\"example.com\"]\nallow_ports=[80]\nmax_request_bytes=10",
    );
    let proxy = Proxy::start("127.0.0.1:0", p, Arc::new(NullMonitor)).unwrap();
    let r = raw(
        &proxy,
        "POST http://example.com/ HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello world",
    );
    assert!(r.starts_with("HTTP/1.1 413"), "{r}");
}

#[test]
fn fetch_checks_policy_before_network() {
    let p = policy("[network]\nallow_domains=[\"example.com\"]");
    let mon = Rec::default();
    let r = fetch(
        &p,
        &mon,
        &HttpRequest {
            method: "GET".into(),
            url: "https://evil.com/".into(),
            ..Default::default()
        },
    );
    assert!(matches!(r, Err(FetchError::Policy(Verdict::Deny(_)))));
    let r = fetch(
        &p,
        &mon,
        &HttpRequest {
            method: "POST".into(),
            url: "https://example.com/".into(),
            body: Some("ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ".into()),
            ..Default::default()
        },
    );
    assert!(matches!(
        r,
        Err(FetchError::Policy(Verdict::Trip(TripKind::SecretExfil, _)))
    ));
    let r = fetch(
        &p,
        &mon,
        &HttpRequest {
            method: "GET".into(),
            url: "http://169.254.169.254/latest/meta-data/".into(),
            ..Default::default()
        },
    );
    assert!(matches!(r, Err(FetchError::Policy(_))));
}
