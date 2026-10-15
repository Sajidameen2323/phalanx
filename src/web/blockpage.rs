//! The block-page server: a small HTTP server on the loopback sinkhole
//! address. The DNS filter answers blocked names with that address, so the
//! browser's request for `http://bad.example/...` arrives here.
//!
//! A request for a blocked site gets `303 See Other` to this server's own
//! block page (`/__phalanx/blocked?token=…`). Redirecting, rather than
//! serving the warning directly, moves the browser off the malicious origin:
//! nothing is cached or stored under its name, and the address bar shows the
//! block page. The reason comes from the redirection cache by token, so the
//! page never trusts its own query string for anything but display fallback.
//!
//! One thread per connection; finished threads are reaped as new ones start.
//! HTTPS connections to the sinkhole fail (no certificate is installed for
//! intercepting TLS), which still blocks the site; the browser extension
//! shows a proper page for those.

use super::cache::{Entry, RedirectionCache};
use super::url::{encode_component, normalize_host, query_pairs};
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

pub const BLOCK_PATH: &str = "/__phalanx/blocked";
const MAX_REQUEST: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(3);
/// After sending, wait this long for the browser to close first, so the
/// redirect is read before the connection goes away.
const LINGER: Duration = Duration::from_secs(1);
/// Connections served at once; more are closed immediately.
const MAX_CLIENTS: usize = 64;

pub struct BlockPageServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl BlockPageServer {
    /// Binds `addr` and starts serving. Fails if the address is in use or
    /// cannot be bound.
    pub fn start(addr: SocketAddr, cache: Arc<RedirectionCache>) -> Result<Self> {
        let listener = TcpListener::bind(addr).with_context(|| format!("starting the block-page server on {addr}"))?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::Builder::new()
            .name("block-page-server".into())
            .spawn(move || serve(listener, addr, cache, flag))
            .context("starting the block-page thread")?;
        Ok(Self { addr, stop, thread: Some(thread) })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept().
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(500));
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for BlockPageServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn serve(listener: TcpListener, addr: SocketAddr, cache: Arc<RedirectionCache>, stop: Arc<AtomicBool>) {
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    for stream in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = stream else { continue };
        workers.retain(|w| !w.is_finished());
        if workers.len() >= MAX_CLIENTS {
            continue; // dropping the stream closes it
        }
        let cache = cache.clone();
        if let Ok(worker) = std::thread::Builder::new().name("block-page-client".into()).spawn(move || {
            let _ = handle(stream, addr, &cache);
        }) {
            workers.push(worker);
        }
    }
    for w in workers {
        let _ = w.join();
    }
}

fn handle(mut stream: TcpStream, addr: SocketAddr, cache: &RedirectionCache) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut request = Vec::with_capacity(1024);
    let mut buf = [0u8; 2048];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < MAX_REQUEST {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&buf[..n]);
    }
    let response = respond(&String::from_utf8_lossy(&request), addr, cache);
    stream.write_all(&response)?;
    stream.flush()?;
    stream.shutdown(Shutdown::Write)?;
    // Linger until the browser closes, so it reads everything we sent.
    stream.set_read_timeout(Some(LINGER))?;
    while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
    Ok(())
}

/// Builds the HTTP response for one raw request.
pub fn respond(request: &str, addr: SocketAddr, cache: &RedirectionCache) -> Vec<u8> {
    let mut lines = request.lines();
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let (method, target) = (first.next().unwrap_or(""), first.next().unwrap_or("/"));
    let host = lines
        .take_while(|l| !l.is_empty())
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("host")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_default();

    if method.is_empty() {
        return http(400, "Bad Request", "text/plain; charset=utf-8", b"Bad request");
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path == BLOCK_PATH {
        let params = query_pairs(query);
        let token = params.iter().find(|(k, _)| k == "token").and_then(|(_, v)| v.parse::<u32>().ok());
        let html = match token.and_then(|t| cache.get(t)) {
            Some(entry) => page(&PageFacts::from_entry(&entry, param(&params, "url"))),
            None => page(&PageFacts::from_params(&params)),
        };
        return http(200, "OK", "text/html; charset=utf-8", html.as_bytes());
    }
    if path == "/favicon.ico" {
        return http(404, "Not Found", "text/plain; charset=utf-8", b"");
    }

    // A request for a blocked site: send the browser to the block page.
    let name = host_without_port(&host);
    let original = format!("http://{host}{target}");
    let location = match cache.find(&name) {
        Some(entry) => block_page_url(addr, Some(&entry), &original),
        // A blocked ad or tracker: answer with nothing.
        None if cache.is_quiet(&name) => return http(204, "No Content", "text/plain; charset=utf-8", b""),
        None => block_page_url(addr, None, &original),
    };
    format!(
        "HTTP/1.1 303 See Other\r\nLocation: {location}\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn host_without_port(host: &str) -> String {
    let bare = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    normalize_host(bare).unwrap_or_default()
}

/// The block-page link: base address plus `token`, category, language,
/// product, version, original URL and threat name.
pub fn block_page_url(addr: SocketAddr, entry: Option<&Entry>, original_url: &str) -> String {
    let port = if addr.port() == 80 { String::new() } else { format!(":{}", addr.port()) };
    let mut url = format!("http://{}{port}{BLOCK_PATH}", addr.ip());
    let (token, category, threat, code, domain) = match entry {
        Some(e) => (e.token.to_string(), e.verdict.category.as_str(), e.verdict.threat.as_str(), e.verdict.code.number().to_string(), e.domain.as_str()),
        None => (String::new(), "", "", String::new(), ""),
    };
    let params = [
        ("token", token.as_str()),
        ("cat", category),
        ("lang", "en"),
        ("prod", "phalanx"),
        ("ver", env!("CARGO_PKG_VERSION")),
        ("url", original_url),
        ("threat", threat),
        ("code", code.as_str()),
        ("domain", domain),
    ];
    for (i, (k, v)) in params.iter().enumerate() {
        url.push(if i == 0 { '?' } else { '&' });
        url.push_str(k);
        url.push('=');
        url.push_str(&encode_component(v));
    }
    url
}

fn param<'a>(params: &'a [(String, String)], key: &str) -> &'a str {
    params.iter().find(|(k, _)| k == key).map_or("", |(_, v)| v.as_str())
}

/// What the block page shows.
struct PageFacts {
    domain: String,
    url: String,
    category: String,
    threat: String,
    reason: String,
    rule: String,
    /// Whether the facts come from this server's own records.
    verified: bool,
}

impl PageFacts {
    fn from_entry(entry: &Entry, url: &str) -> Self {
        Self {
            domain: entry.domain.clone(),
            url: url.to_string(),
            category: entry.verdict.category.clone(),
            threat: entry.verdict.threat.clone(),
            reason: entry.verdict.code.label().to_string(),
            rule: format!("{} `{}`", entry.verdict.list, entry.verdict.rule),
            verified: true,
        }
    }

    fn from_params(params: &[(String, String)]) -> Self {
        Self {
            domain: param(params, "domain").to_string(),
            url: param(params, "url").to_string(),
            category: param(params, "cat").to_string(),
            threat: param(params, "threat").to_string(),
            reason: String::new(),
            rule: String::new(),
            verified: false,
        }
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn page(f: &PageFacts) -> String {
    let row = |label: &str, value: &str| {
        if value.is_empty() { String::new() } else { format!("<dt>{}</dt><dd>{}</dd>", escape(label), escape(value)) }
    };
    let headline = match f.category.as_str() {
        "phishing" => "This site was blocked: it tries to steal passwords or personal details",
        "scam" => "This site was blocked: it is a known scam",
        "" => "This site was blocked by web protection",
        _ => "This site was blocked: it is known to spread malware",
    };
    let details = [
        row("Site", &f.domain),
        row("Address", &f.url),
        row("Category", &f.category),
        row("Threat", &f.threat),
        row("Reason", &f.reason),
        row("Rule", &f.rule),
    ]
    .concat();
    let note = if f.verified { "" } else { "<p class=\"muted\">Details for this block are no longer available (Phalanx was restarted).</p>" };
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Site blocked - Phalanx</title>
<style>
:root {{ color-scheme: dark; }}
body {{ margin: 0; background: #0e131f; color: #e6e9f0; font: 16px/1.5 "Segoe UI", system-ui, sans-serif; }}
main {{ max-width: 640px; margin: 10vh auto; padding: 0 16px; }}
.card {{ background: #182033; border: 1px solid #263048; border-radius: 14px; padding: 28px; }}
h1 {{ font-size: 22px; margin: 0 0 8px; color: #ef4444; }}
dl {{ display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 20px 0; }}
dt {{ color: #8b95ab; }} dd {{ margin: 0; overflow-wrap: anywhere; }}
.muted {{ color: #8b95ab; font-size: 14px; }}
</style></head>
<body><main><div class="card">
<h1>{headline}</h1>
<p>Phalanx stopped your browser from opening this site to protect your PC and your data. Close this tab or go back.</p>
<dl>{details}</dl>
{note}
<p class="muted">If you are sure this site is safe, allow it in Phalanx under Web protection &gt; Allowed sites, then reload.</p>
</div></main></body></html>"#,
        headline = escape(headline),
    )
}

fn http(status: u16, reason: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::rules::{UserLists, WebRules};

    fn setup() -> (Arc<RedirectionCache>, u32, SocketAddr) {
        let rules = WebRules::load(None, &UserLists::default()).unwrap();
        let cache = Arc::new(RedirectionCache::new());
        let token = cache.insert("blocktest.phalanx.invalid", &rules.classify_domain("blocktest.phalanx.invalid"));
        (cache, token, "127.66.0.1:80".parse().unwrap())
    }

    #[test]
    fn blocked_site_gets_303_to_block_page() {
        let (cache, token, addr) = setup();
        let raw = respond("GET /setup.exe?x=1 HTTP/1.1\r\nHost: BlockTest.phalanx.invalid:80\r\n\r\n", addr, &cache);
        let text = String::from_utf8(raw).unwrap();
        assert!(text.starts_with("HTTP/1.1 303 See Other\r\nLocation: http://127.66.0.1/__phalanx/blocked?token="), "{text}");
        assert!(text.contains(&format!("token={token}&cat=malware&lang=en&prod=phalanx&ver=")));
        assert!(text.contains("&url=http%3A%2F%2FBlockTest.phalanx.invalid%3A80%2Fsetup.exe%3Fx%3D1"));
        assert!(text.contains("&threat=Phalanx.TestBlock.Malware&code=2&domain=blocktest.phalanx.invalid"));
        assert!(text.contains("\r\nConnection: close\r\n\r\n"));
    }

    #[test]
    fn blocked_ads_get_an_empty_answer() {
        let (cache, _, addr) = setup();
        cache.insert_quiet("ad.doubleclick.net");
        let text = String::from_utf8(respond("GET /pixel.gif HTTP/1.1\r\nHost: ad.doubleclick.net\r\n\r\n", addr, &cache)).unwrap();
        assert!(text.starts_with("HTTP/1.1 204 No Content\r\n") && text.contains("Content-Length: 0\r\n"), "{text}");
    }

    #[test]
    fn block_page_shows_cached_reason_and_escapes_params() {
        let (cache, token, addr) = setup();
        let ok = String::from_utf8(respond(&format!("GET {BLOCK_PATH}?token={token}&url=x HTTP/1.1\r\n\r\n"), addr, &cache)).unwrap();
        assert!(ok.starts_with("HTTP/1.1 200 OK"));
        assert!(ok.contains("Phalanx.TestBlock.Malware") && ok.contains("domainBlockList"));

        let evil = String::from_utf8(respond(&format!("GET {BLOCK_PATH}?threat=%3Cscript%3E HTTP/1.1\r\n\r\n"), addr, &cache)).unwrap();
        assert!(evil.contains("&lt;script&gt;") && !evil.contains("<script>"));
        assert!(evil.contains("no longer available"));
    }

    #[test]
    fn serves_over_a_real_socket() {
        let (cache, _, _) = setup();
        let server = BlockPageServer::start("127.0.0.1:0".parse().unwrap(), cache).unwrap();
        let mut s = TcpStream::connect(server.local_addr()).unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: blocktest.phalanx.invalid\r\n\r\n").unwrap();
        let mut reply = String::new();
        s.read_to_string(&mut reply).unwrap();
        assert!(reply.starts_with("HTTP/1.1 303 See Other"));
        server.stop();
    }
}
