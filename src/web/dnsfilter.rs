//! The local DNS filter: a resolver on the loopback interface that forwards
//! lookups to the real resolvers and checks both the question and the
//! answers against the web rules.
//!
//! For a blocked name it answers with the sinkhole address, so the browser
//! connects to the block-page server instead, and records the reason in the
//! redirection cache. The question is checked before forwarding (a blocked
//! name never leaves the PC); the answers are checked after (CNAME targets
//! and resolved addresses). Serves UDP and TCP (for truncated replies).
//!
//! It only filters programs that use Windows' resolver, so Windows' DNS
//! server must point at the listen address, and browsers' own "secure DNS"
//! (DNS over HTTPS) bypasses it.

use super::cache::RedirectionCache;
use super::config::Mode;
use super::dns;
use super::events::{self, WebEvent};
use super::rules::Verdict;
use super::SharedRules;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
/// TTL of sinkhole answers: short, so allowing a site takes effect soon.
const SINKHOLE_TTL: u32 = 30;
/// Lookups resolved at once; more are dropped (the client retries).
const MAX_IN_FLIGHT: usize = 256;
/// The same name is logged at most this often (browsers ask for A, AAAA
/// and HTTPS records together).
const LOG_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct FilterConfig {
    pub listen: SocketAddr,
    pub upstreams: Vec<SocketAddr>,
    pub sinkhole: Ipv4Addr,
    pub mode: Mode,
    /// Where to append block events; `None` to not log.
    pub data_dir: Option<PathBuf>,
}

type OnEvent = Box<dyn Fn(&WebEvent) + Send + Sync>;

struct FilterContext {
    config: FilterConfig,
    rules: SharedRules,
    cache: Arc<RedirectionCache>,
    recent: Mutex<HashMap<String, Instant>>,
    on_event: Option<OnEvent>,
    in_flight: AtomicUsize,
}

pub struct DnsFilter {
    stop: Arc<AtomicBool>,
    tcp_addr: SocketAddr,
    threads: Vec<JoinHandle<()>>,
    udp_addr: SocketAddr,
}

impl DnsFilter {
    /// Binds the UDP and TCP listeners and starts serving. `on_event` is
    /// called for each logged block (for notifications).
    pub fn start(config: FilterConfig, rules: SharedRules, cache: Arc<RedirectionCache>, on_event: Option<OnEvent>) -> Result<Self> {
        if config.upstreams.is_empty() {
            anyhow::bail!("no upstream DNS resolver configured");
        }
        let udp = UdpSocket::bind(config.listen).with_context(|| format!("starting the DNS filter on UDP {}", config.listen))?;
        let udp_addr = udp.local_addr()?;
        // Same port for TCP (an ephemeral UDP port is reused when 0 was asked).
        let tcp_listen = SocketAddr::new(config.listen.ip(), udp_addr.port());
        let tcp = TcpListener::bind(tcp_listen).with_context(|| format!("starting the DNS filter on TCP {tcp_listen}"))?;
        let tcp_addr = tcp.local_addr()?;
        udp.set_read_timeout(Some(Duration::from_millis(400)))?;

        let stop = Arc::new(AtomicBool::new(false));
        let ctx = Arc::new(FilterContext {
            config,
            rules,
            cache,
            recent: Mutex::new(HashMap::new()),
            on_event,
            in_flight: AtomicUsize::new(0),
        });
        let mut threads = Vec::new();
        {
            let (ctx, stop) = (ctx.clone(), stop.clone());
            threads.push(std::thread::Builder::new().name("dns-filter-udp".into()).spawn(move || serve_udp(udp, ctx, stop))?);
        }
        {
            let (ctx, stop) = (ctx.clone(), stop.clone());
            threads.push(std::thread::Builder::new().name("dns-filter-tcp".into()).spawn(move || serve_tcp(tcp, ctx, stop))?);
        }
        Ok(Self { stop, tcp_addr, threads, udp_addr })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.udp_addr
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.tcp_addr, Duration::from_millis(500));
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for DnsFilter {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn serve_udp(socket: UdpSocket, ctx: Arc<FilterContext>, stop: Arc<AtomicBool>) {
    let mut buf = vec![0u8; 4096];
    while !stop.load(Ordering::SeqCst) {
        let (n, peer) = match socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(_) => continue, // timeout (checks `stop`) or a reset from a previous send
        };
        if ctx.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
            ctx.in_flight.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let query = buf[..n].to_vec();
        let (ctx2, reply_socket) = (ctx.clone(), socket.try_clone());
        let spawned = std::thread::Builder::new().name("dns-filter-query".into()).spawn(move || {
            if let (Some(reply), Ok(socket)) = (answer(&ctx2, &query, false), reply_socket) {
                let _ = socket.send_to(&reply, peer);
            }
            ctx2.in_flight.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            ctx.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn serve_tcp(listener: TcpListener, ctx: Arc<FilterContext>, stop: Arc<AtomicBool>) {
    for stream in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(mut stream) = stream else { continue };
        if ctx.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
            ctx.in_flight.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let ctx = ctx.clone();
        let _ = std::thread::Builder::new().name("dns-filter-tcp-client".into()).spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            while let Ok(query) = read_framed(&mut stream) {
                let Some(reply) = answer(&ctx, &query, true) else { break };
                if write_framed(&mut stream, &reply).is_err() {
                    break;
                }
            }
            ctx.in_flight.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn read_framed(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len)?;
    let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut msg)?;
    Ok(msg)
}

fn write_framed(stream: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(msg.len() + 2);
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    stream.write_all(&out)
}

/// The reply to one query: a sinkhole answer for blocked names, else the
/// upstream's reply (SERVFAIL if every upstream failed).
fn answer(ctx: &FilterContext, query: &[u8], tcp: bool) -> Option<Vec<u8>> {
    let parsed = dns::parse(query);
    let name = parsed.as_ref().filter(|m| !m.is_response()).and_then(|m| m.question.as_ref()).map(|q| q.name.clone());
    let rules = ctx.rules.read().unwrap_or_else(|e| e.into_inner()).clone();

    if let Some(name) = &name {
        let verdict = rules.classify_domain(name);
        if verdict.blocks() && report(ctx, name, &verdict) {
            return dns::sinkhole_reply(query, ctx.config.sinkhole, SINKHOLE_TTL);
        }
    }

    let Some(response) = forward(&ctx.config.upstreams, query, tcp) else {
        return dns::servfail_reply(query);
    };
    if let (Some(name), Some(message)) = (&name, dns::parse(&response)) {
        let verdict = rules.classify_dns(name, &message.answers);
        if verdict.blocks() && report(ctx, name, &verdict) {
            return dns::sinkhole_reply(query, ctx.config.sinkhole, SINKHOLE_TTL);
        }
    }
    Some(response)
}

/// Records a match. Returns whether to block (false in report-only mode).
fn report(ctx: &FilterContext, name: &str, verdict: &Verdict) -> bool {
    let block = ctx.config.mode == Mode::Block;
    if block {
        ctx.cache.insert(name, verdict);
    }
    let now = Instant::now();
    let fresh = {
        let mut recent = ctx.recent.lock().unwrap_or_else(|e| e.into_inner());
        if recent.len() > 4096 {
            recent.retain(|_, t| now.duration_since(*t) < LOG_INTERVAL);
        }
        match recent.get(name) {
            Some(t) if now.duration_since(*t) < LOG_INTERVAL => false,
            _ => {
                recent.insert(name.to_string(), now);
                true
            }
        }
    };
    if fresh {
        let event = WebEvent::new("dns", block, name, verdict);
        if let Some(dir) = &ctx.config.data_dir {
            events::record(dir, &event);
        }
        if let Some(callback) = &ctx.on_event {
            callback(&event);
        }
    }
    block
}

/// Sends `query` to each upstream in turn until one answers.
fn forward(upstreams: &[SocketAddr], query: &[u8], tcp: bool) -> Option<Vec<u8>> {
    let id = query.get(..2)?;
    upstreams.iter().find_map(|upstream| {
        let reply = if tcp { forward_tcp(*upstream, query) } else { forward_udp(*upstream, query) }.ok()?;
        (reply.get(..2) == Some(id)).then_some(reply)
    })
}

fn forward_udp(upstream: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv4() { "0.0.0.0:0".parse().expect("valid") } else { "[::]:0".parse().expect("valid") };
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    socket.connect(upstream)?;
    socket.send(query)?;
    let mut buf = vec![0u8; 4096];
    let n = socket.recv(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn forward_tcp(upstream: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&upstream, UPSTREAM_TIMEOUT)?;
    stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    write_framed(&mut stream, query)?;
    read_framed(&mut stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::dns::{build_query, parse, tests::response, TYPE_A, TYPE_AAAA, TYPE_CNAME};
    use crate::web::rules::{Answer, Origin, UserLists, WebRules};
    use std::sync::RwLock;

    /// A fake upstream that answers every A query with a CNAME to
    /// `cdn.bad.example` for `alias.example`, 198.51.100.9 for
    /// `hosted.example`, and 192.0.2.1 otherwise.
    fn fake_upstream() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf) {
                let query = &buf[..n];
                let name = parse(query).unwrap().question.unwrap().name;
                let answers = match name.as_str() {
                    "alias.example" => vec![(TYPE_CNAME, vec![3, b'c', b'd', b'n', 3, b'b', b'a', b'd', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0])],
                    "hosted.example" => vec![(TYPE_A, vec![198, 51, 100, 9])],
                    _ => vec![(TYPE_A, vec![192, 0, 2, 1])],
                };
                let _ = socket.send_to(&response(query, &answers), peer);
            }
        });
        addr
    }

    fn lookup(server: SocketAddr, name: &str, qtype: u16) -> dns::Message {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.send_to(&build_query(42, name, qtype), server).unwrap();
        let mut buf = [0u8; 1500];
        let n = socket.recv(&mut buf).unwrap();
        parse(&buf[..n]).unwrap()
    }

    #[test]
    fn filters_questions_cnames_and_addresses() {
        let tmp = tempfile::tempdir().unwrap();
        let mut rules = WebRules::load(None, &UserLists::default()).unwrap();
        rules.add_text("domain cdn.bad.example malware Bad.Cdn\nip 198.51.100.0/24 malware Bad.Net\n", Origin::Feed, "t").unwrap();
        let shared: SharedRules = Arc::new(RwLock::new(Arc::new(rules)));
        let cache = Arc::new(RedirectionCache::new());
        let sinkhole: Ipv4Addr = "127.66.0.1".parse().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let filter = DnsFilter::start(
            FilterConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstreams: vec![fake_upstream()],
                sinkhole,
                mode: Mode::Block,
                data_dir: Some(tmp.path().to_path_buf()),
            },
            shared,
            cache.clone(),
            Some(Box::new(move |e: &WebEvent| seen2.lock().unwrap().push(e.target.clone()))),
        )
        .unwrap();
        let server = filter.local_addr();
        let sink = [Answer::Address(sinkhole.into())];

        assert_eq!(lookup(server, "blocktest.phalanx.invalid", TYPE_A).answers, sink, "question blocked");
        assert!(lookup(server, "blocktest.phalanx.invalid", TYPE_AAAA).answers.is_empty());
        assert_eq!(lookup(server, "alias.example", TYPE_A).answers, sink, "CNAME target blocked");
        assert_eq!(lookup(server, "hosted.example", TYPE_A).answers, sink, "answer address blocked");
        assert_eq!(lookup(server, "fine.example", TYPE_A).answers, [Answer::Address("192.0.2.1".parse().unwrap())]);

        assert_eq!(cache.find("alias.example").unwrap().verdict.code, crate::web::VerdictCode::BadCname);
        assert_eq!(cache.find("hosted.example").unwrap().verdict.code, crate::web::VerdictCode::BadIp);
        assert_eq!(*seen.lock().unwrap(), ["blocktest.phalanx.invalid", "alias.example", "hosted.example"], "logged once per name");
        assert_eq!(events::recent(tmp.path(), 10).len(), 3);
        filter.stop();
    }

    #[test]
    fn report_only_logs_but_resolves() {
        let shared: SharedRules = Arc::new(RwLock::new(Arc::new(WebRules::load(None, &UserLists::default()).unwrap())));
        let filter = DnsFilter::start(
            FilterConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstreams: vec![fake_upstream()],
                sinkhole: "127.66.0.1".parse().unwrap(),
                mode: Mode::ReportOnly,
                data_dir: None,
            },
            shared,
            Arc::new(RedirectionCache::new()),
            None,
        )
        .unwrap();
        let m = lookup(filter.local_addr(), "blocktest.phalanx.invalid", TYPE_A);
        assert_eq!(m.answers, [Answer::Address("192.0.2.1".parse().unwrap())]);
    }
}
