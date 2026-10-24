//! Web protection in the service: the DNS filter and block page, which keep
//! running when nobody is signed in (so Windows never points at a filter
//! that is not there), and the web settings, which the service keeps.

use super::protect::Hub;
use crate::ipc::Event;
use crate::web::blockpage::BlockPageServer;
use crate::web::cache::RedirectionCache;
use crate::web::dnsfilter::{DnsFilter, FilterConfig};
use crate::web::events::WebEvent;
use crate::web::{SharedRules, WebConfig, WebRules};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

/// The reply to `WebStatus`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebStatus {
    /// The DNS filter (and block page) are serving.
    pub dns_filter: bool,
    /// Blocking rules loaded (built-in, feeds and the user's lists).
    pub rules: usize,
    /// Why the rules or the DNS filter could not be loaded or started.
    pub error: Option<String>,
}

#[derive(Default)]
struct State {
    /// What the DNS filter was started with, to restart it only when needed.
    listening: Option<Listening>,
    servers: Option<(DnsFilter, BlockPageServer)>,
    rules: usize,
    error: Option<String>,
}

/// The settings a running DNS filter depends on.
#[derive(Clone, PartialEq)]
struct Listening {
    listen: String,
    upstream: Vec<String>,
    sinkhole: std::net::Ipv4Addr,
    port: u16,
    mode: crate::web::Mode,
}

pub(crate) struct WebGuard {
    data_dir: PathBuf,
    hub: Arc<Hub>,
    rules: SharedRules,
    cache: Arc<RedirectionCache>,
    state: Mutex<State>,
}

impl WebGuard {
    pub fn new(data_dir: &Path, hub: Arc<Hub>) -> Arc<Self> {
        Arc::new(Self {
            data_dir: data_dir.to_path_buf(),
            hub,
            rules: Arc::new(RwLock::new(Arc::new(WebRules::default()))),
            cache: Arc::new(RedirectionCache::new()),
            state: Mutex::default(),
        })
    }

    /// Loads the rules `config` asks for and runs the DNS filter if it is on.
    /// A running filter keeps serving with the new rules; it is restarted
    /// only when where it listens, forwards to or how it answers changed.
    pub fn apply(&self, config: &WebConfig) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.error = None;
        match config.load_rules(&self.data_dir) {
            Ok(rules) => {
                state.rules = rules.counts().blocking();
                *self.rules.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(rules);
            }
            // Keep the rules there were rather than protect with none.
            Err(e) => state.error = Some(format!("the web rules could not be loaded: {e:#}")),
        }
        let wanted = config.dns_filter.then(|| Listening {
            listen: config.dns_listen.clone(),
            upstream: config.dns_upstream.clone(),
            sinkhole: config.sinkhole,
            port: config.block_page_port,
            mode: config.mode,
        });
        if wanted != state.listening || (wanted.is_some() && state.servers.is_none()) {
            if let Some((filter, page)) = state.servers.take() {
                filter.stop();
                page.stop();
            }
            state.listening = wanted.clone();
            if wanted.is_some() {
                match self.start_servers(config) {
                    Ok(servers) => state.servers = Some(servers),
                    Err(e) => state.error = Some(format!("the DNS filter could not start: {e:#}")),
                }
            }
        }
        self.hub.send(&Event::WebApplied { status: Self::status_of(&state) });
    }

    fn start_servers(&self, config: &WebConfig) -> anyhow::Result<(DnsFilter, BlockPageServer)> {
        let listen = config.dns_listen_addr()?;
        let page = BlockPageServer::start(SocketAddr::new(config.sinkhole.into(), config.block_page_port), Arc::clone(&self.cache))?;
        let hub = Arc::clone(&self.hub);
        let on_event = Box::new(move |event: &WebEvent| hub.send(&Event::Web { event: event.clone() }));
        let filter = DnsFilter::start(
            FilterConfig { listen, upstreams: config.upstreams(), sinkhole: config.sinkhole, mode: config.mode, data_dir: Some(self.data_dir.clone()) },
            Arc::clone(&self.rules),
            Arc::clone(&self.cache),
            Some(on_event),
        );
        match filter {
            Ok(filter) => Ok((filter, page)),
            Err(e) => {
                page.stop();
                Err(e)
            }
        }
    }

    /// Loads the rules again with the settings as saved (new feeds arrived).
    pub fn reload(&self) {
        match WebConfig::load(&self.data_dir) {
            Ok(config) => self.apply(&config),
            Err(e) => self.hub.send(&Event::ProtectionError { message: format!("reading the web settings: {e:#}") }),
        }
    }

    pub fn status(&self) -> WebStatus {
        Self::status_of(&self.state.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn status_of(state: &State) -> WebStatus {
        WebStatus { dns_filter: state.servers.is_some(), rules: state.rules, error: state.error.clone() }
    }

    /// Stops the DNS filter and block page (the service is stopping).
    pub fn stop(&self) {
        if let Some((filter, page)) = self.state.lock().unwrap_or_else(PoisonError::into_inner).servers.take() {
            filter.stop();
            page.stop();
        }
    }
}
