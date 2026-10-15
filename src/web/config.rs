//! Web protection settings, shared by the desktop app, the command line, the
//! DNS filter and the browser connector (which runs as its own process and
//! reloads this file when it changes).

use super::rules::{host_of, Cidr, UserLists, WebRules};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

const FILE: &str = "web-protection.json";
/// Downloaded web rules, inside the signature folder.
pub const FEED_FILE: &str = "feed-web.txt";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Block matches and show the block page.
    #[default]
    Block,
    /// Record matches but let every connection through.
    ReportOnly,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    /// Master switch for the browser connector's checks.
    pub enabled: bool,
    pub mode: Mode,
    /// Sites the user allowed (names, URLs or CIDR ranges).
    pub user_allow: Vec<String>,
    /// Sites the user blocked (names, URLs or CIDR ranges).
    pub user_block: Vec<String>,
    /// Names the browser extension asked to exclude.
    pub extension_exclusions: Vec<String>,
    /// Use rules from downloaded feeds (not just built-in and your own).
    pub use_feeds: bool,
    /// Run the local DNS filter (the desktop app runs it while open).
    pub dns_filter: bool,
    /// Where the DNS filter listens. Point Windows' DNS server here.
    pub dns_listen: String,
    /// Resolvers the filter forwards to; empty means the ones Windows used
    /// before (read from the network adapters), else 1.1.1.1.
    pub dns_upstream: Vec<String>,
    /// Loopback address blocked names resolve to; the block-page server
    /// listens there.
    pub sinkhole: Ipv4Addr,
    /// Block-page server port. Browsers connect to port 80 for http://, so
    /// other values only help testing.
    pub block_page_port: u16,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: Mode::Block,
            user_allow: Vec::new(),
            user_block: Vec::new(),
            extension_exclusions: Vec::new(),
            use_feeds: true,
            dns_filter: false,
            dns_listen: "127.0.0.1:53".into(),
            dns_upstream: Vec::new(),
            sinkhole: Ipv4Addr::new(127, 66, 0, 1),
            block_page_port: 80,
        }
    }
}

impl WebConfig {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(FILE)
    }

    /// Loads the settings; a missing file gives the defaults. A file that
    /// cannot be parsed is an error (never silently replaced).
    pub fn load(data_dir: &Path) -> Result<Self> {
        let path = Self::path(data_dir);
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(text.trim_start_matches('\u{feff}')).with_context(|| format!("reading {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, data_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(data_dir).with_context(|| format!("creating {}", data_dir.display()))?;
        let path = Self::path(data_dir);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))
    }

    pub fn user_lists(&self) -> UserLists {
        UserLists {
            allow: self.user_allow.clone(),
            block: self.user_block.clone(),
            extension_exclusions: self.extension_exclusions.clone(),
        }
    }

    /// Loads every rule these settings ask for.
    pub fn load_rules(&self, data_dir: &Path) -> Result<WebRules> {
        let feed = self.use_feeds.then(|| crate::update::signature_dir(data_dir).join(FEED_FILE));
        WebRules::load(feed.as_deref(), &self.user_lists())
    }

    /// Adds `site` to the allow list (removing it from the block list).
    /// Returns the stored form, or `None` if it is not a site.
    pub fn allow(&mut self, site: &str) -> Option<String> {
        let entry = list_entry(site)?;
        self.user_block.retain(|e| !same_site(e, &entry));
        if !self.user_allow.iter().any(|e| same_site(e, &entry)) {
            self.user_allow.push(entry.clone());
        }
        Some(entry)
    }

    /// Adds `site` to the block list (removing it from the allow list).
    pub fn block(&mut self, site: &str) -> Option<String> {
        let entry = list_entry(site)?;
        self.user_allow.retain(|e| !same_site(e, &entry));
        if !self.user_block.iter().any(|e| same_site(e, &entry)) {
            self.user_block.push(entry.clone());
        }
        Some(entry)
    }

    /// Removes `site` from both lists. Returns whether anything changed.
    pub fn forget(&mut self, site: &str) -> bool {
        let Some(entry) = list_entry(site) else { return false };
        let before = self.user_allow.len() + self.user_block.len() + self.extension_exclusions.len();
        self.user_allow.retain(|e| !same_site(e, &entry));
        self.user_block.retain(|e| !same_site(e, &entry));
        self.extension_exclusions.retain(|e| !same_site(e, &entry));
        before != self.user_allow.len() + self.user_block.len() + self.extension_exclusions.len()
    }

    pub fn dns_listen_addr(&self) -> Result<SocketAddr> {
        self.dns_listen.parse().with_context(|| format!("`{}` is not an address:port", self.dns_listen))
    }

    /// The resolvers to forward to.
    pub fn upstreams(&self) -> Vec<SocketAddr> {
        let configured: Vec<SocketAddr> = self.dns_upstream.iter().filter_map(|s| parse_resolver(s)).collect();
        if !configured.is_empty() {
            return configured;
        }
        let listen = self.dns_listen_addr().ok();
        let system: Vec<SocketAddr> = system_resolvers()
            .into_iter()
            .map(|ip| SocketAddr::new(ip, 53))
            .filter(|a| !a.ip().is_loopback() && Some(*a) != listen)
            .collect();
        if system.is_empty() { vec!["1.1.1.1:53".parse().expect("valid"), "1.0.0.1:53".parse().expect("valid")] } else { system }
    }
}

/// `1.1.1.1` or `1.1.1.1:53` or `[2606:4700::1111]:53`.
pub fn parse_resolver(text: &str) -> Option<SocketAddr> {
    let text = text.trim();
    text.parse::<SocketAddr>().ok().or_else(|| text.parse::<std::net::IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)))
}

/// A CIDR range as written, or the host of a name/URL.
fn list_entry(site: &str) -> Option<String> {
    match Cidr::parse(site.trim()) {
        Some(net) => Some(net.to_string()),
        None => host_of(site),
    }
}

fn same_site(a: &str, b: &str) -> bool {
    list_entry(a).is_some_and(|x| x == b)
}

/// DNS servers configured on this PC's network adapters (static or from
/// DHCP), in adapter order, without duplicates.
pub fn system_resolvers() -> Vec<std::net::IpAddr> {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
        let mut out: Vec<std::net::IpAddr> = Vec::new();
        let roots = [
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
            r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces",
        ];
        for root in roots {
            let Ok(interfaces) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(root) else { continue };
            for name in interfaces.enum_keys().flatten() {
                let Ok(key) = interfaces.open_subkey(&name) else { continue };
                for value in ["NameServer", "DhcpNameServer"] {
                    let text: String = key.get_value(value).unwrap_or_default();
                    for ip in text.split([' ', ',']).filter_map(|s| s.trim().parse().ok()) {
                        if !out.contains(&ip) {
                            out.push(ip);
                        }
                    }
                }
            }
        }
        out
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/etc/resolv.conf")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.strip_prefix("nameserver"))
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    }
}

/// Whether any network adapter is set to use `listen`'s address as its DNS
/// server (statically), i.e. whether the DNS filter is actually in the path.
pub fn windows_uses_filter(listen: &SocketAddr) -> bool {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
        let target = listen.ip().to_string();
        let roots = [
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
            r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces",
        ];
        roots.iter().any(|root| {
            RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(root).is_ok_and(|interfaces| {
                interfaces.enum_keys().flatten().any(|name| {
                    interfaces
                        .open_subkey(&name)
                        .and_then(|k| k.get_value::<String, _>("NameServer"))
                        .is_ok_and(|v| v.split([' ', ',']).any(|s| s.trim() == target))
                })
            })
        })
    }
    #[cfg(not(windows))]
    {
        let _ = listen;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_and_block_lists_stay_exclusive() {
        let mut c = WebConfig::default();
        assert_eq!(c.block("https://Bad.Example/x").as_deref(), Some("bad.example"));
        assert_eq!(c.allow("bad.example").as_deref(), Some("bad.example"));
        assert!(c.user_block.is_empty());
        assert_eq!(c.user_allow, ["bad.example"]);
        c.allow("BAD.example.");
        assert_eq!(c.user_allow.len(), 1, "no duplicates");
        assert_eq!(c.block("203.0.113.9/24").as_deref(), Some("203.0.113.0/24"));
        assert!(c.forget("bad.example"));
        assert!(!c.forget("bad.example"));
        assert!(c.allow("not a site").is_none());
    }

    #[test]
    fn saves_and_loads() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(WebConfig::load(tmp.path()).unwrap(), WebConfig::default());
        let mut c = WebConfig::default();
        c.mode = Mode::ReportOnly;
        c.allow("ok.example");
        c.save(tmp.path()).unwrap();
        assert_eq!(WebConfig::load(tmp.path()).unwrap(), c);
        std::fs::write(WebConfig::path(tmp.path()), "{ broken").unwrap();
        assert!(WebConfig::load(tmp.path()).is_err());
    }

    #[test]
    fn resolvers_parse_with_default_port() {
        assert_eq!(parse_resolver("9.9.9.9"), Some("9.9.9.9:53".parse().unwrap()));
        assert_eq!(parse_resolver("[2606:4700::1111]:5353"), Some("[2606:4700::1111]:5353".parse().unwrap()));
        let mut c = WebConfig::default();
        c.dns_upstream = vec!["8.8.8.8".into(), "junk".into()];
        assert_eq!(c.upstreams(), ["8.8.8.8:53".parse().unwrap()]);
    }
}
