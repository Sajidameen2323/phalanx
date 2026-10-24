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
/// Downloaded ad and tracker domains, inside the signature folder.
pub const ADS_FILE: &str = "feed-ads.txt";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Block matches and show the block page.
    #[default]
    Block,
    /// Record matches but let every connection through.
    ReportOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Also block ad and tracker domains (from the downloaded ad list).
    pub block_ads: bool,
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
            block_ads: false,
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
        let ads = self.block_ads.then(|| ads_file(data_dir));
        WebRules::load_with_ads(feed.as_deref(), ads.as_deref(), &self.user_lists())
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

    /// Adds `site` to the block list (removing it from the allow lists,
    /// including the browser's, which would otherwise still let it through).
    pub fn block(&mut self, site: &str) -> Option<String> {
        let entry = list_entry(site)?;
        self.user_allow.retain(|e| !same_site(e, &entry));
        self.extension_exclusions.retain(|e| !same_site(e, &entry));
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

    /// Stops blocking `site`: removes every block entry that covers it or
    /// lies under it (unblocking `www.example.com` removes `example.com`).
    /// Returns the entries removed.
    pub fn unblock(&mut self, site: &str) -> Vec<String> {
        take_related(&mut self.user_block, site)
    }

    /// Stops allowing `site`, in both allow lists, the same way.
    pub fn unallow(&mut self, site: &str) -> Vec<String> {
        let mut removed = take_related(&mut self.user_allow, site);
        removed.extend(take_related(&mut self.extension_exclusions, site));
        removed
    }

    /// Loads the current settings, changes them and saves, so a change made
    /// elsewhere a moment ago is kept. Returns the saved settings.
    pub fn update(data_dir: &Path, change: impl FnOnce(&mut WebConfig)) -> Result<WebConfig> {
        let mut config = Self::load(data_dir)?;
        change(&mut config);
        config.save(data_dir)?;
        Ok(config)
    }

    /// Three-way merge: `self` was edited from `base` while the file became
    /// `theirs`. Fields only one side changed take that side; lists take both
    /// sides' additions and removals; for anything else both changed, `self` wins.
    pub fn merged(&self, base: &WebConfig, theirs: &WebConfig) -> Result<WebConfig> {
        let (ours, base, mut out) = (serde_json::to_value(self)?, serde_json::to_value(base)?, serde_json::to_value(theirs)?);
        let (Some(ours), Some(base), Some(merged)) = (ours.as_object(), base.as_object(), out.as_object_mut()) else {
            return Ok(self.clone());
        };
        for (key, mine) in ours {
            let before = base.get(key);
            if before == Some(mine) {
                continue; // we did not change it
            }
            let other = merged.get(key).and_then(|t| t.as_array()).cloned();
            let value = match (mine.as_array(), before.and_then(|b| b.as_array()), other) {
                (Some(mine), Some(before), Some(other)) => {
                    let mut list: Vec<serde_json::Value> = other.iter().filter(|v| mine.contains(v) || !before.contains(v)).cloned().collect();
                    let added: Vec<serde_json::Value> = mine.iter().filter(|v| !before.contains(v) && !list.contains(v)).cloned().collect();
                    list.extend(added);
                    serde_json::Value::Array(list)
                }
                _ => mine.clone(),
            };
            merged.insert(key.clone(), value);
        }
        Ok(serde_json::from_value(out)?)
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

/// The downloaded ad and tracker list.
pub fn ads_file(data_dir: &Path) -> PathBuf {
    crate::update::signature_dir(data_dir).join(ADS_FILE)
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

/// Removes the entries of `list` that are `site`, a parent domain of it or
/// under it; a CIDR range only when written the same. Returns them.
fn take_related(list: &mut Vec<String>, site: &str) -> Vec<String> {
    let Some(entry) = list_entry(site) else { return Vec::new() };
    let related = |e: &String| match list_entry(e) {
        Some(e) if e == entry => true,
        Some(e) if Cidr::parse(&e).is_some() || Cidr::parse(&entry).is_some() => false,
        Some(e) => entry.ends_with(&format!(".{e}")) || e.ends_with(&format!(".{entry}")),
        None => false,
    };
    let (removed, kept): (Vec<String>, Vec<String>) = list.drain(..).partition(related);
    *list = kept;
    removed
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

/// A change to one site, as the browser (or the command line) asks for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SiteChange {
    /// Block it everywhere; it stops being allowed.
    Block,
    /// Stop blocking it.
    Unblock,
    /// Allow it everywhere ("Always allow this site"); it stops being blocked.
    Allow,
    /// Stop allowing it.
    Unallow,
}

impl SiteChange {
    /// Unblocking and allowing make web protection weaker.
    pub fn weakens(self) -> bool {
        matches!(self, SiteChange::Unblock | SiteChange::Allow)
    }
}

/// Why a site change was not made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SiteError {
    NotAWebAddress,
    /// The site is not on the list it was to leave.
    NotListed(String),
}

impl std::fmt::Display for SiteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SiteError::NotAWebAddress => f.write_str("not a web address"),
            SiteError::NotListed(host) => write!(f, "{host} is not on that list (it may have been changed in the Phalanx app)"),
        }
    }
}

impl WebConfig {
    /// Makes `change` to `site` and returns the host it applied to.
    /// Removing covers the entry that applies: unblocking `www.example.com`
    /// removes an `example.com` entry.
    pub fn change_site(&mut self, change: SiteChange, site: &str) -> Result<String, SiteError> {
        // Only websites: `chrome://settings` must not become a site called "settings".
        let lower = site.trim().to_ascii_lowercase();
        let web_scheme = !lower.contains("://") || lower.starts_with("http://") || lower.starts_with("https://");
        let host = host_of(site)
            .filter(|h| web_scheme && (h.contains('.') || h.parse::<std::net::IpAddr>().is_ok()))
            .ok_or(SiteError::NotAWebAddress)?;
        let add = |list: &mut Vec<String>, host: &str| {
            if !list.iter().any(|h| h == host) {
                list.push(host.to_string());
            }
        };
        let changed = match change {
            SiteChange::Block => {
                self.unallow(&host);
                add(&mut self.user_block, &host);
                true
            }
            SiteChange::Unblock => !self.unblock(&host).is_empty(),
            SiteChange::Allow => {
                self.unblock(&host);
                add(&mut self.extension_exclusions, &host);
                true
            }
            SiteChange::Unallow => !self.unallow(&host).is_empty(),
        };
        if changed { Ok(host) } else { Err(SiteError::NotListed(host)) }
    }

    /// How changing from `self` to `new` weakens web protection, in plain
    /// words; empty when it does not.
    pub fn weakened_by(&self, new: &WebConfig) -> Vec<String> {
        let listed = |list: &[String], entry: &str| list.iter().any(|e| list_entry(e).is_some() && list_entry(e) == list_entry(entry));
        let mut out = Vec::new();
        if self.enabled && !new.enabled {
            out.push("turns off checking sites in browsers".into());
        }
        if self.mode == Mode::Block && new.mode == Mode::ReportOnly {
            out.push("only reports dangerous sites instead of blocking them".into());
        }
        for entry in new.user_allow.iter().chain(&new.extension_exclusions) {
            if !listed(&self.user_allow, entry) && !listed(&self.extension_exclusions, entry) {
                out.push(format!("allows {entry}"));
            }
        }
        for entry in self.user_block.iter().filter(|e| !listed(&new.user_block, e)) {
            out.push(format!("stops blocking {entry}"));
        }
        if self.use_feeds && !new.use_feeds {
            out.push("stops using the downloaded lists of dangerous sites".into());
        }
        if self.block_ads && !new.block_ads {
            out.push("stops blocking ads and trackers".into());
        }
        if self.dns_filter && !new.dns_filter {
            out.push("turns off the DNS filter".into());
        }
        if (&self.dns_listen, &self.dns_upstream, self.sinkhole, self.block_page_port) != (&new.dns_listen, &new.dns_upstream, new.sinkhole, new.block_page_port) {
            out.push("changes where the DNS filter listens or sends lookups".into());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weakening_web_protection_is_told_apart() {
        let mut base = WebConfig { dns_filter: true, block_ads: true, ..Default::default() };
        base.change_site(SiteChange::Block, "https://bad.example/x").unwrap();
        assert!(base.weakened_by(&base).is_empty());

        let mut allowed = base.clone();
        allowed.change_site(SiteChange::Allow, "https://www.shady.test/").unwrap();
        assert_eq!(base.weakened_by(&allowed), ["allows www.shady.test"]);
        let mut unblocked = base.clone();
        unblocked.change_site(SiteChange::Unblock, "bad.example").unwrap();
        assert_eq!(base.weakened_by(&unblocked), ["stops blocking bad.example"]);
        let cases: Vec<(WebConfig, &str)> = vec![
            (WebConfig { enabled: false, ..base.clone() }, "turns off checking sites in browsers"),
            (WebConfig { mode: Mode::ReportOnly, ..base.clone() }, "only reports dangerous sites instead of blocking them"),
            (WebConfig { use_feeds: false, ..base.clone() }, "stops using the downloaded lists of dangerous sites"),
            (WebConfig { block_ads: false, ..base.clone() }, "stops blocking ads and trackers"),
            (WebConfig { dns_filter: false, ..base.clone() }, "turns off the DNS filter"),
            (WebConfig { dns_upstream: vec!["203.0.113.9".into()], ..base.clone() }, "changes where the DNS filter listens or sends lookups"),
        ];
        for (new, why) in cases {
            assert_eq!(base.weakened_by(&new), [why]);
        }

        // Strengthening asks nothing: blocking more, allowing less.
        let mut stronger = allowed.clone();
        stronger.change_site(SiteChange::Unallow, "www.shady.test").unwrap();
        stronger.change_site(SiteChange::Block, "another.test").unwrap();
        assert!(allowed.weakened_by(&stronger).is_empty(), "{:?}", allowed.weakened_by(&stronger));
        assert!(SiteChange::Allow.weakens() && SiteChange::Unblock.weakens() && !SiteChange::Block.weakens() && !SiteChange::Unallow.weakens());
    }

    #[test]
    fn site_changes_take_web_addresses_only() {
        let mut c = WebConfig::default();
        assert_eq!(c.change_site(SiteChange::Block, "chrome://settings"), Err(SiteError::NotAWebAddress));
        assert_eq!(c.change_site(SiteChange::Block, "https://www.Example.com/a?b"), Ok("www.example.com".into()));
        assert_eq!(c.change_site(SiteChange::Unallow, "www.example.com"), Err(SiteError::NotListed("www.example.com".into())));
        assert_eq!(c.change_site(SiteChange::Unblock, "example.com"), Ok("example.com".into()), "the entry that applies");
        assert!(c.user_block.is_empty());
    }

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
    fn blocking_drops_the_browser_exclusion_and_unblocking_covers_parents() {
        let mut c = WebConfig { extension_exclusions: vec!["spicett.com".into()], ..Default::default() };
        c.block("https://spicett.com/");
        assert!(c.extension_exclusions.is_empty(), "an exclusion would still let it through");
        let rules = c.load_rules(tempfile::tempdir().unwrap().path()).unwrap();
        assert!(rules.classify_domain("spicett.com").blocks());

        c.user_block = vec!["spicett.com".into(), "cdn.other.example".into(), "203.0.113.0/24".into(), "notspicett.com".into()];
        assert_eq!(c.unblock("https://www.spicett.com/page"), ["spicett.com"], "parent entry covering it");
        assert_eq!(c.unblock("other.example"), ["cdn.other.example"], "entries under it");
        assert!(c.unblock("203.0.113.9").is_empty(), "ranges only when written the same");
        assert_eq!(c.unblock("203.0.113.0/24"), ["203.0.113.0/24"]);
        assert_eq!(c.user_block, ["notspicett.com"]);
        c.user_allow = vec!["a.example".into()];
        c.extension_exclusions = vec!["www.a.example".into()];
        assert_eq!(c.unallow("a.example").len(), 2);
    }

    #[test]
    fn merge_keeps_both_sides_list_edits() {
        let base = WebConfig { user_block: vec!["one.example".into(), "two.example".into()], ..Default::default() };
        // The app removed two.example and added three.example ...
        let mut ours = base.clone();
        ours.user_block = vec!["one.example".into(), "three.example".into()];
        ours.block_ads = true;
        // ... while the browser blocked four.example and allowed ok.example.
        let mut theirs = base.clone();
        theirs.user_block.push("four.example".into());
        theirs.extension_exclusions = vec!["ok.example".into()];
        theirs.dns_filter = true;
        let m = ours.merged(&base, &theirs).unwrap();
        assert_eq!(m.user_block, ["one.example", "four.example", "three.example"]);
        assert_eq!(m.extension_exclusions, ["ok.example"]);
        assert!(m.block_ads && m.dns_filter, "each side's own change kept");
    }

    #[test]
    fn update_reads_the_file_first() {
        let tmp = tempfile::tempdir().unwrap();
        // Saved by another program after this one last read the file.
        let mut elsewhere = WebConfig::default();
        elsewhere.block("x.example");
        elsewhere.save(tmp.path()).unwrap();
        let saved = WebConfig::update(tmp.path(), |c| c.extension_exclusions.push("y.example".into())).unwrap();
        assert_eq!((saved.user_block.as_slice(), saved.extension_exclusions.as_slice()), (&["x.example".to_string()][..], &["y.example".to_string()][..]));
    }

    #[test]
    fn saves_and_loads() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(WebConfig::load(tmp.path()).unwrap(), WebConfig::default());
        let mut c = WebConfig { mode: Mode::ReportOnly, ..Default::default() };
        c.allow("ok.example");
        c.save(tmp.path()).unwrap();
        assert_eq!(WebConfig::load(tmp.path()).unwrap(), c);
        std::fs::write(WebConfig::path(tmp.path()), "{ broken").unwrap();
        assert!(WebConfig::load(tmp.path()).is_err());
        // Settings from before ad blocking existed load with it off.
        std::fs::write(WebConfig::path(tmp.path()), r#"{"enabled": true}"#).unwrap();
        assert!(!WebConfig::load(tmp.path()).unwrap().block_ads);
        std::fs::write(WebConfig::path(tmp.path()), "{ broken").unwrap();
        assert!(WebConfig::load(tmp.path()).is_err());
    }

    #[test]
    fn ad_list_loads_only_when_switched_on() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(crate::update::signature_dir(tmp.path())).unwrap();
        std::fs::write(ads_file(tmp.path()), "domain doubleclick.net ads StevenBlack.Ads\n").unwrap();
        let mut c = WebConfig::default();
        assert!(!c.load_rules(tmp.path()).unwrap().classify_domain("doubleclick.net").blocks());
        c.block_ads = true;
        let v = c.load_rules(tmp.path()).unwrap().classify_domain("ad.doubleclick.net");
        assert_eq!((v.blocks(), v.category.as_str(), v.list.as_str()), (true, "ads", "adsBlockList"));
    }

    #[test]
    fn resolvers_parse_with_default_port() {
        assert_eq!(parse_resolver("9.9.9.9"), Some("9.9.9.9:53".parse().unwrap()));
        assert_eq!(parse_resolver("[2606:4700::1111]:5353"), Some("[2606:4700::1111]:5353".parse().unwrap()));
        let c = WebConfig { dns_upstream: vec!["8.8.8.8".into(), "junk".into()], ..Default::default() };
        assert_eq!(c.upstreams(), ["8.8.8.8:53".parse().unwrap()]);
    }
}
