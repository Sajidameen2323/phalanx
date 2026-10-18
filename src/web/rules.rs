//! Web rule store and classifier.
//!
//! Rules block on five axes (domain, URL, IP/CIDR, TCP port, and DNS CNAME
//! targets) and come from three places: the built-in list, downloaded feeds
//! and the user's own block list. The optional ad and tracker list is kept
//! apart and only consulted when no threat rule matched. Allow lists (the user's, known-good names,
//! false-positive reductions and exclusions requested by the browser
//! extension) override a match.
//!
//! Every decision is a [`Verdict`] whose [`VerdictCode`] says *why*:
//! codes 1 to 3 block, everything else allows. The threat name and category
//! travel separately, from the rule that matched.

use super::url::{normalize_host, WebAddress};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;

/// Why a name, address or URL was allowed or blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum VerdictCode {
    /// No rule matched.
    Clean = 0,
    /// A bad IP address, CIDR range or port rule matched.
    BadIp = 1,
    /// A bad domain or URL rule matched.
    BadDomain = 2,
    /// A DNS answer's CNAME target is blocked; the alias is blocked with it.
    BadCname = 3,
    /// The user allowed this site.
    UserAllowed = 4,
    /// A false-positive reduction entry overrides a feed match.
    FalsePositive = 5,
    /// Excluded at the browser extension's request.
    ExtensionExcluded = 6,
    /// A known-good name that rules never block.
    KnownGood = 7,
}

impl VerdictCode {
    /// Codes 1, 2 and 3 block; everything else allows.
    pub fn blocks(self) -> bool {
        matches!(self as u8, 1..=3)
    }

    pub fn number(self) -> u8 {
        self as u8
    }

    pub fn label(self) -> &'static str {
        match self {
            VerdictCode::Clean => "no rule matched",
            VerdictCode::BadIp => "malicious IP address or port",
            VerdictCode::BadDomain => "malicious site",
            VerdictCode::BadCname => "redirects to a malicious site (DNS alias)",
            VerdictCode::UserAllowed => "allowed by you",
            VerdictCode::FalsePositive => "allowed: known false positive",
            VerdictCode::ExtensionExcluded => "allowed: browser extension exclusion",
            VerdictCode::KnownGood => "allowed: known-good site",
        }
    }
}

/// Where a block rule came from; decides the list name used in reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Builtin,
    /// Downloaded threat-intelligence feeds (refreshed by `update`).
    Feed,
    User,
    /// The optional ad and tracker list (domains only).
    Ads,
}

#[derive(Debug, Clone)]
struct RuleInfo {
    category: Arc<str>,
    threat: Arc<str>,
    origin: Origin,
}

/// The outcome of classifying a domain, address, port or URL.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verdict {
    pub code: VerdictCode,
    /// The name or address that decided it. For a CNAME block this is the
    /// blocked target, not the name that was asked for.
    pub trigger: String,
    /// Which list decided, e.g. `domainBlockList`, `feedUrlBlockList`,
    /// `userAllowList`; empty when no rule matched.
    pub list: String,
    /// Threat category of the matched rule (empty unless a rule matched).
    pub category: String,
    /// Threat name of the matched rule (empty unless a rule matched).
    pub threat: String,
    /// The rule's own value: a domain, CIDR range, port or URL.
    pub rule: String,
}

impl Verdict {
    fn clean(trigger: &str) -> Self {
        Self::allowed(VerdictCode::Clean, trigger, "", "")
    }

    fn allowed(code: VerdictCode, trigger: &str, list: &str, rule: &str) -> Self {
        Self {
            code,
            trigger: trigger.to_string(),
            list: list.to_string(),
            category: String::new(),
            threat: String::new(),
            rule: rule.to_string(),
        }
    }

    fn matched(code: VerdictCode, trigger: &str, list: String, rule: &str, info: &RuleInfo) -> Self {
        Self {
            code,
            trigger: trigger.to_string(),
            list,
            category: info.category.to_string(),
            threat: info.threat.to_string(),
            rule: rule.to_string(),
        }
    }

    pub fn blocks(&self) -> bool {
        self.code.blocks()
    }

    /// One line for logs and the command line.
    pub fn describe(&self) -> String {
        if self.blocks() {
            format!("BLOCK ({}) {} [{}] via {} rule `{}`", self.code.number(), self.threat, self.category, self.list, self.rule)
        } else if self.code == VerdictCode::Clean {
            "allow (0) no rule matched".to_string()
        } else {
            format!("allow ({}) {}{}", self.code.number(), self.code.label(), if self.rule.is_empty() { String::new() } else { format!(" `{}`", self.rule) })
        }
    }
}

/// An IPv4 or IPv6 network in CIDR form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(text: &str) -> Option<Self> {
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
            None => (text, None),
        };
        let addr: IpAddr = addr.trim_start_matches('[').trim_end_matches(']').parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return None;
        }
        Some(Self { addr: mask(addr, prefix), prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.addr.is_ipv4() && mask(ip, self.prefix) == self.addr
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let max = if self.addr.is_ipv4() { 32 } else { 128 };
        if self.prefix == max { write!(f, "{}", self.addr) } else { write!(f, "{}/{}", self.addr, self.prefix) }
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
            IpAddr::V4(Ipv4Addr::from(bits & m))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix as u32) };
            IpAddr::V6(Ipv6Addr::from(bits & m))
        }
    }
}

/// Addresses that are never blocked: this PC, the local network, and
/// multicast/broadcast. Returns the reason.
pub fn always_allowed(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Some("loopback address")
            } else if v4.is_private() || v4.is_link_local() || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) {
                Some("local network address")
            } else if v4.is_multicast() || v4.is_broadcast() {
                Some("multicast/broadcast address")
            } else if v4.is_unspecified() {
                Some("unspecified address")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            if v6.is_loopback() {
                Some("loopback address")
            } else if (first & 0xFE00) == 0xFC00 || (first & 0xFFC0) == 0xFE80 {
                Some("local network address")
            } else if v6.is_multicast() {
                Some("multicast address")
            } else if v6.is_unspecified() {
                Some("unspecified address")
            } else if let Some(v4) = v6.to_ipv4_mapped() {
                always_allowed(IpAddr::V4(v4))
            } else {
                None
            }
        }
    }
}

/// A decoded DNS answer, as far as classification cares.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    Address(IpAddr),
    Cname(String),
}

/// Counts for display.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct RuleCounts {
    pub domains: usize,
    pub urls: usize,
    pub networks: usize,
    pub ports: usize,
    pub allowed: usize,
    /// Ad and tracker domains (not counted as threat rules).
    pub ads: usize,
}

impl RuleCounts {
    pub fn blocking(&self) -> usize {
        self.domains + self.urls + self.networks + self.ports
    }
}

/// Allow lists kept outside the rule files (in the web protection settings).
#[derive(Debug, Clone, Default)]
pub struct UserLists {
    pub allow: Vec<String>,
    pub block: Vec<String>,
    pub extension_exclusions: Vec<String>,
}

/// All web rules, ready to classify. Cheap to share behind an `Arc`.
#[derive(Default)]
pub struct WebRules {
    domains: HashMap<String, RuleInfo>,
    urls: HashMap<String, RuleInfo>,
    /// Networks grouped by prefix length, so a lookup is one hash probe per
    /// prefix length in use.
    networks: BTreeMap<(bool, u8), HashMap<IpAddr, RuleInfo>>,
    ports: HashMap<u16, RuleInfo>,
    /// Ad and tracker domains, checked after the threat rules.
    ads: HashMap<String, RuleInfo>,
    known_good: HashSet<String>,
    fp_domains: HashSet<String>,
    fp_networks: Vec<Cidr>,
    user_allow: HashSet<String>,
    user_allow_networks: Vec<Cidr>,
    extension_exclusions: HashSet<String>,
    interned: HashMap<String, Arc<str>>,
}

/// The built-in rules shipped with the program.
pub const BUILTIN_RULES: &str = include_str!("../../rules/web.txt");

impl WebRules {
    /// Built-in rules, the downloaded feed file (when given and present) and
    /// the user's lists.
    pub fn load(feed_file: Option<&Path>, user: &UserLists) -> Result<Self> {
        Self::load_with_ads(feed_file, None, user)
    }

    /// As [`load`](Self::load), plus the ad and tracker list when given and
    /// present.
    pub fn load_with_ads(feed_file: Option<&Path>, ads_file: Option<&Path>, user: &UserLists) -> Result<Self> {
        let mut rules = Self::default();
        rules.add_text(BUILTIN_RULES, Origin::Builtin, "built-in web rules")?;
        for (path, origin) in [(feed_file, Origin::Feed), (ads_file, Origin::Ads)] {
            let Some(path) = path else { continue };
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    rules.add_text(&text, origin, &path.display().to_string())?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            }
        }
        rules.add_user_lists(user);
        Ok(rules)
    }

    pub fn add_user_lists(&mut self, user: &UserLists) {
        for entry in &user.allow {
            match Cidr::parse(entry) {
                Some(net) => self.user_allow_networks.push(net),
                None => {
                    if let Some(host) = host_of(entry) {
                        self.user_allow.insert(host);
                    }
                }
            }
        }
        for entry in &user.block {
            let info = RuleInfo { category: self.intern("blocked by you"), threat: self.intern("UserBlocked"), origin: Origin::User };
            if let Some(net) = Cidr::parse(entry) {
                self.networks.entry((net.addr.is_ipv4(), net.prefix)).or_default().insert(net.addr, info);
            } else if let Some(host) = host_of(entry) {
                self.domains.insert(host, info);
            }
        }
        for entry in &user.extension_exclusions {
            if let Some(host) = host_of(entry) {
                self.extension_exclusions.insert(host);
            }
        }
    }

    /// Adds rules in the `rules/web.txt` format. Unknown kinds and malformed
    /// values are skipped, but a file where nothing at all parses is an error.
    pub fn add_text(&mut self, text: &str, origin: Origin, name: &str) -> Result<usize> {
        let mut added = 0;
        let mut meaningful = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            meaningful += 1;
            let mut parts = line.split_whitespace();
            let (Some(kind), Some(value)) = (parts.next(), parts.next()) else { continue };
            let category = parts.next().unwrap_or("malware");
            let rest: Vec<&str> = parts.collect();
            let threat = if rest.is_empty() { format!("Web.{}", capitalize(category)) } else { rest.join(" ") };
            let info = RuleInfo { category: self.intern(category), threat: self.intern(&threat), origin };
            let ok = match kind {
                // The ad list only blocks names; anything else in it is ignored.
                "domain" if origin == Origin::Ads => normalize_host(value).map(|h| self.ads.insert(h, info)).is_some(),
                _ if origin == Origin::Ads => false,
                "domain" => normalize_host(value).map(|h| self.domains.insert(h, info)).is_some(),
                "url" => WebAddress::parse(value).map(|a| self.urls.insert(a.normalized(), info)).is_some(),
                "ip" => Cidr::parse(value)
                    .map(|n| self.networks.entry((n.addr.is_ipv4(), n.prefix)).or_default().insert(n.addr, info))
                    .is_some(),
                "port" => value.parse::<u16>().ok().map(|p| self.ports.insert(p, info)).is_some(),
                "good" => normalize_host(value).map(|h| self.known_good.insert(h)).is_some(),
                "fp" => match Cidr::parse(value) {
                    Some(n) => {
                        self.fp_networks.push(n);
                        true
                    }
                    None => normalize_host(value).map(|h| self.fp_domains.insert(h)).is_some(),
                },
                _ => false,
            };
            added += ok as usize;
        }
        if meaningful > 0 && added == 0 {
            bail!("{name}: no valid web rules");
        }
        Ok(added)
    }

    fn intern(&mut self, text: &str) -> Arc<str> {
        if let Some(existing) = self.interned.get(text) {
            return existing.clone();
        }
        let shared: Arc<str> = Arc::from(text);
        self.interned.insert(text.to_string(), shared.clone());
        shared
    }

    pub fn counts(&self) -> RuleCounts {
        RuleCounts {
            domains: self.domains.len(),
            urls: self.urls.len(),
            networks: self.networks.values().map(HashMap::len).sum(),
            ports: self.ports.len(),
            allowed: self.user_allow.len() + self.user_allow_networks.len(),
            ads: self.ads.len(),
        }
    }

    fn list_name(kind: &str, origin: Origin) -> String {
        match origin {
            Origin::Builtin => format!("{kind}BlockList"),
            Origin::Feed => format!("feed{}BlockList", capitalize(kind)),
            Origin::User => "userBlockList".to_string(),
            Origin::Ads => "adsBlockList".to_string(),
        }
    }

    /// Classifies a host name (or an IP literal). Order follows the domain
    /// classifier: find the most specific matching block rule, then let
    /// known-good, user, false-positive and extension exclusions override it.
    /// The user's own block rules are only overridden by the user's allow list.
    /// Ad and tracker names are only looked up when no threat rule matched.
    pub fn classify_domain(&self, name: &str) -> Verdict {
        let Some(name) = normalize_host(name) else { return Verdict::clean(name) };
        if let Ok(ip) = name.parse::<IpAddr>() {
            return self.classify_ip(ip, None);
        }
        let Some((rule, info)) = suffix_lookup(&self.domains, &name).or_else(|| suffix_lookup(&self.ads, &name)) else {
            return Verdict::clean(&name);
        };
        if info.origin != Origin::User && self.is_known_good(&name) {
            return Verdict::allowed(VerdictCode::KnownGood, &name, "knownGoodList", &name);
        }
        if let Some(allowed) = suffix_contains(&self.user_allow, &name) {
            return Verdict::allowed(VerdictCode::UserAllowed, &name, "userAllowList", allowed);
        }
        if info.origin != Origin::User {
            if let Some(fp) = suffix_contains(&self.fp_domains, &name) {
                return Verdict::allowed(VerdictCode::FalsePositive, &name, "falsePositiveList", fp);
            }
        }
        if let Some(excluded) = suffix_contains(&self.extension_exclusions, &name) {
            return Verdict::allowed(VerdictCode::ExtensionExcluded, &name, "extensionExclusions", excluded);
        }
        Verdict::matched(VerdictCode::BadDomain, &name, Self::list_name("domain", info.origin), rule, info)
    }

    /// Classifies an IP address. `via` is the name it was resolved from, if
    /// any: a known-good or allowed name keeps its addresses allowed.
    pub fn classify_ip(&self, ip: IpAddr, via: Option<&str>) -> Verdict {
        let text = ip.to_string();
        if always_allowed(ip).is_some() {
            return Verdict::clean(&text);
        }
        let Some((net, info)) = self.network_lookup(ip) else { return Verdict::clean(&text) };
        if let Some(net) = self.user_allow_networks.iter().find(|n| n.contains(ip)) {
            return Verdict::allowed(VerdictCode::UserAllowed, &text, "userAllowList", &net.to_string());
        }
        if info.origin != Origin::User {
            if let Some(fp) = self.fp_networks.iter().find(|n| n.contains(ip)) {
                return Verdict::allowed(VerdictCode::FalsePositive, &text, "falsePositiveList", &fp.to_string());
            }
        }
        if self.extension_exclusions.contains(&text) {
            return Verdict::allowed(VerdictCode::ExtensionExcluded, &text, "extensionExclusions", &text);
        }
        if let Some(name) = via.and_then(normalize_host) {
            if self.is_known_good(&name) {
                return Verdict::allowed(VerdictCode::KnownGood, &name, "knownGoodList", &name);
            }
            if let Some(allowed) = suffix_contains(&self.user_allow, &name) {
                return Verdict::allowed(VerdictCode::UserAllowed, &name, "userAllowList", allowed);
            }
        }
        Verdict::matched(VerdictCode::BadIp, &text, Self::list_name("ip", info.origin), &net.to_string(), info)
    }

    /// Classifies a TCP port (an explicit port in a URL).
    pub fn classify_port(&self, port: u16) -> Verdict {
        match self.ports.get(&port) {
            Some(info) => Verdict::matched(VerdictCode::BadIp, &port.to_string(), Self::list_name("port", info.origin), &port.to_string(), info),
            None => Verdict::clean(&port.to_string()),
        }
    }

    /// Classifies a full web address: exact URL rules first (they also apply
    /// on known-good hosts), then the host, then an explicit port.
    pub fn classify_url(&self, input: &str) -> Verdict {
        let Some(address) = WebAddress::parse(input) else { return Verdict::clean(input) };
        let host_allowed = suffix_contains(&self.user_allow, &address.host).is_some()
            || address.ip().is_some_and(|ip| self.user_allow_networks.iter().any(|n| n.contains(ip)));
        let normalized = address.normalized();
        let url_match = self
            .urls
            .get_key_value(&normalized)
            .or_else(|| address.without_query().and_then(|u| self.urls.get_key_value(&u)));
        if let Some((rule, info)) = url_match {
            if host_allowed {
                return Verdict::allowed(VerdictCode::UserAllowed, &address.host, "userAllowList", &address.host);
            }
            return Verdict::matched(VerdictCode::BadDomain, &normalized, Self::list_name("url", info.origin), rule, info);
        }
        let host = self.classify_domain(&address.host);
        if host.code != VerdictCode::Clean {
            return host;
        }
        match address.port {
            Some(port) if !host_allowed => self.classify_port(port),
            _ => host,
        }
    }

    /// Classifies a DNS lookup and its answers. The asked-for name decides
    /// first (and an allow verdict for it covers its answers); otherwise a
    /// blocked CNAME target blocks the alias, and a blocked address blocks
    /// the name.
    pub fn classify_dns(&self, name: &str, answers: &[Answer]) -> Verdict {
        let first = self.classify_domain(name);
        if first.code != VerdictCode::Clean {
            return first;
        }
        for answer in answers {
            if let Answer::Cname(target) = answer {
                let v = self.classify_domain(target);
                if v.blocks() {
                    return Verdict { code: VerdictCode::BadCname, ..v };
                }
            }
        }
        // Report an exclusion that let a matching answer through.
        let mut excluded = None;
        for answer in answers {
            if let Answer::Address(ip) = answer {
                let v = self.classify_ip(*ip, Some(name));
                if v.blocks() {
                    return v;
                }
                if v.code != VerdictCode::Clean {
                    excluded.get_or_insert(v);
                }
            }
        }
        excluded.unwrap_or(first)
    }

    /// Names that would otherwise fall under an ad rule but are allowed
    /// (known-good, the user's allow list, false positives and browser
    /// exclusions), for blockers that cannot ask per request.
    pub fn ad_exclusions(&self) -> Vec<String> {
        Self::exclusions_under(&self.ads, [&self.known_good, &self.user_allow, &self.fp_domains, &self.extension_exclusions])
    }

    /// Threat-rule names that block after every allow list is applied,
    /// sorted, for blockers that must decide before a request is sent (the
    /// browser's declarativeNetRequest rules). Only plain ASCII host names:
    /// those blockers reject anything else.
    pub fn threat_domains(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .domains
            .keys()
            .filter(|name| is_plain_host(name) && self.classify_domain(name).blocks())
            .cloned()
            .collect();
        out.sort();
        out
    }

    /// Names under a threat rule that are allowed anyway (a subdomain of a
    /// blocked domain on an allow list), for the same blockers. Known-good
    /// and false-positive names do not override the user's own block rules,
    /// so those are only exceptions under feed and built-in rules.
    pub fn threat_exclusions(&self) -> Vec<String> {
        let mut out = Self::exclusions_under(&self.domains, [&self.user_allow, &self.extension_exclusions]);
        let not_user = |name: &&String| suffix_lookup(&self.domains, name).is_some_and(|(_, info)| info.origin != Origin::User);
        out.extend([&self.known_good, &self.fp_domains].into_iter().flatten().filter(not_user).cloned());
        out.retain(|name| is_plain_host(name));
        out.sort();
        out.dedup();
        out
    }

    fn exclusions_under<'a, V>(rules: &HashMap<String, V>, lists: impl IntoIterator<Item = &'a HashSet<String>>) -> Vec<String> {
        let mut out: Vec<String> = lists
            .into_iter()
            .flatten()
            .filter(|name| suffix_lookup(rules, name).is_some())
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn is_known_good(&self, name: &str) -> bool {
        self.known_good.contains(name) || name.strip_prefix("www.").is_some_and(|n| self.known_good.contains(n))
    }

    fn network_lookup(&self, ip: IpAddr) -> Option<(Cidr, &RuleInfo)> {
        // Most specific prefix first.
        self.networks.iter().rev().filter(|((v4, _), _)| *v4 == ip.is_ipv4()).find_map(|((_, prefix), nets)| {
            let key = mask(ip, *prefix);
            nets.get(&key).map(|info| (Cidr { addr: key, prefix: *prefix }, info))
        })
    }
}

/// `name`, then each parent domain, in a map.
fn suffix_lookup<'a, V>(map: &'a HashMap<String, V>, name: &str) -> Option<(&'a str, &'a V)> {
    parents(name).find_map(|n| map.get_key_value(n).map(|(k, v)| (k.as_str(), v)))
}

fn suffix_contains<'a>(set: &'a HashSet<String>, name: &str) -> Option<&'a str> {
    parents(name).find_map(|n| set.get(n).map(String::as_str))
}

/// `a.b.c`, `b.c`, `c`.
fn parents(name: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(name), |n| n.split_once('.').map(|(_, rest)| rest)).filter(|n| !n.is_empty())
}

/// The host of a user-entered site: a bare name, an IP or a full URL.
pub fn host_of(entry: &str) -> Option<String> {
    WebAddress::parse(entry).map(|a| a.host)
}

/// A lower-case ASCII host name (letters, digits, `-`, `.`), as browser
/// rule engines require. IP literals and wildcard entries are not.
fn is_plain_host(name: &str) -> bool {
    !name.is_empty()
        && name.contains('.')
        && name.parse::<IpAddr>().is_err()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(extra: &str, user: UserLists) -> WebRules {
        let mut r = WebRules::load(None, &user).unwrap();
        r.add_text(extra, Origin::Feed, "test").unwrap();
        r
    }

    #[test]
    fn domain_rules_cover_subdomains_not_parents() {
        let r = rules("domain bad.example phishing Phish.Kit\n", UserLists::default());
        let v = r.classify_domain("Login.BAD.example.");
        assert_eq!((v.code, v.list.as_str(), v.category.as_str(), v.threat.as_str(), v.rule.as_str()),
            (VerdictCode::BadDomain, "feedDomainBlockList", "phishing", "Phish.Kit", "bad.example"));
        assert!(v.blocks());
        assert_eq!(r.classify_domain("example").code, VerdictCode::Clean);
        assert_eq!(r.classify_domain("notbad.example").code, VerdictCode::Clean);
        assert_eq!(r.classify_domain("blocktest.phalanx.invalid").list, "domainBlockList");
    }

    #[test]
    fn exclusions_override_in_order() {
        let user = UserLists {
            allow: vec!["https://mine.example/page".into()],
            block: vec!["github.com".into()],
            extension_exclusions: vec!["ext.example".into()],
        };
        let r = rules(
            "domain mine.example\ndomain google.com\ndomain www.google.com\ndomain fp.example\nfp fp.example\ndomain ext.example\ndomain x.workers.dev\n",
            user,
        );
        assert_eq!(r.classify_domain("www.google.com").code, VerdictCode::KnownGood);
        assert_eq!(r.classify_domain("sub.mine.example").code, VerdictCode::UserAllowed);
        assert_eq!(r.classify_domain("a.fp.example").code, VerdictCode::FalsePositive);
        assert_eq!(r.classify_domain("ext.example").code, VerdictCode::ExtensionExcluded);
        // Known-good is exact: a subdomain of a hosting platform is still blockable.
        assert_eq!(r.classify_domain("x.workers.dev").code, VerdictCode::BadDomain);
        // The user's own block list wins over the known-good list.
        let user_block = r.classify_domain("github.com");
        assert_eq!((user_block.code, user_block.list.as_str()), (VerdictCode::BadDomain, "userBlockList"));
    }

    #[test]
    fn ip_cidr_and_port_rules() {
        let r = rules("ip 203.0.113.0/24 malware C2.Net\nip 2001:db8::/32\nport 4444 malware Meterpreter\nfp 203.0.113.7\n", UserLists::default());
        let v = r.classify_ip("203.0.113.9".parse().unwrap(), None);
        assert_eq!((v.code, v.rule.as_str(), v.threat.as_str()), (VerdictCode::BadIp, "203.0.113.0/24", "C2.Net"));
        assert_eq!(r.classify_ip("203.0.113.7".parse().unwrap(), None).code, VerdictCode::FalsePositive);
        assert_eq!(r.classify_ip("2001:db8::5".parse().unwrap(), None).code, VerdictCode::BadIp);
        assert_eq!(r.classify_ip("127.0.0.1".parse().unwrap(), None).code, VerdictCode::Clean);
        assert_eq!(r.classify_ip("192.168.1.10".parse().unwrap(), None).code, VerdictCode::Clean);
        assert_eq!(r.classify_ip("203.0.113.9".parse().unwrap(), Some("google.com")).code, VerdictCode::KnownGood);
        assert_eq!(r.classify_url("http://198.51.100.1:4444/x").code, VerdictCode::BadIp);
        assert_eq!(r.classify_url("http://198.51.100.1:4444/x").list, "feedPortBlockList");
        assert_eq!(r.classify_url("http://[2001:db8::1]/").code, VerdictCode::BadIp);
    }

    #[test]
    fn url_rules_match_exactly_even_on_known_good_hosts() {
        let r = rules("url https://github.com/evil/repo/raw/x.exe malware Stealer\n", UserLists::default());
        assert_eq!(r.classify_url("https://GitHub.com/evil/repo/raw/x.exe#a").code, VerdictCode::BadDomain);
        assert_eq!(r.classify_url("https://github.com/evil/repo/raw/x.exe?dl=1").list, "feedUrlBlockList");
        assert_eq!(r.classify_url("https://github.com/evil/repo").code, VerdictCode::Clean);
        assert_eq!(r.classify_url("http://urltest.phalanx.invalid/download.exe").code, VerdictCode::BadDomain);
    }

    #[test]
    fn dns_answers_block_through_cnames_and_addresses() {
        let r = rules("domain tracker.bad.example malware Cname.Target\nip 198.51.100.0/24 malware Bad.Host\n", UserLists::default());
        let cname = r.classify_dns(
            "innocent.example",
            &[Answer::Cname("tracker.bad.example".into()), Answer::Address("192.0.2.1".parse().unwrap())],
        );
        assert_eq!((cname.code, cname.trigger.as_str()), (VerdictCode::BadCname, "tracker.bad.example"));
        let ip = r.classify_dns("other.example", &[Answer::Address("198.51.100.20".parse().unwrap())]);
        assert_eq!(ip.code, VerdictCode::BadIp);
        assert_eq!(r.classify_dns("fine.example", &[Answer::Address("192.0.2.1".parse().unwrap())]).code, VerdictCode::Clean);
        assert_eq!(r.classify_dns("google.com", &[Answer::Address("198.51.100.20".parse().unwrap())]).code, VerdictCode::KnownGood);
    }

    #[test]
    fn threat_domains_for_pre_request_blocking_respect_allow_lists() {
        let user = UserLists {
            allow: vec!["safe.bad.example".into()],
            block: vec!["mine.example".into()],
            extension_exclusions: vec!["excluded.example".into()],
        };
        let r = rules(
            "domain bad.example malware Stealer
domain excluded.example phishing Fake
domain google.com malware Wrong
domain *.wild.example malware W
",
            user,
        );
        let domains = r.threat_domains();
        assert!(domains.contains(&"bad.example".to_string()));
        assert!(domains.contains(&"mine.example".to_string()), "the user's own block list");
        assert!(!domains.contains(&"excluded.example".to_string()), "excluded entirely");
        assert!(!domains.contains(&"google.com".to_string()), "known-good is never blocked");
        assert!(domains.iter().all(|d| is_plain_host(d)), "{domains:?}");
        assert!(domains.windows(2).all(|w| w[0] <= w[1]), "sorted");
        // A subdomain allowed under a blocked domain becomes an exception.
        assert!(r.threat_exclusions().contains(&"safe.bad.example".to_string()));
    }

    #[test]
    fn verdict_codes_block_only_one_to_three() {
        use VerdictCode::*;
        let blocking: Vec<u8> = [Clean, BadIp, BadDomain, BadCname, UserAllowed, FalsePositive, ExtensionExcluded, KnownGood]
            .into_iter()
            .filter(|c| c.blocks())
            .map(VerdictCode::number)
            .collect();
        assert_eq!(blocking, [1, 2, 3]);
    }

    #[test]
    fn ad_rules_are_separate_and_still_excludable() {
        let user = UserLists { allow: vec!["ok.ads.example".into()], ..Default::default() };
        let mut r = rules("domain both.example malware Real.Threat\n", user);
        let ads = "domain ads.example ads StevenBlack.Ads\ndomain both.example ads X\ndomain google.com ads X\nurl http://x.example/a ads X\n";
        assert_eq!(r.add_text(ads, Origin::Ads, "ads").unwrap(), 3);
        let v = r.classify_domain("pixel.ads.example");
        assert_eq!((v.code, v.list.as_str(), v.category.as_str(), v.threat.as_str()), (VerdictCode::BadDomain, "adsBlockList", "ads", "StevenBlack.Ads"));
        assert_eq!(r.classify_url("https://ads.example/track.js").list, "adsBlockList");
        assert_eq!(r.classify_domain("both.example").category, "malware", "threat rules win");
        assert_eq!(r.classify_domain("ok.ads.example").code, VerdictCode::UserAllowed);
        assert_eq!(r.classify_domain("google.com").code, VerdictCode::KnownGood);
        assert_eq!(r.classify_url("http://x.example/a").code, VerdictCode::Clean, "only names come from the ad list");
        // Known-good names under the google.com ad rule come along too.
        assert_eq!(r.ad_exclusions(), ["docs.google.com", "drive.google.com", "google.com", "ok.ads.example"]);
        assert_eq!((r.counts().ads, r.counts().domains), (3, WebRules::load(None, &UserLists::default()).unwrap().counts().domains + 1));
    }

    #[test]
    fn a_file_with_only_garbage_is_rejected() {
        let mut r = WebRules::default();
        assert!(r.add_text("nonsense line\nmore nonsense\n", Origin::Feed, "x").is_err());
        assert_eq!(r.add_text("# only comments\n\n", Origin::Feed, "x").unwrap(), 0);
    }
}
