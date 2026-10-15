//! Signature updates from public threat-intelligence feeds.
//!
//! Each source is downloaded, validated and only then swapped in atomically; a
//! source that fails keeps its previous local copy. Hash feeds publish a
//! rolling window of recent samples, so new hashes are merged into a local
//! list that grows with every update (oldest entries are dropped past a cap).
//! Web feeds (malicious domains, URLs and C2 addresses) are merged the same
//! way into `feed-web.txt`, which web protection loads. The ad and tracker
//! list is a full snapshot instead (entries its maintainers drop are usually
//! false positives), saved as `feed-ads.txt` and only loaded when ad blocking
//! is switched on.

use crate::engine::{encode_rules, parse_digest};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

const USER_AGENT: &str = concat!("threat-scanner/", env!("CARGO_PKG_VERSION"));
const MAX_DOWNLOAD: u64 = 100 * 1024 * 1024;
/// Upper bound on merged feed hashes (roughly 50 MB of memory when loaded).
pub const MAX_FEED_HASHES: usize = 750_000;
const FEED_HASH_FILE: &str = "feed-hashes.txt";
/// Upper bound on merged web rules.
pub const MAX_FEED_WEB: usize = 500_000;
const MANIFEST_FILE: &str = "manifest.json";
/// Fewest names an ad list download must have to replace the current one.
const MIN_ADS: usize = 1000;

pub struct Source {
    pub name: &'static str,
    pub url: &'static str,
    pub kind: SourceKind,
}

pub enum SourceKind {
    /// A zip containing one YARA file ending in `entry_suffix`, saved as `file`.
    YaraZip { entry_suffix: &'static str, file: &'static str },
    /// abuse.ch-style quoted CSV with SHA-256 and malware-family columns.
    HashCsv { hash_column: usize, family_column: usize },
    /// A hosts file (`127.0.0.1 name`) of malicious names.
    WebHostfile { category: &'static str, threat: &'static str },
    /// abuse.ch-style quoted CSV of web indicators.
    WebCsv(WebCsv),
    /// A hosts file of ad and tracker names; replaces the ad list each time.
    AdsHostfile { threat: &'static str },
}

pub struct WebCsv {
    pub kind: WebIoc,
    pub value_column: usize,
    /// Column holding the malware/threat name, if any.
    pub threat_column: Option<usize>,
    /// Prefix for threat names, e.g. `ThreatFox`.
    pub threat_prefix: &'static str,
    /// Column that says "True" for compromised (otherwise legitimate) sites.
    pub compromised_column: Option<usize>,
    /// Column with a 0-100 confidence, and the least accepted.
    pub confidence: Option<(usize, u32)>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum WebIoc {
    Url,
    Domain,
    /// `address:port`; the address is blocked.
    IpPort,
}

pub const SOURCES: &[Source] = &[
    Source {
        name: "YARA Forge (core rules)",
        url: "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
        kind: SourceKind::YaraZip {
            entry_suffix: "yara-rules-core.yar",
            file: "yara-forge-core.rules",
        },
    },
    Source {
        name: "MalwareBazaar (recent samples)",
        url: "https://bazaar.abuse.ch/export/csv/recent/",
        kind: SourceKind::HashCsv { hash_column: 1, family_column: 8 },
    },
    Source {
        name: "ThreatFox (recent SHA-256 IOCs)",
        url: "https://threatfox.abuse.ch/export/csv/sha256/recent/",
        kind: SourceKind::HashCsv { hash_column: 2, family_column: 7 },
    },
    Source {
        name: "URLhaus (malware hosts)",
        url: "https://urlhaus.abuse.ch/downloads/hostfile/",
        kind: SourceKind::WebHostfile { category: "malware", threat: "URLhaus.MalwareHost" },
    },
    Source {
        name: "URLhaus (online malware URLs)",
        url: "https://urlhaus.abuse.ch/downloads/csv_online/",
        kind: SourceKind::WebCsv(WebCsv {
            kind: WebIoc::Url,
            value_column: 2,
            threat_column: None,
            threat_prefix: "URLhaus.MalwareDownload",
            compromised_column: None,
            confidence: None,
        }),
    },
    Source {
        name: "ThreatFox (recent domains)",
        url: "https://threatfox.abuse.ch/export/csv/domains/recent/",
        kind: SourceKind::WebCsv(WebCsv {
            kind: WebIoc::Domain,
            value_column: 2,
            threat_column: Some(7),
            threat_prefix: "ThreatFox",
            compromised_column: Some(10),
            confidence: None,
        }),
    },
    Source {
        name: "ThreatFox (recent URLs)",
        url: "https://threatfox.abuse.ch/export/csv/urls/recent/",
        kind: SourceKind::WebCsv(WebCsv {
            kind: WebIoc::Url,
            value_column: 2,
            threat_column: Some(7),
            threat_prefix: "ThreatFox",
            compromised_column: Some(10),
            confidence: None,
        }),
    },
    Source {
        name: "ThreatFox (recent C2 addresses)",
        url: "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        kind: SourceKind::WebCsv(WebCsv {
            kind: WebIoc::IpPort,
            value_column: 2,
            threat_column: Some(7),
            threat_prefix: "ThreatFox",
            compromised_column: Some(10),
            // Addresses can be shared hosting; only take confident ones.
            confidence: Some((9, 75)),
        }),
    },
    Source {
        // MIT licensed; adware and malware names merged from several lists.
        name: "StevenBlack hosts (ads and trackers)",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        kind: SourceKind::AdsHostfile { threat: "StevenBlack.Ads" },
    },
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub sources: Vec<SourceStatus>,
    pub last_attempt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceStatus {
    pub name: String,
    pub url: String,
    /// Last time this source was successfully installed.
    pub updated_at: Option<String>,
    pub ok: bool,
    pub message: String,
    /// Validators of the installed download, sent back so the server can
    /// answer "not modified" instead of resending it.
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    /// Last time the source was asked for new data (changed or not).
    #[serde(default)]
    pub checked_at: Option<String>,
    /// The last update found nothing new, so nothing was installed.
    #[serde(default)]
    pub unchanged: bool,
}

impl Manifest {
    /// Most recent successful update of any source.
    pub fn last_success(&self) -> Option<&str> {
        self.sources
            .iter()
            .filter_map(|s| s.updated_at.as_deref())
            .max()
    }

    /// Most recent check of any source, whether or not it had new data.
    pub fn last_check(&self) -> Option<&str> {
        self.sources.iter().filter_map(|s| s.checked_at.as_deref().or(s.updated_at.as_deref())).max()
    }

    /// Whether the update that wrote this manifest installed anything new.
    pub fn installed_anything(&self) -> bool {
        self.sources.iter().any(|s| s.ok && !s.unchanged)
    }

    fn source(&self, name: &str) -> Option<&SourceStatus> {
        self.sources.iter().find(|s| s.name == name)
    }
}

/// The local file a source's data ends up in; while it is missing the source
/// is always downloaded in full.
fn installed_file(sig_dir: &Path, source: &Source) -> PathBuf {
    match &source.kind {
        SourceKind::YaraZip { file, .. } => sig_dir.join(file),
        SourceKind::HashCsv { .. } => sig_dir.join(FEED_HASH_FILE),
        SourceKind::WebHostfile { .. } | SourceKind::WebCsv(_) => sig_dir.join(crate::web::config::FEED_FILE),
        SourceKind::AdsHostfile { .. } => sig_dir.join(crate::web::config::ADS_FILE),
    }
}

/// Validators to send for a conditional request, if the source's data is
/// installed and was last fetched successfully.
fn validators<'a>(sig_dir: &Path, source: &Source, previous: &'a Manifest) -> Option<&'a SourceStatus> {
    previous
        .source(source.name)
        .filter(|s| s.ok && (s.etag.is_some() || s.last_modified.is_some()))
        .filter(|_| installed_file(sig_dir, source).is_file())
}

/// What a check for new signatures found.
#[derive(Debug, Clone, Default)]
pub struct CheckResult {
    /// Sources with new data (or never downloaded).
    pub changed: Vec<String>,
    /// Sources that could not be asked.
    pub failed: Vec<String>,
}

/// Asks every source, with small HEAD requests, whether it has data newer
/// than what is installed. Nothing is downloaded or changed.
pub fn check_for_updates(sig_dir: &Path) -> CheckResult {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(30))).build().into();
    let previous = load_manifest(sig_dir);
    let mut result = CheckResult::default();
    for source in SOURCES {
        let Some(known) = validators(sig_dir, source, &previous) else {
            result.changed.push(source.name.to_string());
            continue;
        };
        let mut request = agent.head(source.url).header("User-Agent", USER_AGENT);
        if let Some(etag) = &known.etag {
            request = request.header("If-None-Match", etag);
        }
        if let Some(modified) = &known.last_modified {
            request = request.header("If-Modified-Since", modified);
        }
        match request.call() {
            Ok(response) if response.status().as_u16() == 304 => {}
            Ok(response) => {
                // Some servers ignore conditional HEADs; compare by hand.
                let header = |name: &str| response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
                let same_etag = header("etag").is_some_and(|e| Some(&e) == known.etag.as_ref());
                let same_date = header("last-modified").is_some_and(|m| Some(&m) == known.last_modified.as_ref());
                if !(same_etag || same_date) {
                    result.changed.push(source.name.to_string());
                }
            }
            Err(_) => result.failed.push(source.name.to_string()),
        }
    }
    result
}

pub fn signature_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("signatures")
}

pub fn load_manifest(sig_dir: &Path) -> Manifest {
    fs::read_to_string(sig_dir.join(MANIFEST_FILE))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Updates every source. Unless `force` is set, a source whose server says
/// it has not changed since the last download is skipped (nothing is
/// downloaded). Per-source failures are recorded in the returned manifest;
/// this only fails if the signature folder itself is unusable.
pub fn update_all(sig_dir: &Path, force: bool, on_progress: &mut dyn FnMut(&str)) -> Result<Manifest> {
    fs::create_dir_all(sig_dir).with_context(|| format!("creating {}", sig_dir.display()))?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(180)))
        .build()
        .into();
    let previous = load_manifest(sig_dir);
    let now = crate::store::now();
    let mut feed = FeedHashes::load(&sig_dir.join(FEED_HASH_FILE))?;
    let feed_before = feed.len();
    let web_path = sig_dir.join(crate::web::config::FEED_FILE);
    let mut web = FeedWeb::load(&web_path)?;
    let web_before = web.len();
    let mut statuses = Vec::new();

    for source in SOURCES {
        let earlier = previous.source(source.name);
        let known = if force { None } else { validators(sig_dir, source, &previous) };
        on_progress(&format!("Checking {} for new data…", source.name));
        let fetched = match download(&agent, source.url, known) {
            Ok(Fetched::NotModified) => {
                let mut status = earlier.cloned().expect("validators come from the previous manifest");
                status.checked_at = Some(now.clone());
                status.unchanged = true;
                status.message = format!("up to date (no change since {})", status.updated_at.as_deref().map(short_date).unwrap_or_default());
                statuses.push(status);
                continue;
            }
            Ok(Fetched::Body { bytes, etag, last_modified }) => Ok((bytes, etag, last_modified)),
            Err(e) => Err(e),
        };
        on_progress(&format!("Installing {}…", source.name));
        let validators = fetched.as_ref().ok().map(|(_, e, m)| (e.clone(), m.clone()));
        let result = fetched.and_then(|(bytes, _, _)| {
            match &source.kind {
                SourceKind::YaraZip { entry_suffix, file } => {
                    install_yara_zip(&bytes, entry_suffix, &sig_dir.join(file))
                }
                SourceKind::HashCsv { hash_column, family_column } => {
                    let text = String::from_utf8_lossy(&bytes);
                    let (seen, added) = feed.merge_csv(&text, *hash_column, *family_column)?;
                    Ok(format!("{seen} hashes in feed, {added} new"))
                }
                SourceKind::WebHostfile { category, threat } => {
                    let (seen, added) = web.merge_hostfile(&String::from_utf8_lossy(&bytes), category, threat)?;
                    Ok(format!("{seen} hosts in feed, {added} new"))
                }
                SourceKind::WebCsv(csv) => {
                    let (seen, added) = web.merge_csv(&String::from_utf8_lossy(&bytes), csv)?;
                    Ok(format!("{seen} indicators in feed, {added} new"))
                }
                SourceKind::AdsHostfile { threat } => install_ads(&bytes, threat, &sig_dir.join(crate::web::config::ADS_FILE)),
            }
        });
        statuses.push(match result {
            Ok(message) => {
                let (etag, last_modified) = validators.unwrap_or_default();
                SourceStatus {
                    name: source.name.into(),
                    url: source.url.into(),
                    updated_at: Some(now.clone()),
                    ok: true,
                    message,
                    etag,
                    last_modified,
                    checked_at: Some(now.clone()),
                    unchanged: false,
                }
            }
            // Validators are dropped so the next update downloads it again.
            Err(e) => SourceStatus {
                name: source.name.into(),
                url: source.url.into(),
                updated_at: earlier.and_then(|s| s.updated_at.clone()),
                ok: false,
                message: format!("{e:#}"),
                etag: None,
                last_modified: None,
                checked_at: Some(now.clone()),
                unchanged: false,
            },
        });
    }

    if feed.len() != feed_before || feed.trimmed {
        on_progress("Saving hash list…");
        feed.save(&sig_dir.join(FEED_HASH_FILE))?;
    }
    if web.len() != web_before || web.trimmed {
        on_progress("Saving web rules…");
        web.save(&web_path)?;
    }
    let manifest = Manifest {
        sources: statuses,
        last_attempt: Some(now),
    };
    write_atomic(
        &sig_dir.join(MANIFEST_FILE),
        serde_json::to_string_pretty(&manifest)?.as_bytes(),
    )?;
    Ok(manifest)
}

enum Fetched {
    NotModified,
    Body { bytes: Vec<u8>, etag: Option<String>, last_modified: Option<String> },
}

/// Downloads `url`; with `known` validators the server may answer 304.
fn download(agent: &ureq::Agent, url: &str, known: Option<&SourceStatus>) -> Result<Fetched> {
    let mut request = agent.get(url).header("User-Agent", USER_AGENT);
    if let Some(known) = known {
        if let Some(etag) = &known.etag {
            request = request.header("If-None-Match", etag);
        }
        if let Some(modified) = &known.last_modified {
            request = request.header("If-Modified-Since", modified);
        }
    }
    let response = request.call().map_err(|e| anyhow!("download failed: {e}"))?;
    if response.status().as_u16() == 304 {
        return Ok(Fetched::NotModified);
    }
    let header = |name: &str| response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    let (etag, last_modified) = (header("etag"), header("last-modified"));
    let mut body = response.into_body();
    let bytes = body
        .with_config()
        .limit(MAX_DOWNLOAD)
        .read_to_vec()
        .map_err(|e| anyhow!("download failed: {e}"))?;
    Ok(Fetched::Body { bytes, etag, last_modified })
}

/// `2026-10-15T20:31:02+05:30` → `2026-10-15 20:31`.
fn short_date(rfc3339: &str) -> String {
    rfc3339.get(..16).unwrap_or(rfc3339).replace('T', " ")
}

fn install_yara_zip(bytes: &[u8], entry_suffix: &str, target: &Path) -> Result<String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("not a valid zip")?;
    let mut text = None;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        if entry.name()?.ends_with(entry_suffix) {
            let mut content = String::new();
            entry
                .take(MAX_DOWNLOAD)
                .read_to_string(&mut content)
                .context("reading rules from zip")?;
            text = Some(content);
            break;
        }
    }
    let text = text.ok_or_else(|| anyhow!("zip has no `{entry_suffix}`"))?;

    // Never install rules the engine can't load: that would break every scan.
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(text.as_str())
        .map_err(|e| anyhow!("rules failed to compile, keeping the previous version: {e}"))?;
    let count = compiler.build().iter().count();
    if count == 0 {
        bail!("download contained no rules, keeping the previous version");
    }
    write_atomic(target, &encode_rules(&text))?;
    Ok(format!("{count} rules"))
}

/// Replaces the ad list with the names in a downloaded hosts file.
fn install_ads(bytes: &[u8], threat: &str, target: &Path) -> Result<String> {
    let mut ads = FeedWeb { lines: Vec::new(), known: HashSet::new(), trimmed: false };
    let (seen, _) = ads.merge_hostfile(&String::from_utf8_lossy(bytes), "ads", threat)?;
    // A real ad list has tens of thousands of names; a tiny one is an error page.
    if seen < MIN_ADS {
        bail!("only {seen} names in the ad list, keeping the previous version");
    }
    let mut text = String::from("# Ad and tracker names from `phalanx-cli update`. Do not edit; it is rewritten.\n");
    for line in &ads.lines {
        text.push_str(line);
        text.push('\n');
    }
    write_atomic(target, text.as_bytes())?;
    Ok(format!("{} ad and tracker names", ads.len()))
}

/// The merged local hash list, kept in insertion order (oldest first).
struct FeedHashes {
    lines: Vec<String>,
    known: HashSet<[u8; 32]>,
    trimmed: bool,
}

impl FeedHashes {
    fn load(path: &Path) -> Result<Self> {
        let mut feed = Self {
            lines: Vec::new(),
            known: HashSet::new(),
            trimmed: false,
        };
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(feed),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        for line in text.lines() {
            let Some(digest) = line.split_whitespace().next().and_then(parse_digest) else {
                continue;
            };
            if feed.known.insert(digest) {
                feed.lines.push(line.to_string());
            }
        }
        Ok(feed)
    }

    fn len(&self) -> usize {
        self.lines.len()
    }

    /// Returns (hashes in this feed, newly added).
    fn merge_csv(&mut self, text: &str, hash_column: usize, family_column: usize) -> Result<(usize, usize)> {
        let (mut seen, mut added) = (0, 0);
        for line in text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
            let fields = split_csv_line(line);
            let Some(hash) = fields.get(hash_column) else { continue };
            let hash = hash.to_ascii_lowercase();
            let Some(digest) = parse_digest(&hash) else { continue };
            seen += 1;
            if !self.known.insert(digest) {
                continue;
            }
            let family = fields
                .get(family_column)
                .map(|f| f.trim())
                .filter(|f| !f.is_empty() && !f.eq_ignore_ascii_case("n/a") && !f.eq_ignore_ascii_case("none"))
                .map(|f| f.replace(char::is_whitespace, "-"))
                .unwrap_or_else(|| "KnownHash".into());
            self.lines.push(format!("{hash} malware Malware.{family}"));
            added += 1;
        }
        if seen == 0 {
            bail!("feed contained no SHA-256 hashes (format changed?)");
        }
        if self.lines.len() > MAX_FEED_HASHES {
            let excess = self.lines.len() - MAX_FEED_HASHES;
            for line in self.lines.drain(..excess) {
                if let Some(d) = line.split_whitespace().next().and_then(parse_digest) {
                    self.known.remove(&d);
                }
            }
            self.trimmed = true;
        }
        Ok((seen, added))
    }

    fn save(&self, path: &Path) -> Result<()> {
        let mut text = String::from(
            "# Merged from public feeds by `threat-scanner update`. Do not edit; it is rewritten.\n",
        );
        for line in &self.lines {
            text.push_str(line);
            text.push('\n');
        }
        write_atomic(path, text.as_bytes())
    }
}

/// The merged local web rule list (`<kind> <value> <category> <threat>`),
/// in insertion order (oldest first).
struct FeedWeb {
    lines: Vec<String>,
    known: HashSet<String>,
    trimmed: bool,
}

impl FeedWeb {
    fn load(path: &Path) -> Result<Self> {
        let mut feed = Self { lines: Vec::new(), known: HashSet::new(), trimmed: false };
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(feed),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let Some(key) = Self::key(line) else { continue };
            if feed.known.insert(key) {
                feed.lines.push(line.to_string());
            }
        }
        Ok(feed)
    }

    /// `kind value`, the identity of a rule line.
    fn key(line: &str) -> Option<String> {
        let mut parts = line.split_whitespace();
        Some(format!("{} {}", parts.next()?, parts.next()?))
    }

    fn len(&self) -> usize {
        self.lines.len()
    }

    /// Adds a rule; returns whether it was new.
    fn add(&mut self, kind: &str, value: &str, category: &str, threat: &str) -> bool {
        if !self.known.insert(format!("{kind} {value}")) {
            return false;
        }
        self.lines.push(format!("{kind} {value} {category} {threat}"));
        true
    }

    fn merge_hostfile(&mut self, text: &str, category: &str, threat: &str) -> Result<(usize, usize)> {
        let (mut seen, mut added) = (0, 0);
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let mut parts = line.split_whitespace();
            let (Some(_address), Some(name)) = (parts.next(), parts.next()) else { continue };
            // Hosts files start with entries for this PC (`localhost.localdomain`, `0.0.0.0`).
            let Some(host) = crate::web::url::normalize_host(name)
                .filter(|h| h.contains('.') && !h.contains(':') && h.parse::<std::net::IpAddr>().is_err())
                .filter(|h| !h.starts_with("localhost.") && !h.ends_with(".localdomain"))
            else {
                continue;
            };
            seen += 1;
            added += self.add("domain", &host, category, threat) as usize;
        }
        self.finish(seen, added)
    }

    fn merge_csv(&mut self, text: &str, csv: &WebCsv) -> Result<(usize, usize)> {
        let (mut seen, mut added) = (0, 0);
        for line in text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
            let fields = split_csv_line(line);
            let Some(value) = fields.get(csv.value_column) else { continue };
            if let Some((column, least)) = csv.confidence {
                if fields.get(column).and_then(|c| c.parse::<u32>().ok()).is_some_and(|c| c < least) {
                    continue;
                }
            }
            let (kind, value) = match csv.kind {
                WebIoc::Url => match crate::web::url::WebAddress::parse(value) {
                    Some(a) if value.contains("://") => ("url", a.normalized()),
                    _ => continue,
                },
                WebIoc::Domain => match crate::web::url::normalize_host(value) {
                    Some(h) if h.contains('.') && h.parse::<std::net::IpAddr>().is_err() => ("domain", h),
                    _ => continue,
                },
                WebIoc::IpPort => {
                    let address = value.rsplit_once(':').map_or(value.as_str(), |(a, _)| a);
                    match address.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>() {
                        Ok(ip) => ("ip", ip.to_string()),
                        Err(_) => continue,
                    }
                }
            };
            seen += 1;
            let compromised = csv
                .compromised_column
                .and_then(|c| fields.get(c))
                .is_some_and(|v| v.eq_ignore_ascii_case("true"));
            let category = if compromised { "compromised" } else { "malware" };
            let threat = csv
                .threat_column
                .and_then(|c| fields.get(c))
                .map(|f| f.trim())
                .filter(|f| !f.is_empty() && !f.eq_ignore_ascii_case("none") && !f.eq_ignore_ascii_case("unknown malware"))
                .map(|f| format!("{}.{}", csv.threat_prefix, f.replace(char::is_whitespace, "-")))
                .unwrap_or_else(|| csv.threat_prefix.to_string());
            added += self.add(kind, &value, category, &threat) as usize;
        }
        self.finish(seen, added)
    }

    fn finish(&mut self, seen: usize, added: usize) -> Result<(usize, usize)> {
        if seen == 0 {
            bail!("feed contained no usable entries (format changed?)");
        }
        if self.lines.len() > MAX_FEED_WEB {
            let excess = self.lines.len() - MAX_FEED_WEB;
            for line in self.lines.drain(..excess) {
                if let Some(key) = Self::key(&line) {
                    self.known.remove(&key);
                }
            }
            self.trimmed = true;
        }
        Ok((seen, added))
    }

    fn save(&self, path: &Path) -> Result<()> {
        let mut text = String::from("# Merged from public web threat feeds by `phalanx-cli update`. Do not edit; it is rewritten.\n");
        for line in &self.lines {
            text.push_str(line);
            text.push('\n');
        }
        write_atomic(path, text.as_bytes())
    }
}

/// Splits one line of quoted CSV (`"a", "b, with comma", "c ""quoted"""`).
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => fields.push(std::mem::take(&mut field).trim().to_string()),
            _ => field.push(c),
        }
    }
    fields.push(field.trim().to_string());
    fields
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("download");
    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_lines_with_quoted_commas() {
        let f = split_csv_line(r#""2026-10-14", "abc", "file, name.exe", "say ""hi""", "n/a""#);
        assert_eq!(f, ["2026-10-14", "abc", "file, name.exe", "say \"hi\"", "n/a"]);
    }

    #[test]
    fn feed_merge_dedups_names_families_and_caps() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("feed.txt");
        let (a, b) = ("a".repeat(64), "B".repeat(64));
        let csv = format!(
            "# header\n\"t\", \"{a}\", \"x\", \"Mirai\"\n\"t\", \"{b}\", \"x\", \"n/a\"\n\"t\", \"{a}\", \"x\", \"Mirai\"\n\"t\", \"short\", \"x\", \"y\"\n"
        );
        let mut feed = FeedHashes::load(&path).unwrap();
        assert_eq!(feed.merge_csv(&csv, 1, 3).unwrap(), (3, 2));
        feed.save(&path).unwrap();

        let reloaded = FeedHashes::load(&path).unwrap();
        assert_eq!(reloaded.len(), 2);
        let saved = fs::read_to_string(&path).unwrap();
        assert!(saved.contains(&format!("{a} malware Malware.Mirai")));
        assert!(saved.contains(&format!("{} malware Malware.KnownHash", b.to_ascii_lowercase())));

        let mut again = reloaded;
        assert_eq!(again.merge_csv(&csv, 1, 3).unwrap(), (3, 0), "nothing new the second time");
        assert!(again.merge_csv("# only comments\n", 1, 3).is_err(), "an empty feed is an error");
    }

    #[test]
    fn web_feeds_merge_into_loadable_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("feed-web.txt");
        let mut web = FeedWeb::load(&path).unwrap();
        let hosts = "# header\n127.0.0.1\tBad.Example\n127.0.0.1\tbad.example\n127.0.0.1\tlocalhost\n";
        assert_eq!(web.merge_hostfile(hosts, "malware", "URLhaus.MalwareHost").unwrap(), (2, 1));
        let threatfox = concat!(
            "# \"first_seen_utc\",\"ioc_id\",\"ioc_value\",\"ioc_type\",\"threat_type\",\"fk_malware\",\"malware_alias\",\"malware_printable\",\"last_seen_utc\",\"confidence_level\",\"is_compromised\"\n",
            "\"t\", \"1\", \"c2.example\", \"domain\", \"botnet_cc\", \"win.x\", \"None\", \"Koi Loader\", \"\", \"100\", \"False\"\n",
            "\"t\", \"2\", \"hacked.example\", \"domain\", \"payload_delivery\", \"x\", \"None\", \"Unknown malware\", \"\", \"50\", \"True\"\n",
        );
        let domains = WebCsv { kind: WebIoc::Domain, value_column: 2, threat_column: Some(7), threat_prefix: "ThreatFox", compromised_column: Some(10), confidence: None };
        assert_eq!(web.merge_csv(threatfox, &domains).unwrap(), (2, 2));
        let ips = concat!(
            "\"t\", \"3\", \"203.0.113.5:443\", \"ip:port\", \"botnet_cc\", \"x\", \"None\", \"Vidar\", \"\", \"100\", \"False\"\n",
            "\"t\", \"4\", \"198.51.100.1:80\", \"ip:port\", \"botnet_cc\", \"x\", \"None\", \"Vidar\", \"\", \"50\", \"False\"\n",
        );
        let ip_csv = WebCsv { kind: WebIoc::IpPort, confidence: Some((9, 75)), ..domains };
        assert_eq!(web.merge_csv(ips, &ip_csv).unwrap(), (1, 1), "low confidence skipped");
        let urls = "\"1\",\"2026-10-15\",\"HTTP://Files.Example/x.exe\",\"online\",\"t\",\"malware_download\",\"None\",\"l\",\"r\"\n";
        let url_csv = WebCsv { kind: WebIoc::Url, value_column: 2, threat_column: None, threat_prefix: "URLhaus.MalwareDownload", compromised_column: None, confidence: None };
        assert_eq!(web.merge_csv(urls, &url_csv).unwrap(), (1, 1));
        assert!(web.merge_csv("# nothing\n", &url_csv).is_err());
        web.save(&path).unwrap();

        let rules = crate::web::WebRules::load(Some(&path), &Default::default()).unwrap();
        let v = rules.classify_domain("www.c2.example");
        assert_eq!((v.list.as_str(), v.threat.as_str(), v.category.as_str()), ("feedDomainBlockList", "ThreatFox.Koi-Loader", "malware"));
        assert_eq!(rules.classify_domain("hacked.example").category, "compromised");
        assert_eq!(rules.classify_domain("hacked.example").threat, "ThreatFox");
        assert!(rules.classify_url("http://203.0.113.5/").blocks());
        assert!(!rules.classify_url("http://198.51.100.1/").blocks());
        assert!(rules.classify_url("http://files.example/x.exe").blocks());
        assert!(rules.classify_domain("bad.example").blocks());
        assert_eq!(FeedWeb::load(&path).unwrap().len(), 5);
    }

    #[test]
    fn ad_list_replaces_itself_and_skips_local_names() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join(crate::web::config::ADS_FILE);
        let header = "127.0.0.1 localhost\n127.0.0.1 localhost.localdomain\n255.255.255.255 broadcasthost\n::1 ip6-localhost\n0.0.0.0 0.0.0.0\n";
        let names: String = (0..MIN_ADS).map(|i| format!("0.0.0.0 ads{i}.example\n")).collect();
        let first = format!("{header}0.0.0.0 doubleclick.net\n{names}");
        assert_eq!(install_ads(first.as_bytes(), "StevenBlack.Ads", &target).unwrap(), format!("{} ad and tracker names", MIN_ADS + 1));
        let saved = fs::read_to_string(&target).unwrap();
        assert!(saved.lines().nth(1) == Some("domain doubleclick.net ads StevenBlack.Ads"), "list order is kept");
        assert!(!saved.contains("localhost") && !saved.contains(" 0.0.0.0 "));
        // A new download replaces the list: names it dropped are gone.
        install_ads(format!("{header}{names}").as_bytes(), "StevenBlack.Ads", &target).unwrap();
        assert!(!fs::read_to_string(&target).unwrap().contains("doubleclick"));
        // A short or empty download keeps the previous list.
        assert!(install_ads(b"0.0.0.0 one.example\n", "x", &target).is_err());
        assert!(install_ads(b"<html>rate limited</html>", "x", &target).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap().lines().count(), MIN_ADS + 1);
        assert!(installed_file(tmp.path(), SOURCES.last().unwrap()).ends_with(crate::web::config::ADS_FILE));
    }

    #[test]
    fn bad_yara_download_keeps_previous_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("feed.rules");
        fs::write(&target, encode_rules("rule Previous { condition: false }")).unwrap();

        let mut zipped = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut zipped));
            w.start_file("packages/core/x-core.yar", zip::write::SimpleFileOptions::default()).unwrap();
            std::io::Write::write_all(&mut w, b"rule Broken { condition: nonsense ").unwrap();
            w.finish().unwrap();
        }
        assert!(install_yara_zip(&zipped, "x-core.yar", &target).is_err());
        assert_eq!(fs::read(&target).unwrap(), encode_rules("rule Previous { condition: false }"));
        assert!(install_yara_zip(b"not a zip", "x-core.yar", &target).is_err());
    }
}
