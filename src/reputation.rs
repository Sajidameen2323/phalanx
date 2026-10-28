//! Online reputation of a file by its SHA-256: MalwareBazaar (abuse.ch) and
//! VirusTotal. Only the hash is sent, never the file: files uploaded to
//! VirusTotal can be downloaded by its paying customers, which would leak
//! personal documents.
//!
//! * MalwareBazaar lists malware samples. Found there, a file is known
//!   malware, with its family; not found says nothing either way. It uses
//!   the abuse.ch Auth-Key the signature updates already need.
//! * VirusTotal says how many of about 70 antivirus engines detect a file,
//!   or that it has never seen it. It needs the person's own free key, which
//!   allows 4 lookups a minute and 500 a day, for personal use only.
//!
//! Answers (found or not found) are cached for 24 hours in the data folder,
//! and VirusTotal is asked at most 4 times a minute, so repeated looks at
//! the same file cost nothing and the free quota is never exceeded by us.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The saved VirusTotal key, encrypted (DPAPI, hex), in the data folder.
pub const VIRUSTOTAL_KEY_FILE: &str = "virustotal-key";
/// Used when no key is saved.
pub const VIRUSTOTAL_KEY_ENV: &str = "VIRUSTOTAL_API_KEY";
/// Where people get a free VirusTotal key.
pub const VIRUSTOTAL_PORTAL: &str = "https://www.virustotal.com/gui/my-apikey";
const CACHE_FILE: &str = "reputation-cache.json";
/// How long an answer is reused.
const CACHE_FOR: Duration = Duration::from_secs(24 * 3600);
/// Answers kept at most; the oldest go first.
const MAX_CACHED: usize = 5_000;
/// VirusTotal's free tier: this many lookups per minute.
const VIRUSTOTAL_PER_MINUTE: usize = 4;
/// At least this many engines must flag a file to call it malicious.
pub const MALICIOUS_ENGINES: u32 = 3;
const TIMEOUT: Duration = Duration::from_secs(20);
const USER_AGENT: &str = concat!("threat-scanner/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Service {
    MalwareBazaar,
    VirusTotal,
}

impl Service {
    pub fn name(self) -> &'static str {
        match self {
            Service::MalwareBazaar => "MalwareBazaar",
            Service::VirusTotal => "VirusTotal",
        }
    }

    /// The page about the file on the service's site.
    pub fn link(self, sha256: &str) -> String {
        match self {
            Service::MalwareBazaar => format!("https://bazaar.abuse.ch/sample/{sha256}/"),
            Service::VirusTotal => format!("https://www.virustotal.com/gui/file/{sha256}"),
        }
    }
}

/// What one service said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Outcome {
    /// The service knows the file.
    Found {
        /// VirusTotal: engines flagging it (malicious or suspicious) and
        /// engines that gave an answer. MalwareBazaar lists only malware.
        detections: Option<(u32, u32)>,
        /// The malware family or threat name, when there is one.
        label: Option<String>,
        tags: Vec<String>,
        /// When the service first saw it (`YYYY-MM-DD`).
        first_seen: Option<String>,
    },
    /// The service has never seen this file.
    NotFound,
    /// No key for this service is saved.
    NoKey,
    /// The free quota is used up for now.
    Limited { retry_secs: u64 },
    Failed { error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub service: Service,
    pub outcome: Outcome,
    /// Answered from the 24-hour cache.
    pub cached: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reputation {
    pub sha256: String,
    pub checks: Vec<Check>,
}

/// What the answers add up to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Standing {
    /// Listed by MalwareBazaar, or flagged by at least
    /// [`MALICIOUS_ENGINES`] VirusTotal engines.
    Malicious,
    /// Flagged by one or two engines: often a false positive, worth a look.
    Suspicious,
    /// Known to VirusTotal and flagged by no engine.
    Clean,
    /// Not known anywhere asked (or nothing could be asked).
    Unknown,
}

impl Reputation {
    pub fn standing(&self) -> Standing {
        let mut standing = Standing::Unknown;
        for check in &self.checks {
            let Outcome::Found { detections, .. } = &check.outcome else { continue };
            let this = match (check.service, detections) {
                (Service::MalwareBazaar, _) => Standing::Malicious,
                (Service::VirusTotal, Some((flagged, _))) if *flagged >= MALICIOUS_ENGINES => Standing::Malicious,
                (Service::VirusTotal, Some((flagged, _))) if *flagged > 0 => Standing::Suspicious,
                (Service::VirusTotal, Some((_, answered))) if *answered > 0 => Standing::Clean,
                _ => Standing::Unknown,
            };
            standing = worse(standing, this);
        }
        standing
    }

    /// The family or threat name the services give, if any.
    pub fn label(&self) -> Option<&str> {
        self.checks.iter().find_map(|c| match &c.outcome {
            Outcome::Found { label: Some(label), .. } => Some(label.as_str()),
            _ => None,
        })
    }

    /// One plain sentence about the result.
    pub fn headline(&self) -> String {
        let family = self.label().map(|l| format!(" ({l})")).unwrap_or_default();
        let engines = self.checks.iter().find_map(|c| match (&c.service, &c.outcome) {
            (Service::VirusTotal, Outcome::Found { detections: Some((flagged, answered)), .. }) => Some((*flagged, *answered)),
            _ => None,
        });
        match (self.standing(), engines) {
            (Standing::Malicious, Some((flagged, answered))) if flagged > 0 => format!("Known malware{family}: {flagged} of {answered} antivirus engines detect it"),
            (Standing::Malicious, _) => format!("Known malware{family}: listed by MalwareBazaar"),
            (Standing::Suspicious, Some((flagged, answered))) => format!("{flagged} of {answered} antivirus engines flag it{family}; a few flags are often false positives"),
            (Standing::Clean, Some((_, answered))) => format!("None of {answered} antivirus engines detect it"),
            _ if self.checks.iter().any(|c| c.outcome == Outcome::NotFound) => "Not known online: no service asked has seen this file".to_string(),
            _ => "No online answer".to_string(),
        }
    }

    /// The lines Gemini is given, as facts from outside the file.
    pub fn prompt_lines(&self) -> Vec<String> {
        self.checks
            .iter()
            .map(|c| {
                let said = match &c.outcome {
                    Outcome::Found { detections, label, tags, first_seen } => {
                        let mut parts = Vec::new();
                        match (c.service, detections) {
                            (Service::VirusTotal, Some((flagged, answered))) => parts.push(format!("{flagged} of {answered} engines flag it")),
                            (Service::MalwareBazaar, _) => parts.push("listed as a malware sample".into()),
                            _ => parts.push("known".into()),
                        }
                        if let Some(label) = label {
                            parts.push(format!("label {label}"));
                        }
                        if !tags.is_empty() {
                            parts.push(format!("tags {}", tags.join(", ")));
                        }
                        if let Some(first) = first_seen {
                            parts.push(format!("first seen {first}"));
                        }
                        parts.join("; ")
                    }
                    Outcome::NotFound => "never seen this file".into(),
                    Outcome::NoKey => "not asked (no key)".into(),
                    Outcome::Limited { .. } => "not asked (free quota used up)".into(),
                    Outcome::Failed { error } => format!("could not be asked ({error})"),
                };
                format!("{}: {said}", c.service.name())
            })
            .collect()
    }
}

fn worse(a: Standing, b: Standing) -> Standing {
    let rank = |s: Standing| match s {
        Standing::Unknown => 0,
        Standing::Clean => 1,
        Standing::Suspicious => 2,
        Standing::Malicious => 3,
    };
    if rank(b) > rank(a) { b } else { a }
}

/// The keys lookups use; a service without one is skipped.
#[derive(Default)]
pub struct Keys {
    pub abuse_ch: Option<String>,
    pub virustotal: Option<String>,
}

/// A SHA-256 as 64 lowercase hex digits, or an error.
pub fn normalize(sha256: &str) -> Result<String> {
    let sha = sha256.trim().to_ascii_lowercase();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("`{}` is not a SHA-256 (64 hex digits)", sha256.trim());
    }
    Ok(sha)
}

/// Looks hashes up, with the cache and VirusTotal's rate limit. One per
/// process, shared by its callers.
pub struct Checker {
    dir: PathBuf,
    cache: Mutex<Option<Cache>>,
    virustotal_calls: Mutex<VecDeque<Instant>>,
}

#[derive(Default, Serialize, Deserialize)]
struct Cache {
    /// `service:sha256` → (unix time, answer).
    entries: HashMap<String, (u64, Outcome)>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Checker {
    /// Keeps its cache in `dir`.
    pub fn new(dir: &Path) -> Self {
        Self { dir: dir.to_path_buf(), cache: Mutex::new(None), virustotal_calls: Mutex::new(VecDeque::new()) }
    }

    /// Asks every service with a key about `sha256`.
    pub fn check(&self, sha256: &str, keys: &Keys) -> Result<Reputation> {
        let sha = normalize(sha256)?;
        let checks = [(Service::MalwareBazaar, &keys.abuse_ch), (Service::VirusTotal, &keys.virustotal)]
            .into_iter()
            .map(|(service, key)| self.check_one(service, key.as_deref(), &sha))
            .collect();
        Ok(Reputation { sha256: sha, checks })
    }

    fn check_one(&self, service: Service, key: Option<&str>, sha: &str) -> Check {
        let Some(key) = key.map(str::trim).filter(|k| !k.is_empty()) else {
            return Check { service, outcome: Outcome::NoKey, cached: false };
        };
        let id = format!("{}:{sha}", service.name());
        if let Some(outcome) = self.cached(&id) {
            return Check { service, outcome, cached: true };
        }
        let outcome = match service {
            Service::MalwareBazaar => ask_bazaar(key, sha),
            Service::VirusTotal => match self.virustotal_slot() {
                Ok(()) => ask_virustotal(key, sha),
                Err(retry_secs) => Outcome::Limited { retry_secs },
            },
        };
        if matches!(outcome, Outcome::Found { .. } | Outcome::NotFound) {
            self.remember(id, outcome.clone());
        }
        Check { service, outcome, cached: false }
    }

    /// Takes one of VirusTotal's lookups this minute, or says when one frees up.
    fn virustotal_slot(&self) -> Result<(), u64> {
        let mut calls = self.virustotal_calls.lock().unwrap_or_else(PoisonError::into_inner);
        while calls.front().is_some_and(|t| t.elapsed() >= Duration::from_secs(60)) {
            calls.pop_front();
        }
        if calls.len() >= VIRUSTOTAL_PER_MINUTE {
            let oldest = calls.front().map_or(Duration::ZERO, Instant::elapsed);
            return Err(60u64.saturating_sub(oldest.as_secs()).max(1));
        }
        calls.push_back(Instant::now());
        Ok(())
    }

    fn with_cache<T>(&self, f: impl FnOnce(&mut Cache) -> T) -> T {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let cache = cache.get_or_insert_with(|| {
            std::fs::read(self.dir.join(CACHE_FILE)).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
        });
        f(cache)
    }

    fn cached(&self, id: &str) -> Option<Outcome> {
        self.with_cache(|cache| {
            let (at, outcome) = cache.entries.get(id)?;
            (now().saturating_sub(*at) < CACHE_FOR.as_secs()).then(|| outcome.clone())
        })
    }

    fn remember(&self, id: String, outcome: Outcome) {
        let bytes = self.with_cache(|cache| {
            let fresh = now().saturating_sub(CACHE_FOR.as_secs());
            cache.entries.retain(|_, (at, _)| *at >= fresh);
            if cache.entries.len() >= MAX_CACHED {
                let mut times: Vec<u64> = cache.entries.values().map(|(at, _)| *at).collect();
                times.sort_unstable();
                let cut = times[times.len() - MAX_CACHED / 2];
                cache.entries.retain(|_, (at, _)| *at >= cut);
            }
            cache.entries.insert(id, (now(), outcome));
            serde_json::to_vec(cache).ok()
        });
        // A cache that cannot be written only costs a lookup next time.
        if let Some(bytes) = bytes {
            let temporary = self.dir.join(format!("{CACHE_FILE}.new"));
            if std::fs::write(&temporary, bytes).is_ok() {
                let _ = std::fs::rename(&temporary, self.dir.join(CACHE_FILE));
            }
        }
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(TIMEOUT)).http_status_as_error(false).build().into()
}

fn read_body(response: ureq::http::Response<ureq::Body>) -> (u16, String) {
    let status = response.status().as_u16();
    let body = response.into_body().with_config().limit(4 * 1024 * 1024).read_to_string().unwrap_or_default();
    (status, body)
}

fn ask_bazaar(key: &str, sha: &str) -> Outcome {
    let sent = agent()
        .post("https://mb-api.abuse.ch/api/v1/")
        .header("Auth-Key", key)
        .header("User-Agent", USER_AGENT)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(format!("query=get_info&hash={sha}").as_bytes());
    match sent {
        Ok(response) => {
            let (status, body) = read_body(response);
            parse_bazaar(status, &body)
        }
        Err(e) => Outcome::Failed { error: format!("could not reach MalwareBazaar: {e}") },
    }
}

fn ask_virustotal(key: &str, sha: &str) -> Outcome {
    let sent = agent().get(&format!("https://www.virustotal.com/api/v3/files/{sha}")).header("x-apikey", key).header("User-Agent", USER_AGENT).call();
    match sent {
        Ok(response) => {
            let (status, body) = read_body(response);
            parse_virustotal(status, &body)
        }
        Err(e) => Outcome::Failed { error: format!("could not reach VirusTotal: {e}") },
    }
}

/// MalwareBazaar's `get_info` answer.
pub fn parse_bazaar(status: u16, body: &str) -> Outcome {
    if status == 401 || status == 403 {
        return Outcome::Failed { error: "MalwareBazaar refused the abuse.ch Auth-Key".into() };
    }
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Outcome::Failed { error: format!("MalwareBazaar answered HTTP {status} without JSON") };
    };
    match v["query_status"].as_str().unwrap_or_default() {
        "ok" => {
            let sample = &v["data"][0];
            let tags = sample["tags"].as_array().map(|t| t.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
            Outcome::Found {
                detections: None,
                label: text(&sample["signature"]),
                tags,
                first_seen: text(&sample["first_seen"]).map(|s| s.chars().take(10).collect()),
            }
        }
        "hash_not_found" | "no_results" => Outcome::NotFound,
        "unknown_auth_key" | "no_api_key" => Outcome::Failed { error: "MalwareBazaar refused the abuse.ch Auth-Key".into() },
        other => Outcome::Failed { error: format!("MalwareBazaar answered {}", if other.is_empty() { "unexpectedly" } else { other }) },
    }
}

/// VirusTotal's `/files/{hash}` answer.
pub fn parse_virustotal(status: u16, body: &str) -> Outcome {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    match status {
        200 => {}
        404 => return Outcome::NotFound,
        401 | 403 => return Outcome::Failed { error: "VirusTotal refused the API key; check it in Settings".into() },
        429 => return Outcome::Limited { retry_secs: 60 },
        _ => {
            let message = v["error"]["message"].as_str().map(str::to_string).unwrap_or_else(|| format!("HTTP {status}"));
            return Outcome::Failed { error: format!("VirusTotal: {message}") };
        }
    }
    let a = &v["data"]["attributes"];
    let stats = &a["last_analysis_stats"];
    let count = |name: &str| stats[name].as_u64().unwrap_or(0) as u32;
    let flagged = count("malicious") + count("suspicious");
    let answered = flagged + count("undetected") + count("harmless");
    let label = text(&a["popular_threat_classification"]["suggested_threat_label"]);
    let tags = a["tags"].as_array().map(|t| t.iter().filter_map(|x| x.as_str().map(str::to_string)).take(8).collect()).unwrap_or_default();
    let first_seen = a["first_submission_date"].as_i64().and_then(|t| chrono::DateTime::from_timestamp(t, 0)).map(|d| d.format("%Y-%m-%d").to_string());
    Outcome::Found { detections: Some((flagged, answered)), label, tags, first_seen }
}

/// The SHA-256 of a file's contents, as lowercase hex.
pub fn file_sha256(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn text(v: &Value) -> Option<String> {
    v.as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

/// The VirusTotal key: the saved one in `dir`, else `VIRUSTOTAL_API_KEY`.
pub fn virustotal_key(dir: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(dir.join(VIRUSTOTAL_KEY_FILE)) {
        Ok(stored) => crate::system::unprotect_secret(&stored)
            .map(Some)
            .context("the saved VirusTotal key could not be decrypted; enter it again"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(std::env::var(VIRUSTOTAL_KEY_ENV).ok().map(|k| k.trim().to_string()).filter(|k| !k.is_empty()))
        }
        Err(e) => Err(e).context("reading the saved VirusTotal key"),
    }
}

/// Whether a key is saved in `dir` (not counting the environment variable).
pub fn virustotal_key_saved(dir: &Path) -> bool {
    dir.join(VIRUSTOTAL_KEY_FILE).is_file()
}

/// Saves (encrypted for this Windows account) or, with `None`, removes the key.
pub fn save_virustotal_key(dir: &Path, key: Option<&str>) -> Result<()> {
    let path = dir.join(VIRUSTOTAL_KEY_FILE);
    match key.map(str::trim).filter(|k| !k.is_empty()) {
        Some(key) => {
            if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("that does not look like a VirusTotal API key (64 letters and digits)");
            }
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            let temporary = dir.join(format!("{VIRUSTOTAL_KEY_FILE}.new"));
            std::fs::write(&temporary, crate::system::protect_secret(key)?)?;
            std::fs::rename(&temporary, &path)?;
            Ok(())
        }
        None => match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).context("removing the saved VirusTotal key"),
            _ => Ok(()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "a3f1c2d4e5b6a7980a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071";

    #[test]
    fn hashes_are_checked_and_lowercased() {
        assert_eq!(normalize(&format!(" {} ", SHA.to_uppercase())).unwrap(), SHA);
        assert!(normalize("abc").is_err());
        assert!(normalize(&"g".repeat(64)).is_err());
    }

    #[test]
    fn bazaar_answers_are_read() {
        let found = r#"{"query_status":"ok","data":[{"sha256_hash":"x","signature":"LummaStealer","tags":["exe","Lumma"],"first_seen":"2025-03-01 10:11:12"}]}"#;
        assert_eq!(
            parse_bazaar(200, found),
            Outcome::Found { detections: None, label: Some("LummaStealer".into()), tags: vec!["exe".into(), "Lumma".into()], first_seen: Some("2025-03-01".into()) }
        );
        let unnamed = r#"{"query_status":"ok","data":[{"signature":null,"tags":null,"first_seen":null}]}"#;
        assert_eq!(parse_bazaar(200, unnamed), Outcome::Found { detections: None, label: None, tags: vec![], first_seen: None });
        assert_eq!(parse_bazaar(200, r#"{"query_status":"hash_not_found"}"#), Outcome::NotFound);
        assert!(matches!(parse_bazaar(200, r#"{"query_status":"unknown_auth_key"}"#), Outcome::Failed { error } if error.contains("Auth-Key")));
        assert!(matches!(parse_bazaar(502, "<html>"), Outcome::Failed { .. }));
    }

    #[test]
    fn virustotal_answers_are_read() {
        let found = r#"{"data":{"attributes":{
            "last_analysis_stats":{"malicious":40,"suspicious":1,"undetected":22,"harmless":0,"timeout":2,"type-unsupported":5},
            "popular_threat_classification":{"suggested_threat_label":"trojan.lumma/stealer"},
            "first_submission_date":1735689600,
            "tags":["peexe","spreader"]}}}"#;
        assert_eq!(
            parse_virustotal(200, found),
            Outcome::Found {
                detections: Some((41, 63)),
                label: Some("trojan.lumma/stealer".into()),
                tags: vec!["peexe".into(), "spreader".into()],
                first_seen: Some("2025-01-01".into())
            }
        );
        assert_eq!(parse_virustotal(404, r#"{"error":{"code":"NotFoundError"}}"#), Outcome::NotFound);
        assert_eq!(parse_virustotal(429, r#"{"error":{"code":"QuotaExceededError"}}"#), Outcome::Limited { retry_secs: 60 });
        assert!(matches!(parse_virustotal(401, "{}"), Outcome::Failed { error } if error.contains("key")));
        assert!(matches!(parse_virustotal(500, r#"{"error":{"message":"boom"}}"#), Outcome::Failed { error } if error == "VirusTotal: boom"));
    }

    fn rep(checks: Vec<(Service, Outcome)>) -> Reputation {
        Reputation { sha256: SHA.into(), checks: checks.into_iter().map(|(service, outcome)| Check { service, outcome, cached: false }).collect() }
    }

    fn vt(flagged: u32, answered: u32) -> (Service, Outcome) {
        (Service::VirusTotal, Outcome::Found { detections: Some((flagged, answered)), label: None, tags: vec![], first_seen: None })
    }

    #[test]
    fn answers_add_up_to_a_standing_and_a_headline() {
        let listed = (Service::MalwareBazaar, Outcome::Found { detections: None, label: Some("RedLine".into()), tags: vec![], first_seen: None });
        let r = rep(vec![listed.clone(), vt(52, 70)]);
        assert_eq!(r.standing(), Standing::Malicious);
        assert_eq!(r.headline(), "Known malware (RedLine): 52 of 70 antivirus engines detect it");
        let r = rep(vec![listed, (Service::VirusTotal, Outcome::NoKey)]);
        assert_eq!(r.headline(), "Known malware (RedLine): listed by MalwareBazaar");
        let r = rep(vec![(Service::MalwareBazaar, Outcome::NotFound), vt(2, 70)]);
        assert_eq!(r.standing(), Standing::Suspicious);
        let r = rep(vec![(Service::MalwareBazaar, Outcome::NotFound), vt(0, 68)]);
        assert_eq!((r.standing(), r.headline().as_str()), (Standing::Clean, "None of 68 antivirus engines detect it"));
        let r = rep(vec![(Service::MalwareBazaar, Outcome::NotFound), (Service::VirusTotal, Outcome::NotFound)]);
        assert_eq!((r.standing(), r.headline().as_str()), (Standing::Unknown, "Not known online: no service asked has seen this file"));
        let r = rep(vec![(Service::MalwareBazaar, Outcome::NoKey), (Service::VirusTotal, Outcome::NoKey)]);
        assert_eq!(r.headline(), "No online answer");
        assert_eq!(r.prompt_lines(), ["MalwareBazaar: not asked (no key)", "VirusTotal: not asked (no key)"]);
    }

    #[test]
    fn without_keys_nothing_is_asked_and_answers_are_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let checker = Checker::new(tmp.path());
        let r = checker.check(SHA, &Keys::default()).unwrap();
        assert!(r.checks.iter().all(|c| c.outcome == Outcome::NoKey));

        // A remembered answer is reused, also by a new checker (the file).
        let id = format!("VirusTotal:{SHA}");
        checker.remember(id.clone(), Outcome::NotFound);
        let again = Checker::new(tmp.path());
        let keys = Keys { abuse_ch: None, virustotal: Some("k".into()) };
        let r = again.check(SHA, &keys).unwrap();
        assert_eq!(r.checks[1], Check { service: Service::VirusTotal, outcome: Outcome::NotFound, cached: true });
    }

    #[test]
    fn virustotal_is_asked_at_most_four_times_a_minute() {
        let tmp = tempfile::tempdir().unwrap();
        let checker = Checker::new(tmp.path());
        for _ in 0..VIRUSTOTAL_PER_MINUTE {
            assert!(checker.virustotal_slot().is_ok());
        }
        assert!(matches!(checker.virustotal_slot(), Err(secs) if (1..=60).contains(&secs)));
    }

    #[cfg(windows)]
    #[test]
    fn keys_are_saved_encrypted_and_checked() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(save_virustotal_key(tmp.path(), Some("not a key")).is_err());
        let key = "0123456789abcdef".repeat(4);
        save_virustotal_key(tmp.path(), Some(&key)).unwrap();
        assert!(virustotal_key_saved(tmp.path()));
        assert!(!std::fs::read_to_string(tmp.path().join(VIRUSTOTAL_KEY_FILE)).unwrap().contains(&key));
        assert_eq!(virustotal_key(tmp.path()).unwrap().as_deref(), Some(key.as_str()));
        save_virustotal_key(tmp.path(), None).unwrap();
        assert!(!virustotal_key_saved(tmp.path()));
    }
}
