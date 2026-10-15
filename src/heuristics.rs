//! Static heuristics for Windows PE files.
//!
//! Each indicator adds to a score; a file reaching [`THRESHOLD`] is reported as
//! `suspicious`. Heuristics never claim `malware`: they describe traits that
//! malware commonly has, and legitimate software sometimes has too.

use crate::{Category, Finding, Source};
use goblin::pe::PE;
use serde::Serialize;
use std::collections::HashSet;

pub const THRESHOLD: u32 = 60;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const HIGH_ENTROPY: f64 = 7.2;
const MIN_ENTROPY_SECTION: usize = 4096;

const PACKER_SECTIONS: &[&str] = &[
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "MPRESS1", "MPRESS2", ".petite", ".nsp0",
    ".nsp1", ".themida", "Themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2",
];

#[derive(Debug, Clone, Serialize)]
pub struct Indicator {
    pub name: String,
    pub weight: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeReport {
    pub score: u32,
    pub signed: bool,
    pub indicators: Vec<Indicator>,
}

impl PeReport {
    pub fn finding(&self) -> Option<Finding> {
        (self.score >= THRESHOLD).then(|| Finding {
            threat: "Suspicious.Heuristic.PE".to_string(),
            category: Category::Suspicious,
            source: Source::Heuristic,
            details: format!(
                "score {} ({})",
                self.score,
                self.indicators
                    .iter()
                    .map(|i| format!("{} +{}", i.name, i.weight))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        })
    }
}

/// Returns `None` for anything that is not a parseable PE file.
pub fn analyze(data: &[u8]) -> Option<PeReport> {
    if !data.starts_with(b"MZ") {
        return None;
    }
    let pe = PE::parse(data).ok()?;
    let mut indicators = Vec::new();
    let mut add = |name: String, weight: u32| indicators.push(Indicator { name, weight });

    let mut packer_named = false;
    for section in &pe.sections {
        let name = section.name().unwrap_or("").to_string();
        if !packer_named && PACKER_SECTIONS.iter().any(|p| p.eq_ignore_ascii_case(&name)) {
            packer_named = true;
            add(format!("packer section `{name}`"), 30);
        }
        let flags = section.characteristics;
        let executable = flags & IMAGE_SCN_MEM_EXECUTE != 0;
        if executable && flags & IMAGE_SCN_MEM_WRITE != 0 {
            add(format!("writable+executable section `{name}`"), 20);
        }
        if executable {
            let start = section.pointer_to_raw_data as usize;
            let end = start.saturating_add(section.size_of_raw_data as usize).min(data.len());
            if end > start && end - start >= MIN_ENTROPY_SECTION {
                let e = entropy(&data[start..end]);
                if e > HIGH_ENTROPY {
                    add(format!("packed/encrypted code section `{name}` (entropy {e:.2})"), 30);
                }
            }
        }
    }

    let imports: HashSet<&str> = pe.imports.iter().map(|i| i.name.as_ref()).collect();
    let has = |name: &str| imports.contains(name);
    let has_any = |names: &[&str]| names.iter().any(|n| imports.contains(n));

    if has("VirtualAllocEx")
        && has("WriteProcessMemory")
        && has_any(&["CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC"])
    {
        add("remote process injection APIs".to_string(), 40);
    }
    if has_any(&["NtUnmapViewOfSection", "ZwUnmapViewOfSection"]) && has("SetThreadContext") {
        add("process hollowing APIs".to_string(), 40);
    }
    if has_any(&["SetWindowsHookExA", "SetWindowsHookExW"])
        && has_any(&["GetAsyncKeyState", "GetKeyboardState"])
    {
        add("keyboard hook + key state APIs".to_string(), 20);
    }
    if pe.imports.is_empty() && !pe.is_lib {
        add("executable with no imports".to_string(), 15);
    } else if imports.len() <= 5
        && has("GetProcAddress")
        && has_any(&["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"])
    {
        add("tiny import table resolving APIs at runtime".to_string(), 20);
    }

    let signed = !pe.certificates.is_empty();
    // Being unsigned only matters alongside other traits; plenty of clean tools are unsigned.
    if !signed && !indicators.is_empty() {
        indicators.push(Indicator {
            name: "no Authenticode signature".to_string(),
            weight: 10,
        });
    }

    let score = indicators.iter().map(|i| i.weight).sum();
    Some(PeReport {
        score,
        signed,
        indicators,
    })
}

/// Shannon entropy in bits per byte (0.0 to 8.0).
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7u8; 1000]), 0.0);
        let all: Vec<u8> = (0..=255u8).cycle().take(256 * 64).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn non_pe_is_ignored() {
        assert!(analyze(b"plain text").is_none());
        assert!(analyze(b"MZ but truncated").is_none());
    }

    #[test]
    fn parses_a_real_pe_without_flagging_it() {
        // The test binary itself is an ordinary, unpacked executable.
        let exe = std::env::current_exe().unwrap();
        let data = std::fs::read(exe).unwrap();
        if !data.starts_with(b"MZ") {
            return; // not on Windows
        }
        let report = analyze(&data).expect("test binary should parse as PE");
        assert!(report.finding().is_none(), "{report:?}");
    }
}
