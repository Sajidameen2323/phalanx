//! Higher-risk file types: programs, scripts and other files that run code
//! when opened, plus names disguised to look like documents.
//!
//! This is about *type*, not verdict: a risky file is not a threat, it is a
//! file worth a second look before opening it.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskKind {
    /// Runs as a program or installs one.
    Program,
    /// Runs through a script host or interpreter.
    Script,
    /// Opens something else: shortcuts and similar launchers.
    Shortcut,
    /// Mounts as a drive; often used to slip programs past download warnings.
    DiskImage,
}

impl RiskKind {
    pub fn label(self) -> &'static str {
        match self {
            RiskKind::Program => "program",
            RiskKind::Script => "script",
            RiskKind::Shortcut => "shortcut",
            RiskKind::DiskImage => "disk image",
        }
    }
}

const PROGRAMS: &[&str] = &[
    "exe", "scr", "com", "pif", "cpl", "msi", "msp", "msix", "msixbundle", "appx", "appxbundle",
    "application", "appref-ms", "dll", "sys", "gadget",
];
const SCRIPTS: &[&str] = &[
    "ps1", "psm1", "psd1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "py",
    "pyw", "pyc", "jar", "reg", "msc", "sct", "inf", "chm", "xll",
];
const SHORTCUTS: &[&str] = &["lnk", "url", "scf", "library-ms", "settingcontent-ms", "search-ms"];
const DISK_IMAGES: &[&str] = &["iso", "img", "vhd", "vhdx"];

/// Extensions people expect to be harmless documents or media; one of these
/// right before a risky extension (`invoice.pdf.exe`) is a disguise.
const DOCUMENT_LOOKALIKES: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png",
    "gif", "bmp", "mp3", "mp4", "mov", "avi", "mkv", "wav", "zip", "rar", "html", "htm",
];

/// Right-to-left override: renders `exe.pdf` for a name ending in `fdp.exe`.
const RTL_OVERRIDE: char = '\u{202E}';

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskyFile {
    pub kind: RiskKind,
    /// Lower-case final extension.
    pub extension: String,
    /// Why the name looks disguised, if it does.
    pub disguise: Option<String>,
}

/// `None` for ordinary documents and media.
pub fn classify(path: &Path) -> Option<RiskyFile> {
    let name = path.file_name()?.to_str()?;
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    let ext = extension.as_str();
    let kind = if PROGRAMS.contains(&ext) {
        RiskKind::Program
    } else if SCRIPTS.contains(&ext) {
        RiskKind::Script
    } else if SHORTCUTS.contains(&ext) {
        RiskKind::Shortcut
    } else if DISK_IMAGES.contains(&ext) {
        RiskKind::DiskImage
    } else {
        return None;
    };

    let stem = &name[..name.len() - extension.len() - 1];
    let disguise = if name.contains(RTL_OVERRIDE) {
        Some("the name contains a hidden right-to-left character that reverses how it is shown".to_string())
    } else if let Some(inner) = Path::new(stem)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .filter(|inner| DOCUMENT_LOOKALIKES.contains(&inner.as_str()))
    {
        Some(format!("it looks like a .{inner} file but is really a .{extension} {}", kind.label()))
    } else if stem.ends_with("   ") {
        Some("the name is padded with spaces to push the real extension out of view".to_string())
    } else {
        None
    };
    Some(RiskyFile { kind, extension, disguise })
}

/// Where a download came from, from its Mark of the Web
/// (the `Zone.Identifier` stream browsers attach to downloads).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadOrigin {
    /// 3 is the Internet zone.
    pub zone: Option<u32>,
    pub host_url: Option<String>,
    pub referrer_url: Option<String>,
}

impl DownloadOrigin {
    /// The download site's host name, for short messages.
    pub fn host(&self) -> Option<&str> {
        let url = self.host_url.as_deref().or(self.referrer_url.as_deref())?;
        let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
        let host = rest.split(['/', '?', '#']).next()?;
        let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
        (!host.is_empty()).then_some(host)
    }
}

/// Reads the Mark of the Web. `None` when the file has none (not downloaded
/// by a browser, or extracted by a tool that drops it) or off Windows.
pub fn download_origin(path: &Path) -> Option<DownloadOrigin> {
    if !cfg!(windows) {
        return None;
    }
    let mut stream = path.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    let bytes = std::fs::read(stream).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    parse_zone_identifier(text.trim_start_matches('\u{feff}'))
}

pub fn parse_zone_identifier(text: &str) -> Option<DownloadOrigin> {
    let mut origin = DownloadOrigin::default();
    let mut in_section = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line.eq_ignore_ascii_case("[ZoneTransfer]");
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        if !in_section {
            continue;
        }
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "zoneid" => origin.zone = value.parse().ok(),
            "hosturl" if !value.is_empty() => origin.host_url = Some(value.to_string()),
            "referrerurl" if !value.is_empty() => origin.referrer_url = Some(value.to_string()),
            _ => {}
        }
    }
    (origin != DownloadOrigin::default()).then_some(origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programs_and_scripts_are_risky_documents_are_not() {
        assert_eq!(classify(Path::new("C:/d/setup.EXE")).unwrap().kind, RiskKind::Program);
        assert_eq!(classify(Path::new("C:/d/tool.py")).unwrap().kind, RiskKind::Script);
        assert_eq!(classify(Path::new("C:/d/run.ps1")).unwrap().kind, RiskKind::Script);
        assert_eq!(classify(Path::new("C:/d/film.iso")).unwrap().kind, RiskKind::DiskImage);
        assert_eq!(classify(Path::new("C:/d/link.lnk")).unwrap().kind, RiskKind::Shortcut);
        assert!(classify(Path::new("C:/d/report.pdf")).is_none());
        assert!(classify(Path::new("C:/d/README")).is_none());
    }

    #[test]
    fn disguised_names_are_explained() {
        let r = classify(Path::new("C:/d/invoice.pdf.exe")).unwrap();
        assert!(r.disguise.unwrap().contains(".pdf"));
        let r = classify(Path::new("C:/d/photo\u{202E}gpj.exe")).unwrap();
        assert!(r.disguise.unwrap().contains("right-to-left"));
        let r = classify(Path::new("C:/d/notes.txt          .bat")).unwrap();
        assert!(r.disguise.is_some());
        assert!(classify(Path::new("C:/d/python-3.13.exe")).unwrap().disguise.is_none());
    }

    #[test]
    fn mark_of_the_web_is_parsed() {
        let text = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.org/page\r\nHostUrl=https://dl.example.com/files/setup.exe?x=1\r\n";
        let origin = parse_zone_identifier(text).unwrap();
        assert_eq!(origin.zone, Some(3));
        assert_eq!(origin.host(), Some("dl.example.com"));
        assert!(parse_zone_identifier("[Other]\nZoneId=3").is_none());
        assert!(parse_zone_identifier("").is_none());
    }
}
