//! What a file holds beyond its own bytes: the program inside a padded
//! executable, the files inside an archive, and the command a shortcut runs.
//!
//! These are the usual ways past a scanner. Stealers are padded with
//! hundreds of megabytes of zeros so they exceed scanners' size limits;
//! payloads are delivered in ZIP or 7z archives, often password-protected;
//! and a shortcut that looks like a document starts PowerShell. The engine
//! scans a file's bytes; this module also looks inside them.
//!
//! Findings about something inside a file are reported on the file itself
//! (the archive, the shortcut), with where they were found in `details`.

use crate::cmdline::{self, Confidence};
use crate::engine::{FileScanner, Verdict};
use crate::{risk, Category, Finding, Source};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::Path;

/// Archives inside archives are opened this many levels deep.
const MAX_DEPTH: usize = 3;
/// Most bytes unpacked from one file, all of its members together.
const MAX_UNPACKED: u64 = 512 * 1024 * 1024;
/// Most archive members looked at in one file.
const MAX_ENTRIES: usize = 10_000;
/// A member unpacking to more than this many times its packed size is a
/// decompression bomb (above [`BOMB_FLOOR`] bytes).
const MAX_RATIO: u64 = 100;
const BOMB_FLOOR: u64 = 1024 * 1024;
/// Padding after a program's end that makes it suspicious.
const MIN_PADDING: u64 = 10 * 1024 * 1024;
/// The start of a file read to find where its program ends.
const HEADER_BYTES: u64 = 64 * 1024;
/// The PE heuristics' finding; members of an archive cannot be checked for
/// a publisher signature, so it is not reported for them.
const PE_HEURISTIC: &str = "Suspicious.Heuristic.PE";

#[derive(Debug, Clone)]
pub struct Options {
    /// Larger files are skipped, unless they are padded programs.
    pub max_size: u64,
    /// Look inside ZIP and 7z archives.
    pub archives: bool,
}

pub struct Examined {
    pub verdict: Verdict,
    /// Bytes read and scanned.
    pub bytes: u64,
    /// The whole file, when it was read whole (kept for quarantine).
    pub data: Option<Vec<u8>>,
}

/// Examines the file at `path`. `None` when it is larger than
/// `options.max_size` and is not a padded program: skipped.
pub fn examine_file(scanner: &mut FileScanner<'_>, path: &Path, options: &Options) -> io::Result<Option<Examined>> {
    let len = std::fs::metadata(path)?.len();
    if len <= options.max_size {
        let data = std::fs::read(path)?;
        let verdict = examine(scanner, &data, options);
        return Ok(Some(Examined { bytes: data.len() as u64, verdict, data: Some(data) }));
    }
    let mut file = File::open(path)?;
    let Some(image_end) = padded_image_end(&mut file, len)? else { return Ok(None) };
    if image_end > options.max_size {
        return Ok(None);
    }
    let mut image = vec![0; image_end as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut image)?;
    // The padding is checked here, so `examine` sees only the program.
    let mut verdict = examine(scanner, &image, options);
    verdict.findings.push(padded_finding(len - image_end, &verdict.sha256));
    sort(&mut verdict.findings);
    // History and quarantine identify the file as it is on disk.
    verdict.sha256 = sha256_of(&mut file)?;
    Ok(Some(Examined { verdict, bytes: image_end, data: None }))
}

/// Scans `data` and what it holds.
pub fn examine(scanner: &mut FileScanner<'_>, data: &[u8], options: &Options) -> Verdict {
    let verdict = scanner.scan(data);
    let mut walk = Walk { scanner, options, unpacked: 0, entries: 0, findings: verdict.findings, warnings: verdict.warnings };
    walk.inspect(data, "", 0);
    let Walk { mut findings, warnings, .. } = walk;
    sort(&mut findings);
    Verdict { sha256: verdict.sha256, findings, warnings }
}

fn sort(findings: &mut [Finding]) {
    findings.sort_by_key(|f| std::cmp::Reverse(f.category));
}

/// One file being examined, with everything found inside it so far.
struct Walk<'a, 'e> {
    scanner: &'a mut FileScanner<'e>,
    options: &'a Options,
    unpacked: u64,
    entries: usize,
    findings: Vec<Finding>,
    warnings: Vec<String>,
}

impl Walk<'_, '_> {
    /// Records `finding` about the data at `at` (a member path inside the
    /// file, `""` for the file itself).
    fn add(&mut self, finding: Finding, at: &str) {
        if !at.is_empty() {
            // Stored (uncompressed) members also match in the archive's own
            // bytes; the match that says where it is wins.
            self.findings.retain(|f| f.threat != finding.threat || f.details.contains(" · inside "));
        }
        let finding = if at.is_empty() { finding } else { Finding { details: format!("{} · inside {at}", finding.details), ..finding } };
        if !self.findings.iter().any(|f| f.threat == finding.threat && f.details == finding.details) {
            self.findings.push(finding);
        }
    }

    fn warn(&mut self, at: &str, message: impl AsRef<str>) {
        let message = message.as_ref();
        self.warnings.push(if at.is_empty() { message.to_string() } else { format!("{at}: {message}") });
    }

    /// Looks at what `data` (already scanned) holds.
    fn inspect(&mut self, data: &[u8], at: &str, depth: usize) {
        if let Some(end) = pe_image_end(data).filter(|&end| end < data.len() as u64) {
            let padding = &data[end as usize..];
            if padding.len() as u64 >= MIN_PADDING && looks_like_padding(&sample_slice(padding)) {
                // Signatures and hash lists know the program, not the padding.
                let inner = self.scanner.scan(&data[..end as usize]);
                for f in inner.findings {
                    self.add(f, at);
                }
                self.add(padded_finding(padding.len() as u64, &inner.sha256), at);
            }
        }
        if let Some(f) = shortcut_finding(data) {
            self.add(f, at);
        }
        if self.options.archives && depth < MAX_DEPTH {
            if data.starts_with(b"PK\x03\x04") {
                self.zip(data, at, depth);
            } else if data.starts_with(b"7z\xBC\xAF\x27\x1C") {
                self.sevenz(data, at, depth);
            }
        }
    }

    /// Scans an unpacked member and what it holds.
    fn member(&mut self, data: &[u8], at: &str, depth: usize) {
        let verdict = self.scanner.scan(data);
        for f in verdict.findings {
            if f.threat != PE_HEURISTIC {
                self.add(f, at);
            }
        }
        for w in verdict.warnings {
            self.warn(at, w);
        }
        self.inspect(data, at, depth);
    }

    /// Counts one more member; `false` once there are too many.
    fn next_entry(&mut self, at: &str) -> bool {
        if self.entries >= MAX_ENTRIES {
            self.warn(at, format!("stopped after {MAX_ENTRIES} files inside archives"));
            return false;
        }
        self.entries += 1;
        true
    }

    fn zip(&mut self, data: &[u8], at: &str, depth: usize) {
        let mut archive = match zip::ZipArchive::new(Cursor::new(data)) {
            Ok(archive) => archive,
            Err(e) => return self.warn(at, format!("could not open the ZIP archive: {e}")),
        };
        let mut locked = false;
        for i in 0..archive.len() {
            if !self.next_entry(at) {
                return;
            }
            let (name, encrypted, size, packed) = match archive.by_index_raw(i) {
                Ok(f) if f.is_dir() => continue,
                Ok(f) => (f.name().map(|n| n.into_owned()).unwrap_or_default(), f.encrypted(), f.size(), f.compressed_size()),
                Err(e) => {
                    self.warn(at, format!("could not read file {i} of the ZIP archive: {e}"));
                    continue;
                }
            };
            let path = within(at, &name);
            if encrypted {
                if !locked && risk::classify(Path::new(&name)).is_some() {
                    locked = true;
                    self.add(locked_finding(&name), at);
                }
                continue;
            }
            if size > self.options.max_size {
                self.warn(&path, "larger than the size limit; not unpacked");
                continue;
            }
            if size > BOMB_FLOOR && size / packed.max(1) > MAX_RATIO {
                return self.warn(&path, "unpacks to over 100 times its size (a decompression bomb); the archive was not scanned further");
            }
            if self.unpacked + size > MAX_UNPACKED {
                return self.warn(at, "more than 512 MB inside; the rest was not scanned");
            }
            let mut bytes = Vec::with_capacity(size as usize);
            let read = archive.by_index(i).and_then(|f| f.take(size + 1).read_to_end(&mut bytes).map_err(Into::into));
            if let Err(e) = read {
                self.warn(&path, format!("could not unpack: {e}"));
                continue;
            }
            if bytes.len() as u64 > size {
                return self.warn(&path, "holds more than it claims; the archive was not scanned further");
            }
            self.unpacked += size;
            self.member(&bytes, &path, depth + 1);
        }
    }

    fn sevenz(&mut self, data: &[u8], at: &str, depth: usize) {
        use sevenz_rust2::{ArchiveReader, Error, Password};
        let mut reader = match ArchiveReader::new(Cursor::new(data), Password::empty()) {
            Ok(reader) => reader,
            Err(Error::PasswordRequired | Error::MaybeBadPassword(_)) => {
                return self.warn(at, "the 7z archive is password-protected, including its file names; its contents were not scanned");
            }
            Err(e) => return self.warn(at, format!("could not open the 7z archive: {e}")),
        };
        reader.set_thread_count(1);
        let files: Vec<(String, u64)> = reader.archive().files.iter().filter(|f| !f.is_directory()).map(|f| (f.name().to_string(), f.size())).collect();
        let total: u64 = files.iter().map(|(_, size)| size).sum();
        if total > BOMB_FLOOR && total / (data.len() as u64).max(1) > MAX_RATIO {
            return self.warn(at, "unpacks to over 100 times its size (a decompression bomb); its contents were not scanned");
        }
        let mut stopped = false;
        let result = reader.for_each_entries(|entry, read| {
            if entry.is_directory() {
                return Ok(true);
            }
            if !self.next_entry(at) {
                stopped = true;
                return Ok(false);
            }
            let size = entry.size();
            let path = within(at, entry.name());
            // Every member is read: the next one starts where this one ends.
            if self.unpacked + size > MAX_UNPACKED {
                self.warn(at, "more than 512 MB inside; the rest was not scanned");
                stopped = true;
                return Ok(false);
            }
            self.unpacked += size;
            if size > self.options.max_size {
                io::copy(read, &mut io::sink())?;
                self.warn(&path, "larger than the size limit; not scanned");
                return Ok(true);
            }
            let mut bytes = Vec::with_capacity(size as usize);
            read.take(size).read_to_end(&mut bytes)?;
            self.member(&bytes, &path, depth + 1);
            Ok(true)
        });
        match result {
            Ok(()) => {}
            Err(Error::PasswordRequired | Error::MaybeBadPassword(_)) if !stopped => {
                match files.iter().find(|(name, _)| risk::classify(Path::new(name)).is_some()) {
                    Some((name, _)) => self.add(locked_finding(name), at),
                    None => self.warn(at, "the 7z archive is password-protected; its contents were not scanned"),
                }
            }
            Err(e) => self.warn(at, format!("could not unpack the 7z archive: {e}")),
        }
    }
}

/// `outer.zip > inner.exe`.
fn within(at: &str, name: &str) -> String {
    if at.is_empty() { name.to_string() } else { format!("{at} > {name}") }
}

fn padded_finding(padding: u64, image_sha256: &str) -> Finding {
    Finding {
        threat: "Suspicious.PaddedExecutable".into(),
        category: Category::Suspicious,
        source: Source::Heuristic,
        details: format!(
            "{} MB of padding after the program, a trick to get past scanners' size limits; the program itself (sha256 {image_sha256}) was scanned",
            padding / (1024 * 1024)
        ),
    }
}

fn locked_finding(name: &str) -> Finding {
    Finding {
        threat: "Suspicious.LockedArchive".into(),
        category: Category::Suspicious,
        source: Source::Heuristic,
        details: format!("a password-protected archive holding {name}, which no scanner can look inside; a common way to deliver malware"),
    }
}

// ---------------------------------------------------------------------------
// Padded programs
// ---------------------------------------------------------------------------

/// Where a Windows program's own data ends (its last section, or its
/// signature): anything after it is appended data.
pub fn pe_image_end(h: &[u8]) -> Option<u64> {
    let u16_at = |at: usize| h.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |at: usize| h.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    if !h.starts_with(b"MZ") {
        return None;
    }
    let pe = u32_at(0x3C)? as usize;
    if h.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe + 4;
    let sections = u16_at(coff + 2)? as usize;
    let optional_size = u16_at(coff + 16)? as usize;
    let optional = coff + 20;
    let directories = match u16_at(optional)? {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => return None,
    };
    let mut end = 0u64;
    // Directory 4 (the signature) is a file offset, after the sections.
    if u32_at(directories - 4)? > 4 {
        let (offset, size) = (u32_at(directories + 32)?, u32_at(directories + 36)?);
        if offset != 0 {
            end = end.max(offset as u64 + size as u64);
        }
    }
    let table = optional + optional_size;
    for i in 0..sections.min(96) {
        let s = table + i * 40;
        let (size, offset) = (u32_at(s + 16)?, u32_at(s + 20)?);
        if size > 0 {
            end = end.max(offset as u64 + size as u64);
        }
    }
    (end > 0).then_some(end)
}

/// Where the program in `file` ends, if what follows is at least
/// [`MIN_PADDING`] of padding.
fn padded_image_end(file: &mut File, len: u64) -> io::Result<Option<u64>> {
    let mut header = vec![0; HEADER_BYTES.min(len) as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    let Some(end) = pe_image_end(&header).filter(|&end| end < len && len - end >= MIN_PADDING) else { return Ok(None) };
    // Samples spread over the appended data.
    let mut sample = Vec::new();
    let window = 4096u64;
    let span = len - end - window;
    for i in 0..64u64 {
        file.seek(SeekFrom::Start(end + span * i / 63))?;
        let mut chunk = vec![0; window as usize];
        file.read_exact(&mut chunk)?;
        sample.extend_from_slice(&chunk);
    }
    Ok(looks_like_padding(&sample).then_some(end))
}

/// Up to 64 windows of 4 KiB spread over `data`.
fn sample_slice(data: &[u8]) -> Vec<u8> {
    let window = 4096.min(data.len());
    let span = data.len() - window;
    (0..64).flat_map(|i| &data[span * i / 63..span * i / 63 + window]).copied().collect()
}

/// Mostly one repeated byte, or very low entropy (a short repeated
/// pattern): filler, not compressed data or code.
fn looks_like_padding(sample: &[u8]) -> bool {
    if sample.is_empty() {
        return false;
    }
    let mut counts = [0u64; 256];
    for &b in sample {
        counts[b as usize] += 1;
    }
    let n = sample.len() as f64;
    let top = *counts.iter().max().unwrap_or(&0) as f64 / n;
    let entropy: f64 = counts.iter().filter(|&&c| c > 0).map(|&c| c as f64 / n).map(|p| -p * p.log2()).sum();
    top >= 0.9 || entropy < 1.5
}

fn sha256_of(file: &mut File) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
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

/// Whether the file at `path` starts like a Windows program; large ones
/// are worth opening to check for padding.
pub fn starts_like_program(path: &Path) -> bool {
    let mut magic = [0u8; 2];
    File::open(path).and_then(|mut f| f.read_exact(&mut magic)).is_ok() && &magic == b"MZ"
}

// ---------------------------------------------------------------------------
// Shortcuts
// ---------------------------------------------------------------------------

/// A shortcut's header: its size and the shell link class id.
const LNK_HEADER: [u8; 20] = [0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
/// A run of spaces this long in a shortcut's arguments hides them from its
/// Properties box.
const PADDED_ARGUMENTS: usize = 100;

/// What a `.lnk` shortcut runs.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Shortcut {
    pub target: Option<String>,
    pub arguments: String,
}

/// Reads a shell link (MS-SHLLINK); `None` if `data` is not one.
pub fn parse_shortcut(data: &[u8]) -> Option<Shortcut> {
    if !data.starts_with(&LNK_HEADER) {
        return None;
    }
    let u16_at = |at: usize| data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize);
    let u32_at = |at: usize| data.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let flags = u32_at(0x14)?;
    let unicode = flags & 0x80 != 0;
    let mut pos = 0x4C;
    let mut out = Shortcut::default();
    let mut id_names = None;
    if flags & 0x1 != 0 {
        let size = u16_at(pos)?;
        id_names = last_program_name(data.get(pos + 2..pos + 2 + size)?);
        pos += 2 + size;
    }
    if flags & 0x2 != 0 {
        let size = u32_at(pos)?;
        let info = data.get(pos..pos + size)?;
        let info_u32 = |at: usize| info.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
        if info_u32(8)? & 0x1 != 0 {
            let header = info_u32(4)?;
            out.target = if header >= 0x24 {
                info_u32(28).and_then(|o| utf16_cstr(info.get(o..)?))
            } else {
                None
            }
            .or_else(|| info_u32(16).and_then(|o| ansi_cstr(info.get(o..)?)))
            .filter(|t| !t.is_empty());
        }
        pos += size;
    }
    // Name, relative path, working directory, arguments, icon, in that order.
    let mut relative = None;
    for bit in [0x4, 0x8, 0x10, 0x20, 0x40] {
        if flags & bit == 0 {
            continue;
        }
        let count = u16_at(pos)?;
        let bytes = if unicode { count * 2 } else { count };
        let raw = data.get(pos + 2..pos + 2 + bytes)?;
        let text = if unicode {
            String::from_utf16_lossy(&raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>())
        } else {
            raw.iter().map(|&b| b as char).collect()
        };
        match bit {
            0x8 => relative = Some(text),
            0x20 => out.arguments = text,
            _ => {}
        }
        pos += 2 + bytes;
    }
    // Extra data: an environment-variable target (`%windir%\…`) is how
    // shortcuts made by attackers usually name PowerShell.
    let mut env_target = None;
    while let (Some(size), Some(signature)) = (u32_at(pos), u32_at(pos + 4)) {
        if size < 8 {
            break;
        }
        if signature == 0xA000_0001 {
            env_target = data.get(pos + 268..pos + 788).and_then(utf16_cstr).or_else(|| data.get(pos + 8..pos + 268).and_then(ansi_cstr));
        }
        pos += size;
    }
    out.target = out.target.or(env_target.filter(|t| !t.is_empty())).or(relative).or(id_names);
    Some(out)
}

/// The last `*.exe` name in a shortcut's item id list, the program it
/// points to when no path is stored.
fn last_program_name(ids: &[u8]) -> Option<String> {
    let mut found = None;
    let ascii = ids.split(|b| !(0x20..0x7F).contains(b)).map(|run| String::from_utf8_lossy(run).into_owned());
    let units: Vec<u16> = ids.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let odd: Vec<u16> = ids.get(1..).unwrap_or_default().chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let wide = [units, odd].into_iter().flat_map(|u| u.split(|c| !(0x20..0x7F).contains(c)).map(String::from_utf16_lossy).collect::<Vec<_>>());
    for run in ascii.chain(wide) {
        if run.len() > 4 && run.to_ascii_lowercase().ends_with(".exe") {
            found = Some(run);
        }
    }
    found
}

fn ansi_cstr(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0)?;
    Some(bytes[..end].iter().map(|&b| b as char).collect())
}

fn utf16_cstr(bytes: &[u8]) -> Option<String> {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

/// A shortcut whose command matches the command-line rules, or whose
/// arguments are pushed out of view with spaces.
fn shortcut_finding(data: &[u8]) -> Option<Finding> {
    let link = parse_shortcut(data)?;
    let target = link.target.unwrap_or_default();
    let mut matches = cmdline::host(&target).map(|host| cmdline::analyze(host, &link.arguments)).unwrap_or_default();
    let longest_gap = link.arguments.split(|c: char| !c.is_whitespace()).map(str::len).max().unwrap_or(0);
    if longest_gap >= PADDED_ARGUMENTS {
        matches.push(cmdline::Match::new(
            "shortcut.hidden-arguments",
            "its command is pushed out of view with spaces, so its Properties box shows nothing suspicious",
            Confidence::High,
        ));
    }
    matches.sort_by_key(|m| std::cmp::Reverse(m.confidence));
    let top = matches.first()?;
    let reasons: Vec<&str> = matches.iter().map(|m| m.reason.as_str()).collect();
    let arguments: String = link.arguments.split_whitespace().collect::<Vec<_>>().join(" ");
    Some(Finding {
        threat: format!("Suspicious.Shortcut.{}", top.rule),
        category: Category::Suspicious,
        source: Source::Heuristic,
        details: format!("shortcut: {} · runs: {target} {}", reasons.join("; "), arguments.chars().take(500).collect::<String>()),
    })
}

#[cfg(test)]
mod tests;
