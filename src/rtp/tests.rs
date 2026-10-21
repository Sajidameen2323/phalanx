use super::*;
use crate::engine::EngineConfig;
use std::fs;

fn marker() -> String {
    "threat-scanner-test-marker-7f3a".to_ascii_uppercase()
}

fn config(folder: &Path) -> RtpConfig {
    let mut config = RtpConfig::new(vec![folder.to_path_buf()]);
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
    cfg.process_protection = true;
    cfg.quarantine_floor = Some(Category::Pup);
    cfg.defer_when_fullscreen = false;
    cfg.max_size_bytes = 1 << 20;
    let mut run = Run::start(&data_dir, cfg);
    assert!(run.until(|m| m.starts_with("started")));
    assert_eq!(run.seen[0], "started 0 true");
    // Let the first look at running programs pass, so this one counts as new.
    std::thread::sleep(Duration::from_millis(1500));

    let mut child = std::process::Command::new(&exe)
        .args(["-n", "60", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
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
