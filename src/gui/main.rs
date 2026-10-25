//! Desktop GUI for threat-scanner.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod brand;
mod desktop;
mod dots;
mod link;
mod mark;
mod motion;
mod pages;
mod audit_page;
mod web_page;
mod widgets;

use eframe::egui;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};
use threat_scanner::ai::{self, AiReport, Evidence};
use threat_scanner::engine::{Engine, EngineConfig};
use threat_scanner::posture::{self, Check};
use threat_scanner::ipc::{self, Event, Request};
use threat_scanner::scan::{self, FileReport, ScanOptions, ScanReport};
use threat_scanner::service::settings::ProtectionSettings;
use threat_scanner::store::{DetectionRow, MonthRow, QuarantineRow, ScanErrorRow, ScanRow};
use threat_scanner::system::{self, Performance};
use threat_scanner::update::{self, Manifest};
use threat_scanner::risk::{DownloadOrigin, RiskyFile};
use threat_scanner::cmdline::Confidence;
use threat_scanner::rtp::{CommandHit, CommandSource, Origin, ProcessHit, RiskyOutcome, SideLoadHit};
use threat_scanner::Category;
use widgets::APP_TITLE;

/// Passed by the "start with Windows" entry: start hidden in the tray.
const BACKGROUND_FLAG: &str = "--background";
/// Quit the running copy and exit (the installer and uninstaller use it).
/// Exits with 0 once no copy is running, 1 if one could not be stopped.
const QUIT_FLAG: &str = "--quit";
const MAX_ACTIVITY: usize = 100;

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == QUIT_FLAG) {
        std::process::exit(if desktop::quit_existing() { 0 } else { 1 });
    }
    let background = args.iter().any(|a| a == BACKGROUND_FLAG);
    let scan_paths: Vec<PathBuf> = args
        .iter()
        .filter(|a| *a != BACKGROUND_FLAG)
        .map(PathBuf::from)
        .collect();

    // One copy only: a second launch brings the running one to the front,
    // unless it is another start-up entry (`--background`): that one must
    // never pop the window up at sign-in.
    let Some(instance) = desktop::SingleInstance::acquire() else {
        if !background {
            desktop::show_existing_window();
        }
        return Ok(());
    };

    let (rgba, width, height) = widgets::icon_rgba();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(APP_TITLE)
            .with_icon(egui::IconData { rgba, width, height })
            .with_inner_size([1430.0, 780.0])
            .with_min_inner_size([560.0, 520.0])
            .with_visible(!background),
        ..Default::default()
    };
    eframe::run_native(
        APP_TITLE,
        options,
        Box::new(move |cc| {
            // Started at sign-in: stay in the tray until the user opens it.
            if background {
                desktop::hold_hidden(cc);
            }
            instance.listen_for_show_requests(cc.egui_ctx.clone());
            let app = App::new(&cc.egui_ctx, scan_paths);
            instance.listen_for_quit_requests(cc.egui_ctx.clone(), app.quitting.clone());
            Ok(Box::new(app))
        }),
    )
}

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Dashboard,
    Scan,
    Protection,
    Web,
    Inspect,
    Privacy,
    Audit,
    Quarantine,
    History,
    Settings,
}

#[derive(Clone, Copy, PartialEq)]
enum SettingsTab {
    General,
    Scanning,
    Exclusions,
    Signatures,
    Ai,
}

/// Light, dark, or whatever Windows is set to.
#[derive(Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
enum Appearance {
    #[default]
    System,
    Light,
    Dark,
}

impl Appearance {
    fn preference(self) -> egui::ThemePreference {
        match self {
            Appearance::System => egui::ThemePreference::System,
            Appearance::Light => egui::ThemePreference::Light,
            Appearance::Dark => egui::ThemePreference::Dark,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
struct Settings {
    appearance: Appearance,
    heuristics: bool,
    auto_quarantine: bool,
    quarantine_suspicious: bool,
    max_size_mb: u64,
    performance: Performance,
    exclusions: Vec<PathBuf>,
    watch_enabled: bool,
    watch_folders: Vec<PathBuf>,
    notifications: bool,
    /// Warn as soon as a program or script lands in a watched folder.
    risky_file_alerts: bool,
    /// Real-time protection also scans every program as it starts.
    program_protection: bool,
    /// Stop a running program detected as malware.
    stop_running_threats: bool,
    /// Flag signed programs loading a planted Windows DLL.
    side_loading: bool,
    /// Ignore heuristic-only findings on validly signed files.
    trust_signed: bool,
    /// Look inside ZIP and 7z archives.
    scan_archives: bool,
    /// Real-time protection checks drives that appear (disk images, USB).
    scan_new_drives: bool,
    /// Hold back non-urgent protection scans during full-screen games.
    defer_when_fullscreen: bool,
    close_to_tray: bool,
    /// Unix time the watcher was last known to be running; on start it
    /// catches up on files changed since then.
    watch_checkpoint: Option<u64>,
    ai_enabled: bool,
    ai_model: String,
    /// Gemini API key, encrypted for this Windows user (DPAPI, hex). Never
    /// stored in plain text.
    ai_key_protected: Option<String>,
    /// Send the text of scripts and other text files (binaries never are).
    ai_send_text: bool,
    ai_max_text_kb: u32,
    /// Check the feeds for new signatures and web rules automatically.
    auto_update: bool,
    auto_update_hours: u32,
    /// Unix time of the last automatic or manual check.
    last_update_check: Option<u64>,
}

impl Default for Settings {
    fn default() -> Self {
        let downloads = home_dir().map(|h| h.join("Downloads")).filter(|p| p.is_dir());
        Self {
            appearance: Appearance::System,
            heuristics: true,
            auto_quarantine: false,
            quarantine_suspicious: false,
            max_size_mb: 100,
            performance: Performance::LowImpact,
            exclusions: Vec::new(),
            watch_enabled: false,
            watch_folders: downloads.into_iter().collect(),
            notifications: true,
            risky_file_alerts: true,
            program_protection: true,
            stop_running_threats: true,
            side_loading: true,
            trust_signed: true,
            scan_archives: true,
            scan_new_drives: true,
            defer_when_fullscreen: true,
            close_to_tray: true,
            watch_checkpoint: None,
            ai_enabled: false,
            ai_model: ai::DEFAULT_MODEL.to_string(),
            ai_key_protected: None,
            ai_send_text: true,
            ai_max_text_kb: ai::DEFAULT_MAX_TEXT_KB,
            auto_update: true,
            auto_update_hours: 4,
            last_update_check: None,
        }
    }
}

impl Settings {
    fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("gui-settings.json")
    }
    /// Loads settings. An unreadable file is kept as `gui-settings.json.bad`
    /// (and reported) rather than silently replaced by defaults.
    fn load(data_dir: &Path) -> (Self, Option<String>) {
        let path = Self::path(data_dir);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return (Self::default(), None);
        };
        // Editors and PowerShell often add a UTF-8 byte-order mark.
        match serde_json::from_str(text.trim_start_matches('\u{feff}')) {
            Ok(settings) => (settings, None),
            Err(e) => {
                let backup = path.with_extension("json.bad");
                let _ = std::fs::rename(&path, &backup);
                let warning = format!("Settings could not be read ({e}); defaults are in use and the old file was kept as {}", backup.display());
                (Self::default(), Some(warning))
            }
        }
    }
    fn save(&self, data_dir: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(Self::path(data_dir), text).map_err(|e| e.to_string())
    }
    fn engine_config(&self, data_dir: &Path) -> EngineConfig {
        EngineConfig {
            signature_dir: Some(update::signature_dir(data_dir)),
            heuristics: self.heuristics,
            ..Default::default()
        }
    }
    fn exclude(&self) -> Vec<PathBuf> {
        self.exclusions.clone()
    }
    fn quarantine_floor(&self) -> Option<Category> {
        if self.quarantine_suspicious {
            Some(Category::Suspicious)
        } else if self.auto_quarantine {
            Some(Category::Pup)
        } else {
            None
        }
    }
    fn max_size_bytes(&self) -> u64 {
        self.max_size_mb.saturating_mul(1024 * 1024)
    }
    fn scan_options(&self, paths: Vec<PathBuf>, kind: &str, signatures: Option<String>) -> ScanOptions {
        let mut options = ScanOptions::new(paths, kind);
        options.max_size_bytes = self.max_size_bytes();
        options.quarantine_floor = self.quarantine_floor();
        options.exclude = self.exclude();
        options.threads = system::worker_threads(self.performance);
        options.background = self.performance.background();
        options.signatures = signatures;
        options.trust_signed = self.trust_signed;
        options.archives = self.scan_archives;
        options
    }
}

/// Where the Gemini key comes from.
enum KeySource {
    Saved(String),
    Environment(String),
    None,
}

impl Settings {
    /// The saved key, else `GEMINI_API_KEY`. A saved key that cannot be
    /// decrypted (copied from another account or PC) is an error, not absent.
    fn gemini_key(&self) -> Result<KeySource, String> {
        if let Some(stored) = &self.ai_key_protected {
            return system::unprotect_secret(stored)
                .map(KeySource::Saved)
                .map_err(|e| format!("the saved API key could not be decrypted ({e:#}); enter it again"));
        }
        Ok(match std::env::var("GEMINI_API_KEY") {
            Ok(key) if !key.trim().is_empty() => KeySource::Environment(key),
            _ => KeySource::None,
        })
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}

enum WorkerMsg {
    Progress { path: String, files: i64, bytes: i64 },
    Detection(FileReport),
    Done(Result<ScanReport, String>),
}

struct ScanJob {
    rx: Receiver<WorkerMsg>,
    /// Events for this scan are passed on here.
    tx: Sender<WorkerMsg>,
    /// The service's job number, once it replied.
    job: Option<u64>,
    cancelling: bool,
    started: Instant,
    targets: String,
    kind: String,
    threads: usize,
    current: String,
    files: i64,
    bytes: i64,
}

/// An update the service is running, as its events report it.
struct UpdateJob {
    step: String,
}

enum WatchMsg {
    Started { watching: usize, failed: Vec<(PathBuf, String)>, programs: bool },
    FolderLost { folder: PathBuf, reason: String },
    FolderRestored(PathBuf),
    FolderRescan(PathBuf),
    /// `repeat`: a program already detected that was started again.
    Detection { report: FileReport, processes: Vec<ProcessHit>, repeat: bool },
    Scanned { origin: Origin, files: i64, threats: usize },
    Restarting { error: String, retry_in: Duration },
    RiskyFile { path: PathBuf, risk: RiskyFile, origin: Option<DownloadOrigin> },
    RiskyChecked { path: PathBuf, outcome: RiskyOutcome },
    ProgramWatch { events: bool, reason: Option<String> },
    SideLoad(SideLoadHit),
    Command(CommandHit),
    DriveAdded { root: PathBuf, files: usize },
    Error(String),
}

#[derive(Clone, Copy, PartialEq)]
enum ActivityKind {
    Threat,
    /// A program or script landed.
    Risky,
    Info,
    Problem,
}

struct Activity {
    time: String,
    kind: ActivityKind,
    text: String,
    detail: String,
    /// The file concerned, offered for AI inspection.
    path: Option<PathBuf>,
}

/// The protection service, as last checked.
#[derive(Clone)]
enum ServiceView {
    NotInstalled,
    /// Installed but not running (stopped, starting, stopping).
    Down(&'static str),
    Running { version: String, user: String, admin: bool },
    /// Running by Windows' account, but not answering on its pipe.
    Unreachable(String),
}

/// How often the service is checked.
const SERVICE_CHECK_EVERY: Duration = Duration::from_secs(10);

#[derive(Default)]
struct WatchState {
    running: bool,
    watching: usize,
    failed: Vec<(PathBuf, String)>,
    /// Programs are scanned as they start.
    programs: bool,
    /// Programs are seen through Windows' process events, not by reading
    /// the process list twice a second.
    program_events: bool,
    files_checked: i64,
    programs_checked: i64,
    /// Times protection recovered from a failure this session.
    restarts: usize,
    threats: usize,
    since: Option<String>,
}

struct ResultRow {
    report: FileReport,
    selected: bool,
}

struct Finished {
    scan_id: i64,
    elapsed: Duration,
    files: i64,
    bytes: i64,
    infected: usize,
    quarantined: i64,
    errors: i64,
    threads: usize,
    cancelled: bool,
}

struct Toast {
    text: String,
    ok: bool,
    shown: Instant,
}

struct ScanDetails {
    detections: Vec<DetectionRow>,
    errors: Vec<ScanErrorRow>,
}

/// The AI inspection page: one file at a time.
#[derive(Default)]
struct InspectState {
    target: Option<PathBuf>,
    preparing: Option<Receiver<Result<Evidence, String>>>,
    evidence: Option<Result<Evidence, String>>,
    running: Option<(Receiver<Result<AiReport, String>>, Instant)>,
    report: Option<Result<AiReport, String>>,
}

#[derive(Clone, Copy, PartialEq)]
enum HistoryFilter {
    All,
    Manual,
    Watch,
}

struct App {
    page: Page,
    data_dir: PathBuf,
    settings: Settings,
    saved_settings: Settings,
    signatures: Result<(usize, usize), String>,
    /// Compiled once (seconds with thousands of rules) and shared by scans
    /// and the watcher.
    engine: Option<Arc<Engine>>,
    engine_rx: Option<Receiver<Result<Arc<Engine>, String>>>,
    job: Option<ScanJob>,
    /// Scan events that arrived before the service said which job is ours.
    early_scan_events: Vec<(u64, WorkerMsg)>,
    results: Vec<ResultRow>,
    finished: Option<Finished>,
    quarantine: Vec<QuarantineRow>,
    scans: Vec<ScanRow>,
    months: Vec<MonthRow>,
    pending_delete: Option<String>,
    toast: Option<Toast>,
    manifest: Manifest,
    updating: Option<UpdateJob>,
    // Real-time protection (in the service)
    watch: WatchState,
    activity: VecDeque<Activity>,
    // Protection service
    link: link::Link,
    /// Which notifications the event connection shows.
    notify_prefs: Arc<link::NotifyPrefs>,
    /// Connected to the service; why not, when not.
    connected: bool,
    service_lost: Option<String>,
    /// The service's data folder (signatures, web rules), once connected.
    service_dir: Option<PathBuf>,
    /// The protection settings as the service last reported them.
    service_settings: Option<ProtectionSettings>,
    /// A change waiting for Windows' administrator prompt: what it is.
    approval: Option<String>,
    service: Option<ServiceView>,
    service_rx: Option<Receiver<ServiceView>>,
    service_checked: Option<Instant>,
    // History
    history_filter: HistoryFilter,
    expanded: HashMap<i64, ScanDetails>,
    // Desktop
    tray: Option<desktop::Tray>,
    quitting: Arc<AtomicBool>,
    hidden_notice_shown: bool,
    autostart: bool,
    /// Setup starts the tray agent for every user (installed per machine).
    machine_autostart: bool,
    /// Whether notifications carry the app's own name, or why not.
    notification_identity: Result<(), String>,
    // Windows security and privacy checks
    security: Option<Vec<Check>>,
    privacy: Option<Vec<Check>>,
    posture_rx: Option<Receiver<(Vec<Check>, Vec<Check>)>>,
    posture_checked: Option<String>,
    /// An administrator fix waiting for the user's confirmation, one running,
    /// the last one applied (checked when the settings are re-read) and a
    /// note about its outcome.
    pending_fix: Option<posture::Fix>,
    /// The fix being run, kept on screen until it finishes.
    running_fix: Option<posture::Fix>,
    fix_rx: Option<Receiver<(posture::Fix, Result<system::Elevated, String>)>>,
    applied_fix: Option<posture::Fix>,
    fix_note: Option<String>,
    // Web protection
    web: web_page::WebState,
    // AI inspection
    inspect: InspectState,
    // Settings page
    settings_tab: SettingsTab,
    key_input: String,
    key_visible: bool,
    /// The abuse.ch Auth-Key being typed, and whether one is saved.
    abuse_key_input: String,
    abuse_key_saved: bool,
    ai_models: Vec<String>,
    ai_models_rx: Option<Receiver<Result<Vec<String>, String>>>,
    audit: audit_page::AuditState,
    logo: brand::Logo,
    /// The dot-matrix scan stage, and which scan it is showing.
    scan_fx: dots::ScanStage,
    scan_run: u64,
    hero_fx: dots::Hero,
    /// The background before an appearance change, and when it changed.
    theme_fade: Option<(egui::Color32, f64)>,
}

/// Writes the notification icon and registers the app's notification name
/// and Start-menu shortcut, so toasts pop up as Phalanx.
fn register_notifications(data_dir: &Path) -> Result<(), String> {
    // Windows caches icons by path, so each icon version gets its own file
    // name; older versions are removed.
    let png = write_versioned(data_dir, "notification-icon", "png", widgets::ICON_PNG)?;
    let ico = write_versioned(data_dir, "app-icon", "ico", widgets::ICON_ICO)?;
    let exe = std::env::current_exe().map_err(|e| format!("finding this program: {e}"))?;
    // When the icon is built into the program, the shortcut uses it: the taskbar
    // takes its icon from the shortcut and caches it by path, and the program's
    // path does not change when the icon does.
    let shortcut_icon = if cfg!(embedded_icon) { exe.clone() } else { ico };
    system::register_notification_identity(&png, &shortcut_icon, &exe).map_err(|e| format!("{e:#}"))
}

/// Writes `bytes` to `<stem>-<content hash>.<ext>` in `dir` and deletes
/// other versions; returns the path.
fn write_versioned(dir: &Path, stem: &str, ext: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    // FNV-1a: only needs to change when the bytes do.
    let hash = bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3));
    let path = dir.join(format!("{stem}-{:08x}.{ext}", hash as u32));
    if std::fs::read(&path).ok().as_deref() != Some(bytes) {
        std::fs::write(&path, bytes).map_err(|e| format!("writing {}: {e}", path.display()))?;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let old_version = name.starts_with(&format!("{stem}-")) && name.ends_with(&format!(".{ext}")) && entry.path() != path;
            // The unversioned file earlier releases wrote.
            if old_version || name == format!("{stem}.{ext}") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    Ok(path)
}

/// The program a start-up command names (quoted first, as written by
/// [`autostart_command`]).
fn autostart_program(command: &str) -> &str {
    match command.trim().strip_prefix('"') {
        Some(rest) => rest.split('"').next().unwrap_or(""),
        None => command.split_whitespace().next().unwrap_or(""),
    }
}

/// Whether the program a start-up command names is still there.
fn autostart_program_exists(command: &str) -> bool {
    let program = autostart_program(command);
    !program.is_empty() && Path::new(program).is_file()
}

/// Whether a start-up command runs this very program.
fn autostart_names_this_program(command: &str) -> bool {
    let program = autostart_program(command);
    let same = |a: &Path, b: &Path| a.canonicalize().ok().zip(b.canonicalize().ok()).is_some_and(|(a, b)| a == b);
    std::env::current_exe().is_ok_and(|exe| same(Path::new(program), &exe))
}

/// The command the "start with Windows" entry should run.
fn autostart_command() -> String {
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
    format!("\"{exe}\" {BACKGROUND_FLAG}")
}

impl App {
    fn new(ctx: &egui::Context, scan_paths: Vec<PathBuf>) -> Self {
        widgets::apply_style(ctx);
        let data_dir = scan::default_data_dir();
        let _ = std::fs::create_dir_all(&data_dir);
        let (settings, settings_warning) = Settings::load(&data_dir);
        let manifest = Manifest::default();
        let (web, web_warning) = web_page::WebState::new(&data_dir);
        let quitting = Arc::new(AtomicBool::new(false));
        let tray = desktop::Tray::create(ctx, quitting.clone()).ok();
        let notification_identity = register_notifications(&data_dir);
        // An existing "start with Windows" entry whose program no longer
        // exists (the app was renamed or moved) is pointed at this program.
        // An entry that still names a working Phalanx is the user's choice and
        // is left alone, even when another copy (a test build) starts.
        // An entry for this program without `--background` (written by hand or
        // by an old version) would open the window at every sign-in.
        // Installed for the whole PC, setup's entry starts the tray agent for
        // everyone: a per-user entry (from 0.4) would only repeat it.
        let machine_autostart = system::machine_autostart_command().is_some();
        if machine_autostart {
            if system::autostart_enabled() {
                let _ = system::set_autostart(false, "");
            }
        } else if let Some(command) = system::autostart_command()
            && (!autostart_program_exists(&command) || (autostart_names_this_program(&command) && !command.contains(BACKGROUND_FLAG)))
        {
            let _ = system::set_autostart(true, &autostart_command());
        }
        let abuse_key_saved = update::auth_key_saved(&update::signature_dir(&data_dir));
        let notify_prefs = Arc::new(link::NotifyPrefs::default());
        notify_prefs.set(settings.notifications, settings.risky_file_alerts);
        let link = link::Link::start(ctx, Arc::clone(&notify_prefs));
        let mut app = Self {
            page: Page::Dashboard,
            data_dir,
            saved_settings: settings.clone(),
            settings,
            signatures: Ok((0, 0)),
            engine: None,
            engine_rx: None,
            job: None,
            early_scan_events: Vec::new(),
            results: Vec::new(),
            finished: None,
            quarantine: Vec::new(),
            scans: Vec::new(),
            months: Vec::new(),
            pending_delete: None,
            toast: None,
            manifest,
            updating: None,
            watch: WatchState::default(),
            activity: VecDeque::new(),
            link,
            notify_prefs,
            connected: false,
            service_lost: None,
            service_dir: None,
            service_settings: None,
            approval: None,
            service: None,
            service_rx: None,
            service_checked: None,
            history_filter: HistoryFilter::All,
            expanded: HashMap::new(),
            tray,
            quitting,
            hidden_notice_shown: false,
            autostart: system::autostart_enabled(),
            machine_autostart,
            notification_identity,
            security: None,
            privacy: None,
            posture_rx: None,
            posture_checked: None,
            pending_fix: None,
            running_fix: None,
            fix_rx: None,
            applied_fix: None,
            fix_note: None,
            web,
            inspect: InspectState::default(),
            settings_tab: SettingsTab::General,
            key_input: String::new(),
            key_visible: false,
            abuse_key_input: String::new(),
            abuse_key_saved,
            ai_models: Vec::new(),
            ai_models_rx: None,
            audit: audit_page::AuditState::default(),
            logo: brand::Logo::new(ctx),
            scan_fx: dots::ScanStage::default(),
            scan_run: 0,
            hero_fx: dots::Hero::default(),
            theme_fade: None,
        };
        // Signatures and history come once the service answers.
        app.refresh_posture(ctx);
        if let Some(warning) = settings_warning.or(web_warning) {
            app.notify(warning, false);
        }
        if !scan_paths.is_empty() {
            app.start_scan(ctx, scan_paths, "custom");
        }
        app
    }

    fn notify(&mut self, text: impl Into<String>, ok: bool) {
        self.toast = Some(Toast {
            text: text.into(),
            ok,
            shown: Instant::now(),
        });
    }

    /// Reads the quarantine, the scans and the monthly totals from the service.
    fn refresh(&mut self) {
        if !self.connected {
            return;
        }
        self.link.run(
            || -> Result<_, String> {
                use link::read;
                let q: Vec<QuarantineRow> = read(Request::Quarantine { include_restored: false })?;
                let s: Vec<ScanRow> = read(Request::RecentScans { limit: 300, kind: None })?;
                let m: Vec<MonthRow> = read(Request::MonthlySummary)?;
                Ok((q, s, m))
            },
            |app, loaded| match loaded {
                Ok((q, s, m)) => {
                    app.quarantine = q;
                    app.scans = s;
                    app.months = m;
                    app.expanded.clear();
                }
                Err(e) => app.notify(format!("Could not read history: {e}"), false),
            },
        );
    }

    /// Where signatures and web rules are read from: the service's folder
    /// once connected (users may read it), else the app's own.
    fn signatures_home(&self) -> &Path {
        self.service_dir.as_deref().unwrap_or(&self.data_dir)
    }

    fn signatures_label(&self) -> Option<String> {
        self.manifest.last_success().map(str::to_string)
    }

    // ---------- signatures / engine ----------

    /// Rebuilds the engine on a background thread; the UI stays responsive.
    fn reload_signatures(&mut self, ctx: &egui::Context) {
        let (tx, rx) = mpsc::channel();
        // A read-only engine for AI Inspect and the Stealer check; scans run
        // in the service.
        let config = self.settings.engine_config(self.signatures_home());
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = Engine::new(&config).map(Arc::new).map_err(|e| format!("{e:#}"));
            let _ = tx.send(result);
            ctx.request_repaint();
        });
        self.engine_rx = Some(rx);
    }

    fn set_engine(&mut self, result: Result<Arc<Engine>, String>) {
        self.engine_rx = None;
        match result {
            Ok(engine) => {
                self.signatures = Ok((engine.rule_count(), engine.hash_count()));
                self.engine = Some(engine);
            }
            Err(e) => {
                self.signatures = Err(e.clone());
                self.engine = None;
                self.notify(format!("Signatures failed to load: {e}"), false);
            }
        }
    }

    fn poll_engine(&mut self) {
        let Some(rx) = &self.engine_rx else { return };
        let Ok(result) = rx.try_recv() else { return };
        self.set_engine(result);
    }

    /// Asks the service to download new signatures; progress and the result
    /// arrive as events.
    fn start_update(&mut self) {
        if self.updating.is_some() {
            return;
        }
        self.updating = Some(UpdateJob { step: "Starting…".into() });
        self.link.run(
            || link::call(Request::UpdateSignatures { force: false }).and_then(|r| r.into_result::<serde_json::Value>().map_err(|e| e.to_string())),
            |app, started| {
                if let Err(e) = started {
                    // Already running (the service's schedule): follow that one.
                    if !e.contains("already running") {
                        app.updating = None;
                        app.notify(format!("Could not start the update: {e}"), false);
                    }
                }
            },
        );
    }

    /// An update ended (one asked for here, or the service's own schedule).
    fn update_finished(&mut self, ctx: &egui::Context, installed: bool, failed: Vec<String>, error: Option<String>) {
        let asked = self.updating.take().is_some();
        self.manifest = update::load_manifest(&update::signature_dir(self.signatures_home()));
        if installed {
            self.reload_signatures(ctx);
            let home = self.signatures_home().to_path_buf();
            self.web.reload_rules(&home);
        }
        match (error, installed, failed.is_empty()) {
            (Some(e), _, _) if asked => self.notify(format!("Signature update failed: {e}"), false),
            (None, _, false) if asked => self.notify(format!("Some sources failed and kept their previous version: {}", failed.join(", ")), false),
            (None, true, _) => self.notify("Signatures updated", true),
            (None, false, _) if asked => self.notify("Signatures are already up to date", true),
            _ => {}
        }
    }

    // ---------- manual scans ----------

    fn start_scan(&mut self, ctx: &egui::Context, paths: Vec<PathBuf>, kind: &str) {
        if self.job.is_some() || paths.is_empty() {
            return;
        }
        if !self.connected {
            return self.notify("The protection service is not running, so nothing can be scanned", false);
        }
        let _ = ctx;
        let options = self.settings.scan_options(paths, kind, self.signatures_label());
        let (tx, rx) = mpsc::channel();
        let targets = options
            .paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let threads = options.threads;
        let (paths, kind_name) = (options.paths.clone(), kind.to_string());
        self.link.run(
            move || link::call(Request::Scan { paths, kind: kind_name }).and_then(|r| r.into_result::<serde_json::Value>().map_err(|e| e.to_string())),
            |app, started| match started {
                Ok(reply) => {
                    let id = reply["job"].as_u64();
                    if let Some(job) = &mut app.job {
                        job.job = id;
                        // Events that came before the reply.
                        let early = std::mem::take(&mut app.early_scan_events);
                        for (event_job, msg) in early {
                            if Some(event_job) == id {
                                let _ = job.tx.send(msg);
                            }
                        }
                    }
                }
                Err(e) => {
                    if let Some(job) = &app.job {
                        let _ = job.tx.send(WorkerMsg::Done(Err(e)));
                    }
                }
            },
        );

        self.results.clear();
        self.finished = None;
        self.scan_run += 1;
        self.job = Some(ScanJob {
            rx,
            tx,
            job: None,
            cancelling: false,
            started: Instant::now(),
            targets,
            kind: kind.to_string(),
            threads,
            current: String::new(),
            files: 0,
            bytes: 0,
        });
        self.page = Page::Scan;
    }

    fn poll_job(&mut self) {
        let Some(job) = &mut self.job else { return };
        let mut done = None;
        while let Ok(msg) = job.rx.try_recv() {
            match msg {
                WorkerMsg::Progress { path, files, bytes } => {
                    job.current = path;
                    job.files = files;
                    job.bytes = bytes;
                }
                WorkerMsg::Detection(report) => self.results.push(ResultRow {
                    selected: report.action == "reported",
                    report,
                }),
                WorkerMsg::Done(result) => done = Some(result),
            }
        }
        let Some(result) = done else { return };
        self.job = None;
        match result {
            Ok(report) => {
                let infected = report.infected.len();
                self.finished = Some(Finished {
                    scan_id: report.scan_id,
                    elapsed: Duration::from_millis(report.elapsed_ms),
                    files: report.stats.files_scanned,
                    bytes: report.stats.bytes_scanned,
                    infected,
                    quarantined: report.stats.quarantined,
                    errors: report.stats.errors,
                    threads: report.threads,
                    cancelled: report.cancelled,
                });
                let text = match (report.cancelled, infected) {
                    (true, _) => "Scan cancelled".to_string(),
                    (false, 0) => "Scan complete: no threats found".to_string(),
                    (false, n) => format!("Scan complete: {n} threat(s) found"),
                };
                self.notify(text, infected == 0);
            }
            Err(e) => self.notify(format!("Scan failed: {e}"), false),
        }
        self.refresh();
    }

    /// Asks the scan for each selected detection to be quarantined (the
    /// service moves only what its scan detected, unchanged since).
    fn quarantine_selected(&mut self) {
        let Some(scan) = self.finished.as_ref().map(|f| f.scan_id) else { return };
        let paths: Vec<String> = self.results.iter().filter(|r| r.selected).map(|r| r.report.path.clone()).collect();
        for row in self.results.iter_mut().filter(|r| r.selected) {
            row.selected = false;
        }
        self.link.run(
            move || {
                paths
                    .into_iter()
                    .map(|path| {
                        let result = link::call(Request::QuarantineDetection { scan, path: PathBuf::from(&path) })
                            .and_then(|r| r.into_result::<String>().map_err(|e| e.to_string()));
                        (path, result)
                    })
                    .collect::<Vec<_>>()
            },
            |app, outcomes| {
                let (mut ok, mut failed) = (0, 0);
                for (path, result) in outcomes {
                    let Some(row) = app.results.iter_mut().find(|r| r.report.path == path) else { continue };
                    match result {
                        Ok(id) => {
                            row.report.action = format!("quarantined ({id})");
                            ok += 1;
                        }
                        Err(e) => {
                            row.report.action = format!("quarantine failed: {e}");
                            failed += 1;
                        }
                    }
                }
                let failed_text = if failed > 0 { format!(", {failed} failed") } else { String::new() };
                app.notify(format!("Quarantined {ok} file(s){failed_text}"), failed == 0);
                app.refresh();
            },
        );
    }

    /// Restores or deletes a quarantined file: the service asks for an
    /// administrator, so Windows' prompt appears.
    fn quarantine_action(&mut self, id: &str, restore: bool) {
        let (request, args) = if restore {
            (Request::Restore { item: id.to_string(), force: false }, format!("service restore {id}"))
        } else {
            (Request::DeleteQuarantined { item: id.to_string() }, format!("service delete-quarantined {id}"))
        };
        self.approval = Some(if restore { "Restoring needs an administrator's approval".into() } else { "Deleting needs an administrator's approval".into() });
        self.link.run(
            move || link::with_approval::<serde_json::Value>(request, &args, || Ok(serde_json::Value::Null)),
            move |app, outcome| {
                app.approval = None;
                match outcome {
                    link::Approval::Done(_) => app.notify(if restore { "Restored" } else { "Deleted permanently" }, true),
                    link::Approval::Declined => app.notify("Not changed: Windows' administrator prompt was declined", false),
                    link::Approval::Failed(e) => app.notify(e, false),
                }
                app.refresh();
            },
        );
    }

    /// Asks the service to stop the running scan.
    fn cancel_scan(&mut self) {
        let Some(job) = &mut self.job else { return };
        let Some(id) = job.job else { return };
        job.cancelling = true;
        self.link.run(move || link::call(Request::CancelScan { job: id }), |_, _| {});
    }

    /// Gives the service the Auth-Key saved for this user (`Some`), or
    /// removes the service's: an administrator's approval either way.
    fn set_service_auth_key(&mut self, save: Option<()>) {
        let saving = save.is_some();
        let (request, args) = if saving {
            let key = update::auth_key(&update::signature_dir(&self.data_dir)).ok().flatten();
            (Request::SetAuthKey { key }, "service auth-key --from-app")
        } else {
            (Request::SetAuthKey { key: None }, "service auth-key --remove")
        };
        self.approval = Some("Changing the Auth-Key needs an administrator's approval".into());
        self.link.run(
            move || link::with_approval::<serde_json::Value>(request, args, || Ok(serde_json::Value::Null)),
            move |app, outcome| {
                app.approval = None;
                match outcome {
                    link::Approval::Done(_) => {
                        app.abuse_key_saved = saving;
                        if saving {
                            app.notify("Auth-Key saved; downloading the abuse.ch feeds", true);
                            app.start_update();
                        } else {
                            app.notify("Auth-Key removed; the abuse.ch feeds will be skipped", true);
                        }
                    }
                    link::Approval::Declined => app.notify("Not changed: Windows' administrator prompt was declined", false),
                    link::Approval::Failed(e) => app.notify(format!("Could not change the Auth-Key: {e}"), false),
                }
            },
        );
    }

    // ---------- Windows checks ----------

    /// Re-reads Windows security and privacy settings in the background.
    fn refresh_posture(&mut self, ctx: &egui::Context) {
        if self.posture_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            system::enter_background_mode();
            let defender = posture::read_defender_state();
            let checks = (posture::security_checks(&defender), posture::privacy_checks());
            let _ = tx.send(checks);
            ctx.request_repaint();
        });
        self.posture_rx = Some(rx);
    }

    fn poll_posture(&mut self) {
        let Some(rx) = &self.posture_rx else { return };
        let Ok((security, privacy)) = rx.try_recv() else { return };
        self.posture_rx = None;
        // Did the fix just applied take effect? Windows can accept a command
        // without the setting changing (managed PCs, unsupported editions).
        if let Some(fix) = self.applied_fix.take() {
            let still_needed = security.iter().chain(&privacy).any(|c| c.fix == Some(fix));
            self.fix_note = still_needed.then(|| {
                if fix == posture::FIX_NETWORK_PROTECTION {
                    "Windows accepted the command, but Network protection still reads as off. It may not be available on this edition of Windows (it is documented for Pro and Enterprise). Phalanx's browser and DNS blocking still protect you.".to_string()
                } else if fix == posture::FIX_WEB_SEARCH {
                    "Windows accepted the command, but your account's setting has not changed. The Windows prompt was probably approved with another administrator account, so the policy went to that account instead. Run it from your own administrator account.".to_string()
                } else {
                    format!("Windows accepted `{}`, but the setting has not changed. Another policy or security product may control it.", fix.command)
                }
            });
        }
        self.security = Some(security);
        self.privacy = Some(privacy);
        self.posture_checked = Some(chrono::Local::now().format("%H:%M").to_string());
    }

    /// Runs a fix as administrator in the background, then re-reads the settings.
    fn apply_fix(&mut self, ctx: &egui::Context, fix: posture::Fix) {
        if self.fix_rx.is_some() {
            return;
        }
        self.fix_note = None;
        self.running_fix = Some(fix);
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = fix.apply().map_err(|e| format!("{e:#}"));
            let _ = tx.send((fix, result));
            ctx.request_repaint();
        });
        self.fix_rx = Some(rx);
    }

    fn poll_fix(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.fix_rx else { return };
        let Ok((fix, result)) = rx.try_recv() else { return };
        self.fix_rx = None;
        self.running_fix = None;
        match result {
            Ok(system::Elevated::Exited(0)) if fix == posture::OFFLINE_SCAN => {
                self.notify("Offline scan scheduled: Windows restarts shortly", true)
            }
            Ok(system::Elevated::Exited(0)) => {
                self.notify("Done. Checking the setting again…", true);
                self.applied_fix = Some(fix);
                self.refresh_posture(ctx);
            }
            Ok(system::Elevated::Exited(code)) => self.notify(format!("`{}` failed (exit code {code}); nothing was changed", fix.command), false),
            Ok(system::Elevated::Declined) => self.notify("Cancelled at the Windows prompt; nothing was changed", false),
            Err(e) => self.notify(e, false),
        }
    }

    fn open_link(&mut self, link: posture::Link) {
        self.open_link_in_profile(link, None);
    }

    /// Opens a link; a browser page opens in that browser profile.
    fn open_link_in_profile(&mut self, link: posture::Link, profile: Option<&str>) {
        if let Err(e) = link.open_in_profile(profile) {
            self.notify(format!("Could not open {}: {e}", if link.target.starts_with("start:") { "the browser" } else { "Windows settings" }), false);
        }
    }

    /// Flips a per-user Windows setting (no administrator rights), then
    /// re-reads the settings to show the result.
    fn apply_toggle(&mut self, ctx: &egui::Context, toggle: posture::Toggle, protective: bool) {
        match toggle.apply(protective) {
            Ok(()) => {
                let note = match toggle {
                    posture::Toggle::StartSuggestions | posture::Toggle::StartRecommendations | posture::Toggle::TrackLaunches => " (Start may update after you sign out and back in)",
                    _ => "",
                };
                self.notify(format!("Changed{note}. Checking the setting again…"), true);
            }
            Err(e) => self.notify(format!("Could not change the setting: {e:#}"), false),
        }
        self.refresh_posture(ctx);
    }

    // ---------- AI inspection ----------

    /// Examines `path` locally (signatures, type, origin, content) so the
    /// user can review what would be sent before sending it.
    fn inspect_file(&mut self, ctx: &egui::Context, path: PathBuf) {
        self.page = Page::Inspect;
        if self.inspect.running.is_some() {
            return self.notify("Wait for the current inspection to finish", false);
        }
        let (tx, rx) = mpsc::channel();
        let engine = self.engine.clone();
        let (max_kb, send_text) = (self.settings.ai_max_text_kb, self.settings.ai_send_text);
        let ctx = ctx.clone();
        let worker_path = path.clone();
        std::thread::spawn(move || {
            let result = ai::collect(&worker_path, engine.as_deref(), max_kb, send_text).map_err(|e| format!("{e:#}"));
            let _ = tx.send(result);
            ctx.request_repaint();
        });
        self.inspect = InspectState { target: Some(path), preparing: Some(rx), ..Default::default() };
    }

    fn run_inspection(&mut self, ctx: &egui::Context) {
        let Some(Ok(evidence)) = &self.inspect.evidence else { return };
        let key = match self.settings.gemini_key() {
            Ok(KeySource::Saved(k) | KeySource::Environment(k)) => k,
            Ok(KeySource::None) => return self.notify("Add a Gemini API key in Settings > AI inspection first", false),
            Err(e) => return self.notify(e, false),
        };
        let config = ai::GeminiConfig {
            api_key: key,
            model: self.settings.ai_model.trim().to_string(),
            timeout: Duration::from_secs(180),
        };
        let evidence = evidence.clone();
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = ai::inspect(&config, &evidence).map_err(|e| format!("{e:#}"));
            let _ = tx.send(result);
            ctx.request_repaint();
        });
        self.inspect.report = None;
        self.inspect.running = Some((rx, Instant::now()));
    }

    fn poll_inspect(&mut self) {
        if let Some(rx) = &self.inspect.preparing && let Ok(result) = rx.try_recv() {
            self.inspect.preparing = None;
            self.inspect.evidence = Some(result);
        }
        if let Some((rx, _)) = &self.inspect.running && let Ok(result) = rx.try_recv() {
            self.inspect.running = None;
            if let Ok(report) = &result {
                let file = self.inspect.target.as_deref().map(|p| widgets::file_name(&p.display().to_string())).unwrap_or_default();
                self.notify(format!("AI inspection of {file}: {}", report.assessment.verdict.label()), report.assessment.verdict == ai::Verdict::Safe);
            }
            self.inspect.report = Some(result);
        }
    }

    /// Quarantines the inspected file if it is unchanged since inspection.
    fn quarantine_inspected(&mut self) {
        let Some(Ok(evidence)) = &self.inspect.evidence else { return };
        let threat = match &evidence.local_findings {
            Some(f) if !f.is_empty() => f[0].threat.clone(),
            _ => match &self.inspect.report {
                Some(Ok(r)) => format!("AI.Gemini.{:?}", r.assessment.verdict),
                _ => "AI.Gemini.Reviewed".to_string(),
            },
        };
        let path = evidence.path.clone();
        // A name the command line cannot misread.
        let threat: String = threat.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')).collect();
        let args = format!("service quarantine \"{}\" --threat {threat}", path.display());
        let request = Request::QuarantineFile { path: path.clone(), threat };
        self.approval = Some("Quarantining a file no scan detected needs an administrator's approval".into());
        self.link.run(
            move || link::with_approval::<serde_json::Value>(request, &args, || Ok(serde_json::Value::Null)),
            move |app, outcome| {
                app.approval = None;
                match outcome {
                    link::Approval::Done(_) => {
                        app.notify(format!("Quarantined {}", path.display()), true);
                        app.inspect = InspectState::default();
                    }
                    link::Approval::Declined => app.notify("Not quarantined: Windows' administrator prompt was declined", false),
                    link::Approval::Failed(e) => app.notify(format!("Could not quarantine: {e}"), false),
                }
                app.refresh();
            },
        );
    }

    fn save_api_key(&mut self) {
        let key = self.key_input.trim().to_string();
        if key.is_empty() {
            return;
        }
        match system::protect_secret(&key) {
            Ok(stored) => {
                self.settings.ai_key_protected = Some(stored);
                self.key_input.clear();
                self.key_visible = false;
                self.notify("API key saved, encrypted for your Windows account", true);
            }
            Err(e) => self.notify(format!("Could not save the API key: {e:#}"), false),
        }
    }

    fn fetch_models(&mut self, ctx: &egui::Context) {
        let key = match self.settings.gemini_key() {
            Ok(KeySource::Saved(k) | KeySource::Environment(k)) => k,
            Ok(KeySource::None) => return self.notify("Save an API key first", false),
            Err(e) => return self.notify(e, false),
        };
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = ai::list_models(&key, Duration::from_secs(30)).map_err(|e| format!("{e:#}"));
            let _ = tx.send(result);
            ctx.request_repaint();
        });
        self.ai_models_rx = Some(rx);
    }

    fn poll_models(&mut self) {
        let Some(rx) = &self.ai_models_rx else { return };
        let Ok(result) = rx.try_recv() else { return };
        self.ai_models_rx = None;
        match result {
            Ok(models) if models.is_empty() => self.notify("This key has no Gemini models available", false),
            Ok(models) => {
                self.notify(format!("Connected: {} models available", models.len()), true);
                self.ai_models = models;
            }
            Err(e) => self.notify(e, false),
        }
    }

    // ---------- protection service ----------

    /// Picks up the last check and starts the next one every
    /// [`SERVICE_CHECK_EVERY`], on a thread: a hung service never blocks
    /// the window.
    fn poll_service(&mut self, ctx: &egui::Context) {
        if let Some(view) = self.service_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.service = Some(view);
            self.service_rx = None;
        }
        let due = self.service_checked.is_none_or(|t| t.elapsed() >= SERVICE_CHECK_EVERY);
        if self.service_rx.is_some() || !due {
            return;
        }
        self.service_checked = Some(Instant::now());
        let (tx, rx) = mpsc::channel();
        self.service_rx = Some(rx);
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(check_service());
            repaint.request_repaint();
        });
    }

    // ---------- real-time protection ----------

    // ---------- the service link ----------

    /// Handles what the service link delivered since the last frame.
    fn poll_link(&mut self, ctx: &egui::Context) {
        self.notify_prefs.set(self.settings.notifications, self.settings.risky_file_alerts);
        let messages: Vec<link::LinkMsg> = self.link.rx.try_iter().collect();
        for msg in messages {
            match msg {
                link::LinkMsg::Connected => self.connect_service(ctx),
                link::LinkMsg::Lost(reason) => {
                    let was_connected = std::mem::replace(&mut self.connected, false);
                    self.service_lost = Some(reason);
                    self.watch.running = false;
                    self.updating = None;
                    self.web.service_lost();
                    if let Some(job) = &self.job {
                        let _ = job.tx.send(WorkerMsg::Done(Err("the protection service stopped".into())));
                    }
                    // Without the service, AI Inspect and the Stealer check use
                    // the app's own signatures.
                    if !was_connected && self.engine.is_none() && self.engine_rx.is_none() {
                        self.reload_signatures(ctx);
                    }
                }
                link::LinkMsg::Event(event) => self.on_event(ctx, *event),
                link::LinkMsg::Done(apply) => apply(self),
            }
        }
    }

    /// The service answered: read its settings and state.
    fn connect_service(&mut self, ctx: &egui::Context) {
        let ctx = ctx.clone();
        self.link.run(
            || -> Result<_, String> {
                let mut client = ipc::Client::connect().map_err(|e| ipc::describe(&e))?;
                let status = client.status().map_err(|e| e.to_string())?;
                let settings: ProtectionSettings = client.call(Request::GetSettings).and_then(|r| r.into_result()).map_err(|e| e.to_string())?;
                let web: threat_scanner::web::WebConfig = client.call(Request::GetWebSettings).and_then(|r| r.into_result()).map_err(|e| e.to_string())?;
                let protection: ipc::ProtectionStatus = client.call(Request::ProtectionStatus).and_then(|r| r.into_result()).map_err(|e| e.to_string())?;
                let web_status: threat_scanner::service::web::WebStatus = client.call(Request::WebStatus).and_then(|r| r.into_result()).map_err(|e| e.to_string())?;
                Ok((status, settings, web, protection, web_status))
            },
            move |app, read| match read {
                Ok((status, settings, web, protection, web_status)) => {
                    app.connected = true;
                    app.service_lost = None;
                    let moved = app.service_dir.as_ref() != Some(&status.data_dir);
                    app.service_dir = Some(status.data_dir);
                    app.apply_service_settings(settings);
                    let home = app.signatures_home().to_path_buf();
                    app.web.use_service_config(web, &home);
                    app.web.service_status = Some(web_status);
                    app.abuse_key_saved = update::auth_key_saved(&update::signature_dir(&home));
                    // The "started" event may have come first.
                    if protection.watching {
                        app.watch.running = true;
                        app.watch.watching = protection.folders;
                        app.watch.programs = protection.programs;
                        app.watch.program_events = protection.program_events;
                    }
                    app.manifest = update::load_manifest(&update::signature_dir(app.signatures_home()));
                    if moved || app.engine.is_none() {
                        app.reload_signatures(&ctx);
                    }
                    app.refresh();
                }
                Err(e) => app.service_lost = Some(e),
            },
        );
    }

    /// The service's protection settings: shown on the pages, and the
    /// baseline changes are compared with.
    fn apply_service_settings(&mut self, settings: ProtectionSettings) {
        copy_protection(&mut self.settings, &settings);
        copy_protection(&mut self.saved_settings, &settings);
        self.service_settings = Some(settings);
    }

    /// Sends protection settings changed on a page to the service; a change
    /// that weakens protection runs `phalanx-cli` elevated (Windows' prompt).
    /// Declined or failed, the pages show the service's settings again.
    fn send_settings(&mut self) {
        let Some(service) = &self.service_settings else { return };
        let wanted = protection_from(&self.settings, service);
        if wanted == *service || self.approval.is_some() {
            return;
        }
        self.service_settings = Some(wanted.clone());
        let args = format!("service set-settings --json {}", link::hex_json(&wanted));
        self.link.run(
            move || {
                let read = || link::call(Request::GetSettings).and_then(|r| r.into_result::<ProtectionSettings>().map_err(|e| e.to_string()));
                match link::with_approval::<ProtectionSettings>(Request::SetSettings { settings: wanted }, &args, read) {
                    link::Approval::Done(settings) => (Ok(settings), None),
                    link::Approval::Declined => (read(), Some("Not changed: Windows' administrator prompt was declined".to_string())),
                    link::Approval::Failed(e) => (read(), Some(format!("Could not change the settings: {e}"))),
                }
            },
            |app, (settings, note)| {
                app.approval = None;
                if let Ok(settings) = settings {
                    app.apply_service_settings(settings);
                }
                if let Some(note) = note {
                    app.notify(note, false);
                }
            },
        );
        self.approval = Some("Changes that weaken protection need an administrator's approval".into());
    }

    /// One event from the service.
    fn on_event(&mut self, ctx: &egui::Context, event: Event) {
        match event {
            Event::EngineReady { rules, hashes } => self.signatures = Ok((rules, hashes)),
            Event::EngineFailed { error } => self.log_activity(ActivityKind::Problem, "The service could not load its signatures", error),
            Event::ProtectionOff => {
                self.watch.running = false;
                self.log_activity(ActivityKind::Info, "Real-time protection is off", "");
            }
            Event::SettingsChanged { settings } => self.apply_service_settings(settings),
            Event::WebSettingsChanged { settings } => {
                let home = self.signatures_home().to_path_buf();
                self.web.use_service_config(settings, &home);
            }
            Event::WebApplied { status } => self.web.service_status = Some(status),
            Event::Web { event } => self.web.add_event(event),
            Event::UpdateProgress { step } => match &mut self.updating {
                Some(job) => job.step = step,
                None => self.updating = Some(UpdateJob { step }),
            },
            Event::UpdateFinished { installed, failed, .. } => self.update_finished(ctx, installed, failed, None),
            Event::UpdateFailed { error } => self.update_finished(ctx, false, Vec::new(), Some(error)),
            Event::ScanProgress { job, files, bytes, path, .. } => self.scan_event(job, WorkerMsg::Progress { path: path.display().to_string(), files, bytes }),
            Event::ScanDetection { job, report } => self.scan_event(job, WorkerMsg::Detection(report)),
            Event::ScanFinished { job, report } => self.scan_event(job, WorkerMsg::Done(Ok(report))),
            Event::ScanFailed { job, error } => self.scan_event(job, WorkerMsg::Done(Err(error))),
            other => {
                if let Some(msg) = watch_msg(other) {
                    self.on_watch(vec![msg]);
                }
            }
        }
    }

    /// Passes a scan event to the scan this app started, holding it until
    /// the service has said which job that is.
    fn scan_event(&mut self, job: u64, msg: WorkerMsg) {
        match &self.job {
            Some(ours) if ours.job == Some(job) => {
                let _ = ours.tx.send(msg);
            }
            Some(ours) if ours.job.is_none() => self.early_scan_events.push((job, msg)),
            _ => {}
        }
    }

    fn log_activity(&mut self, kind: ActivityKind, text: impl Into<String>, detail: impl Into<String>) {
        self.log_file_activity(kind, text, detail, None);
    }

    fn log_file_activity(&mut self, kind: ActivityKind, text: impl Into<String>, detail: impl Into<String>, path: Option<PathBuf>) {
        self.activity.push_front(Activity {
            time: chrono::Local::now().format("%H:%M:%S").to_string(),
            kind,
            text: text.into(),
            detail: detail.into(),
            path,
        });
        self.activity.truncate(MAX_ACTIVITY);
    }

    fn on_watch(&mut self, messages: Vec<WatchMsg>) {
        let mut changed_history = false;
        for msg in messages {
            match msg {
                WatchMsg::Started { watching, failed, programs } => {
                    self.watch.watching = watching;
                    self.watch.programs = programs;
                    let mut text = format!("Watching {watching} folder(s)");
                    if programs {
                        text.push_str(" and programs as they start");
                    }
                    for (folder, e) in &failed {
                        self.log_activity(
                            ActivityKind::Problem,
                            format!("Cannot watch {}", folder.display()),
                            format!("{e}. Retrying every few seconds."),
                        );
                    }
                    self.watch.failed = failed;
                    self.log_activity(ActivityKind::Info, text, "");
                    self.watch.running = true;
                    self.watch.since = Some(chrono::Local::now().format("%H:%M").to_string());
                }
                WatchMsg::FolderLost { folder, reason } => {
                    self.watch.watching = self.watch.watching.saturating_sub(1);
                    self.log_activity(
                        ActivityKind::Problem,
                        format!("Stopped watching {}", folder.display()),
                        format!("{reason}. It is watched again as soon as it is back."),
                    );
                    self.watch.failed.retain(|(f, _)| f != &folder);
                    self.watch.failed.push((folder, reason));
                }
                WatchMsg::FolderRestored(folder) => {
                    self.watch.watching += 1;
                    self.watch.failed.retain(|(f, _)| f != &folder);
                    self.log_activity(ActivityKind::Info, format!("Watching {} again", folder.display()), "Checking files that changed meanwhile.");
                }
                WatchMsg::FolderRescan(folder) => self.log_activity(
                    ActivityKind::Info,
                    format!("Many changes at once in {}", folder.display()),
                    "Windows dropped some change notices, so recent files are being rescanned.",
                ),
                WatchMsg::Detection { report, processes, repeat } => {
                    if !repeat {
                        self.watch.threats += 1;
                        changed_history = true;
                    }
                    let worst = report.worst().clone();
                    let mut detail = format!("{} · {}", report.path, report.action);
                    for p in &processes {
                        match &p.stopped {
                            Some(Ok(())) => detail.push_str(&format!(" · stopped {} (pid {})", p.name, p.pid)),
                            Some(Err(e)) => detail.push_str(&format!(" · could not stop {} (pid {}): {e}", p.name, p.pid)),
                            None => detail.push_str(&format!(" · {} (pid {}) left running", p.name, p.pid)),
                        }
                    }
                    let text = if repeat {
                        format!("{} started again and was stopped: {}", widgets::file_name(&report.path), worst.threat)
                    } else {
                        format!("{} in {}", worst.threat, widgets::file_name(&report.path))
                    };
                    let quarantined = report.action.contains("quarantined (");
                    self.log_file_activity(ActivityKind::Threat, text, detail, (!quarantined).then(|| PathBuf::from(&report.path)));
                    if !repeat {
                        let source = if processes.is_empty() { "in a watched folder" } else { "in a running program" };
                        self.notify(format!("Threat detected {source}: {}", worst.threat), false);
                    }
                }
                WatchMsg::Scanned { origin, files, threats } => {
                    match origin {
                        Origin::Folder => {
                            self.watch.files_checked += files;
                            if files > 0 {
                                let text = match threats {
                                    0 => format!("Checked {files} new file(s): clean"),
                                    n => format!("Checked {files} new file(s): {n} threat(s)"),
                                };
                                self.log_activity(ActivityKind::Info, text, "");
                            }
                        }
                        // Programs are checked constantly; only threats are logged.
                        Origin::Program => self.watch.programs_checked += files,
                    }
                    changed_history |= threats > 0 || origin == Origin::Folder;
                }
                WatchMsg::RiskyFile { path, risk, origin } => {
                    let file = widgets::file_name(&path.display().to_string());
                    let mut detail = path.display().to_string();
                    if let Some(host) = origin.as_ref().and_then(|o| o.host()) {
                        detail.push_str(&format!(" · from {host}"));
                    }
                    if let Some(d) = &risk.disguise {
                        detail.push_str(&format!(" · disguised: {d}"));
                    }
                    let what = if risk.disguise.is_some() { format!("Disguised {}", risk.kind.label()) } else { format!("New {}", risk.kind.label()) };
                    self.log_file_activity(ActivityKind::Risky, format!("{what}: {file}"), detail, Some(path));
                }
                WatchMsg::RiskyChecked { path, outcome } => {
                    let file = widgets::file_name(&path.display().to_string());
                    match outcome {
                        RiskyOutcome::NoThreatFound => {
                            self.log_file_activity(ActivityKind::Info, format!("{file}: no known threats found"), "", Some(path))
                        }
                        RiskyOutcome::NotScanned(reason) => {
                            self.log_file_activity(ActivityKind::Problem, format!("{file} was not scanned"), reason, Some(path))
                        }
                        RiskyOutcome::Threat(_) => {}
                    }
                }
                WatchMsg::ProgramWatch { events, reason } => {
                    self.watch.program_events = events;
                    if !events && let Some(reason) = reason {
                        self.log_activity(
                            ActivityKind::Info,
                            "Programs are checked twice a second".to_string(),
                            format!("Windows' process events are not available: {reason}. Very short-lived programs can finish unseen."),
                        );
                    }
                }
                WatchMsg::SideLoad(hit) => {
                    let mut detail = vec![format!("program: {} (pid {})", hit.image.display(), hit.pid)];
                    if let Some(signer) = &hit.signer {
                        detail.push(format!("signed by {signer}"));
                    }
                    detail.push("Malware often hides in a trusted program this way. Report-only: nothing was stopped; the DLL is being scanned".into());
                    self.log_activity(ActivityKind::Threat, format!("Possible DLL side-loading: {}", hit.headline()), detail.join(" · "));
                    changed_history = true;
                }
                WatchMsg::Command(hit) => {
                    let kind = if hit.confidence() == Confidence::High { ActivityKind::Threat } else { ActivityKind::Risky };
                    let mut detail: Vec<String> = hit.matches.iter().map(|m| m.reason.clone()).collect();
                    detail.push(format!("command: {}", hit.command));
                    if let Some(script) = &hit.script {
                        detail.push(format!("decoded: {script}"));
                    }
                    match (hit.pid, &hit.parent) {
                        (Some(pid), Some(parent)) => detail.push(format!("pid {pid}, started by {parent}")),
                        (Some(pid), None) => detail.push(format!("pid {pid}")),
                        _ => {}
                    }
                    detail.push("Report-only: nothing was stopped".into());
                    if !hit.in_history() {
                        detail.push("Medium confidence, so not kept in History".into());
                    }
                    let text = match hit.source {
                        CommandSource::Program => format!("Suspicious command in {}: {}", hit.program, hit.headline()),
                        CommandSource::RunBox => format!("Suspicious command in the Run box: {}", hit.headline()),
                    };
                    self.log_activity(kind, text, detail.join(" · "));
                    changed_history |= hit.in_history();
                }
                WatchMsg::DriveAdded { root, files } => self.log_activity(
                    ActivityKind::Info,
                    format!("New drive {}", root.display()),
                    format!("A disk image was opened or a drive was connected; checking {files} file(s) near its top."),
                ),
                WatchMsg::Restarting { error, retry_in } => {
                    self.watch.restarts += 1;
                    self.log_activity(
                        ActivityKind::Problem,
                        format!("Protection hit a problem; restarting in {} s", retry_in.as_secs().max(1)),
                        error,
                    );
                }
                WatchMsg::Error(e) => self.log_activity(ActivityKind::Problem, "Protection problem", e),
            }
        }
        if changed_history {
            self.refresh();
        }
    }

    /// Saves settings when they change; the checkpoint at most once a minute.
    fn persist_settings(&mut self) {
        self.send_settings();
        if self.settings != self.saved_settings {
            match self.settings.save(&self.data_dir) {
                Ok(()) => self.saved_settings = self.settings.clone(),
                Err(e) => {
                    self.saved_settings = self.settings.clone(); // don't retry every frame
                    self.notify(format!("Could not save settings: {e}"), false);
                }
            }
        }
    }

    fn set_autostart(&mut self, enabled: bool) {
        match system::set_autostart(enabled, &autostart_command()) {
            Ok(()) => {
                self.autostart = system::autostart_enabled();
                self.notify(
                    if enabled { "Phalanx will start in the tray when you sign in" } else { "Start with Windows turned off" },
                    true,
                );
            }
            Err(e) => self.notify(format!("Could not change start-up setting: {e:#}"), false),
        }
    }
}

/// The protection settings the pages show, from the service's.
fn copy_protection(s: &mut Settings, p: &ProtectionSettings) {
    s.watch_enabled = p.watch_enabled;
    s.watch_folders = p.watch_folders.clone();
    s.program_protection = p.program_protection;
    s.stop_running_threats = p.stop_running_threats;
    s.side_loading = p.side_loading;
    s.scan_new_drives = p.scan_new_drives;
    s.defer_when_fullscreen = p.defer_when_fullscreen;
    s.heuristics = p.heuristics;
    s.trust_signed = p.trust_signed;
    s.scan_archives = p.scan_archives;
    s.max_size_mb = p.max_size_mb;
    s.exclusions = p.exclusions.clone();
    s.performance = p.performance;
    s.auto_quarantine = p.auto_quarantine;
    s.quarantine_suspicious = p.quarantine_suspicious;
    s.auto_update = p.auto_update;
    s.auto_update_hours = p.auto_update_hours;
}

/// The protection settings as the pages have them; what the pages do not
/// show is kept as the service has it.
fn protection_from(s: &Settings, service: &ProtectionSettings) -> ProtectionSettings {
    ProtectionSettings {
        watch_enabled: s.watch_enabled,
        watch_folders: s.watch_folders.clone(),
        program_protection: s.program_protection,
        stop_running_threats: s.stop_running_threats,
        side_loading: s.side_loading,
        scan_new_drives: s.scan_new_drives,
        defer_when_fullscreen: s.defer_when_fullscreen,
        heuristics: s.heuristics,
        trust_signed: s.trust_signed,
        scan_archives: s.scan_archives,
        max_size_mb: s.max_size_mb,
        exclusions: s.exclusions.clone(),
        performance: s.performance,
        auto_quarantine: s.auto_quarantine,
        quarantine_suspicious: s.quarantine_suspicious,
        auto_update: s.auto_update,
        auto_update_hours: s.auto_update_hours,
        ..service.clone()
    }
}

/// The activity-log entry for a real-time protection event.
fn watch_msg(event: Event) -> Option<WatchMsg> {
    Some(match event {
        Event::ProtectionStarted { watching, failed, programs } => WatchMsg::Started { watching, failed, programs },
        Event::FolderLost { folder, reason } => WatchMsg::FolderLost { folder, reason },
        Event::FolderRestored { folder } => WatchMsg::FolderRestored(folder),
        Event::FolderRescan { folder } => WatchMsg::FolderRescan(folder),
        Event::Detection { report, processes, repeat } => WatchMsg::Detection { report, processes, repeat },
        Event::Scanned { origin, files, threats } => WatchMsg::Scanned { origin, files, threats },
        Event::RiskyFile { path, risk, origin } => WatchMsg::RiskyFile { path, risk, origin },
        Event::RiskyChecked { path, outcome } => WatchMsg::RiskyChecked { path, outcome },
        Event::ProgramWatch { events, reason } => WatchMsg::ProgramWatch { events, reason },
        Event::SideLoad { hit } => WatchMsg::SideLoad(hit),
        Event::Command { hit } => WatchMsg::Command(hit),
        Event::DriveAdded { root, files } => WatchMsg::DriveAdded { root, files },
        Event::Restarting { error, retry_in_secs } => WatchMsg::Restarting { error, retry_in: Duration::from_secs(retry_in_secs) },
        Event::ProtectionError { message } => WatchMsg::Error(message),
        _ => return None,
    })
}

/// Shows a Windows notification for an event, as the settings say. Called
/// by the event connection's thread, so it works with the window hidden.
fn notify_event(event: &Event, prefs: &link::NotifyPrefs) {
    match event {
        Event::Detection { report, processes, repeat } if prefs.threats() => {
            let (title, body) = threat_notification(report, processes, *repeat);
            system::notify(&title, &body);
        }
        Event::RiskyFile { path, risk, origin } if prefs.risky() => {
            let (title, body) = risky_notification(path, risk, origin.as_ref());
            system::notify(&title, &body);
        }
        Event::RiskyChecked { path, outcome } if prefs.risky() => {
            let file = widgets::file_name(&path.display().to_string());
            match outcome {
                RiskyOutcome::NoThreatFound => system::notify(
                    &format!("No known threats in {file}"),
                    "Nothing known was found, which does not prove it is safe. Open Phalanx to have the AI inspect it.",
                ),
                RiskyOutcome::NotScanned(reason) => system::notify(&format!("{file} was not scanned"), reason),
                // Reported by the detection notification.
                RiskyOutcome::Threat(_) => {}
            }
        }
        Event::Web { event } if prefs.threats() && event.action == "blocked" => system::notify(
            &format!("Blocked a dangerous site: {}", event.target),
            &format!("{} ({}). Phalanx stopped this connection.", event.threat, event.category),
        ),
        // Medium-confidence matches are common in admin tools; only logged.
        Event::SideLoad { hit } if prefs.threats() => {
            let title = format!("Possible DLL side-loading in {}", hit.program);
            let body = format!("{}. Phalanx only reported it and is scanning the DLL. If you did not just install or update this program, check it.", capitalize_first(&hit.headline()));
            system::notify(&title, &body);
        }
        Event::Command { hit } if prefs.threats() && hit.confidence() == Confidence::High => {
            let (title, body) = command_notification(hit);
            system::notify(&title, &body);
        }
        _ => {}
    }
}

/// Title and body of the "threat detected" notification; `repeat` for a
/// program already detected that was started again.
fn threat_notification(report: &FileReport, processes: &[ProcessHit], repeat: bool) -> (String, String) {
    let worst = report.worst();
    let file = widgets::file_name(&report.path);
    let stopped = processes.iter().filter(|p| matches!(p.stopped, Some(Ok(())))).count();
    let failed = processes.iter().filter(|p| matches!(p.stopped, Some(Err(_)))).count();
    let title = if repeat {
        format!("Stopped {file} again: {}", worst.threat)
    } else if processes.is_empty() {
        format!("Threat detected: {}", worst.threat)
    } else {
        format!("Threat running: {}", worst.threat)
    };
    let mut body = format!("{file} ({}). ", worst.category);
    if stopped > 0 {
        body.push_str("The program was stopped. ");
    }
    if failed > 0 {
        body.push_str("It could not be stopped; close it yourself. ");
    } else if !processes.is_empty() && stopped == 0 {
        body.push_str("It is still running. ");
    }
    body.push_str(if report.action.contains("quarantined (") { "It was quarantined." } else { "Open Phalanx to review it." });
    (title, body)
}

/// The protection service's state, from Windows and from the service itself.
fn check_service() -> ServiceView {
    #[cfg(windows)]
    {
        use threat_scanner::service::manage::{self, State};
        match manage::state() {
            Ok(State::NotInstalled) => ServiceView::NotInstalled,
            Ok(State::Running) => match threat_scanner::ipc::status_within(Duration::from_secs(3)) {
                Ok(status) => ServiceView::Running { version: status.version, user: status.caller.user, admin: status.caller.admin },
                Err(e) => ServiceView::Unreachable(e),
            },
            Ok(state) => ServiceView::Down(state.label()),
            Err(e) => ServiceView::Unreachable(format!("{e:#}")),
        }
    }
    #[cfg(not(windows))]
    ServiceView::NotInstalled
}

/// Title and body of the "suspicious command" notification.
fn command_notification(hit: &CommandHit) -> (String, String) {
    let title = match hit.source {
        CommandSource::Program => format!("Suspicious command in {}", hit.program),
        CommandSource::RunBox => "Suspicious command in the Run box".to_string(),
    };
    let mut body = format!("{}.", capitalize_first(hit.headline()));
    body.push_str(" Phalanx only reported it. If a web page told you to run this, close it and do not run it again.");
    (title, body)
}

fn capitalize_first(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default()
}

/// Title and body of the "a program just landed" notification.
fn risky_notification(path: &Path, risk: &RiskyFile, origin: Option<&DownloadOrigin>) -> (String, String) {
    let file = widgets::file_name(&path.display().to_string());
    let folder = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "a watched folder".into());
    let title = match risk.disguise {
        Some(_) => format!("Disguised {} in {folder}: {file}", risk.kind.label()),
        None => format!("New {} in {folder}: {file}", risk.kind.label()),
    };
    let mut body = String::new();
    if let Some(d) = &risk.disguise {
        body.push_str(&format!("Careful: {d}. "));
    }
    if let Some(host) = origin.and_then(DownloadOrigin::host) {
        body.push_str(&format!("Downloaded from {host}. "));
    }
    body.push_str("It is being scanned now. Don't open it unless you trust where it came from.");
    (title, body)
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = self.settings.save(&self.data_dir);
    }
}

impl eframe::App for App {
    /// Runs before every frame and also while the window is hidden in the
    /// tray (whenever a background thread requests a repaint).
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_link(ctx);
        self.poll_engine();
        self.poll_job();
        self.poll_service(ctx);
        self.poll_posture();
        self.poll_fix(ctx);
        self.poll_audit(ctx);
        self.poll_hardening();
        self.poll_dns_change();
        self.poll_inspect();
        self.poll_models();
        self.poll_web(ctx);
        self.persist_settings();
        let busy = self.inspect.preparing.is_some()
            || self.inspect.running.is_some()
            || self.posture_rx.is_some()
            || self.fix_rx.is_some()
            || self.audit_busy()
            || self.ai_models_rx.is_some()
            || self.approval.is_some()
            || self.web_busy();
        if self.job.is_some() || self.updating.is_some() || self.engine_rx.is_some() || busy {
            ctx.request_repaint_after(Duration::from_millis(200));
        } else if self.page == Page::Web {
            // Picks up exceptions added from the browser and new blocks.
            ctx.request_repaint_after(Duration::from_secs(3));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let preference = self.settings.appearance.preference();
        if ctx.options(|o| o.theme_preference) != preference {
            ctx.set_theme(preference);
        }
        if let Some(previous) = widgets::sync_theme(&ctx) {
            self.theme_fade = Some((previous, ctx.input(|i| i.time)));
        }
        // Closing hides to the tray (protection keeps running) unless quitting.
        if ctx.input(|i| i.viewport().close_requested())
            && !self.quitting.load(Ordering::Relaxed)
            && self.settings.close_to_tray
            && self.tray.is_some()
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            if !self.hidden_notice_shown {
                self.hidden_notice_shown = true;
                system::notify(
                    "Phalanx is still running",
                    "It keeps protecting your folders from the tray. Right-click the tray icon to quit.",
                );
            }
        }

        // Drop files or folders anywhere on the window to scan them.
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .filter(|p| !p.as_os_str().is_empty())
                .collect()
        });
        // On the AI page, a single dropped file is inspected instead.
        if self.page == Page::Inspect && dropped.len() == 1 && dropped[0].is_file() {
            let path = dropped.into_iter().next().unwrap_or_default();
            self.inspect_file(&ctx, path);
        } else if !dropped.is_empty() {
            self.start_scan(&ctx, dropped, "custom");
        }

        self.draw(ui, &ctx);
    }
}
