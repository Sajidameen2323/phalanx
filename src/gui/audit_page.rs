//! The stealer check page: the browser data watch (a switch, and what it
//! caught, with a way to stop or allow each), then the persistence audit,
//! listing what it found, worst first, with ways to look closer (open the
//! folder, scan the file, ask the AI). Nothing is removed from here.

use super::*;
use eframe::egui::{Align, Color32, Layout, RichText, Ui};
use threat_scanner::audit::{self, AuditItem, AuditReport, DefenderExclusions, Severity, Signature};
use threat_scanner::rtp::process;
use widgets::*;

/// Browser data alerts kept on the page, newest first.
const MAX_BROWSER_HITS: usize = 20;

#[derive(Default)]
pub(super) struct AuditState {
    report: Option<AuditReport>,
    running: Option<(Receiver<AuditReport>, Instant)>,
    exclusions_rx: Option<Receiver<Result<Option<DefenderExclusions>, String>>>,
    exclusions: Option<DefenderExclusions>,
    show_fine: bool,
    show_leftovers: bool,
    /// What the browser data watch caught since the app started.
    browser_hits: Vec<BrowserHit>,
}

impl AuditState {
    pub(super) fn add_browser_hit(&mut self, hit: BrowserHit) {
        self.browser_hits.insert(0, hit);
        self.browser_hits.truncate(MAX_BROWSER_HITS);
    }
}

enum WatchAction {
    Stop(usize),
    Allow(PathBuf),
    Disallow(usize),
    OpenFolder(PathBuf),
    Scan(PathBuf),
    History,
}

fn severity_color(s: Severity) -> Color32 {
    match s {
        Severity::High => theme().red,
        Severity::Medium => theme().amber,
        Severity::Low => theme().yellow,
        Severity::Info => theme().green,
    }
}

impl App {
    /// Whether the browser data watch was told to let this program (or DLL)
    /// read browser data.
    pub(super) fn allowed_to_read(&self, path: &Path) -> bool {
        self.settings.browser_guard_allowed.iter().any(|a| a.as_os_str().eq_ignore_ascii_case(path.as_os_str()))
    }

    fn audit_dir(&self) -> PathBuf {
        self.data_dir.join("audit")
    }

    fn start_audit(&mut self, ctx: &egui::Context) {
        if self.audit.running.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let engine = self.engine.clone();
        let exclusions = self.audit.exclusions.clone();
        let dir = self.audit_dir();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            system::enter_background_mode();
            let report = audit::run(engine.as_deref(), exclusions.as_ref(), &dir);
            let _ = tx.send(report);
            ctx.request_repaint();
        });
        self.audit.running = Some((rx, Instant::now()));
    }

    /// Reads Defender's exclusions as administrator, then re-runs the check.
    fn check_exclusions(&mut self, ctx: &egui::Context) {
        if self.audit.exclusions_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let dir = self.audit_dir();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(audit::read_defender_exclusions(&dir).map_err(|e| format!("{e:#}")));
            ctx.request_repaint();
        });
        self.audit.exclusions_rx = Some(rx);
    }

    pub(super) fn poll_audit(&mut self, ctx: &egui::Context) {
        if let Some((rx, _)) = &self.audit.running && let Ok(report) = rx.try_recv() {
            self.audit.running = None;
            let high = report.count(Severity::High);
            self.notify(
                match high {
                    0 => "Stealer check finished: nothing high-risk found".to_string(),
                    n => format!("Stealer check: {n} high-risk item(s) found"),
                },
                high == 0,
            );
            self.audit.report = Some(report);
        }
        if let Some(rx) = &self.audit.exclusions_rx && let Ok(result) = rx.try_recv() {
            self.audit.exclusions_rx = None;
            match result {
                Ok(Some(ex)) => {
                    let n = ex.paths.len() + ex.processes.len() + ex.extensions.len();
                    self.notify(format!("Defender has {n} exclusion(s); checking them now"), true);
                    self.audit.exclusions = Some(ex);
                    self.start_audit(ctx);
                }
                Ok(None) => self.notify("Cancelled at the Windows prompt; exclusions were not read", false),
                Err(e) => self.notify(format!("Could not read Defender's exclusions: {e}"), false),
            }
        }
    }

    pub(super) fn audit_busy(&self) -> bool {
        self.audit.running.is_some() || self.audit.exclusions_rx.is_some()
    }

    /// The browser data watch: its switches, whether it runs, and what it
    /// caught.
    fn browser_watch(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        let mut action = None;
        card(ui, |ui| {
            group_title(ui, "Browser data watch", "");
            setting_toggle(
                ui,
                &mut self.settings.browser_guard,
                "Watch who opens browser passwords and cookies",
                "Catches programs other than your browser opening its saved passwords, sign-in cookies or the key that unlocks them (and Discord's, Telegram's and crypto wallets' sign-in data), reading a browser's memory, or loading unsigned code into it, and browsers started in secret for remote control or with a planted extension. Stolen sign-in cookies let a thief read your email, password-reset codes included, without your password or second factor. It watches every file opened on the PC, so it uses some processor time and a few MB of memory.",
            );
            row_divider(ui);
            ui.add_enabled_ui(self.settings.browser_guard, |ui| {
                setting_toggle(
                    ui,
                    &mut self.settings.browser_guard_stop,
                    "Stop what it catches",
                    "End a script host, Windows tool or unsigned program the moment it opens browser data, and a hidden browser under remote control. Signed programs, such as backup tools and password managers, are only reported.",
                );
            });
            ui.add_space(6.0);
            let (color, status) = if !self.settings.browser_guard {
                (theme().muted, "Off".to_string())
            } else if !self.settings.watch_enabled {
                (theme().amber, "Not running: turn on real-time protection on the Protection page".to_string())
            } else {
                match &self.watch.browser_guard {
                    Some(Ok(())) => (theme().green, "Watching browser data".to_string()),
                    Some(Err(why)) => (theme().amber, format!("Not running: {why}")),
                    None => (theme().muted, "Starting…".to_string()),
                }
            };
            ui.horizontal_wrapped(|ui| {
                status_dot(ui, color, 4.0);
                ui.label(RichText::new(status).color(theme().text));
            });
            if !self.settings.browser_guard_allowed.is_empty() {
                ui.add_space(6.0);
                small(ui, "Allowed to read browser data:");
                for (i, program) in self.settings.browser_guard_allowed.iter().enumerate() {
                    ui.horizontal(|ui| {
                        truncated(ui, program.display().to_string(), theme().text, 12.5);
                        if small_button(ui, "Remove").clicked() {
                            action = Some(WatchAction::Disallow(i));
                        }
                    });
                }
            }
        });

        // Alerts about programs allowed since are no longer shown.
        let mut hidden = 0;
        for (i, hit) in self.audit.browser_hits.iter().enumerate() {
            if self.allowed_to_read(subject(hit)) {
                hidden += 1;
                continue;
            }
            ui.add_space(8.0);
            browser_hit_card(ui, i, hit, &mut action);
        }
        if hidden > 0 {
            ui.add_space(6.0);
            small(ui, format!("{hidden} alert(s) about programs you allowed are hidden."));
        }
        if !self.audit.browser_hits.is_empty() {
            ui.add_space(6.0);
            if small_button(ui, "All browser data alerts in History").clicked() {
                action = Some(WatchAction::History);
            }
        }

        match action {
            Some(WatchAction::Stop(i)) => {
                let Some(hit) = self.audit.browser_hits.get_mut(i) else { return };
                let Some(id) = hit.process() else { return };
                let result = process::terminate(&id);
                hit.stopped = Some(result.clone());
                let program = hit.program.clone();
                match result {
                    Ok(()) => self.notify(format!("Stopped {program}"), true),
                    Err(e) => self.notify(format!("Could not stop {program}: {e}"), false),
                }
            }
            Some(WatchAction::Allow(program)) => self.settings.browser_guard_allowed.push(program),
            Some(WatchAction::Disallow(i)) => {
                self.settings.browser_guard_allowed.remove(i);
            }
            Some(WatchAction::OpenFolder(path)) => {
                let _ = std::process::Command::new("explorer").arg(format!("/select,{}", path.display())).spawn();
            }
            Some(WatchAction::Scan(path)) => self.start_scan(ctx, vec![path], "custom"),
            Some(WatchAction::History) => {
                self.history.filter = HistoryFilter::BrowserData;
                self.page = Page::History;
                self.load_history(Load::New);
            }
            None => {}
        }
    }

    pub(super) fn audit_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Stealer check");

        self.browser_watch(ui, ctx);
        ui.add_space(14.0);

        let (mut run, mut exclusions) = (false, false);
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                if let Some((_, started)) = &self.audit.running {
                    spinner(ui);
                    muted(ui, format!("Checking… {}", fmt_duration(started.elapsed())));
                } else {
                    run = primary_button(ui, if self.audit.report.is_some() { "Check again" } else { "Run stealer check" }).clicked();
                }
                let reading = self.audit.exclusions_rx.is_some();
                let label = if self.audit.exclusions.is_some() { "Re-read Defender exclusions…" } else { "Also check Defender exclusions…" };
                exclusions = ui.add_enabled_ui(!reading && self.audit.running.is_none(), |ui| secondary_button(ui, label).clicked()).inner;
            });
            small(ui, "Defender exclusions can only be read as administrator; Windows asks first. Malware often adds exclusions so Defender stops scanning its files.");
            if let Some(report) = &self.audit.report {
                ui.add_space(6.0);
                facts(
                    ui,
                    &[
                        ("High", report.count(Severity::High).to_string()),
                        ("To review", report.count(Severity::Medium).to_string()),
                        ("Low", report.count(Severity::Low).to_string()),
                        ("Fine", report.items.iter().filter(|i| i.severity == Severity::Info && !i.leftover).count().to_string()),
                        ("Leftovers", report.items.iter().filter(|i| i.leftover).count().to_string()),
                        ("Took", fmt_duration(Duration::from_millis(report.elapsed_ms as u64))),
                    ],
                );
                for e in &report.errors {
                    small(ui, format!("Not checked: {e}"));
                }
            }
        });
        if run {
            self.start_audit(ctx);
        }
        if exclusions {
            self.check_exclusions(ctx);
        }
        ui.add_space(14.0);

        let Some(report) = &self.audit.report else {
            card(ui, |ui| {
                section_title(ui, "After an account takeover");
                muted(ui, "Run this check, a full scan and a Microsoft Defender Offline scan (Protection page). Then sign out of every session and change passwords from a device you trust. Check browser extensions on the Web protection page.");
            });
            return;
        };

        let mut action: Option<ItemAction> = None;
        let flagged: Vec<&AuditItem> = report.items.iter().filter(|i| i.severity > Severity::Info).collect();
        if flagged.is_empty() {
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    status_dot(ui, theme().green, 6.0);
                    ui.label(RichText::new("Nothing suspicious found").size(17.0).strong().color(theme().text));
                });
                muted(ui, "No start-up entry, task, service, browser shortcut, policy, proxy or hosts entry looks wrong. That lowers the odds that a stealer is still active, but cannot rule out one that has not been seen before.");
            });
            ui.add_space(14.0);
        } else if report.count(Severity::High) > 0 {
            notice(ui, theme().red, "High-risk items: do not just delete them. Note where they are, run a Microsoft Defender Offline scan, and if Phalanx or Defender confirms malware, resetting Windows is the safest cleanup. Change passwords from another device.");
            ui.add_space(10.0);
        }
        for it in &flagged {
            item_card(ui, it, self.settings.ai_enabled, &mut action);
            ui.add_space(8.0);
        }

        let leftovers: Vec<&AuditItem> = report.items.iter().filter(|i| i.leftover && i.severity == Severity::Info).collect();
        if !leftovers.is_empty() {
            ui.add_space(6.0);
            let n = leftovers.len();
            let label = if self.audit.show_leftovers { format!("Hide {n} leftover(s) from uninstalled programs") } else { format!("Show {n} leftover(s) from uninstalled programs") };
            if small_button(ui, &label).clicked() {
                self.audit.show_leftovers = !self.audit.show_leftovers;
            }
            if self.audit.show_leftovers {
                small(ui, "Tasks and services whose program was removed from Program Files. They fail harmlessly at start-up, and only an administrator could put a program in their place. Delete them in Task Scheduler or with `sc delete <name>` as administrator if you like.");
                ui.add_space(6.0);
                for it in &leftovers {
                    item_card(ui, it, self.settings.ai_enabled, &mut action);
                    ui.add_space(8.0);
                }
            }
        }

        let fine = report.items.len() - flagged.len() - leftovers.len();
        if fine > 0 {
            ui.add_space(6.0);
            let label = if self.audit.show_fine { format!("Hide {fine} entries with nothing wrong") } else { format!("Show {fine} entries with nothing wrong") };
            if small_button(ui, &label).clicked() {
                self.audit.show_fine = !self.audit.show_fine;
            }
            if self.audit.show_fine {
                ui.add_space(6.0);
                for it in report.items.iter().filter(|i| i.severity == Severity::Info && !i.leftover) {
                    item_card(ui, it, self.settings.ai_enabled, &mut action);
                    ui.add_space(8.0);
                }
            }
        }

        match action {
            Some(ItemAction::OpenFolder(path)) => {
                let _ = std::process::Command::new("explorer").arg(format!("/select,{}", path.display())).spawn();
            }
            Some(ItemAction::Scan(path)) => self.start_scan(ctx, vec![path], "custom"),
            Some(ItemAction::Inspect(path)) => self.inspect_file(ctx, path),
            None => {}
        }
    }
}

fn browser_hit_card(ui: &mut Ui, index: usize, hit: &BrowserHit, action: &mut Option<WatchAction>) {
    let (label, color) = match hit.level {
        BrowserLevel::High => ("HIGH", theme().red),
        BrowserLevel::Review => ("REVIEW", theme().amber),
    };
    let stopped = matches!(hit.stopped, Some(Ok(())));
    card(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            badge(ui, label, color);
            if stopped {
                badge(ui, "STOPPED", theme().green);
            }
            ui.add(egui::Label::new(RichText::new(capitalize_first(&hit.headline())).strong().color(theme().text)).wrap());
        });
        ui.with_layout(Layout::top_down(Align::Min), |ui| {
            ui.add(egui::Label::new(RichText::new(format!("• Why: {}", hit.reason)).size(13.0).color(color.lerp_to_gamma(theme().text, 0.35))).wrap());
            if !hit.image.as_os_str().is_empty() {
                truncated(ui, format!("Program: {} (pid {})", hit.image.display(), hit.pid), theme().muted, 12.0);
            }
            if let Some(signer) = &hit.signer {
                small(ui, format!("Signed by {signer}"));
            }
            if let Some(c) = &hit.controller {
                truncated(ui, format!("Started by: {} (pid {})", c.image.display(), c.pid), theme().muted, 12.0);
            }
            for file in hit.files.iter().take(4) {
                truncated(ui, format!("Opened: {}", file.display()), theme().muted, 12.0);
            }
            if hit.files.len() > 4 {
                small(ui, format!("and {} more file(s)", hit.files.len() - 4));
            }
            if !hit.switches.is_empty() {
                truncated(ui, format!("Started with: {}", hit.switches.join(" ")), theme().muted, 12.0);
            }
            if !hit.connections.is_empty() {
                truncated(ui, format!("Connected to: {}", hit.connections.join(", ")), theme().muted, 12.0);
            }
            small(ui, capitalize_first(&hit.action()));
            if hit.level == BrowserLevel::High {
                small(ui, "It may have copied the data before it was caught. From a device you trust, sign out of other sessions (Google, Microsoft and your email all offer this) and change those passwords.");
            }
        });
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            if !stopped && hit.process().is_some() && small_button(ui, "Stop it").clicked() {
                *action = Some(WatchAction::Stop(index));
            }
            let file = subject(hit).is_file().then(|| subject(hit).to_path_buf());
            if let Some(path) = &file {
                let label = if hit.kind == BrowserGuardKind::Injected { "Allow this DLL" } else { "Allow this program" };
                if hit.kind != BrowserGuardKind::RemoteControl && small_button(ui, label).clicked() {
                    *action = Some(WatchAction::Allow(path.clone()));
                }
                if small_button(ui, "Open folder").clicked() {
                    *action = Some(WatchAction::OpenFolder(path.clone()));
                }
                if small_button(ui, "Scan file").clicked() {
                    *action = Some(WatchAction::Scan(path.clone()));
                }
            }
        });
    });
}

/// The file an alert is about: the DLL loaded into a browser, otherwise
/// the program.
fn subject(hit: &BrowserHit) -> &Path {
    match (hit.kind, hit.files.first()) {
        (BrowserGuardKind::Injected, Some(dll)) => dll,
        _ => &hit.image,
    }
}

enum ItemAction {
    OpenFolder(PathBuf),
    Scan(PathBuf),
    Inspect(PathBuf),
}

fn item_card(ui: &mut Ui, it: &AuditItem, ai_enabled: bool, action: &mut Option<ItemAction>) {
    let color = severity_color(it.severity);
    card(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            badge(ui, it.severity.label(), color);
            badge(ui, it.kind.label(), theme().muted);
            ui.add(egui::Label::new(RichText::new(&it.title).strong().color(theme().text)).wrap());
        });
        ui.with_layout(Layout::top_down(Align::Min), |ui| {
            for r in &it.reasons {
                ui.add(egui::Label::new(RichText::new(format!("• {r}")).size(13.0).color(if it.severity > Severity::Info { color.lerp_to_gamma(theme().text, 0.35) } else { theme().muted })).wrap());
            }
            truncated(ui, format!("Where: {}", it.location), theme().muted, 12.0);
            if !it.command.is_empty() {
                ui.add(egui::Label::new(RichText::new(&it.command).monospace().size(11.5).color(theme().muted)).truncate());
            }
            match &it.signature {
                Signature::Signed { signer } => small(ui, format!("Signed by {signer}")),
                Signature::Unsigned => small(ui, "Not digitally signed"),
                Signature::Invalid { status } => small(ui, format!("Signature does not verify: {status}")),
                Signature::Unknown => {}
            }
            for d in &it.detections {
                ui.horizontal_wrapped(|ui| {
                    badge(ui, &d.category.as_str().to_uppercase(), category_color(d.category));
                    ui.label(RichText::new(&d.threat).color(theme().text));
                });
            }
        });
        if let Some(path) = it.program.as_ref().filter(|p| p.is_file()) {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                if small_button(ui, "Open folder").clicked() {
                    *action = Some(ItemAction::OpenFolder(path.clone()));
                }
                if small_button(ui, "Scan file").clicked() {
                    *action = Some(ItemAction::Scan(path.clone()));
                }
                if ai_enabled && small_button(ui, "Inspect with AI").clicked() {
                    *action = Some(ItemAction::Inspect(path.clone()));
                }
            });
        }
    });
}
