//! The stealer check page: runs the persistence audit and lists what it
//! found, worst first, with ways to look closer (open the folder, scan the
//! file, ask the AI). Nothing is removed from here.

use super::*;
use eframe::egui::{Align, Color32, Layout, RichText, Ui};
use threat_scanner::audit::{self, AuditItem, AuditReport, DefenderExclusions, Severity, Signature};
use widgets::*;

#[derive(Default)]
pub(super) struct AuditState {
    report: Option<AuditReport>,
    running: Option<(Receiver<AuditReport>, Instant)>,
    exclusions_rx: Option<Receiver<Result<Option<DefenderExclusions>, String>>>,
    exclusions: Option<DefenderExclusions>,
    show_fine: bool,
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

    pub(super) fn audit_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Stealer check");

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
                        ("Fine", report.count(Severity::Info).to_string()),
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

        let fine = report.items.len() - flagged.len();
        if fine > 0 {
            ui.add_space(6.0);
            let label = if self.audit.show_fine { format!("Hide {fine} entries with nothing wrong") } else { format!("Show {fine} entries with nothing wrong") };
            if small_button(ui, &label).clicked() {
                self.audit.show_fine = !self.audit.show_fine;
            }
            if self.audit.show_fine {
                ui.add_space(6.0);
                for it in report.items.iter().filter(|i| i.severity == Severity::Info) {
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
