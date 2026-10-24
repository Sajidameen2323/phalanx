//! Page layouts. Everything here adapts to the window width: tiles reflow,
//! button rows wrap, long text truncates, and the sidebar narrows.

use super::*;
use dots::{HeroScan, Outcome, StageMode};
use eframe::egui::{pos2, vec2, Align, Align2, FontId, Id, Layout, Margin, Rect, RichText, Sense, Stroke, Ui, Vec2};
use threat_scanner::posture::Status;
use widgets::*;

/// How long a toast stays up, in seconds.
const TOAST_LIFE: f32 = 6.0;

impl App {
    pub(super) fn draw(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        let window = ui.max_rect();
        let narrow = ui.available_width() < 820.0;
        egui::Panel::left("nav")
            .exact_size(if narrow { 176.0 } else { 222.0 })
            .resizable(false)
            .frame(egui::Frame::new().fill(theme().sidebar).inner_margin(Margin::symmetric(12, 16)))
            .show(ui, |ui| self.sidebar(ui));

        // A page arrives with a short fade and rise. It is sprung, so a quick
        // second click picks up from wherever the first one had got to.
        let enter = Id::new("page-enter");
        let shown: Option<Page> = ctx.data(|d| d.get_temp(Id::new("page-shown")));
        if shown != Some(self.page) {
            ctx.data_mut(|d| d.insert_temp(Id::new("page-shown"), self.page));
            // History and quarantine change elsewhere too (real-time
            // protection, the command line, other users): read them again.
            if shown.is_some() && matches!(self.page, Page::Dashboard | Page::Quarantine | Page::History) {
                self.refresh();
            }
            if shown.is_some() {
                motion::set(ctx, enter, 0.0);
            }
        }
        let t = motion::spring(ctx, enter, 1.0, 0.34, 1.0);

        let margin: i8 = if narrow { 18 } else { 32 };
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme().bg).inner_margin(Margin { left: margin, right: margin, top: 24, bottom: 0 }))
            .show(ui, |ui| {
                self.toast_overlay(ui);
                egui::ScrollArea::vertical()
                    .id_salt(self.page as u8)
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        ui.multiply_opacity(t);
                        ui.add_space((1.0 - t) * 14.0);
                        self.service_banner(ui);
                        match self.page {
                            Page::Dashboard => self.dashboard(ui, ctx),
                            Page::Scan => self.scan_page(ui, ctx),
                            Page::Protection => self.protection_page(ui, ctx),
                            Page::Web => self.web_page(ui, ctx),
                            Page::Inspect => self.inspect_page(ui, ctx),
                            Page::Privacy => self.privacy_page(ui, ctx),
                            Page::Audit => self.audit_page(ui, ctx),
                            Page::Quarantine => self.quarantine_page(ui),
                            Page::History => self.history_page(ui),
                            Page::Settings => self.settings_page(ui, ctx),
                        }
                        if self.page != Page::Dashboard {
                            ui.add_space(28.0);
                        }
                    });
            });

        // Popups float over whichever page asked for them.
        self.fix_dialog(ctx);
        self.dns_dialog(ctx);

        // An appearance change eases over from the old background instead of cutting.
        if let Some((previous, since)) = self.theme_fade {
            let fade = 1.0 - motion::settle((ctx.input(|i| i.time) - since) as f32, 0.45);
            if fade <= 0.01 {
                self.theme_fade = None;
            } else {
                let layer = egui::LayerId::new(egui::Order::Foreground, Id::new("theme-fade"));
                ctx.layer_painter(layer).rect_filled(window, 0.0, previous.gamma_multiply(fade));
                ctx.request_repaint();
            }
        }
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            self.logo.show(ui, 30.0);
            ui.add_space(4.0);
            brand::wordmark(ui, 12.5, theme().text);
        });
        ui.add_space(18.0);

        let quarantined = self.quarantine.len();
        let protection = if self.watch.running { Some(("On".to_string(), theme().green)) } else { None };
        let inspecting = self.inspect.running.is_some() || self.inspect.preparing.is_some();
        let privacy = self
            .privacy
            .as_deref()
            .and_then(posture::score)
            .map(|s| (s.percent.to_string(), score_color(s.percent)));
        // Grouped by what the user is doing: protect, investigate, review, configure.
        let items = [
            (Page::Dashboard, "Dashboard", None, false),
            (Page::Scan, "Scan", self.job.as_ref().map(|_| ("Running".to_string(), theme().accent)), false),
            (Page::Protection, "Protection", protection, false),
            (Page::Web, "Web protection", self.web.running().then(|| ("On".to_string(), theme().green)), false),
            (Page::Inspect, "AI Inspect", inspecting.then(|| ("Working".to_string(), theme().accent)), true),
            (Page::Privacy, "Privacy", privacy, false),
            (Page::Audit, "Stealer check", self.audit_busy().then(|| ("Checking".to_string(), theme().accent)), false),
            (Page::Quarantine, "Quarantine", (quarantined > 0).then(|| (quarantined.to_string(), theme().muted)), true),
            (Page::History, "History", None, false),
            (Page::Settings, "Settings", None, true),
        ];
        // The selection is one pill that glides between rows, painted under them.
        let pill = ui.painter().add(egui::Shape::Noop);
        let mut selected = None;
        for (page, label, badge, gap) in items {
            if gap {
                ui.add_space(12.0);
            }
            let (rect, response) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 34.0), Sense::click());
            let active = self.page == page;
            if active {
                selected = Some(rect);
            }
            let hover = motion::spring(ui.ctx(), response.id.with("hover"), (response.hovered() && !active) as u8 as f32, 0.2, 1.0);
            if hover > 0.001 {
                ui.painter().rect_filled(rect, 10.0, theme().hover.gamma_multiply(hover * 0.6));
            }
            let (font, color) = if active { (semibold(14.0), theme().text) } else { (FontId::proportional(14.0), theme().nav_text) };
            ui.painter().text(rect.left_center() + vec2(12.0, 0.0), Align2::LEFT_CENTER, label, font, color);
            if let Some((badge, color)) = badge {
                ui.painter().text(rect.right_center() - vec2(12.0, 0.0), Align2::RIGHT_CENTER, badge, FontId::proportional(12.0), color);
            }
            if response.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                self.page = page;
                self.pending_delete = None;
            }
        }
        if let Some(target) = selected {
            let top = motion::spring(ui.ctx(), Id::new("nav-pill"), target.top(), 0.32, 1.0);
            let rect = Rect::from_min_size(pos2(target.left(), top), target.size());
            ui.painter().set(pill, egui::Shape::rect_filled(rect, 10.0, theme().control));
        }

        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            let counts = match &self.signatures {
                _ if self.engine_rx.is_some() => "Loading signatures…".to_string(),
                Ok((rules, hashes)) => format!("{rules} rules · {hashes} hashes"),
                Err(_) => "Signatures failed to load".to_string(),
            };
            let updated = self
                .manifest
                .last_success()
                .map(|t| format!("Updated {}", short_time(t)))
                .unwrap_or_else(|| "Signatures never updated".into());
            small(ui, format!("v{}", env!("CARGO_PKG_VERSION")));
            small(ui, counts);
            small(ui, updated);
        });
    }

    /// Above the pages that show protection: the service is missing, or a
    /// change waits for Windows' administrator prompt.
    fn service_banner(&mut self, ui: &mut Ui) {
        let protection_page = !matches!(self.page, Page::Inspect | Page::Privacy | Page::Audit);
        if let Some(waiting) = &self.approval {
            notice(ui, theme().amber, &format!("{waiting}. Answer Windows' prompt to go on."));
            ui.add_space(12.0);
        } else if protection_page && !self.connected && self.service_lost.is_some() {
            notice(
                ui,
                theme().red,
                "The Phalanx protection service is not running, so this PC is not protected. Start Phalanx Protection in Windows' Services app, or reinstall Phalanx.",
            );
            ui.add_space(12.0);
        }
    }

    fn dashboard(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        // Threats from any scan (manual or real-time protection) in the last 7
        // days that were not quarantined need attention.
        let week_ago = (chrono::Local::now() - chrono::Duration::days(7)).to_rfc3339();
        let unresolved: Vec<&ScanRow> = self
            .scans
            .iter()
            .filter(|s| s.started_at >= week_ago && s.detections > s.quarantined)
            .collect();
        let last_manual = self.scans.iter().find(|s| s.finished_at.is_some() && !s.cancelled && !is_protection_kind(&s.kind));
        let threat_count: i64 = unresolved.iter().map(|s| s.detections - s.quarantined).sum();
        let (color, title, detail) = if let Some(job) = &self.job {
            let found = match self.results.len() {
                0 => String::new(),
                n => format!(" · {n} threat(s)"),
            };
            // Neutral while it works; the result colour arrives when the scan ends.
            (theme().muted, "Scanning".to_string(), format!("{} files · {}{found}", job.files, fmt_duration(job.started.elapsed())))
        } else if let Some(latest) = unresolved.first() {
            let found_by = if is_protection_kind(&latest.kind) { "real-time protection" } else { "a scan" };
            (
                theme().red,
                "Threats need review".to_string(),
                format!("{threat_count} not removed in the last 7 days · latest found by {found_by}, {}", short_time(&latest.started_at)),
            )
        } else {
            match last_manual {
                None => (theme().amber, "No scans yet".to_string(), "Run a quick scan to check this PC.".to_string()),
                Some(s) => (
                    theme().green,
                    "No threats found".to_string(),
                    format!("Last scan {} · {} files", short_time(&s.started_at), s.files_scanned),
                ),
            }
        };
        let scanning = self.job.is_some();

        // ---- the hero: an open dot field, no frame ----
        let width = ui.available_width();
        let narrow = width < 760.0;
        // The hero takes whatever height the rest of the page leaves (measured
        // last frame), so the dashboard always fits without scrolling.
        let viewport = ui.clip_rect().bottom() - ui.cursor().top();
        let rest_id = Id::new("dashboard-rest");
        let rest: f32 = ctx.data(|d| d.get_temp(rest_id)).unwrap_or(300.0);
        let hero_height = if narrow { 300.0 } else { (viewport - rest - 4.0).clamp(300.0, 560.0) };
        let (rect, _) = ui.allocate_exact_size(vec2(width, hero_height), Sense::hover());
        let half = (hero_height * 0.34).min(170.0);
        let (center, clear) = if narrow {
            (pos2(rect.center().x, rect.center().y), Rect::NOTHING)
        } else {
            let center = pos2(rect.left() + (width * 0.21).max(half * 1.2), rect.center().y);
            let left = center.x + half * 1.25;
            (center, Rect::from_min_max(pos2(left, rect.center().y - 86.0), pos2(rect.right() - 24.0, rect.center().y + 86.0)))
        };
        let scan = self.job.as_ref().map(|job| HeroScan { files: job.files, threats: self.results.len() });
        let status = dots::HeroStatus { color, live: self.watch.running, threats: threat_count.max(0) as usize, scan };
        self.hero_fx.show(ui, rect, center, half, clear, status);

        let (mut quick, mut full, mut folder, mut view, mut review, mut cancel) = (false, false, false, false, false, false);
        let mut headline = |ui: &mut Ui| {
            ui.label(RichText::new(&title).font(bold(if narrow { 30.0 } else { 40.0 })).extra_letter_spacing(-1.0).color(theme().text));
            ui.add(egui::Label::new(RichText::new(&detail).size(15.0).color(theme().muted)).wrap());
            ui.add_space(18.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                if scanning {
                    view = primary_button(ui, "Scan details").clicked();
                    cancel = secondary_button(ui, "Cancel scan").clicked();
                } else {
                    quick = primary_button(ui, "Quick scan").clicked();
                    full = secondary_button(ui, "Full scan").clicked();
                    folder = secondary_button(ui, "Scan folder").clicked();
                }
                if threat_count > 0 && !scanning {
                    review = secondary_button(ui, "Review threats").clicked();
                }
            });
        };
        if narrow {
            ui.add_space(4.0);
            headline(ui);
        } else {
            ui.scope_builder(egui::UiBuilder::new().max_rect(clear.shrink2(vec2(0.0, 4.0))).layout(Layout::top_down(Align::Min)), |ui| headline(ui));
            // The headline sits inside the hero; carry on below the hero, not below the headline.
            let below = rect.bottom() - ui.cursor().top();
            if below > 0.0 {
                ui.add_space(below);
            }
        }
        // Scans started here play out in the hero, so the page stays.
        if quick {
            self.start_scan(ctx, quick_scan_targets(), "quick");
            self.page = Page::Dashboard;
        }
        if full {
            self.start_scan(ctx, system::fixed_drives(), "full");
            self.page = Page::Dashboard;
        }
        if folder && let Some(dir) = rfd::FileDialog::new().pick_folder() {
            self.start_scan(ctx, vec![dir], "custom");
            self.page = Page::Dashboard;
        }
        if cancel {
            self.cancel_scan();
        }
        if view {
            self.page = Page::Scan;
        }
        if review {
            self.page = Page::History;
        }
        ui.add_space(10.0);

        // ---- this month, as a strip of figures ----
        let this_month = chrono::Local::now().format("%Y-%m").to_string();
        let month = self.months.first().filter(|m| m.month == this_month);
        let figures = [
            ("Scans this month", month.map_or(0, |m| m.scans).to_string()),
            ("Files scanned", month.map_or(0, |m| m.files_scanned).to_string()),
            ("Threats found", month.map_or(0, |m| m.detections).to_string()),
            ("In quarantine", self.quarantine.len().to_string()),
        ];
        let per_row = if narrow { 2 } else { 4 };
        for row in figures.chunks(per_row) {
            let (strip, _) = ui.allocate_exact_size(vec2(width, 66.0), Sense::hover());
            let column = strip.width() / per_row as f32;
            let painter = ui.painter();
            for (i, (label, value)) in row.iter().enumerate() {
                let x = strip.left() + column * i as f32 + if i == 0 { 0.0 } else { 22.0 };
                if i > 0 {
                    painter.vline(strip.left() + column * i as f32, (strip.top() + 8.0)..=(strip.bottom() - 8.0), Stroke::new(1.0, theme().hairline));
                }
                painter.text(pos2(x, strip.top() + 4.0), Align2::LEFT_TOP, value, semibold(30.0), theme().text);
                painter.text(pos2(x, strip.top() + 44.0), Align2::LEFT_TOP, *label, FontId::proportional(12.5), theme().muted);
            }
        }
        ui.add_space(18.0);

        // ---- status, as a plain list ----
        let mut open_protection = false;
        let mut update_clicked = false;
        row_divider(ui);
        if self.watch.running {
            let mut parts = vec![format!("{} folder(s)", self.watch.watching), format!("{} files checked", self.watch.files_checked)];
            if self.watch.programs {
                parts.push(format!("{} programs checked", self.watch.programs_checked));
            }
            setting_row(ui, "Real-time protection", &parts.join(" · "), |ui| badge(ui, "On", theme().green));
        } else {
            setting_row(ui, "Real-time protection", "Off", |ui| {
                open_protection |= small_button(ui, "Turn on").clicked();
            });
        }
        if let Some(checks) = &self.security {
            let risks = checks.iter().filter(|c| c.status == Status::Risk).count();
            let issues = risks + checks.iter().filter(|c| c.status == Status::Attention).count();
            row_divider(ui);
            if issues == 0 {
                setting_row(ui, "Windows protections", "All on", |ui| badge(ui, "On", theme().green));
            } else {
                setting_row(ui, "Windows protections", &format!("{issues} setting(s) need attention"), |ui| {
                    open_protection |= small_button(ui, "Review").clicked();
                    badge(ui, if risks > 0 { "At risk" } else { "Review" }, if risks > 0 { theme().red } else { theme().amber });
                });
            }
        }
        row_divider(ui);
        let counts = match &self.signatures {
            _ if self.engine_rx.is_some() => "Loading…".into(),
            Ok((r, h)) => format!("{r} rules · {h} hashes · {} web rules", self.web.counts.blocking()),
            Err(_) => "Failed to load".into(),
        };
        let every = match (self.settings.auto_update, self.settings.auto_update_hours) {
            (false, _) => "Auto-update off".to_string(),
            (true, 1) => "Auto-update hourly".to_string(),
            (true, h) => format!("Auto-update every {h} hours"),
        };
        let summary = match (&self.updating, self.manifest.last_success()) {
            (Some(job), _) => job.step.clone(),
            (None, Some(t)) => format!("Updated {} · {counts} · {every}", short_time(t)),
            (None, None) => format!("Never updated · built-in set only · {every}"),
        };
        setting_row(ui, "Signatures", &summary, |ui| {
            if self.updating.is_some() {
                spinner(ui);
            } else {
                update_clicked = small_button(ui, "Check now").clicked();
            }
        });
        if open_protection {
            self.page = Page::Protection;
        }
        if update_clicked {
            self.start_update();
        }
        let rest_now = ui.cursor().top() - rect.bottom();
        if (rest_now - rest).abs() > 0.5 {
            ctx.data_mut(|d| d.insert_temp(rest_id, rest_now));
            ctx.request_repaint();
        }
    }

    /// The three ways to start a scan, as tiles that reflow with the width.
    fn scan_modes(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        #[derive(Clone, Copy)]
        enum Mode {
            Quick,
            Full,
            Custom,
        }
        let busy = self.job.is_some();
        let drives = system::fixed_drives();
        let drive_list = drives.iter().map(|d| d.display().to_string().trim_end_matches('\\').to_string()).collect::<Vec<_>>().join(", ");
        let mut start: Option<(Vec<PathBuf>, &str)> = None;
        let (mut pick_folder, mut pick_files) = (false, false);
        let modes = [Mode::Quick, Mode::Full, Mode::Custom];
        let per_row = columns_for(ui, 230.0, modes.len());
        for (index, row) in modes.chunks(per_row).enumerate() {
            if index > 0 {
                ui.add_space(8.0);
            }
            ui.columns(per_row, |cols| {
                for (col, mode) in cols.iter_mut().zip(row) {
                    card(col, |ui| {
                        ui.set_min_height(112.0);
                        let (title, text) = match mode {
                            Mode::Quick => ("Quick scan", "Downloads, Desktop, Documents, Temp".to_string()),
                            Mode::Full => ("Full scan", format!("All internal drives · {drive_list}")),
                            Mode::Custom => ("Custom scan", "Folders or files you choose".to_string()),
                        };
                        section_title(ui, title);
                        // Columns justify wrapped text; a plain top-down layout does not.
                        ui.with_layout(Layout::top_down(Align::Min), |ui| {
                            ui.add(egui::Label::new(RichText::new(text).size(12.5).color(theme().muted)).wrap());
                        });
                        ui.add_space(8.0);
                        ui.add_enabled_ui(!busy, |ui| {
                            ui.horizontal_wrapped(|ui| match mode {
                                Mode::Quick => {
                                    if primary_button(ui, "Start scan").clicked() {
                                        start = Some((quick_scan_targets(), "quick"));
                                    }
                                }
                                Mode::Full => {
                                    if secondary_button(ui, "Start scan").clicked() {
                                        start = Some((drives.clone(), "full"));
                                    }
                                }
                                Mode::Custom => {
                                    pick_folder = secondary_button(ui, "Choose folder").clicked();
                                    pick_files = secondary_button(ui, "Choose files").clicked();
                                }
                            });
                        });
                    });
                }
            });
        }
        if busy {
            ui.add_space(4.0);
            small(ui, "Scan in progress");
        }
        if pick_folder && let Some(dir) = rfd::FileDialog::new().pick_folder() {
            start = Some((vec![dir], "custom"));
        }
        if pick_files && let Some(files) = rfd::FileDialog::new().pick_files() {
            start = Some((files, "custom"));
        }
        if let Some((paths, kind)) = start {
            self.start_scan(ctx, paths, kind);
        }
    }

    fn scan_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Scan");

        if let Some(job) = &self.job {
            let cancelling = job.cancelling;
            self.scan_fx.show(ui, self.scan_run, StageMode::Scanning { files: job.files, threats: self.results.len(), cancelling });
            ui.add_space(14.0);
            let mut cancel = false;
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    let state = if cancelling { "Cancelling" } else { "Scanning" };
                    ui.label(RichText::new(state).font(semibold(18.0)).color(theme().text));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        cancel = ui.add_enabled_ui(!cancelling, |ui| secondary_button(ui, "Cancel scan").clicked()).inner;
                    });
                });
                truncated(ui, job.targets.clone(), theme().muted, 13.0);
                ui.add_space(8.0);
                facts(
                    ui,
                    &[
                        ("Files", job.files.to_string()),
                        ("Data", fmt_bytes(job.bytes)),
                        ("Threats", self.results.len().to_string()),
                        ("Elapsed", fmt_duration(job.started.elapsed())),
                        ("Threads", job.threads.to_string()),
                        ("Type", capitalize(&job.kind)),
                    ],
                );
                ui.add_space(4.0);
                truncated(ui, job.current.clone(), theme().muted, 12.0);
            });
            if cancel {
                self.cancel_scan();
            }
            ui.add_space(14.0);
        } else if let Some(done) = &self.finished {
            let (outcome, title) = match (done.cancelled, done.infected) {
                (true, _) => (Outcome::Cancelled, "Scan cancelled".to_string()),
                (false, 0) => (Outcome::Clean, "No threats found".to_string()),
                (false, n) => (Outcome::Threats, format!("{n} threat(s) found")),
            };
            self.scan_fx.show(ui, self.scan_run, StageMode::Done(outcome));
            ui.add_space(14.0);
            let mut new_scan = false;
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(title).font(semibold(18.0)).color(theme().text));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        new_scan = secondary_button(ui, "New scan").clicked();
                    });
                });
                facts(
                    ui,
                    &[
                        ("Scan", format!("#{}", done.scan_id)),
                        ("Files", done.files.to_string()),
                        ("Data", fmt_bytes(done.bytes)),
                        ("Took", fmt_duration(done.elapsed)),
                        ("Threads", done.threads.to_string()),
                        ("Quarantined", done.quarantined.to_string()),
                        ("Unreadable", done.errors.to_string()),
                    ],
                );
            });
            if new_scan {
                // Back to the scan choices on this page.
                self.finished = None;
                self.results.clear();
            }
            ui.add_space(14.0);
        } else {
            self.scan_modes(ui, ctx);
            return;
        }

        if self.results.is_empty() {
            return;
        }
        let selectable = self.results.iter().filter(|r| r.report.action == "reported").count();
        let selected = self.results.iter().filter(|r| r.selected).count();
        ui.horizontal_wrapped(|ui| {
            section_title(ui, "Detections");
            ui.add_space(12.0);
            if selectable > 0 && secondary_button(ui, "Select all").clicked() {
                for r in &mut self.results {
                    r.selected = r.report.action == "reported";
                }
            }
            let enabled = selected > 0 && self.job.is_none();
            if ui.add_enabled(enabled, danger_button(&format!("Quarantine selected ({selected})"))).clicked() {
                self.quarantine_selected();
            }
        });
        ui.add_space(6.0);
        let mut inspect = None;
        let ai_enabled = self.settings.ai_enabled;
        for row in &mut self.results {
            if detection_card(ui, row, ai_enabled) {
                inspect = Some(PathBuf::from(&row.report.path));
            }
            ui.add_space(8.0);
        }
        if let Some(path) = inspect {
            self.inspect_file(ctx, path);
        }
    }

    /// The protection service: whether it is installed, running and answering.
    fn service_card(&self, ui: &mut Ui) {
        let (color, title, detail) = match &self.service {
            None => (theme().muted, "Checking the protection service…".to_string(), String::new()),
            Some(ServiceView::NotInstalled) => (
                theme().muted,
                "Protection service: not installed".to_string(),
                "Protection runs inside this app for now. The service is being built to keep protecting when the app is closed and nobody is signed in.".to_string(),
            ),
            Some(ServiceView::Down(state)) => (
                theme().amber,
                format!("Protection service: {state}"),
                "Windows restarts it automatically after a failure. An administrator can start it with `phalanx-cli service start`.".to_string(),
            ),
            Some(ServiceView::Running { version, user, admin }) => (
                theme().green,
                format!("Protection service: running ({version})"),
                if *admin {
                    format!("Signed in as {user}, an administrator: you can change every setting.")
                } else {
                    format!("Signed in as {user}. Changes that weaken protection will need an administrator's approval.")
                },
            ),
            Some(ServiceView::Unreachable(e)) => (theme().red, "Protection service: not answering".to_string(), capitalize(e)),
        };
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                status_dot(ui, color, 6.0);
                ui.label(RichText::new(title).size(16.0).strong().color(theme().text));
            });
            if !detail.is_empty() {
                small(ui, detail);
            }
        });
    }

    fn protection_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Protection");

        self.security_card(ui, ctx);
        ui.add_space(14.0);

        self.service_card(ui);
        ui.add_space(14.0);

        let mut toggle = false;
        let nothing_to_protect = self.settings.watch_folders.is_empty() && !self.settings.program_protection;
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                let (color, title) = match (self.settings.watch_enabled, self.watch.running) {
                    (true, true) if !self.watch.failed.is_empty() => (theme().amber, "Real-time protection is on, with problems"),
                    (true, true) => (theme().green, "Real-time protection is on"),
                    (true, false) if nothing_to_protect => (theme().amber, "Add a folder or turn on program protection"),
                    (true, false) => (theme().amber, "Starting…"),
                    (false, _) => (theme().muted, "Real-time protection is off"),
                };
                status_dot(ui, color, 6.0);
                ui.label(RichText::new(title).size(18.0).strong().color(theme().text));
            });
            if self.watch.running {
                let mut items = vec![
                    ("Watching", format!("{} folder(s)", self.watch.watching)),
                    ("New files checked", self.watch.files_checked.to_string()),
                ];
                if self.watch.programs {
                    items.push(("Programs checked", self.watch.programs_checked.to_string()));
                }
                items.push(("Threats", self.watch.threats.to_string()));
                items.push(("Running since", self.watch.since.clone().unwrap_or_default()));
                if self.watch.restarts > 0 {
                    items.push(("Recovered from problems", self.watch.restarts.to_string()));
                }
                facts(ui, &items);
            }
            ui.add_space(6.0);
            let label = if self.settings.watch_enabled { "Turn off" } else { "Turn on protection" };
            toggle = if self.settings.watch_enabled {
                secondary_button(ui, label).clicked()
            } else {
                primary_button(ui, label).clicked()
            };
        });
        if toggle {
            self.settings.watch_enabled = !self.settings.watch_enabled;
        }
        ui.add_space(14.0);

        let mut remove = None;
        let mut add = false;
        card(ui, |ui| {
            section_title(ui, "Watched folders");
            ui.add_space(4.0);
            if self.settings.watch_folders.is_empty() {
                small(ui, "No folders watched");
            }
            for (i, folder) in self.settings.watch_folders.iter().enumerate() {
                let failed = self.watch.failed.iter().find(|(f, _)| f == folder);
                ui.horizontal(|ui| {
                    status_dot(ui, if failed.is_some() { theme().red } else if self.watch.running { theme().green } else { theme().muted }, 4.0);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if small_button(ui, "Remove").clicked() {
                            remove = Some(i);
                        }
                        truncated(ui, folder.display().to_string(), theme().text, 13.5);
                    });
                });
                if let Some((_, e)) = failed {
                    small(ui, format!("Not watched right now: {e}. Retrying every few seconds."));
                }
            }
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                add = secondary_button(ui, "Add folder…").clicked();
                if let Some(downloads) = home_dir().map(|h| h.join("Downloads"))
                    && downloads.is_dir()
                    && !self.settings.watch_folders.contains(&downloads)
                    && secondary_button(ui, "Add Downloads").clicked()
                {
                    self.settings.watch_folders.push(downloads);
                }
            });
        });
        if let Some(i) = remove {
            self.settings.watch_folders.remove(i);
        }
        if add {
            add_folder(&mut self.settings.watch_folders);
        }
        ui.add_space(14.0);

        card(ui, |ui| {
            group_title(ui, "Program protection", "");
            setting_toggle(
                ui,
                &mut self.settings.program_protection,
                "Scan programs as they start",
                "Each program is checked once (until it changes), within about a second of starting. Very short-lived programs can finish first.",
            );
            row_divider(ui);
            ui.add_enabled_ui(self.settings.program_protection, |ui| {
                setting_toggle(
                    ui,
                    &mut self.settings.stop_running_threats,
                    "Stop malware that is running",
                    "End a running program found to be malware. Potentially unwanted programs, hacking tools and suspicious (heuristic) findings are reported but left running. Programs running as administrator can only be stopped if Phalanx runs as administrator too.",
                );
            });
        });
        ui.add_space(14.0);

        card(ui, |ui| {
            group_title(ui, "Behavior", "");
            setting_toggle(
                ui,
                &mut self.settings.scan_new_drives,
                "Check drives as they appear",
                "When a disk image (ISO, VHD) is opened or a USB drive is connected, scan the files near its top. Files inside disk images skip Windows' download warnings.",
            );
            row_divider(ui);
            setting_toggle(
                ui,
                &mut self.settings.defer_when_fullscreen,
                "Wait during games and presentations",
                "Ordinary files are scanned after a full-screen game or presentation ends (at most 10 minutes later). New programs are always checked straight away.",
            );
        });
        ui.add_space(14.0);

        let ai_enabled = self.settings.ai_enabled;
        let mut inspect = None;
        card(ui, |ui| {
            section_title(ui, "Recent activity");
            if self.activity.is_empty() {
                small(ui, "No activity yet");
            }
            for item in self.activity.iter().take(40) {
                let color = match item.kind {
                    ActivityKind::Threat => theme().red,
                    ActivityKind::Risky | ActivityKind::Problem => theme().amber,
                    ActivityKind::Info => theme().muted,
                };
                ui.horizontal(|ui| {
                    status_dot(ui, color, 3.5);
                    ui.label(RichText::new(&item.time).size(12.0).color(theme().muted));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if let (true, Some(path)) = (ai_enabled, &item.path)
                            && path.is_file() && small_button(ui, "Inspect with AI").clicked()
                        {
                            inspect = Some(path.clone());
                        }
                        let text_color = match item.kind {
                            ActivityKind::Threat => theme().red,
                            ActivityKind::Risky => theme().amber,
                            _ => theme().text,
                        };
                        ui.with_layout(Layout::left_to_right(Align::Center), |ui| truncated(ui, item.text.clone(), text_color, 13.0));
                    });
                });
                if !item.detail.is_empty() {
                    truncated(ui, item.detail.clone(), theme().muted, 12.0);
                }
            }
        });
        if let Some(path) = inspect {
            self.inspect_file(ctx, path);
        }
    }

    fn quarantine_page(&mut self, ui: &mut Ui) {
        page_header(ui, "Quarantine");
        if self.quarantine.is_empty() {
            card(ui, |ui| muted(ui, "Quarantine is empty"));
            return;
        }
        let mut action: Option<(String, bool)> = None;
        for item in &self.quarantine {
            card(ui, |ui| {
                ui.label(RichText::new(&item.threat).font(semibold(15.0)).color(theme().text));
                path_lines(ui, &item.original_path);
                small(ui, format!("{} · {}", short_time(&item.quarantined_at), fmt_bytes(item.size)));
                ui.horizontal_wrapped(|ui| {
                    if secondary_button(ui, "Restore").clicked() {
                        action = Some((item.id.clone(), true));
                    }
                    let confirming = self.pending_delete.as_deref() == Some(item.id.as_str());
                    if confirming {
                        if ui.add(danger_button("Confirm delete")).clicked() {
                            action = Some((item.id.clone(), false));
                        }
                    } else if secondary_button(ui, "Delete").clicked() {
                        self.pending_delete = Some(item.id.clone());
                    }
                });
            });
            ui.add_space(8.0);
        }
        if let Some((id, restore)) = action {
            self.pending_delete = None;
            self.quarantine_action(&id, restore);
        }
    }

    fn history_page(&mut self, ui: &mut Ui) {
        page_header(ui, "History");

        let this_month = chrono::Local::now().format("%Y-%m").to_string();
        let month = self.months.first().filter(|m| m.month == this_month);
        stat_tiles(
            ui,
            &[
                ("Scans this month", month.map_or(0, |m| m.scans).to_string()),
                ("Files this month", month.map_or(0, |m| m.files_scanned).to_string()),
                ("Threats this month", month.map_or(0, |m| m.detections).to_string()),
                ("Quarantined this month", month.map_or(0, |m| m.quarantined).to_string()),
            ],
        );
        ui.add_space(14.0);

        ui.horizontal_wrapped(|ui| {
            for (filter, label) in [
                (HistoryFilter::All, "All scans"),
                (HistoryFilter::Manual, "Manual"),
                (HistoryFilter::Watch, "Real-time protection"),
            ] {
                if chip(ui, label, self.history_filter == filter) {
                    self.history_filter = filter;
                }
            }
        });
        ui.add_space(8.0);

        let filter = self.history_filter;
        let scans: Vec<ScanRow> = self
            .scans
            .iter()
            .filter(|s| match filter {
                HistoryFilter::All => true,
                HistoryFilter::Manual => !is_protection_kind(&s.kind),
                HistoryFilter::Watch => is_protection_kind(&s.kind),
            })
            .take(100)
            .cloned()
            .collect();
        if scans.is_empty() {
            card(ui, |ui| muted(ui, "No scans of this kind yet."));
        }
        let mut toggle = None;
        for s in &scans {
            let expanded = self.expanded.get(&s.id);
            card(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let kind_color = if is_protection_kind(&s.kind) { theme().green } else { theme().accent };
                    badge(ui, &s.kind.to_uppercase(), kind_color);
                    ui.label(RichText::new(format!("#{} · {}", s.id, short_time(&s.started_at))).strong().color(theme().text));
                    let (status, color) = match (&s.finished_at, s.cancelled, s.detections) {
                        // A command line, not a file scan; nothing was stopped.
                        _ if s.kind == "command" => ("Suspicious command".to_string(), theme().amber),
                        (None, _, _) => ("Incomplete".to_string(), theme().amber),
                        (_, true, _) => ("Cancelled".to_string(), theme().amber),
                        (_, _, 0) => ("Clean".to_string(), theme().green),
                        (_, _, n) => (format!("{n} threat(s)"), theme().red),
                    };
                    badge(ui, &status, color);
                });
                if s.kind == "command" {
                    facts(ui, &[("Action", "Reported only: command-line rules do not stop programs yet".to_string())]);
                } else {
                    facts(
                        ui,
                        &[
                            ("Took", s.elapsed_ms.map(|ms| fmt_duration(Duration::from_millis(ms as u64))).unwrap_or_else(|| "?".into())),
                            ("Files", s.files_scanned.to_string()),
                            ("Data", fmt_bytes(s.bytes_scanned)),
                            ("Skipped", s.files_skipped.to_string()),
                            ("Unreadable", s.errors.to_string()),
                            ("Quarantined", s.quarantined.to_string()),
                            ("Threads", s.threads.to_string()),
                            ("Signatures", s.signatures.as_deref().map(short_time).unwrap_or_else(|| "built-in".into())),
                        ],
                    );
                }
                truncated(ui, s.targets.clone(), theme().muted, 12.5);
                let has_details = s.detections > 0 || s.errors > 0;
                if has_details {
                    let label = if expanded.is_some() { "Hide details" } else { "Show details" };
                    if small_button(ui, label).clicked() {
                        toggle = Some(s.id);
                    }
                }
                if let Some(details) = expanded {
                    ui.add_space(4.0);
                    for d in &details.detections {
                        ui.horizontal(|ui| {
                            badge(ui, &d.category.to_uppercase(), category_color_str(&d.category));
                            truncated(ui, format!("{} · {}", d.threat, d.source), theme().text, 13.0);
                        });
                        path_lines(ui, &d.path);
                        small(ui, format!("Action: {}", d.action));
                    }
                    if !details.errors.is_empty() {
                        ui.add_space(4.0);
                        small(ui, format!("Could not read {} file(s):", s.errors));
                        for e in details.errors.iter().take(30) {
                            truncated(ui, format!("{}: {}", e.path, e.message), theme().muted, 12.0);
                        }
                        if s.errors > 30 {
                            small(ui, format!("…and {} more", s.errors - 30));
                        }
                    }
                }
            });
            ui.add_space(8.0);
        }
        if let Some(id) = toggle && self.expanded.remove(&id).is_none() {
            self.link.run(
                move || link::read::<(Vec<DetectionRow>, Vec<ScanErrorRow>)>(Request::ScanDetails { scan: id }),
                move |app, details| match details {
                    Ok((detections, errors)) => {
                        app.expanded.insert(id, ScanDetails { detections, errors });
                    }
                    Err(e) => app.notify(format!("Could not load scan details: {e}"), false),
                },
            );
        }
    }

    fn settings_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Settings");
        ui.horizontal_wrapped(|ui| {
            for (tab, label) in [
                (SettingsTab::General, "General"),
                (SettingsTab::Scanning, "Scanning"),
                (SettingsTab::Exclusions, "Exclusions"),
                (SettingsTab::Signatures, "Signatures"),
                (SettingsTab::Ai, "AI inspection"),
            ] {
                if chip(ui, label, self.settings_tab == tab) {
                    self.settings_tab = tab;
                }
            }
        });
        ui.add_space(14.0);

        let heuristics_before = self.settings.heuristics;
        match self.settings_tab {
            SettingsTab::General => self.settings_general(ui),
            SettingsTab::Scanning => self.settings_scanning(ui),
            SettingsTab::Exclusions => self.settings_exclusions(ui),
            SettingsTab::Signatures => self.settings_signatures(ui, ctx),
            SettingsTab::Ai => self.settings_ai(ui, ctx),
        }
        if self.settings.heuristics != heuristics_before {
            self.reload_signatures(ctx);
        }
    }

    fn settings_general(&mut self, ui: &mut Ui) {
        card(ui, |ui| {
            group_title(ui, "Appearance", "");
            setting_row(ui, "Theme", "", |ui| {
                // Right to left, so the choices read System, Light, Dark.
                for (appearance, label) in [(Appearance::Dark, "Dark"), (Appearance::Light, "Light"), (Appearance::System, "System")] {
                    if chip(ui, label, self.settings.appearance == appearance) {
                        self.settings.appearance = appearance;
                    }
                }
            });
        });
        ui.add_space(14.0);

        let mut autostart = self.autostart;
        let has_tray = self.tray.is_some();
        card(ui, |ui| {
            group_title(ui, "Startup and background", "");
            setting_toggle(
                ui,
                &mut autostart,
                "Start with Windows",
                "Opens in the tray when you sign in, so real-time protection starts automatically. Adds a per-user sign-in entry; no administrator rights are needed.",
            );
            row_divider(ui);
            ui.add_enabled_ui(has_tray, |ui| {
                setting_toggle(
                    ui,
                    &mut self.settings.close_to_tray,
                    "Keep running in the tray when the window is closed",
                    if has_tray {
                        "Real-time protection keeps working with the window closed. Right-click the tray icon to quit."
                    } else {
                        "Unavailable: the tray icon could not be created, so closing the window quits."
                    },
                );
            });
        });
        if autostart != self.autostart {
            self.set_autostart(autostart);
        }
        ui.add_space(14.0);

        let mut test = false;
        card(ui, |ui| {
            group_title(ui, "Notifications", "Windows notifications from real-time protection. They work while the window is closed.");
            setting_toggle(
                ui,
                &mut self.settings.notifications,
                "When a threat is found",
                "Notify when real-time protection detects malware, a potentially unwanted program or a hacking tool.",
            );
            row_divider(ui);
            setting_toggle(
                ui,
                &mut self.settings.risky_file_alerts,
                "When a program or script arrives",
                "Warn as soon as an .exe, .msi, .ps1, .py, .bat or similar file lands in a watched folder, before you open it, then report its scan result. Also points out disguised names such as invoice.pdf.exe.",
            );
            row_divider(ui);
            let (description, label, color) = match &self.notification_identity {
                Ok(()) => ("Notifications pop up with this app's name and icon. A Start-menu shortcut named Phalanx is needed for that.", APP_TITLE, theme().green),
                Err(_) => (
                    "The app's name could not be registered, so Windows shows notifications as Windows PowerShell.",
                    "PowerShell",
                    theme().amber,
                ),
            };
            setting_row(ui, "Shown as", description, |ui| {
                test = small_button(ui, "Send a test").clicked();
                badge(ui, label, color);
            });
            if let Err(e) = &self.notification_identity {
                small(ui, e.clone());
            }
        });
        if test {
            system::notify("Test notification", &format!("This is how {APP_TITLE} notifications look."));
        }
        ui.add_space(14.0);

        let mut open = false;
        card(ui, |ui| {
            group_title(ui, "Data", "History, quarantine, downloaded signatures and settings.");
            setting_row(ui, "Data folder", &self.data_dir.display().to_string(), |ui| {
                open = small_button(ui, "Open folder").clicked();
            });
        });
        if open {
            let _ = std::process::Command::new("explorer").arg(&self.data_dir).spawn();
        }
    }

    fn settings_scanning(&mut self, ui: &mut Ui) {
        card(ui, |ui| {
            group_title(ui, "Scan performance", "How hard manual scans may work. Lower settings take longer but keep the PC fully usable.");
            for level in [Performance::LowImpact, Performance::Balanced, Performance::Fast] {
                let threads = system::worker_threads(level);
                let (title, detail) = match level {
                    Performance::LowImpact => ("Low impact (recommended)", format!("{threads} thread(s) at background priority.")),
                    Performance::Balanced => ("Balanced", format!("{threads} thread(s) at background priority.")),
                    Performance::Fast => ("Fast", format!("{threads} thread(s) at normal priority: quickest, but the PC may feel busy.")),
                };
                if choice_row(ui, self.settings.performance == level, title, &detail) {
                    self.settings.performance = level;
                }
                ui.add_space(2.0);
            }
            small(ui, "Real-time protection scans one file at a time: new programs at normal priority, everything else at background priority.");
        });
        ui.add_space(14.0);

        card(ui, |ui| {
            group_title(ui, "Detection", "");
            setting_toggle(
                ui,
                &mut self.settings.heuristics,
                "PE heuristics",
                "Flag packed or injection-capable Windows programs as suspicious. Occasionally flags legitimate software.",
            );
            row_divider(ui);
            setting_toggle(
                ui,
                &mut self.settings.trust_signed,
                "Trust signed software",
                "Don't report heuristic findings on programs with a valid publisher signature (including Windows' own). Signature and hash matches are always reported.",
            );
            row_divider(ui);
            setting_toggle(
                ui,
                &mut self.settings.scan_archives,
                "Scan inside archives",
                "Open ZIP and 7z files (up to 3 levels deep, 512 MB unpacked) and scan what is inside. Password-protected archives holding programs are reported.",
            );
            row_divider(ui);
            setting_row(
                ui,
                "Skip files larger than",
                "Larger files are counted as skipped, except programs padded past the limit: those are scanned without their padding. Applies to scans and real-time protection.",
                |ui| {
                    ui.add(egui::DragValue::new(&mut self.settings.max_size_mb).range(1..=4096).suffix(" MiB"));
                },
            );
        });
        ui.add_space(14.0);

        card(ui, |ui| {
            group_title(ui, "Quarantine", "Quarantined files are encoded so they cannot run. You can restore them from the Quarantine page.");
            setting_toggle(
                ui,
                &mut self.settings.auto_quarantine,
                "Quarantine threats automatically",
                "Malware, potentially unwanted programs and hacking tools are isolated as soon as they are found.",
            );
            row_divider(ui);
            let auto = self.settings.auto_quarantine;
            ui.add_enabled_ui(auto, |ui| {
                ui.indent("quarantine-suspicious", |ui| {
                    setting_toggle(
                        ui,
                        &mut self.settings.quarantine_suspicious,
                        "Also quarantine suspicious files",
                        if auto {
                            "Includes heuristic detections, which are sometimes legitimate software."
                        } else {
                            "Turn on automatic quarantine first."
                        },
                    );
                });
            });
            if !auto {
                self.settings.quarantine_suspicious = false;
            }
        });
    }

    fn settings_exclusions(&mut self, ui: &mut Ui) {
        let mut remove = None;
        let mut add_dir = false;
        let mut add_file = false;
        card(ui, |ui| {
            group_title(ui, "Exclusions", "Never scanned, by manual scans or real-time protection. Subfolders are included.");
            if self.settings.exclusions.is_empty() {
                small(ui, "No exclusions.");
            }
            for (i, path) in self.settings.exclusions.iter().enumerate() {
                if i > 0 {
                    row_divider(ui);
                }
                ui.horizontal(|ui| {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if small_button(ui, "Remove").clicked() {
                            remove = Some(i);
                        }
                        truncated(ui, path.display().to_string(), theme().text, 13.5);
                    });
                });
            }
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                add_dir = secondary_button(ui, "Exclude a folder…").clicked();
                add_file = secondary_button(ui, "Exclude a file…").clicked();
            });
        });
        if let Some(i) = remove {
            self.settings.exclusions.remove(i);
        }
        if add_dir {
            add_folder(&mut self.settings.exclusions);
        }
        if add_file && let Some(file) = rfd::FileDialog::new().pick_file() && !self.settings.exclusions.contains(&file) {
            self.settings.exclusions.push(file);
        }
    }

    fn settings_signatures(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        let mut update_clicked = false;
        let mut check_clicked = false;
        card(ui, |ui| {
            group_title(ui, "Automatic updates", "");
            setting_toggle(
                ui,
                &mut self.settings.auto_update,
                "Keep signatures and web rules up to date",
                "Asks each feed whether it has new data (a few small requests) and downloads only the feeds that changed. Runs in the background, also from the tray.",
            );
            if self.settings.auto_update {
                setting_row(ui, "Check every", "", |ui| {
                    for hours in [24, 12, 4, 1] {
                        let label = if hours == 1 { "hour".to_string() } else { format!("{hours} hours") };
                        if chip(ui, &label, self.settings.auto_update_hours == hours) {
                            self.settings.auto_update_hours = hours;
                        }
                    }
                });
            }
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                if let Some(job) = &self.updating {
                    spinner(ui);
                    muted(ui, job.step.clone());
                } else {
                    let status = match self.manifest.last_check() {
                        Some(t) => format!("Last checked {}.", short_time(t)),
                        None => "Not checked yet.".to_string(),
                    };
                    muted(ui, status);
                    check_clicked = small_button(ui, "Check now").clicked();
                }
            });
        });
        if check_clicked {
            self.start_update();
        }
        ui.add_space(14.0);
        card(ui, |ui| {
            group_title(ui, "Downloaded signatures", "");
            match &self.signatures {
                _ if self.engine_rx.is_some() => muted(ui, "Loading signatures…"),
                Ok((rules, hashes)) => muted(ui, format!("Loaded {rules} YARA rules and {hashes} known-bad hashes.")),
                Err(e) => {
                    ui.label(RichText::new(format!("Failed to load: {e}")).color(theme().red));
                }
            }
            ui.add_space(6.0);
            for source in update::SOURCES {
                let status = self.manifest.sources.iter().find(|s| s.name == source.name);
                ui.horizontal_wrapped(|ui| {
                    let color = match status {
                        Some(s) if s.ok => theme().green,
                        Some(s) if s.skipped => theme().amber,
                        Some(_) => theme().red,
                        None => theme().muted,
                    };
                    status_dot(ui, color, 4.0);
                    ui.label(source.name);
                    let when = status
                        .and_then(|s| s.updated_at.as_deref())
                        .map(|t| format!("updated {}", short_time(t)))
                        .unwrap_or_else(|| "never updated".into());
                    small(ui, when);
                });
                if let Some(s) = status {
                    truncated(ui, s.message.clone(), if s.ok || s.skipped { theme().muted } else { theme().red }, 12.0);
                }
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if let Some(job) = &self.updating {
                    spinner(ui);
                    truncated(ui, job.step.clone(), theme().muted, 13.0);
                } else {
                    update_clicked = primary_button(ui, "Update now").clicked();
                }
            });
            small(ui, "Sources: YARA Forge (licences vary per rule), malware-filter's URLhaus host list (CC0), StevenBlack hosts (MIT) and, with an Auth-Key, abuse.ch MalwareBazaar, ThreatFox and URLhaus (CC0). Only feeds with new data are downloaded, and downloads are validated before they replace your current signatures. Web protection picks up new web rules automatically.");
        });
        if update_clicked {
            self.start_update();
        }
        ui.add_space(14.0);
        self.abuse_key_card(ui, ctx);
    }

    /// The free abuse.ch Auth-Key that MalwareBazaar, ThreatFox and URLhaus
    /// need for their known-bad hashes and malware sites.
    fn abuse_key_card(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        let saved = self.abuse_key_saved;
        let from_env = !saved && std::env::var(update::AUTH_KEY_ENV).is_ok_and(|k| !k.trim().is_empty());
        let (mut save, mut remove) = (false, false);
        card(ui, |ui| {
            group_title(ui, "abuse.ch Auth-Key", "");
            let (state, color) = match (saved, from_env) {
                (true, _) => ("Saved", theme().green),
                (false, true) => ("From environment", theme().green),
                _ => ("Not set", theme().amber),
            };
            setting_row(
                ui,
                "Known-bad hashes and malware sites",
                "MalwareBazaar, ThreatFox and URLhaus only share their data with a free personal key (sign in at abuse.ch with a GitHub, Google or Microsoft account and copy your Auth-Key). Without it those feeds are skipped; YARA rules and the other feeds still update. The protection service keeps the key encrypted, readable only by administrators, so saving or removing it asks for an administrator's approval.",
                |ui| badge(ui, state, color),
            );
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.abuse_key_input)
                        .password(true)
                        .hint_text(if saved { "Paste a new key to replace the saved one" } else { "Paste your Auth-Key" })
                        .desired_width(300.0),
                );
                let has_input = !self.abuse_key_input.trim().is_empty();
                save = ui.add_enabled_ui(has_input, |ui| primary_button(ui, "Save key").clicked()).inner;
                if saved {
                    remove = secondary_button(ui, "Remove key").clicked();
                }
            });
            ui.hyperlink_to(RichText::new("Get a free Auth-Key at auth.abuse.ch").size(12.5), update::AUTH_KEY_PORTAL);
        });
        let _ = ctx;
        if save {
            // Saved for this user first (encrypted for them), where the
            // elevated `phalanx-cli` reads it: the key never goes on a
            // command line.
            let sig_dir = update::signature_dir(&self.data_dir);
            match update::save_auth_key(&sig_dir, Some(self.abuse_key_input.trim())) {
                Ok(()) => {
                    self.abuse_key_input.clear();
                    self.set_service_auth_key(Some(()));
                }
                Err(e) => self.notify(format!("Could not save the Auth-Key: {e:#}"), false),
            }
        }
        if remove {
            self.set_service_auth_key(None);
        }
    }

    fn settings_ai(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        card(ui, |ui| {
            group_title(ui, "AI file inspection", "Ask Google Gemini whether a file looks safe. You choose each file; nothing is ever sent automatically.");
            setting_toggle(
                ui,
                &mut self.settings.ai_enabled,
                "Enable AI inspection",
                "Use the AI Inspect page, or the Inspect with AI buttons on scan results and folder-protection activity.",
            );
            ui.add_space(8.0);
            notice(
                ui,
                theme().amber,
                "What is sent to Google: scripts and other text files are sent as text, up to the limit below. Programs and other binaries are never uploaded; only facts extracted on this PC (structure, imported functions, readable strings). On Gemini's free tier Google may use what you send to improve its products, so don't inspect files that contain personal or confidential information.",
            );
        });
        ui.add_space(14.0);

        let enabled = self.settings.ai_enabled;
        let saved = self.settings.ai_key_protected.is_some();
        let from_env = !saved && std::env::var("GEMINI_API_KEY").is_ok_and(|k| !k.trim().is_empty());
        let (mut save, mut remove, mut list) = (false, false, false);
        ui.add_enabled_ui(enabled, |ui| {
            card(ui, |ui| {
                group_title(ui, "Gemini connection", "");
                let (state, color) = match (saved, from_env) {
                    (true, _) => ("Saved", theme().green),
                    (false, true) => ("From environment", theme().green),
                    _ => ("Not set", theme().amber),
                };
                setting_row(
                    ui,
                    "API key",
                    if from_env {
                        "Using the GEMINI_API_KEY environment variable. Saving a key here takes precedence."
                    } else {
                        "Create a free key in Google AI Studio. It is stored encrypted by Windows, so only your account on this PC can read it."
                    },
                    |ui| badge(ui, state, color),
                );
                ui.horizontal_wrapped(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.key_input)
                            .password(!self.key_visible)
                            .hint_text(if saved { "Paste a new key to replace the saved one" } else { "Paste your API key" })
                            .desired_width(300.0),
                    );
                    ui.checkbox(&mut self.key_visible, "Show");
                    let has_input = !self.key_input.trim().is_empty();
                    save = ui.add_enabled_ui(has_input, |ui| primary_button(ui, "Save key").clicked()).inner;
                    if saved {
                        remove = secondary_button(ui, "Remove key").clicked();
                    }
                });
                ui.hyperlink_to(RichText::new("Get a free API key from Google AI Studio").size(12.5), "https://aistudio.google.com/apikey");
                row_divider(ui);

                setting_row(
                    ui,
                    "Model",
                    "gemini-flash-latest always points to Google's current fast model. Test the connection to choose another.",
                    |ui| {
                        let checking = self.ai_models_rx.is_some();
                        list = ui
                            .add_enabled_ui(!checking, |ui| small_button(ui, if checking { "Checking…" } else { "Test connection" }).clicked())
                            .inner;
                        egui::ComboBox::from_id_salt("ai-model")
                            .selected_text(self.settings.ai_model.clone())
                            .width(170.0)
                            .show_ui(ui, |ui| {
                                let models = std::iter::once(ai::DEFAULT_MODEL.to_string()).chain(self.ai_models.iter().cloned());
                                for model in models {
                                    ui.selectable_value(&mut self.settings.ai_model, model.clone(), model);
                                }
                            });
                    },
                );
                row_divider(ui);

                setting_toggle(
                    ui,
                    &mut self.settings.ai_send_text,
                    "Send the text of scripts",
                    "Lets Gemini read scripts and other text files. Turn off to send only the file's name, type, hash, origin and local scan result.",
                );
                row_divider(ui);
                let send_text = self.settings.ai_send_text;
                ui.add_enabled_ui(send_text, |ui| {
                    setting_row(
                        ui,
                        "Most text sent per file",
                        "Longer files are cut off at this size, and Gemini is told the text is incomplete.",
                        |ui| {
                            ui.add(egui::DragValue::new(&mut self.settings.ai_max_text_kb).range(8..=2048).suffix(" KB"));
                        },
                    );
                });
            });
        });
        if save {
            self.save_api_key();
        }
        if remove {
            self.settings.ai_key_protected = None;
            self.notify("Saved API key removed", true);
        }
        if list {
            self.fetch_models(ctx);
        }
    }

    /// Windows Security settings that block threats as they run, with the
    /// switches and administrator fixes Phalanx can apply.
    fn security_card(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        let mut recheck = false;
        let mut open = None;
        let mut confirm = None;
        let mut toggle = None;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "Windows protection status");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if self.posture_rx.is_some() {
                        spinner(ui);
                    } else {
                        recheck = small_button(ui, "Check again").clicked();
                    }
                    if let Some(t) = &self.posture_checked {
                        small(ui, format!("checked {t}"));
                    }
                });
            });
            ui.add_space(4.0);
            let Some(checks) = &self.security else {
                ui.horizontal(|ui| {
                    spinner(ui);
                    muted(ui, "Reading Windows Security settings…");
                });
                return;
            };
            if let Some(score) = posture::score(checks) {
                let on = checks.iter().filter(|c| c.status == Status::Good && c.weight > 0).count();
                ui.horizontal(|ui| {
                    score_badge(ui, score.percent);
                    ui.vertical(|ui| {
                        let issues = checks.iter().filter(|c| matches!(c.status, Status::Risk | Status::Attention)).count();
                        let title = match issues {
                            0 => "Your Windows protections are on".to_string(),
                            n => format!("{n} setting(s) need attention"),
                        };
                        ui.label(RichText::new(title).size(16.0).strong().color(theme().text));
                        let unknown = if score.unknown > 0 { format!(" {} could not be read.", score.unknown) } else { String::new() };
                        muted(ui, format!("{on} of {} scored protections are on.{unknown}", score.scored));
                    });
                });
                ui.add_space(6.0);
            }
            let rank = |s: Status| match s {
                Status::Risk => 0,
                Status::Attention => 1,
                Status::Unknown => 2,
                Status::Good => 3,
                Status::Info => 4,
            };
            let mut sorted: Vec<&Check> = checks.iter().collect();
            sorted.sort_by_key(|c| (rank(c.status), std::cmp::Reverse(c.weight)));
            for check in sorted {
                row_divider(ui);
                match check_row(ui, check, false) {
                    Some(CheckAction::OpenSettings) => open = Some(check.link),
                    Some(CheckAction::ApplyFix) => confirm = check.fix,
                    Some(CheckAction::Toggle(protective)) => toggle = check.toggle.map(|t| (t, protective)),
                    None => {}
                }
            }
            row_divider(ui);
            let idle = self.fix_rx.is_none();
            setting_row(
                ui,
                "Microsoft Defender Offline scan",
                "Restarts the PC and scans before Windows starts, reaching malware that hides while Windows runs. Recommended after an account takeover or an infostealer infection.",
                |ui| {
                    if ui.add_enabled_ui(idle, |ui| small_button(ui, "Run offline scan…").clicked()).inner {
                        confirm = Some(posture::OFFLINE_SCAN);
                    }
                },
            );
        });
        if recheck {
            self.refresh_posture(ctx);
        }
        if let Some(link) = open {
            self.open_link(link);
        }
        if confirm.is_some() {
            self.pending_fix = confirm;
        }
        if let Some((t, protective)) = toggle {
            self.apply_toggle(ctx, t, protective);
        }
    }

    /// The administrator fix popup: asks first (with the exact command),
    /// stays up while it runs, and explains when Windows accepted the
    /// command but the setting did not change.
    fn fix_dialog(&mut self, ctx: &egui::Context) {
        let running = self.fix_rx.as_ref().map(|_| ());
        if let Some(note) = self.fix_note.clone().filter(|_| running.is_none() && self.pending_fix.is_none()) {
            let choice = dialog(ctx, "fix-note", "The setting did not change", false, |ui| {
                ui.add(egui::Label::new(RichText::new(note).color(theme().text)).wrap());
                ui.add_space(10.0);
                primary_button(ui, "OK").clicked().then_some(DialogChoice::Confirm)
            });
            if choice.is_some() {
                self.fix_note = None;
            }
            return;
        }
        let Some(fix) = self.pending_fix.or(self.running_fix) else { return };
        let restarts = fix == posture::OFFLINE_SCAN;
        let title = if restarts { "Run Microsoft Defender Offline scan?" } else { "Change this Windows setting?" };
        let run = if restarts { danger_button("Restart and scan") } else { egui::Button::new(RichText::new("Run as administrator").strong()) };
        let busy = running.is_some();
        let choice = dialog(ctx, "fix-confirm", title, busy, |ui| admin_command_body(ui, fix.effect, Some(fix.command), run, busy));
        match choice {
            Some(DialogChoice::Confirm) => {
                self.pending_fix = None;
                self.apply_fix(ctx, fix);
            }
            Some(DialogChoice::Cancel) => self.pending_fix = None,
            None => {}
        }
    }

    fn privacy_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Privacy");
        let Some(checks) = self.privacy.clone() else {
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    spinner(ui);
                    muted(ui, "Reading privacy settings…");
                });
            });
            return;
        };
        let mut recheck = false;
        let mut open = None;
        let mut confirm = None;
        let mut toggle = None;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                match posture::score(&checks) {
                    Some(score) => {
                        score_badge(ui, score.percent);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(format!("Privacy level: {}", posture::level(score.percent))).size(18.0).strong().color(theme().text));
                            let private = checks.iter().filter(|c| c.status == Status::Good && c.weight > 0).count();
                            let unknown = if score.unknown > 0 { format!(" {} could not be read.", score.unknown) } else { String::new() };
                            muted(ui, format!("{private} of {} scored settings are private.{unknown}", score.scored));
                            small(ui, "More important settings count for more. Phalanx can switch most of them for you; each also links to the Windows page where you can change it.");
                        });
                    }
                    None => {
                        ui.label(RichText::new("Privacy level unknown").size(18.0).strong().color(theme().text));
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                    if self.posture_rx.is_some() {
                        spinner(ui);
                    } else {
                        recheck = small_button(ui, "Check again").clicked();
                    }
                });
            });
        });

        const GROUPS: &[(&str, &str, &[&str])] = &[
            (
                "Advertising and tracking",
                "Settings that let Microsoft and apps build a profile of you for ads and suggestions.",
                &["advertising_id", "tailored", "language_list", "track_launches", "suggested_content", "start_suggestions"],
            ),
            ("Diagnostics", "What Windows reports back to Microsoft about how you use your PC.", &["diagnostics", "feedback"]),
            (
                "Speech, typing and search",
                "Features that send what you say, type or search for to Microsoft's cloud.",
                &["online_speech", "typing", "web_search", "cloud_search"],
            ),
            ("App permissions", "Sensors apps can ask to use.", &["location", "camera", "microphone"]),
        ];
        for (title, description, ids) in GROUPS {
            let items: Vec<&Check> = ids.iter().filter_map(|id| checks.iter().find(|c| c.id == *id)).collect();
            if items.is_empty() {
                continue;
            }
            ui.add_space(14.0);
            card(ui, |ui| {
                group_title(ui, title, description);
                for (i, check) in items.into_iter().enumerate() {
                    if i > 0 {
                        row_divider(ui);
                    }
                    match check_row(ui, check, true) {
                        Some(CheckAction::OpenSettings) => open = Some(check.link),
                        Some(CheckAction::ApplyFix) => confirm = check.fix,
                        Some(CheckAction::Toggle(protective)) => toggle = check.toggle.map(|t| (t, protective)),
                        None => {}
                    }
                }
            });
        }
        if recheck {
            self.refresh_posture(ctx);
        }
        if let Some(link) = open {
            self.open_link(link);
        }
        if confirm.is_some() {
            self.pending_fix = confirm;
        }
        if let Some((t, protective)) = toggle {
            self.apply_toggle(ctx, t, protective);
        }
    }

    fn inspect_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "AI Inspect");
        let has_key = self.settings.ai_key_protected.is_some() || std::env::var("GEMINI_API_KEY").is_ok_and(|k| !k.trim().is_empty());
        let ready = self.settings.ai_enabled && has_key;
        if !ready {
            let mut open_settings = false;
            card(ui, |ui| {
                section_title(ui, "Set up AI inspection");
                muted(
                    ui,
                    if self.settings.ai_enabled {
                        "Add a free Gemini API key in Settings to inspect files. You can still check a file locally below."
                    } else {
                        "AI inspection is off. Turn it on and add a free Gemini API key in Settings. You can still check a file locally below."
                    },
                );
                ui.add_space(6.0);
                open_settings = primary_button(ui, "Open AI settings").clicked();
            });
            if open_settings {
                self.page = Page::Settings;
                self.settings_tab = SettingsTab::Ai;
            }
            ui.add_space(14.0);
        }

        let mut pick: Option<PathBuf> = None;
        let mut choose = false;
        card(ui, |ui| {
            section_title(ui, "Choose a file");
            muted(ui, "Pick a file or drop one onto this page. It is checked on this PC first, and nothing is sent until you press Inspect.");
            ui.add_space(6.0);
            choose = secondary_button(ui, "Choose a file…").clicked();
            let mut recent: Vec<&PathBuf> = Vec::new();
            for item in &self.activity {
                if let (ActivityKind::Risky | ActivityKind::Threat, Some(p)) = (item.kind, &item.path)
                    && !recent.contains(&p) && p.is_file()
                {
                    recent.push(p);
                }
            }
            if !recent.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new("Recently found by real-time protection").strong().color(theme().text));
                for p in recent.into_iter().take(6) {
                    ui.horizontal(|ui| {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if small_button(ui, "Inspect").clicked() {
                                pick = Some(p.clone());
                            }
                            truncated(ui, p.display().to_string(), theme().text, 13.0);
                        });
                    });
                }
            }
        });
        if choose {
            pick = rfd::FileDialog::new().pick_file();
        }
        if let Some(path) = pick {
            self.inspect_file(ctx, path);
        }
        ui.add_space(14.0);

        if self.inspect.preparing.is_some() {
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    spinner(ui);
                    muted(ui, "Checking the file on this PC…");
                });
            });
            return;
        }
        let evidence = match &self.inspect.evidence {
            None => return,
            Some(Err(e)) => {
                let e = e.clone();
                card(ui, |ui| {
                    ui.label(RichText::new("Could not read the file").strong().color(theme().red));
                    ui.add(egui::Label::new(RichText::new(e).color(theme().muted)).wrap());
                });
                return;
            }
            Some(Ok(e)) => e.clone(),
        };

        let running = self.inspect.running.is_some();
        let mut send = false;
        card(ui, |ui| {
            path_lines(ui, &evidence.path.display().to_string());
            facts(
                ui,
                &[
                    ("Type", evidence.file_type.clone()),
                    ("Size", fmt_bytes(evidence.size as i64)),
                    ("SHA-256", format!("{}…", &evidence.sha256[..16])),
                    ("From", evidence.origin.as_ref().and_then(|o| o.host()).unwrap_or("unknown").to_string()),
                ],
            );
            if let Some(d) = evidence.risk.as_ref().and_then(|r| r.disguise.as_ref()) {
                notice(ui, theme().amber, &format!("Disguised name: {d}."));
            }
            ui.add_space(4.0);
            match &evidence.local_findings {
                None => small(ui, "Local scan: skipped because signatures were still loading."),
                Some(f) if f.is_empty() => {
                    ui.horizontal_wrapped(|ui| {
                        status_dot(ui, theme().green, 4.0);
                        ui.label(RichText::new("Local scan: no known threats.").color(theme().text));
                        small(ui, "That does not prove a file is safe.");
                    });
                }
                Some(f) => {
                    for x in f {
                        ui.horizontal_wrapped(|ui| {
                            badge(ui, &x.category.as_str().to_uppercase(), category_color(x.category));
                            ui.label(RichText::new(&x.threat).strong().color(theme().text));
                            small(ui, format!("found by {}", x.source.as_str()));
                        });
                    }
                }
            }
            ui.add_space(8.0);
            ui.label(RichText::new("What will be sent to Google Gemini").strong().color(theme().text));
            for line in evidence.sent_summary() {
                ui.horizontal_wrapped(|ui| {
                    status_dot(ui, theme().muted, 2.5);
                    ui.add(egui::Label::new(RichText::new(line).size(12.5).color(theme().muted)).wrap());
                });
            }
            small(ui, format!("Model: {}", self.settings.ai_model));
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                send = ui.add_enabled_ui(ready && !running, |ui| primary_button(ui, "Inspect with Gemini").clicked()).inner;
                if !ready {
                    small(ui, "Set up AI inspection to send it.");
                }
            });
        });
        if send {
            self.run_inspection(ctx);
        }
        ui.add_space(14.0);

        if let Some((_, started)) = &self.inspect.running {
            let elapsed = started.elapsed();
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    spinner(ui);
                    ui.label(RichText::new("Gemini is reading the file…").size(16.0).strong().color(theme().text));
                    small(ui, fmt_duration(elapsed));
                });
            });
            return;
        }
        let mut again = false;
        let mut quarantine = false;
        match &self.inspect.report {
            None => {}
            Some(Err(e)) => {
                card(ui, |ui| {
                    ui.label(RichText::new("The inspection failed").strong().color(theme().red));
                    ui.add(egui::Label::new(RichText::new(e).color(theme().muted)).wrap());
                    ui.add_space(6.0);
                    again = secondary_button(ui, "Try again").clicked();
                });
            }
            Some(Ok(report)) => {
                let a = &report.assessment;
                let color = verdict_color(a.verdict);
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (rect, _) = ui.allocate_exact_size(Vec2::splat(46.0), egui::Sense::hover());
                        ui.painter().circle_filled(rect.center(), 23.0, color.gamma_multiply(0.18));
                        ui.painter().circle_filled(rect.center(), 9.0, color);
                        ui.add_space(8.0);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(a.verdict.label()).size(20.0).strong().color(color));
                            muted(ui, format!("{} confidence · {}", capitalize(&a.confidence), evidence.file_name));
                        });
                    });
                    ui.add_space(6.0);
                    ui.add(egui::Label::new(RichText::new(&a.summary).color(theme().text)).wrap());
                    if a.manipulation_attempt {
                        ui.add_space(4.0);
                        notice(ui, theme().red, "The file contains text aimed at the AI or at security scanners, trying to influence the verdict. That is a strong sign of malicious intent.");
                    }
                    let local_hit = evidence.local_findings.as_ref().is_some_and(|f| !f.is_empty());
                    if local_hit && a.verdict == ai::Verdict::Safe {
                        ui.add_space(4.0);
                        notice(ui, theme().amber, "The local scanner flagged this file even though the AI did not. Trust the scanner's detection.");
                    }
                    if !a.behaviors.is_empty() {
                        ui.add_space(8.0);
                        ui.label(RichText::new("What it does").strong().color(theme().text));
                        for b in &a.behaviors {
                            ui.horizontal_wrapped(|ui| {
                                badge(ui, &b.severity.to_uppercase(), severity_color(&b.severity));
                                ui.add(egui::Label::new(RichText::new(&b.title).strong().color(theme().text)).wrap());
                            });
                            ui.add(egui::Label::new(RichText::new(&b.evidence).monospace().size(12.0).color(theme().muted)).wrap());
                            ui.add_space(4.0);
                        }
                    }
                    if !a.recommendation.is_empty() {
                        ui.add_space(4.0);
                        ui.label(RichText::new("What to do").strong().color(theme().text));
                        ui.add(egui::Label::new(RichText::new(&a.recommendation).color(theme().text)).wrap());
                    }
                    ui.add_space(8.0);
                    let tokens = match (report.prompt_tokens, report.output_tokens) {
                        (Some(i), Some(o)) => format!(" · {i} tokens in, {o} out"),
                        _ => String::new(),
                    };
                    small(
                        ui,
                        format!(
                            "{}{tokens} · {}. AI can be wrong or misled by the file; \"likely safe\" is not a guarantee.",
                            report.model,
                            fmt_duration(Duration::from_millis(report.elapsed_ms as u64))
                        ),
                    );
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        let flagged = a.verdict != ai::Verdict::Safe || local_hit;
                        if flagged && evidence.path.is_file() {
                            quarantine = ui.add(danger_button("Quarantine this file")).clicked();
                        }
                        again = secondary_button(ui, "Inspect again").clicked();
                    });
                });
            }
        }
        if again {
            self.run_inspection(ctx);
        }
        if quarantine {
            self.quarantine_inspected();
        }
    }

    /// The latest notice, floating over the top of the page. It drops in on a
    /// spring, so a new notice arriving mid-animation carries on smoothly, and
    /// fades out at the end of its life.
    fn toast_overlay(&mut self, ui: &mut Ui) {
        let Some(toast) = &self.toast else { return };
        let age = toast.shown.elapsed().as_secs_f32();
        if age > TOAST_LIFE {
            self.toast = None;
            return;
        }
        let ctx = ui.ctx().clone();
        let id = Id::new("toast");
        let key: Option<Instant> = ctx.data(|d| d.get_temp(id.with("shown")));
        if key != Some(toast.shown) {
            ctx.data_mut(|d| d.insert_temp(id.with("shown"), toast.shown));
            motion::set(&ctx, id, 0.0);
        }
        let enter = motion::spring(&ctx, id, 1.0, 0.45, 0.8);
        let exit = ((TOAST_LIFE - age) / 0.35).clamp(0.0, 1.0);
        let panel = ui.max_rect();
        let color = if toast.ok { theme().green } else { theme().red };
        egui::Area::new(id)
            .order(egui::Order::Foreground)
            .pivot(Align2::CENTER_TOP)
            .fixed_pos(pos2(panel.center().x, panel.top() - 30.0 + 34.0 * enter))
            .interactable(false)
            .show(&ctx, |ui| {
                ui.multiply_opacity(enter.clamp(0.0, 1.0) * exit);
                egui::Frame::new()
                    .fill(theme().toast)
                    .stroke(Stroke::new(1.0, theme().toast_edge))
                    .corner_radius(20.0)
                    .inner_margin(Margin::symmetric(16, 10))
                    .shadow(egui::Shadow { offset: [0, 10], blur: 28, spread: 0, color: theme().shadow })
                    .show(ui, |ui| {
                        ui.set_max_width((panel.width() - 40.0).clamp(200.0, 560.0));
                        ui.horizontal(|ui| {
                            status_dot(ui, color, 3.5);
                            ui.add(egui::Label::new(RichText::new(&toast.text).color(theme().text)).wrap());
                        });
                    });
            });
        let next = if exit < 1.0 { 16 } else { ((TOAST_LIFE - 0.35 - age).max(0.0) * 1000.0) as u64 };
        ctx.request_repaint_after(Duration::from_millis(next));
    }
}

/// Returns true when "Inspect with AI" was clicked.
fn detection_card(ui: &mut Ui, row: &mut ResultRow, ai_enabled: bool) -> bool {
    let worst = row.report.worst().clone();
    let color = category_color(worst.category);
    let mut inspect = false;
    egui::Frame::new()
        .fill(theme().card)
        .stroke(Stroke::new(1.0, theme().hairline))
        .corner_radius(14.0)
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                let selectable = row.report.action == "reported";
                ui.add_enabled(selectable, egui::Checkbox::without_text(&mut row.selected));
                badge(ui, &worst.category.as_str().to_uppercase(), color);
                ui.label(RichText::new(&worst.threat).font(semibold(15.0)).color(theme().text));
                let (text, c) = if row.report.action.starts_with("quarantined") {
                    ("Quarantined", theme().green)
                } else if row.report.action.starts_with("quarantine failed") {
                    ("Quarantine failed", theme().red)
                } else {
                    ("Not removed", theme().muted)
                };
                ui.label(RichText::new(text).size(12.5).color(c));
            });
            path_lines(ui, &row.report.path);
            for f in &row.report.findings {
                truncated(ui, format!("{} · {}", f.source.as_str(), f.details), theme().muted, 12.0);
            }
            if row.report.action.starts_with("quarantine failed") {
                truncated(ui, row.report.action.clone(), theme().red, 12.0);
            }
            if ai_enabled && !row.report.action.starts_with("quarantined") {
                inspect = small_button(ui, "Inspect with AI").clicked();
            }
        });
    inspect
}

/// Scans recorded by real-time protection rather than started by the user.
fn is_protection_kind(kind: &str) -> bool {
    kind == "watch" || kind == "process" || kind == "command"
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default()
}

fn quick_scan_targets() -> Vec<PathBuf> {
    let mut targets = Vec::new();
    if let Some(home) = home_dir() {
        for sub in ["Downloads", "Desktop", "Documents"] {
            targets.push(home.join(sub));
        }
    }
    targets.push(std::env::temp_dir());
    targets.retain(|p| p.exists());
    targets
}
