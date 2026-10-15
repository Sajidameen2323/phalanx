//! Page layouts. Everything here adapts to the window width: tiles reflow,
//! button rows wrap, long text truncates, and the sidebar narrows.

use super::*;
use eframe::egui::{Align, Color32, FontId, Layout, Margin, RichText, Stroke, Ui, Vec2};
use threat_scanner::posture::Status;
use widgets::*;

impl App {
    pub(super) fn draw(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        let narrow = ui.available_width() < 820.0;
        egui::Panel::left("nav")
            .exact_size(if narrow { 168.0 } else { 214.0 })
            .resizable(false)
            .frame(egui::Frame::new().fill(SIDEBAR).inner_margin(Margin::same(12)))
            .show(ui, |ui| self.sidebar(ui));

        let margin = if narrow { 16 } else { 28 };
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG).inner_margin(Margin::same(margin)))
            .show(ui, |ui| {
                self.toast_bar(ui);
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| match self.page {
                        Page::Dashboard => self.dashboard(ui, ctx),
                        Page::Scan => self.scan_page(ui, ctx),
                        Page::Protection => self.protection_page(ui, ctx),
                        Page::Web => self.web_page(ui, ctx),
                        Page::Inspect => self.inspect_page(ui, ctx),
                        Page::Privacy => self.privacy_page(ui, ctx),
                        Page::Quarantine => self.quarantine_page(ui),
                        Page::History => self.history_page(ui),
                        Page::Settings => self.settings_page(ui, ctx),
                    });
            });
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add(egui::Image::new(egui::load::SizedTexture::new(self.logo.id(), Vec2::splat(38.0))));
            ui.add_space(2.0);
            ui.label(RichText::new(APP_TITLE.to_uppercase()).size(17.0).strong().extra_letter_spacing(1.5).color(TEXT));
        });
        ui.add_space(20.0);

        let quarantined = self.quarantine.len();
        let protection = if self.watch.running { Some(("on".to_string(), GREEN)) } else { None };
        let inspecting = self.inspect.running.is_some() || self.inspect.preparing.is_some();
        let privacy = self
            .privacy
            .as_deref()
            .and_then(posture::score)
            .map(|s| (s.percent.to_string(), score_color(s.percent)));
        let items = [
            (Page::Dashboard, "Dashboard", None),
            (Page::Scan, "Scan", self.job.as_ref().map(|_| ("running".to_string(), ACCENT))),
            (Page::Protection, "Protection", protection),
            (Page::Web, "Web protection", self.web.running().then(|| ("on".to_string(), GREEN))),
            (Page::Inspect, "AI Inspect", inspecting.then(|| ("working".to_string(), ACCENT))),
            (Page::Privacy, "Privacy", privacy),
            (Page::Quarantine, "Quarantine", (quarantined > 0).then(|| (quarantined.to_string(), ACCENT))),
            (Page::History, "History", None),
            (Page::Settings, "Settings", None),
        ];
        for (page, label, badge) in items {
            let active = self.page == page;
            let text = RichText::new(label).size(14.5).color(if active { TEXT } else { MUTED });
            let button = egui::Button::new(text)
                .fill(if active { CARD } else { Color32::TRANSPARENT })
                .stroke(Stroke::NONE)
                .corner_radius(8.0)
                .min_size(Vec2::new(ui.available_width(), 38.0));
            let response = ui.add(button);
            if let Some((badge, color)) = badge {
                let pos = response.rect.right_center() - Vec2::new(14.0, 0.0);
                ui.painter().text(pos, egui::Align2::RIGHT_CENTER, badge, FontId::proportional(12.0), color);
            }
            if response.clicked() {
                self.page = page;
                self.pending_delete = None;
            }
        }

        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            let counts = match &self.signatures {
                _ if self.engine_rx.is_some() => "loading signatures…".to_string(),
                Ok((rules, hashes)) => format!("{rules} rules · {hashes} hashes"),
                Err(_) => "signatures failed to load".to_string(),
            };
            let updated = self
                .manifest
                .last_success()
                .map(|t| format!("updated {}", short_time(t)))
                .unwrap_or_else(|| "signatures never updated".into());
            small(ui, updated);
            small(ui, counts);
            small(ui, format!("v{}", env!("CARGO_PKG_VERSION")));
        });
    }

    fn dashboard(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Dashboard", "Scan files and folders for malware, potentially unwanted programs and hacking tools.");

        // Threats from any scan (manual or folder protection) in the last 7
        // days that were not quarantined need attention.
        let week_ago = (chrono::Local::now() - chrono::Duration::days(7)).to_rfc3339();
        let unresolved: Vec<&ScanRow> = self
            .scans
            .iter()
            .filter(|s| s.started_at >= week_ago && s.detections > s.quarantined)
            .collect();
        let last_manual = self.scans.iter().find(|s| s.finished_at.is_some() && s.kind != "watch");
        let (color, title, detail) = if let Some(latest) = unresolved.first() {
            let count: i64 = unresolved.iter().map(|s| s.detections - s.quarantined).sum();
            let found_by = if latest.kind == "watch" { "folder protection" } else { "a scan" };
            (
                RED,
                "Threats need your review",
                format!(
                    "{count} threat(s) found in the last 7 days were not removed. Latest found by {found_by} on {}. Review them in History.",
                    short_time(&latest.started_at)
                ),
            )
        } else {
            match last_manual {
                None => (AMBER, "No scans yet", "Run your first scan to check this PC.".to_string()),
                Some(s) => (
                    GREEN,
                    "No threats found",
                    format!("Last scan {} checked {} files.", short_time(&s.started_at), s.files_scanned),
                ),
            }
        };
        let mut open_protection = false;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(46.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 23.0, color.gamma_multiply(0.18));
                ui.painter().circle_filled(rect.center(), 9.0, color);
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).size(20.0).strong().color(TEXT));
                    muted(ui, detail);
                });
            });
            ui.add_space(6.0);
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                if self.watch.running {
                    status_dot(ui, GREEN, 4.5);
                    ui.label(format!(
                        "Folder protection is on: watching {} folder(s), {} new file(s) checked",
                        self.watch.watching, self.watch.files_checked
                    ));
                } else {
                    status_dot(ui, MUTED, 4.5);
                    ui.label("Folder protection is off.");
                    open_protection = small_button(ui, "Set up").clicked();
                }
            });
            if let Some(checks) = &self.security {
                let risks = checks.iter().filter(|c| c.status == Status::Risk).count();
                let issues = risks + checks.iter().filter(|c| c.status == Status::Attention).count();
                ui.horizontal_wrapped(|ui| {
                    if issues == 0 {
                        status_dot(ui, GREEN, 4.5);
                        ui.label("Windows protections are on.");
                    } else {
                        status_dot(ui, if risks > 0 { RED } else { AMBER }, 4.5);
                        ui.label(format!("{issues} Windows protection setting(s) need attention."));
                        open_protection |= small_button(ui, "Review").clicked();
                    }
                });
            }
        });
        if open_protection {
            self.page = Page::Protection;
        }
        ui.add_space(14.0);

        let mut update_clicked = false;
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.vertical(|ui| {
                    section_title(ui, "Signatures");
                    let counts = match &self.signatures {
                        _ if self.engine_rx.is_some() => "loading…".into(),
                        Ok((r, h)) => format!("{r} rules · {h} known-bad hashes"),
                        Err(_) => "failed to load".into(),
                    };
                    match self.manifest.last_success() {
                        Some(t) => muted(ui, format!("Updated {} · {counts}", short_time(t))),
                        None => {
                            ui.label(RichText::new("Never updated: only the small built-in set is active.").color(AMBER));
                        }
                    }
                });
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if let Some(job) = &self.updating {
                    ui.add(egui::Spinner::new().color(ACCENT));
                    truncated(ui, job.step.clone(), MUTED, 13.0);
                } else {
                    update_clicked = primary_button(ui, "Update now").clicked();
                }
            });
        });
        if update_clicked {
            self.start_update(ctx, false);
        }
        ui.add_space(14.0);

        let this_month = chrono::Local::now().format("%Y-%m").to_string();
        let month = self.months.first().filter(|m| m.month == this_month);
        stat_tiles(
            ui,
            &[
                ("Scans this month", month.map_or(0, |m| m.scans).to_string()),
                ("Files scanned", month.map_or(0, |m| m.files_scanned).to_string()),
                ("Threats found", month.map_or(0, |m| m.detections).to_string()),
                ("In quarantine", self.quarantine.len().to_string()),
            ],
        );
        ui.add_space(14.0);

        section_title(ui, "Start a scan");
        ui.add_space(4.0);
        self.scan_modes(ui, ctx);
        ui.horizontal_wrapped(|ui| {
            let threads = system::worker_threads(self.settings.performance);
            small(
                ui,
                format!(
                    "Performance: {} ({threads} thread(s){}). Change it in Settings.",
                    self.settings.performance.label(),
                    if self.settings.performance.background() { ", background priority" } else { "" }
                ),
            );
            if small_button(ui, "Inspect a file with AI…").clicked() {
                if let Some(file) = rfd::FileDialog::new().pick_file() {
                    self.inspect_file(ctx, file);
                }
            }
        });
    }

    /// The three ways to start a scan, as tiles that reflow with the width.
    fn scan_modes(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        #[derive(Clone, Copy)]
        enum Mode {
            Quick,
            Full,
            Custom,
        }
        let busy = self.job.is_some() || self.queued_scan.is_some();
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
                        ui.set_min_height(132.0);
                        let (title, text) = match mode {
                            Mode::Quick => ("Quick scan", "Downloads, Desktop, Documents and the temp folder, where downloaded threats usually land. Usually a few minutes.".to_string()),
                            Mode::Full => ("Full scan", format!("Every file on your internal drives ({drive_list}). Can take an hour or more; you can keep working.")),
                            Mode::Custom => ("Custom scan", "Choose folders or files to check. You can also drop them onto this window.".to_string()),
                        };
                        section_title(ui, title);
                        // Columns justify wrapped text; a plain top-down layout does not.
                        ui.with_layout(Layout::top_down(Align::Min), |ui| {
                            ui.add(egui::Label::new(RichText::new(text).size(12.5).color(MUTED)).wrap());
                        });
                        ui.add_space(6.0);
                        ui.add_enabled_ui(!busy, |ui| {
                            ui.horizontal_wrapped(|ui| match mode {
                                Mode::Quick => {
                                    if primary_button(ui, "Start quick scan").clicked() {
                                        start = Some((quick_scan_targets(), "quick"));
                                    }
                                }
                                Mode::Full => {
                                    if secondary_button(ui, "Start full scan").clicked() {
                                        start = Some((drives.clone(), "full"));
                                    }
                                }
                                Mode::Custom => {
                                    pick_folder = secondary_button(ui, "Folder…").clicked();
                                    pick_files = secondary_button(ui, "Files…").clicked();
                                }
                            });
                        });
                    });
                }
            });
        }
        if busy {
            ui.add_space(4.0);
            small(ui, "A scan is running. Cancel it on the Scan page to start another.");
        }
        if pick_folder {
            if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                start = Some((vec![dir], "custom"));
            }
        }
        if pick_files {
            if let Some(files) = rfd::FileDialog::new().pick_files() {
                start = Some((files, "custom"));
            }
        }
        if let Some((paths, kind)) = start {
            self.start_scan(ctx, paths, kind);
        }
    }

    fn scan_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Scan", "Choose a scan, follow its progress and review what it found.");

        if let Some(job) = &self.job {
            let mut cancel = false;
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(24.0).color(ACCENT));
                    let state = if job.cancel.load(Ordering::Relaxed) { "Cancelling…" } else { "Scanning…" };
                    ui.label(RichText::new(state).size(18.0).strong().color(TEXT));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        cancel = secondary_button(ui, "Cancel").clicked();
                    });
                });
                truncated(ui, job.targets.clone(), MUTED, 13.0);
                ui.add_space(8.0);
                facts(
                    ui,
                    &[
                        ("Files", job.files.to_string()),
                        ("Data", fmt_bytes(job.bytes)),
                        ("Threats", self.results.len().to_string()),
                        ("Elapsed", fmt_duration(job.started.elapsed())),
                        ("Threads", job.threads.to_string()),
                        ("Type", job.kind.clone()),
                    ],
                );
                ui.add_space(4.0);
                truncated(ui, job.current.clone(), MUTED, 12.0);
            });
            if cancel {
                job.cancel.store(true, Ordering::Relaxed);
            }
            ui.add_space(14.0);
        } else if self.queued_scan.is_some() {
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(24.0).color(ACCENT));
                    ui.label(RichText::new("Loading signatures…").size(18.0).strong().color(TEXT));
                });
                muted(ui, "The scan starts as soon as the rules are compiled.");
            });
            return;
        } else if let Some(done) = &self.finished {
            let (color, title) = match (done.cancelled, done.infected) {
                (true, _) => (AMBER, "Scan cancelled".to_string()),
                (false, 0) => (GREEN, "No threats found".to_string()),
                (false, n) => (RED, format!("{n} threat(s) found")),
            };
            let mut new_scan = false;
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    status_dot(ui, color, 6.0);
                    ui.label(RichText::new(title).size(18.0).strong().color(TEXT));
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

    fn protection_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(
            ui,
            "Protection",
            "Watch folders for new files and scan them automatically, at low priority, after they finish downloading.",
        );

        self.security_card(ui, ctx);
        ui.add_space(14.0);

        let mut toggle = false;
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                let (color, title) = match (self.settings.watch_enabled, self.watch.running) {
                    (true, true) => (GREEN, "Folder protection is on"),
                    (true, false) if self.settings.watch_folders.is_empty() => (AMBER, "Add a folder to start protection"),
                    (true, false) => (AMBER, "Starting…"),
                    (false, _) => (MUTED, "Folder protection is off"),
                };
                status_dot(ui, color, 6.0);
                ui.label(RichText::new(title).size(18.0).strong().color(TEXT));
            });
            if self.watch.running {
                facts(
                    ui,
                    &[
                        ("Watching", format!("{} folder(s)", self.watch.watching)),
                        ("New files checked", self.watch.files_checked.to_string()),
                        ("Threats", self.watch.threats.to_string()),
                        ("Running since", self.watch.since.clone().unwrap_or_default()),
                    ],
                );
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
            muted(ui, "Includes subfolders. Partial downloads (.crdownload, .part…) are scanned once they are complete.");
            ui.add_space(6.0);
            if self.settings.watch_folders.is_empty() {
                small(ui, "No folders yet.");
            }
            for (i, folder) in self.settings.watch_folders.iter().enumerate() {
                let failed = self.watch.failed.iter().find(|(f, _)| f == folder);
                ui.horizontal(|ui| {
                    status_dot(ui, if failed.is_some() { RED } else if self.watch.running { GREEN } else { MUTED }, 4.0);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if small_button(ui, "Remove").clicked() {
                            remove = Some(i);
                        }
                        truncated(ui, folder.display().to_string(), TEXT, 13.5);
                    });
                });
                if let Some((_, e)) = failed {
                    small(ui, format!("Cannot watch: {e}"));
                }
            }
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                add = secondary_button(ui, "Add folder…").clicked();
                if let Some(downloads) = home_dir().map(|h| h.join("Downloads")) {
                    if downloads.is_dir()
                        && !self.settings.watch_folders.contains(&downloads)
                        && secondary_button(ui, "Add Downloads").clicked()
                    {
                        self.settings.watch_folders.push(downloads);
                    }
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
            section_title(ui, "How it behaves");
            muted(ui, if self.settings.risky_file_alerts {
                "Programs, scripts and disk images are announced the moment they land, before you open them, and their scan result follows a few seconds later."
            } else {
                "Alerts for new programs and scripts are off; turn them on in Settings > General."
            });
            muted(ui, format!(
                "Runs on one background-priority thread. Threat notifications are {}. {}",
                if self.settings.notifications { "on" } else { "off" },
                if self.autostart {
                    "Starts in the tray when you sign in to Windows."
                } else {
                    "Turn on \"Start with Windows\" in Settings to protect from sign-in."
                }
            ));
            muted(ui, format!("Files that arrive while {APP_TITLE} is closed are checked the next time it starts."));
        });
        ui.add_space(14.0);

        let ai_enabled = self.settings.ai_enabled;
        let mut inspect = None;
        card(ui, |ui| {
            section_title(ui, "Recent activity");
            if self.activity.is_empty() {
                small(ui, "Nothing yet.");
            }
            for item in self.activity.iter().take(40) {
                let color = match item.kind {
                    ActivityKind::Threat => RED,
                    ActivityKind::Risky | ActivityKind::Problem => AMBER,
                    ActivityKind::Info => MUTED,
                };
                ui.horizontal(|ui| {
                    status_dot(ui, color, 3.5);
                    ui.label(RichText::new(&item.time).size(12.0).color(MUTED));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if let (true, Some(path)) = (ai_enabled, &item.path) {
                            if path.is_file() && small_button(ui, "Inspect with AI").clicked() {
                                inspect = Some(path.clone());
                            }
                        }
                        let text_color = match item.kind {
                            ActivityKind::Threat => RED,
                            ActivityKind::Risky => AMBER,
                            _ => TEXT,
                        };
                        ui.with_layout(Layout::left_to_right(Align::Center), |ui| truncated(ui, item.text.clone(), text_color, 13.0));
                    });
                });
                if !item.detail.is_empty() {
                    truncated(ui, item.detail.clone(), MUTED, 12.0);
                }
            }
        });
        if let Some(path) = inspect {
            self.inspect_file(ctx, path);
        }
    }

    fn quarantine_page(&mut self, ui: &mut Ui) {
        page_header(ui, "Quarantine", "Isolated files are encoded so they cannot run. Restore puts a file back exactly where it was.");
        if self.quarantine.is_empty() {
            card(ui, |ui| {
                section_title(ui, "Quarantine is empty");
                muted(ui, "Files you quarantine will appear here.");
            });
            return;
        }
        let mut action: Option<(String, bool)> = None;
        for item in &self.quarantine {
            card(ui, |ui| {
                ui.label(RichText::new(&item.threat).size(15.0).strong().color(TEXT));
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
        page_header(ui, "History", "Every scan on this PC, with what it checked, what it found and how long it took.");

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
                (HistoryFilter::Watch, "Folder protection"),
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
                HistoryFilter::Manual => s.kind != "watch",
                HistoryFilter::Watch => s.kind == "watch",
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
                    let kind_color = if s.kind == "watch" { GREEN } else { ACCENT };
                    badge(ui, &s.kind.to_uppercase(), kind_color);
                    ui.label(RichText::new(format!("#{} · {}", s.id, short_time(&s.started_at))).strong().color(TEXT));
                    let (status, color) = match (&s.finished_at, s.cancelled, s.detections) {
                        (None, _, _) => ("Incomplete".to_string(), AMBER),
                        (_, true, _) => ("Cancelled".to_string(), AMBER),
                        (_, _, 0) => ("Clean".to_string(), GREEN),
                        (_, _, n) => (format!("{n} threat(s)"), RED),
                    };
                    badge(ui, &status, color);
                });
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
                truncated(ui, s.targets.clone(), MUTED, 12.5);
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
                            truncated(ui, format!("{} · {}", d.threat, d.source), TEXT, 13.0);
                        });
                        path_lines(ui, &d.path);
                        small(ui, format!("Action: {}", d.action));
                    }
                    if !details.errors.is_empty() {
                        ui.add_space(4.0);
                        small(ui, format!("Could not read {} file(s):", s.errors));
                        for e in details.errors.iter().take(30) {
                            truncated(ui, format!("{}: {}", e.path, e.message), MUTED, 12.0);
                        }
                        if s.errors > 30 {
                            small(ui, format!("…and {} more", s.errors - 30));
                        }
                    }
                }
            });
            ui.add_space(8.0);
        }
        if let Some(id) = toggle {
            if self.expanded.remove(&id).is_none() {
                let details = self.store().and_then(|store| {
                    Ok(ScanDetails {
                        detections: store.scan_detections(id).map_err(|e| e.to_string())?,
                        errors: store.scan_errors(id).map_err(|e| e.to_string())?,
                    })
                });
                match details {
                    Ok(details) => {
                        self.expanded.insert(id, details);
                    }
                    Err(e) => self.notify(format!("Could not load scan details: {e}"), false),
                }
            }
        }
    }

    fn settings_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Settings", "Changes are saved automatically.");
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

        let engine_before = (self.settings.heuristics, self.settings.rules_dir.clone(), self.settings.hashes_file.clone());
        let mut reload = false;
        match self.settings_tab {
            SettingsTab::General => self.settings_general(ui),
            SettingsTab::Scanning => self.settings_scanning(ui),
            SettingsTab::Exclusions => self.settings_exclusions(ui),
            SettingsTab::Signatures => self.settings_signatures(ui, ctx, &mut reload),
            SettingsTab::Ai => self.settings_ai(ui, ctx),
        }
        let engine_after = (self.settings.heuristics, self.settings.rules_dir.clone(), self.settings.hashes_file.clone());
        if reload || engine_after != engine_before {
            self.reload_signatures(ctx);
        }
    }

    fn settings_general(&mut self, ui: &mut Ui) {
        let mut autostart = self.autostart;
        let has_tray = self.tray.is_some();
        card(ui, |ui| {
            group_title(ui, "Startup and background", "");
            setting_toggle(
                ui,
                &mut autostart,
                "Start with Windows",
                "Opens in the tray when you sign in, so folder protection starts automatically. Adds a per-user sign-in entry; no administrator rights are needed.",
            );
            row_divider(ui);
            ui.add_enabled_ui(has_tray, |ui| {
                setting_toggle(
                    ui,
                    &mut self.settings.close_to_tray,
                    "Keep running in the tray when the window is closed",
                    if has_tray {
                        "Folder protection keeps working with the window closed. Right-click the tray icon to quit."
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
            group_title(ui, "Notifications", "Windows notifications from folder protection. They work while the window is closed.");
            setting_toggle(
                ui,
                &mut self.settings.notifications,
                "When a threat is found",
                "Notify when folder protection detects malware, a potentially unwanted program or a hacking tool.",
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
                Ok(()) => ("Notifications pop up with this app's name and icon. A Start-menu shortcut named Phalanx is needed for that.", APP_TITLE, GREEN),
                Err(_) => (
                    "The app's name could not be registered, so Windows shows notifications as Windows PowerShell.",
                    "PowerShell",
                    AMBER,
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
            small(ui, "Folder protection always uses one background-priority thread.");
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
            setting_row(
                ui,
                "Skip files larger than",
                "Larger files are counted as skipped. Applies to scans and folder protection.",
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
            group_title(ui, "Exclusions", "Never scanned, by manual scans or folder protection. Subfolders are included.");
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
                        truncated(ui, path.display().to_string(), TEXT, 13.5);
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
        if add_file {
            if let Some(file) = rfd::FileDialog::new().pick_file() {
                if !self.settings.exclusions.contains(&file) {
                    self.settings.exclusions.push(file);
                }
            }
        }
    }

    fn settings_signatures(&mut self, ui: &mut Ui, ctx: &egui::Context, reload: &mut bool) {
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
                if self.update_check_rx.is_some() {
                    ui.add(egui::Spinner::new().color(ACCENT));
                    muted(ui, "Checking feeds for new data…");
                } else {
                    let status = match &self.update_check {
                        Some((time, r)) if r.changed.is_empty() && r.failed.is_empty() => format!("Checked at {time}: everything is up to date."),
                        Some((time, r)) if r.changed.is_empty() => format!("Checked at {time}: could not reach {}.", r.failed.join(", ")),
                        Some((time, r)) => format!("Checked at {time}: new data from {}.", r.changed.join(", ")),
                        None => match self.settings.last_update_check {
                            Some(t) => format!("Last checked {} ago.", fmt_duration(Duration::from_secs(unix_now().saturating_sub(t)))),
                            None => "Not checked yet.".to_string(),
                        },
                    };
                    muted(ui, status);
                    check_clicked = self.updating.is_none() && small_button(ui, "Check now").clicked();
                }
            });
        });
        if check_clicked {
            self.check_updates_now(ctx);
        }
        ui.add_space(14.0);
        card(ui, |ui| {
            group_title(ui, "Downloaded signatures", "");
            match &self.signatures {
                _ if self.engine_rx.is_some() => muted(ui, "Loading signatures…"),
                Ok((rules, hashes)) => muted(ui, format!("Loaded {rules} YARA rules and {hashes} known-bad hashes.")),
                Err(e) => {
                    ui.label(RichText::new(format!("Failed to load: {e}")).color(RED));
                }
            }
            ui.add_space(6.0);
            for source in update::SOURCES {
                let status = self.manifest.sources.iter().find(|s| s.name == source.name);
                ui.horizontal_wrapped(|ui| {
                    let color = match status {
                        Some(s) if s.ok => GREEN,
                        Some(_) => RED,
                        None => MUTED,
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
                    truncated(ui, s.message.clone(), if s.ok { MUTED } else { RED }, 12.0);
                }
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if let Some(job) = &self.updating {
                    ui.add(egui::Spinner::new().color(ACCENT));
                    truncated(ui, job.step.clone(), MUTED, 13.0);
                } else {
                    update_clicked = primary_button(ui, "Update now").clicked();
                }
            });
            small(ui, "Sources: YARA Forge (licences vary per rule) and abuse.ch MalwareBazaar, ThreatFox and URLhaus (CC0). Only feeds with new data are downloaded, and downloads are validated before they replace your current signatures. Web protection picks up new web rules automatically.");
        });
        if update_clicked {
            self.start_update(ctx, false);
        }
        ui.add_space(14.0);

        card(ui, |ui| {
            group_title(ui, "Your own signatures", "These are never scanned, since they contain the patterns they detect.");
            path_setting(ui, "Extra YARA rules folder", &mut self.settings.rules_dir, true, reload);
            row_divider(ui);
            path_setting(ui, "Extra hash list file", &mut self.settings.hashes_file, false, reload);
            row_divider(ui);
            setting_row(ui, "Reload", "Compile the rules again, for example after editing your own rule files.", |ui| {
                if small_button(ui, "Reload signatures").clicked() {
                    *reload = true;
                }
            });
        });
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
                AMBER,
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
                    (true, _) => ("Saved", GREEN),
                    (false, true) => ("From environment", GREEN),
                    _ => ("Not set", AMBER),
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

    /// Windows Security settings that block threats as they run (read-only).
    fn security_card(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        let mut recheck = false;
        let mut open = None;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "Windows protection status");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if self.posture_rx.is_some() {
                        ui.add(egui::Spinner::new().color(ACCENT));
                    } else {
                        recheck = small_button(ui, "Check again").clicked();
                    }
                    if let Some(t) = &self.posture_checked {
                        small(ui, format!("checked {t}"));
                    }
                });
            });
            ui.add(
                egui::Label::new(
                    RichText::new(format!("{APP_TITLE} checks files; these Windows features block threats while programs run. This only reads your settings: use the links to change them in Windows."))
                        .color(MUTED),
                )
                .wrap(),
            );
            ui.add_space(8.0);
            let Some(checks) = &self.security else {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().color(ACCENT));
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
                        ui.label(RichText::new(title).size(16.0).strong().color(TEXT));
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
                if check_row(ui, check, false) {
                    open = Some(check.link);
                }
            }
        });
        if recheck {
            self.refresh_posture(ctx);
        }
        if let Some(link) = open {
            self.open_link(link);
        }
    }

    fn privacy_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(
            ui,
            "Privacy",
            "A checklist of Windows settings that decide how much this PC shares about you. Read-only: Phalanx never changes them.",
        );
        let Some(checks) = self.privacy.clone() else {
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().color(ACCENT));
                    muted(ui, "Reading privacy settings…");
                });
            });
            return;
        };
        let mut recheck = false;
        let mut open = None;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                match posture::score(&checks) {
                    Some(score) => {
                        score_badge(ui, score.percent);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(format!("Privacy level: {}", posture::level(score.percent))).size(18.0).strong().color(TEXT));
                            let private = checks.iter().filter(|c| c.status == Status::Good && c.weight > 0).count();
                            let unknown = if score.unknown > 0 { format!(" {} could not be read.", score.unknown) } else { String::new() };
                            muted(ui, format!("{private} of {} scored settings are private.{unknown}", score.scored));
                            small(ui, "More important settings count for more. Each one links to the Windows page where you can change it.");
                        });
                    }
                    None => {
                        ui.label(RichText::new("Privacy level unknown").size(18.0).strong().color(TEXT));
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                    if self.posture_rx.is_some() {
                        ui.add(egui::Spinner::new().color(ACCENT));
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
                    if check_row(ui, check, true) {
                        open = Some(check.link);
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
    }

    fn inspect_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(
            ui,
            "AI Inspect",
            "Ask Google Gemini to read a file you are unsure about and explain what it would do. Works best on scripts such as .py, .ps1, .js and .bat.",
        );
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
                if let (ActivityKind::Risky | ActivityKind::Threat, Some(p)) = (item.kind, &item.path) {
                    if !recent.contains(&p) && p.is_file() {
                        recent.push(p);
                    }
                }
            }
            if !recent.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new("Recently found by folder protection").strong().color(TEXT));
                for p in recent.into_iter().take(6) {
                    ui.horizontal(|ui| {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if small_button(ui, "Inspect").clicked() {
                                pick = Some(p.clone());
                            }
                            truncated(ui, p.display().to_string(), TEXT, 13.0);
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
                    ui.add(egui::Spinner::new().color(ACCENT));
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
                    ui.label(RichText::new("Could not read the file").strong().color(RED));
                    ui.add(egui::Label::new(RichText::new(e).color(MUTED)).wrap());
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
                notice(ui, AMBER, &format!("Disguised name: {d}."));
            }
            ui.add_space(4.0);
            match &evidence.local_findings {
                None => small(ui, "Local scan: skipped because signatures were still loading."),
                Some(f) if f.is_empty() => {
                    ui.horizontal_wrapped(|ui| {
                        status_dot(ui, GREEN, 4.0);
                        ui.label(RichText::new("Local scan: no known threats.").color(TEXT));
                        small(ui, "That does not prove a file is safe.");
                    });
                }
                Some(f) => {
                    for x in f {
                        ui.horizontal_wrapped(|ui| {
                            badge(ui, &x.category.as_str().to_uppercase(), category_color(x.category));
                            ui.label(RichText::new(&x.threat).strong().color(TEXT));
                            small(ui, format!("found by {}", x.source.as_str()));
                        });
                    }
                }
            }
            ui.add_space(8.0);
            ui.label(RichText::new("What will be sent to Google Gemini").strong().color(TEXT));
            for line in evidence.sent_summary() {
                ui.horizontal_wrapped(|ui| {
                    status_dot(ui, MUTED, 2.5);
                    ui.add(egui::Label::new(RichText::new(line).size(12.5).color(MUTED)).wrap());
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
                    ui.add(egui::Spinner::new().size(22.0).color(ACCENT));
                    ui.label(RichText::new("Gemini is reading the file…").size(16.0).strong().color(TEXT));
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
                    ui.label(RichText::new("The inspection failed").strong().color(RED));
                    ui.add(egui::Label::new(RichText::new(e).color(MUTED)).wrap());
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
                    ui.add(egui::Label::new(RichText::new(&a.summary).color(TEXT)).wrap());
                    if a.manipulation_attempt {
                        ui.add_space(4.0);
                        notice(ui, RED, "The file contains text aimed at the AI or at security scanners, trying to influence the verdict. That is a strong sign of malicious intent.");
                    }
                    let local_hit = evidence.local_findings.as_ref().is_some_and(|f| !f.is_empty());
                    if local_hit && a.verdict == ai::Verdict::Safe {
                        ui.add_space(4.0);
                        notice(ui, AMBER, "The local scanner flagged this file even though the AI did not. Trust the scanner's detection.");
                    }
                    if !a.behaviors.is_empty() {
                        ui.add_space(8.0);
                        ui.label(RichText::new("What it does").strong().color(TEXT));
                        for b in &a.behaviors {
                            ui.horizontal_wrapped(|ui| {
                                badge(ui, &b.severity.to_uppercase(), severity_color(&b.severity));
                                ui.add(egui::Label::new(RichText::new(&b.title).strong().color(TEXT)).wrap());
                            });
                            ui.add(egui::Label::new(RichText::new(&b.evidence).monospace().size(12.0).color(MUTED)).wrap());
                            ui.add_space(4.0);
                        }
                    }
                    if !a.recommendation.is_empty() {
                        ui.add_space(4.0);
                        ui.label(RichText::new("What to do").strong().color(TEXT));
                        ui.add(egui::Label::new(RichText::new(&a.recommendation).color(TEXT)).wrap());
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

    fn toast_bar(&mut self, ui: &mut Ui) {
        let Some(toast) = &self.toast else { return };
        if toast.shown.elapsed() > Duration::from_secs(6) {
            self.toast = None;
            return;
        }
        let color = if toast.ok { GREEN } else { RED };
        egui::Frame::new()
            .fill(color.gamma_multiply(0.14))
            .stroke(Stroke::new(1.0, color.gamma_multiply(0.5)))
            .corner_radius(8.0)
            .inner_margin(Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new(&toast.text).color(TEXT));
            });
        ui.add_space(12.0);
        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }
}

/// Returns true when "Inspect with AI" was clicked.
fn detection_card(ui: &mut Ui, row: &mut ResultRow, ai_enabled: bool) -> bool {
    let worst = row.report.worst().clone();
    let color = category_color(worst.category);
    let mut inspect = false;
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(10.0)
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                let selectable = row.report.action == "reported";
                ui.add_enabled(selectable, egui::Checkbox::without_text(&mut row.selected));
                badge(ui, &worst.category.as_str().to_uppercase(), color);
                ui.label(RichText::new(&worst.threat).size(15.0).strong().color(TEXT));
                let (text, c) = if row.report.action.starts_with("quarantined") {
                    ("Quarantined", GREEN)
                } else if row.report.action.starts_with("quarantine failed") {
                    ("Quarantine failed", RED)
                } else {
                    ("Not removed", MUTED)
                };
                ui.label(RichText::new(text).size(12.5).color(c));
            });
            path_lines(ui, &row.report.path);
            for f in &row.report.findings {
                truncated(ui, format!("{} · {}", f.source.as_str(), f.details), MUTED, 12.0);
            }
            if row.report.action.starts_with("quarantine failed") {
                truncated(ui, row.report.action.clone(), RED, 12.0);
            }
            if ai_enabled && !row.report.action.starts_with("quarantined") {
                inspect = small_button(ui, "Inspect with AI").clicked();
            }
        });
    inspect
}

fn path_setting(ui: &mut Ui, label: &str, value: &mut Option<PathBuf>, folder: bool, changed: &mut bool) {
    let shown = value.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "None".into());
    setting_row(ui, label, &shown, |ui| {
        if small_button(ui, "Choose…").clicked() {
            let picked = if folder {
                rfd::FileDialog::new().pick_folder()
            } else {
                rfd::FileDialog::new().add_filter("Hash list", &["txt"]).pick_file()
            };
            if picked.is_some() {
                *value = picked;
                *changed = true;
            }
        }
        if value.is_some() && small_button(ui, "Clear").clicked() {
            *value = None;
            *changed = true;
        }
    });
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
