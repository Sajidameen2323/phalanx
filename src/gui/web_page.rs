//! The Web protection page: blocking mode, the browser connector, the local
//! DNS filter, site checks, the user's allow/block lists, recent blocks and
//! the browser extension scan.

use super::*;
use eframe::egui::{Align, Layout, RichText, Ui};
use std::net::SocketAddr;
use std::time::SystemTime;
use threat_scanner::web::blockpage::BlockPageServer;
use threat_scanner::web::cache::RedirectionCache;
use threat_scanner::web::config::{self as web_config, Mode};
use threat_scanner::web::dnsfilter::{DnsFilter, FilterConfig};
use threat_scanner::web::events::{self as web_events, WebEvent};
use threat_scanner::web::extensions::{self, BrowserScan, KnownBad};
use threat_scanner::web::native::{self, BrowserRegistration, GuardState};
use threat_scanner::web::rules::RuleCounts;
use threat_scanner::web::{SharedRules, Verdict, WebConfig, WebRules};
use widgets::*;

/// How often settings changed by the browser connector or the command line
/// are picked up, and the event log re-read.
const WEB_POLL: Duration = Duration::from_secs(3);

pub(super) struct WebState {
    pub(super) config: WebConfig,
    saved: WebConfig,
    config_stamp: Option<SystemTime>,
    rules: SharedRules,
    pub(super) counts: RuleCounts,
    rules_error: Option<String>,
    cache: Arc<RedirectionCache>,
    /// The running DNS filter and block-page server, with the settings
    /// they were started from.
    filter: Option<(DnsFilter, BlockPageServer)>,
    filter_key: Option<String>,
    filter_error: Option<String>,
    filter_tx: mpsc::Sender<WebEvent>,
    filter_rx: Receiver<WebEvent>,
    windows_dns: bool,
    browsers: Vec<BrowserRegistration>,
    events: Vec<WebEvent>,
    events_stamp: Option<SystemTime>,
    last_poll: Instant,
    check_input: String,
    check_result: Option<(String, Verdict)>,
    site_input: String,
    upstream_input: String,
    scan_rx: Option<Receiver<BrowserScan>>,
    scan: Option<BrowserScan>,
    hardening: Option<threat_scanner::web::hardening::HardeningReport>,
    hardening_rx: Option<Receiver<threat_scanner::web::hardening::HardeningReport>>,
    /// Pointing Windows' DNS at the filter: keep a fallback server, the
    /// change waiting for confirmation, and the one running.
    dns_fallback: bool,
    dns_confirm: Option<DnsChange>,
    dns_rx: Option<Receiver<(DnsChange, Result<threat_scanner::system::Elevated, String>)>>,
    tab: WebTab,
    /// When the browser rows were last re-read (extensions and contact).
    browsers_checked: Instant,
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum WebTab {
    Overview,
    Browsers,
    Sites,
    Extensions,
    Dns,
    Activity,
}

/// How often the browser rows are re-read while the page is open.
const BROWSER_REFRESH: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, PartialEq)]
pub(super) enum DnsChange {
    Apply,
    Restore,
}

/// The settings that decide which rules are loaded.
fn rule_inputs(c: &WebConfig) -> (&[String], &[String], &[String], bool, bool) {
    (&c.user_allow, &c.user_block, &c.extension_exclusions, c.use_feeds, c.block_ads)
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

impl WebState {
    pub(super) fn new(data_dir: &Path) -> (Self, Option<String>) {
        let (config, warning) = match WebConfig::load(data_dir) {
            Ok(c) => (c, None),
            Err(e) => (WebConfig::default(), Some(format!("Web protection settings could not be read ({e:#}); defaults are in use"))),
        };
        let (filter_tx, filter_rx) = mpsc::channel();
        let mut state = Self {
            upstream_input: config.dns_upstream.join(", "),
            saved: config.clone(),
            config,
            config_stamp: modified(&WebConfig::path(data_dir)),
            rules: Arc::new(std::sync::RwLock::new(Arc::new(WebRules::default()))),
            counts: RuleCounts::default(),
            rules_error: None,
            cache: Arc::new(RedirectionCache::new()),
            filter: None,
            filter_key: None,
            filter_error: None,
            filter_tx,
            filter_rx,
            windows_dns: false,
            browsers: native::status(data_dir),
            events: web_events::recent(data_dir, 50),
            events_stamp: modified(&web_events::path(data_dir)),
            last_poll: Instant::now(),
            check_input: String::new(),
            check_result: None,
            site_input: String::new(),
            scan_rx: None,
            scan: None,
            hardening: None,
            hardening_rx: None,
            dns_fallback: true,
            dns_confirm: None,
            dns_rx: None,
            tab: WebTab::Overview,
            browsers_checked: Instant::now(),
        };
        state.reload_rules(data_dir);
        // After an upgrade, the browsers load the new extension files from
        // here (on their next start, or Reload in the extensions page).
        if state.browsers.iter().any(|b| b.current) {
            let _ = native::write_extension(&native::extension_dir(data_dir));
        }
        state.windows_dns = state.config.dns_listen_addr().is_ok_and(|a| web_config::windows_uses_filter(&a));
        (state, warning)
    }

    /// Reloads rules (built-in, feeds and the user's lists) for the page,
    /// the site checker and the running DNS filter.
    pub(super) fn reload_rules(&mut self, data_dir: &Path) {
        match self.config.load_rules(data_dir) {
            Ok(rules) => {
                self.counts = rules.counts();
                *self.rules.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(rules);
                self.rules_error = None;
            }
            Err(e) => self.rules_error = Some(format!("{e:#}")),
        }
    }

    pub(super) fn running(&self) -> bool {
        self.config.enabled && (self.protected_browsers() > 0 || self.filter.is_some())
    }

    /// Browsers whose extension is added and linked to this copy.
    fn protected_browsers(&self) -> usize {
        self.browsers.iter().filter(|b| matches!(b.state(), GuardState::Protecting | GuardState::Waiting)).count()
    }

    fn installed_browsers(&self) -> usize {
        self.browsers.iter().filter(|b| b.state() != GuardState::NotInstalled).count()
    }

    fn filter_key(&self) -> String {
        serde_json::to_string(&(
            self.config.dns_filter,
            &self.config.dns_listen,
            self.config.upstreams(),
            self.config.sinkhole,
            self.config.block_page_port,
            self.config.mode,
        ))
        .unwrap_or_default()
    }

    /// Starts, restarts or stops the DNS filter to match the settings.
    fn sync_filter(&mut self, data_dir: &Path, ctx: &egui::Context) {
        let key = self.filter_key();
        if self.filter_key.as_deref() == Some(key.as_str()) {
            return;
        }
        self.filter_key = Some(key);
        if let Some((filter, page)) = self.filter.take() {
            filter.stop();
            page.stop();
        }
        self.filter_error = None;
        if !self.config.dns_filter {
            return;
        }
        let page_addr = SocketAddr::new(self.config.sinkhole.into(), self.config.block_page_port);
        let started = self.config.dns_listen_addr().and_then(|listen| {
            let page = BlockPageServer::start(page_addr, self.cache.clone())?;
            let tx = self.filter_tx.clone();
            let ctx = ctx.clone();
            let filter = DnsFilter::start(
                FilterConfig {
                    listen,
                    upstreams: self.config.upstreams(),
                    sinkhole: self.config.sinkhole,
                    mode: self.config.mode,
                    data_dir: Some(data_dir.to_path_buf()),
                },
                self.rules.clone(),
                self.cache.clone(),
                Some(Box::new(move |event: &WebEvent| {
                    let _ = tx.send(event.clone());
                    ctx.request_repaint();
                })),
            )?;
            Ok((filter, page))
        });
        match started {
            Ok(servers) => self.filter = Some(servers),
            Err(e) => self.filter_error = Some(format!("{e:#}")),
        }
    }
}

impl App {
    /// Saves changed settings, follows changes made elsewhere, keeps the DNS
    /// filter in step and collects its events. Called every frame.
    pub(super) fn poll_web(&mut self, ctx: &egui::Context) {
        let path = WebConfig::path(&self.data_dir);
        if self.web.config != self.web.saved {
            // The browser connector or the command line may have saved since
            // this page last read the file: merge, so neither side's edit is lost.
            if modified(&path) != self.web.config_stamp {
                if let Ok(theirs) = WebConfig::load(&self.data_dir) {
                    if let Ok(merged) = self.web.config.merged(&self.web.saved, &theirs) {
                        self.web.config = merged;
                    }
                }
            }
            match self.web.config.save(&self.data_dir) {
                Ok(()) => {
                    let lists_changed = rule_inputs(&self.web.config) != rule_inputs(&self.web.saved);
                    self.web.saved = self.web.config.clone();
                    self.web.config_stamp = modified(&path);
                    if lists_changed {
                        self.web.reload_rules(&self.data_dir);
                    }
                }
                Err(e) => {
                    self.web.saved = self.web.config.clone();
                    self.notify(format!("Could not save web protection settings: {e:#}"), false);
                }
            }
        }
        if self.web.last_poll.elapsed() >= WEB_POLL {
            self.web.last_poll = Instant::now();
            let stamp = modified(&path);
            if stamp != self.web.config_stamp {
                // Changed by the browser connector or the command line.
                self.web.config_stamp = stamp;
                if let Ok(config) = WebConfig::load(&self.data_dir) {
                    self.web.upstream_input = config.dns_upstream.join(", ");
                    self.web.config = config.clone();
                    self.web.saved = config;
                    self.web.reload_rules(&self.data_dir);
                }
            }
            if self.web.filter.is_some() {
                self.web.windows_dns = self.web.config.dns_listen_addr().is_ok_and(|a| web_config::windows_uses_filter(&a));
            }
            let events_stamp = modified(&web_events::path(&self.data_dir));
            if events_stamp != self.web.events_stamp {
                self.web.events_stamp = events_stamp;
                self.web.events = web_events::recent(&self.data_dir, 50);
            }
        }
        let data_dir = self.data_dir.clone();
        self.web.sync_filter(&data_dir, ctx);
        while let Ok(event) = self.web.filter_rx.try_recv() {
            if self.settings.notifications && event.action == "blocked" {
                system::notify(
                    &format!("Blocked a dangerous site: {}", event.target),
                    &format!("{} ({}). Phalanx stopped this connection.", event.threat, event.category),
                );
            }
            self.web.events.insert(0, event);
            self.web.events.truncate(50);
        }
        if let Some(rx) = &self.web.scan_rx {
            if let Ok(scan) = rx.try_recv() {
                self.web.scan_rx = None;
                self.web.scan = Some(scan);
            }
        }
    }

    pub(super) fn web_busy(&self) -> bool {
        self.web.scan_rx.is_some() || self.web.dns_rx.is_some() || self.web.hardening_rx.is_some()
    }

    fn start_browser_scan(&mut self, ctx: &egui::Context) {
        if self.web.scan_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let rules = self.web.rules.read().unwrap_or_else(|e| e.into_inner()).clone();
        let sig_dir = update::signature_dir(&self.data_dir);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(extensions::scan(Some(&rules), &KnownBad::load(Some(&sig_dir))));
            ctx.request_repaint();
        });
        self.web.scan_rx = Some(rx);
    }

    fn remove_browser_extension(&mut self, ctx: &egui::Context, browser: &str, profile: &str, id: &str, name: &str) {
        let Some(found) = extensions::browsers().into_iter().find(|b| b.name == browser) else {
            return self.notify(format!("{browser} was not found"), false);
        };
        match extensions::remove_extension(&found, profile, id, &self.data_dir.join("browser-backups")) {
            Ok(backup) => {
                self.notify(format!("Removed {name} from {browser}. A backup is in {}", backup.display()), true);
                self.start_browser_scan(ctx);
            }
            Err(e) => self.notify(format!("Could not remove {name}: {e:#}"), false),
        }
    }

    fn connect_browsers(&mut self) {
        let result = native::host_exe().and_then(|exe| native::install(&self.data_dir, &exe));
        match result {
            Ok(browsers) => {
                self.web.browsers = browsers;
                self.notify("Browsers connected. Now add the Browser Guard extension (steps below).", true);
            }
            Err(e) => self.notify(format!("Could not connect browsers: {e:#}"), false),
        }
    }

    pub(super) fn web_page(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Web protection");
        // Extensions get added and browsers report in while the page is open.
        if self.web.browsers_checked.elapsed() >= BROWSER_REFRESH {
            self.web.browsers = native::status(&self.data_dir);
            self.web.browsers_checked = Instant::now();
        }
        let sites = self.web.config.user_allow.len() + self.web.config.user_block.len() + self.web.config.extension_exclusions.len();
        ui.horizontal_wrapped(|ui| {
            for (tab, label) in [
                (WebTab::Overview, "Overview".to_string()),
                (WebTab::Browsers, "Browsers".to_string()),
                (WebTab::Sites, if sites == 0 { "Your sites".to_string() } else { format!("Your sites ({sites})") }),
                (WebTab::Extensions, "Extensions".to_string()),
                (WebTab::Dns, "DNS filter".to_string()),
                (WebTab::Activity, "Activity".to_string()),
            ] {
                if chip(ui, &label, self.web.tab == tab) {
                    self.web.tab = tab;
                }
            }
        });
        ui.add_space(14.0);
        match self.web.tab {
            WebTab::Overview => {
                self.web_status_card(ui);
                ui.add_space(14.0);
                self.web_summary_card(ui);
                ui.add_space(14.0);
                self.web_check_card(ui);
            }
            WebTab::Browsers => {
                self.web_browser_card(ui);
                ui.add_space(14.0);
                self.web_hardening_card(ui, ctx);
            }
            WebTab::Sites => self.web_lists_card(ui),
            WebTab::Extensions => self.web_extensions_card(ui, ctx),
            WebTab::Dns => self.web_dns_card(ui),
            WebTab::Activity => self.web_events_card(ui),
        }
    }

    /// One line per area, each leading to its tab.
    fn web_summary_card(&mut self, ui: &mut Ui) {
        let web = &self.web;
        let (protected, installed) = (web.protected_browsers(), web.installed_browsers());
        let browsers = match (protected, installed) {
            (_, 0) => (theme().muted, "No supported browser found".to_string()),
            (0, _) => (theme().amber, "No browser is protected yet: connect browsers and add the extension".to_string()),
            (p, i) if p < i => (theme().amber, format!("{p} of {i} browsers protected")),
            (p, _) => (theme().green, format!("All {p} browsers protected")),
        };
        let hardening = match &web.hardening {
            None => (theme().muted, "Not checked yet".to_string()),
            Some(report) => {
                use threat_scanner::posture::Status;
                let issues = report
                    .versions
                    .iter()
                    .map(|v| &v.check)
                    .chain(report.profiles.iter().flat_map(|p| p.checks.iter()))
                    .filter(|c| matches!(c.status, Status::Risk | Status::Attention))
                    .count();
                if issues == 0 { (theme().green, "Browsers up to date, no settings to review".to_string()) } else { (theme().amber, format!("{issues} item(s) to review")) }
            }
        };
        let extensions = match &web.scan {
            None => (theme().muted, "Not checked yet".to_string()),
            Some(scan) => match (scan.flagged().filter(|e| e.category.is_some()).count(), scan.flagged().count()) {
                (0, 0) => (theme().green, "Nothing needs your attention".to_string()),
                (0, n) => (theme().amber, format!("{n} worth reviewing")),
                (t, _) => (theme().red, format!("{t} dangerous extension(s)")),
            },
        };
        let dns = match (&web.filter, &web.filter_error) {
            (_, Some(_)) => (theme().red, "Could not start".to_string()),
            (Some(_), None) if web.windows_dns => (theme().green, "Running, and Windows uses it".to_string()),
            (Some(_), None) => (theme().amber, "Running, but Windows does not use it yet".to_string()),
            (None, None) => (theme().muted, "Off (optional: protects every program, not just browsers)".to_string()),
        };
        let day_ago = (chrono::Local::now() - chrono::Duration::days(1)).to_rfc3339();
        let recent = web.events.iter().filter(|e| e.time >= day_ago && e.action == "blocked").count();
        let activity = (if recent == 0 { theme().muted } else { theme().red }, format!("{recent} dangerous site(s) blocked in the last 24 hours"));
        let rows = [
            ("Browser Guard", browsers, WebTab::Browsers),
            ("Browser hardening", hardening, WebTab::Browsers),
            ("Browser extensions", extensions, WebTab::Extensions),
            ("DNS filter", dns, WebTab::Dns),
            ("Activity", activity, WebTab::Activity),
        ];
        let mut go = None;
        card(ui, |ui| {
            for (i, (label, (color, text), tab)) in rows.into_iter().enumerate() {
                if i > 0 {
                    row_divider(ui);
                }
                setting_row(ui, label, &text, |ui| {
                    if small_button(ui, "Open").clicked() {
                        go = Some(tab);
                    }
                    status_dot(ui, color, 5.0);
                });
            }
        });
        if let Some(tab) = go {
            self.web.tab = tab;
        }
    }

    fn web_status_card(&mut self, ui: &mut Ui) {
        let connected = self.web.protected_browsers();
        let installed = self.web.installed_browsers();
        let ads_blocked = self.web.filter.as_ref().map(|(f, _)| f.ads_blocked());
        let config = &mut self.web.config;
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                let (color, title) = match (config.enabled, config.mode) {
                    (false, _) => (theme().muted, "Web protection is off"),
                    (true, Mode::ReportOnly) => (theme().amber, "Report-only: matches are logged, not blocked"),
                    (true, Mode::Block) if connected == 0 && self.web.filter.is_none() => (theme().amber, "Add the extension to a browser to start blocking"),
                    (true, Mode::Block) => (theme().green, "Web protection is on"),
                };
                status_dot(ui, color, 6.0);
                ui.label(RichText::new(title).size(18.0).strong().color(theme().text));
            });
            facts(
                ui,
                &[
                    ("Blocking rules", self.web.counts.blocking().to_string()),
                    ("Sites", self.web.counts.domains.to_string()),
                    ("Addresses", (self.web.counts.urls + self.web.counts.networks + self.web.counts.ports).to_string()),
                    ("Browsers protected", format!("{connected} of {installed}")),
                    ("DNS filter", if self.web.filter.is_some() { "running".into() } else { "off".into() }),
                ],
            );
            if let Some(e) = &self.web.rules_error {
                notice(ui, theme().red, &format!("Some web rules could not be loaded: {e}"));
            }
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                if chip(ui, "Block", config.enabled && config.mode == Mode::Block) {
                    (config.enabled, config.mode) = (true, Mode::Block);
                }
                if chip(ui, "Report only", config.enabled && config.mode == Mode::ReportOnly) {
                    (config.enabled, config.mode) = (true, Mode::ReportOnly);
                }
                if chip(ui, "Off", !config.enabled) {
                    config.enabled = false;
                }
            });
            ui.add_space(4.0);
            setting_toggle(
                ui,
                &mut config.use_feeds,
                "Use downloaded threat feeds",
                "URLhaus and ThreatFox lists of malware sites, download links and command-and-control servers, refreshed with Update signatures.",
            );
            setting_toggle(
                ui,
                &mut config.block_ads,
                "Block ads and trackers",
                "Uses the StevenBlack ad and tracker list (refreshed with Update signatures) in Browser Guard, inside pages too, and in the DNS filter. Ad blocks are counted, not logged or notified.",
            );
            if config.block_ads {
                let mut line = match self.web.counts.ads {
                    0 => "The ad list is not downloaded yet. Run Update signatures.".to_string(),
                    n => format!("{n} ad and tracker names"),
                };
                if let Some(n) = ads_blocked {
                    line.push_str(&format!(" · {n} blocked by the DNS filter since it started"));
                }
                small(ui, line);
            }
        });
    }

    fn web_browser_card(&mut self, ui: &mut Ui) {
        let mut connect = false;
        let mut disconnect = false;
        let mut open_folder = false;
        let any = self.web.browsers.iter().any(|b| b.current);
        let missing: Vec<&str> = self
            .web
            .browsers
            .iter()
            .filter(|b| b.state() == GuardState::ExtensionMissing)
            .map(|b| b.browser.as_str())
            .collect();
        card(ui, |ui| {
            section_title(ui, "Browser Guard");
            muted(ui, "The Phalanx extension checks every page your browser opens and shows a warning page instead of a dangerous site, including https:// sites. A browser is protected once the extension is added and has reached Phalanx.");
            ui.add_space(6.0);
            for b in &self.web.browsers {
                let state = b.state();
                let color = match state {
                    GuardState::Protecting => theme().green,
                    GuardState::Waiting | GuardState::ExtensionMissing | GuardState::OtherCopy => theme().amber,
                    GuardState::NotConnected if b.installed => theme().amber,
                    _ => theme().muted,
                };
                setting_row(ui, &b.browser, &b.describe(), |ui| status_dot(ui, color, 5.0));
            }
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                connect = if any { secondary_button(ui, "Reconnect browsers").clicked() } else { primary_button(ui, "Connect browsers").clicked() };
                if any {
                    open_folder = secondary_button(ui, "Open extension folder").clicked();
                    disconnect = small_button(ui, "Disconnect").clicked();
                }
            });
            if any && !missing.is_empty() {
                ui.add_space(6.0);
                let folder = native::extension_dir(&self.data_dir);
                muted(ui, format!("Add the extension to {}:", missing.join(", ")));
                muted(ui, "1. Open chrome://extensions (Edge: edge://extensions, Brave: brave://extensions) and turn on Developer mode.");
                muted(ui, format!("2. Choose Load unpacked and pick {}", folder.display()));
                if missing.contains(&"Firefox") {
                    muted(ui, "Firefox: about:debugging > This Firefox > Load Temporary Add-on, and pick manifest.json in that folder (it is removed when Firefox restarts).");
                }
            }
            small(ui, "Connecting only lets the extension talk to Phalanx; the extension does the blocking. Its icon shows \"!\" when it cannot reach Phalanx.");
        });
        if connect {
            self.connect_browsers();
        }
        if disconnect {
            match native::uninstall() {
                Ok(()) => self.notify("Browsers disconnected. Remove the extension from them too.", true),
                Err(e) => self.notify(format!("Could not disconnect: {e:#}"), false),
            }
            self.web.browsers = native::status(&self.data_dir);
        }
        if open_folder {
            let folder = native::extension_dir(&self.data_dir);
            if let Err(e) = native::write_extension(&folder).and_then(|()| Ok(std::process::Command::new("explorer.exe").arg(&folder).spawn()?)) {
                self.notify(format!("Could not open {}: {e:#}", folder.display()), false);
            }
        }
    }

    fn web_check_card(&mut self, ui: &mut Ui) {
        let mut check = false;
        card(ui, |ui| {
            section_title(ui, "Check a site");
            ui.horizontal_wrapped(|ui| {
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.web.check_input)
                        .hint_text("Address, e.g. example.com or https://…")
                        .desired_width(320.0),
                );
                let entered = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                check = secondary_button(ui, "Check").clicked() || entered;
            });
            if let Some((target, verdict)) = &self.web.check_result {
                ui.add_space(6.0);
                let (color, text) = if verdict.blocks() {
                    (theme().red, format!("{target} would be blocked: {} ({}), via {}", verdict.threat, verdict.category, verdict.list))
                } else if verdict.code == threat_scanner::web::VerdictCode::Clean {
                    (theme().green, format!("{target}: no known threats"))
                } else {
                    (theme().green, format!("{target}: {}", verdict.code.label()))
                };
                notice(ui, color, &text);
            }
        });
        if check && !self.web.check_input.trim().is_empty() {
            let target = self.web.check_input.trim().to_string();
            let verdict = self.web.rules.read().unwrap_or_else(|e| e.into_inner()).classify_url(&target);
            self.web.check_result = Some((target, verdict));
        }
    }

    fn web_lists_card(&mut self, ui: &mut Ui) {
        let mut forget = None;
        let mut add: Option<bool> = None;
        card(ui, |ui| {
            section_title(ui, "Your sites");
            muted(ui, "Allowed sites are never blocked; blocked sites always are. Both include their subdomains. You can also enter an IP range such as 203.0.113.0/24.");
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.web.site_input).hint_text("example.com").desired_width(260.0));
                if secondary_button(ui, "Allow").clicked() {
                    add = Some(true);
                }
                if secondary_button(ui, "Block").clicked() {
                    add = Some(false);
                }
            });
            let config = &self.web.config;
            let lists = [
                ("Allowed", &config.user_allow, theme().green),
                ("Blocked", &config.user_block, theme().red),
                ("Allowed from the browser's warning page", &config.extension_exclusions, theme().amber),
            ];
            if lists.iter().all(|(_, l, _)| l.is_empty()) {
                small(ui, "No sites yet.");
            }
            for (label, list, color) in lists {
                if list.is_empty() {
                    continue;
                }
                ui.add_space(6.0);
                ui.label(RichText::new(label).size(13.0).color(theme().muted));
                for site in list {
                    ui.horizontal(|ui| {
                        status_dot(ui, color, 3.5);
                        ui.label(RichText::new(site).color(theme().text));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if small_button(ui, "Remove").clicked() {
                                forget = Some(site.clone());
                            }
                        });
                    });
                }
            }
        });
        if let Some(allow) = add {
            let site = self.web.site_input.trim().to_string();
            let entry = if allow { self.web.config.allow(&site) } else { self.web.config.block(&site) };
            match entry {
                Some(entry) => {
                    self.web.site_input.clear();
                    self.notify(format!("{} {entry}", if allow { "Allowed" } else { "Blocked" }), true);
                }
                None => self.notify(format!("`{site}` is not a site address or IP range"), false),
            }
        }
        if let Some(site) = forget {
            self.web.config.forget(&site);
        }
    }

    fn web_extensions_card(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        let mut scan = false;
        let mut remove = None;
        card(ui, |ui| {
            section_title(ui, "Browser extensions");
            muted(ui, "Checks the extensions in Chrome, Edge, Brave and Vivaldi for known-bad add-ons, ones your browser flagged, risky permissions and hijacked search or start-up pages.");
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                if self.web.scan_rx.is_some() {
                    ui.spinner();
                    muted(ui, "Checking browsers…");
                } else {
                    scan = secondary_button(ui, if self.web.scan.is_some() { "Check again" } else { "Check browsers" }).clicked();
                }
            });
            let Some(report) = &self.web.scan else { return };
            ui.add_space(6.0);
            small(
                ui,
                format!(
                    "{} extension(s) in {} profile(s) of {}",
                    report.extensions.len(),
                    report.profiles,
                    if report.browsers.is_empty() { "no Chromium browsers".to_string() } else { report.browsers.join(", ") }
                ),
            );
            if report.flagged().count() == 0 && report.settings.is_empty() {
                notice(ui, theme().green, "Nothing needs your attention.");
            }
            for e in report.flagged() {
                ui.add_space(8.0);
                let color = e.category.map(category_color).unwrap_or(theme().muted);
                ui.horizontal_wrapped(|ui| {
                    badge(ui, &e.rating().to_uppercase(), color);
                    ui.label(RichText::new(format!("{} {}", e.name, e.version)).strong().color(theme().text));
                    small(ui, format!("{} · {} · risk {}/100", e.browser, e.profile_name, e.score));
                });
                for r in &e.reasons {
                    small(ui, format!("• {r}"));
                }
                if small_button(ui, "Remove…").clicked() {
                    remove = Some((e.browser.clone(), e.profile.clone(), e.id.clone(), e.name.clone()));
                }
            }
            for s in &report.settings {
                ui.add_space(8.0);
                let color = if s.blocked { theme().red } else { theme().amber };
                ui.horizontal_wrapped(|ui| {
                    badge(ui, if s.blocked { "THREAT" } else { "REVIEW" }, color);
                    ui.label(RichText::new(format!("{} {}: {}", s.browser, s.setting, s.value)).color(theme().text));
                });
                small(ui, format!("{} ({}). Change it in the browser's settings.", s.reason, s.profile_name));
            }
            for err in &report.errors {
                small(ui, format!("Could not read {err}"));
            }
        });
        if scan {
            self.start_browser_scan(ctx);
        }
        if let Some((browser, profile, id, name)) = remove {
            let confirmed = rfd::MessageDialog::new()
                .set_title("Remove extension")
                .set_description(format!(
                    "Remove \"{name}\" from {browser}?\n\nClose {browser} first. A backup is kept so it can be restored with phalanx-cli web restore-extension."
                ))
                .set_buttons(rfd::MessageButtons::OkCancel)
                .show();
            if confirmed == rfd::MessageDialogResult::Ok {
                self.remove_browser_extension(ctx, &browser, &profile, &id, &name);
            }
        }
    }

    /// Browser hardening: updates and the settings that matter against
    /// exploits and stealers, per browser profile (read-only).
    fn web_hardening_card(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        if self.web.hardening.is_none() && self.web.hardening_rx.is_none() {
            self.start_hardening_check(ctx);
        }
        let mut recheck = false;
        let mut open = None;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "Browser hardening");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if self.web.hardening_rx.is_some() {
                        spinner(ui);
                    } else {
                        recheck = small_button(ui, "Check again").clicked();
                    }
                });
            });
            muted(ui, "Updates and the settings that matter most against exploits from a just-opened page and against stealers copying saved data. Read-only: each item links to the browser's own setting.");
            let Some(report) = &self.web.hardening else { return };
            for v in &report.versions {
                row_divider(ui);
                ui.label(RichText::new(&v.browser).strong().color(theme().text));
                if check_row(ui, &v.check, false) == Some(CheckAction::OpenSettings) {
                    open = Some(v.check.link);
                }
            }
            for p in &report.profiles {
                row_divider(ui);
                ui.label(RichText::new(format!("{} · {}", p.browser, p.profile)).strong().color(theme().text));
                for c in p.checks.iter().filter(|c| c.status != threat_scanner::posture::Status::Info || c.id == "secure_dns") {
                    if check_row(ui, c, false) == Some(CheckAction::OpenSettings) {
                        open = Some(c.link);
                    }
                }
            }
            if report.versions.is_empty() && report.profiles.is_empty() {
                small(ui, "No Chromium browser (Chrome, Edge, Brave, Vivaldi) found for this user.");
            }
        });
        if recheck {
            self.start_hardening_check(ctx);
        }
        match open {
            Some(link) if link.target.is_empty() => {} // already on this page (Browser Guard card above)
            Some(link) => self.open_link(link),
            None => {}
        }
    }

    fn start_hardening_check(&mut self, ctx: &egui::Context) {
        if self.web.hardening_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(threat_scanner::web::hardening::check(true));
            ctx.request_repaint();
        });
        self.web.hardening_rx = Some(rx);
    }

    pub(super) fn poll_hardening(&mut self) {
        let Some(rx) = &self.web.hardening_rx else { return };
        if let Ok(report) = rx.try_recv() {
            self.web.hardening_rx = None;
            self.web.hardening = Some(report);
        }
    }

    fn start_dns_change(&mut self, change: DnsChange) {
        let (tx, rx) = mpsc::channel();
        let data_dir = self.data_dir.clone();
        let listen = self.web.config.dns_listen_addr();
        let fallback = self.web.dns_fallback;
        std::thread::spawn(move || {
            let result = match change {
                DnsChange::Apply => listen.and_then(|l| threat_scanner::web::windows_dns::apply(&data_dir, &l, fallback)),
                DnsChange::Restore => threat_scanner::web::windows_dns::restore(&data_dir),
            };
            let _ = tx.send((change, result.map_err(|e| format!("{e:#}"))));
        });
        self.web.dns_rx = Some(rx);
    }

    pub(super) fn poll_dns_change(&mut self) {
        let Some(rx) = &self.web.dns_rx else { return };
        let Ok((change, result)) = rx.try_recv() else { return };
        self.web.dns_rx = None;
        self.web.windows_dns = self.web.config.dns_listen_addr().is_ok_and(|a| web_config::windows_uses_filter(&a));
        use threat_scanner::system::Elevated;
        match (change, result) {
            (DnsChange::Apply, Ok(Elevated::Exited(0))) if self.web.windows_dns => self.notify("Windows now sends DNS lookups to the Phalanx filter", true),
            (DnsChange::Apply, Ok(Elevated::Exited(0))) => self.notify("The command ran, but Windows does not report the filter as its DNS server yet", false),
            (DnsChange::Restore, Ok(Elevated::Exited(0))) => self.notify("Previous DNS settings restored", true),
            (_, Ok(Elevated::Exited(code))) => self.notify(format!("The DNS change failed (exit code {code}); check your network settings"), false),
            (_, Ok(Elevated::Declined)) => self.notify("Cancelled at the Windows prompt; nothing was changed", false),
            (_, Err(e)) => self.notify(e, false),
        }
    }

    fn web_dns_card(&mut self, ui: &mut Ui) {
        let mut start_dns_change = None;
        let running = self.web.filter.is_some();
        let upstreams: Vec<String> = self.web.config.upstreams().iter().map(ToString::to_string).collect();
        let mut apply_upstream = false;
        card(ui, |ui| {
            section_title(ui, "DNS filter (whole PC)");
            setting_toggle(
                ui,
                &mut self.web.config.dns_filter,
                "Filter DNS while Phalanx runs",
                "A local resolver that answers blocked names with a block address, so every program, not just browsers, is stopped from reaching them.",
            );
            if let Some(e) = &self.web.filter_error {
                notice(ui, theme().red, &format!("The DNS filter could not start: {e}. Another program may be using the address; change it below."));
            } else if running {
                let note = if self.web.windows_dns {
                    (theme().green, format!("Running on {}, forwarding to {}. Windows is using it.", self.web.config.dns_listen, upstreams.join(", ")))
                } else {
                    (
                        theme().amber,
                        format!(
                            "Running on {}, but Windows does not use it yet. Set your network adapter's DNS server to {} (Settings > Network & internet > your connection > DNS server assignment), and set the router as the alternate so the internet keeps working when Phalanx is closed.",
                            self.web.config.dns_listen,
                            self.web.config.dns_listen_addr().map(|a| a.ip().to_string()).unwrap_or_default()
                        ),
                    )
                };
                notice(ui, note.0, &note.1);
            }
            ui.add_space(6.0);
            setting_row(ui, "Listen address", "Where Windows should send DNS lookups.", |ui| {
                ui.add(egui::TextEdit::singleline(&mut self.web.config.dns_listen).desired_width(160.0));
            });
            setting_row(ui, "Forward to", "Comma-separated resolvers. Leave empty to use this PC's own resolvers.", |ui| {
                apply_upstream = small_button(ui, "Apply").clicked();
                ui.add(egui::TextEdit::singleline(&mut self.web.upstream_input).hint_text(upstreams.join(", ")).desired_width(200.0));
            });
            small(ui, "Browsers' own \"secure DNS\" (DNS over HTTPS) bypasses this filter; Browser Guard still protects them. https:// sites blocked here fail to load instead of showing the warning page.");

            // One-step Windows DNS setup (administrator), with a restore.
            ui.add_space(6.0);
            row_divider(ui);
            let listen = self.web.config.dns_listen_addr().ok();
            let usable = listen.as_ref().map(threat_scanner::web::windows_dns::usable_listen);
            let backup = threat_scanner::web::windows_dns::has_backup(&self.data_dir);
            let busy = self.web.dns_rx.is_some();
            setting_row(
                ui,
                "Use the filter for Windows DNS",
                "Points every connected network adapter's DNS (IPv4 and IPv6) at the filter, after saving the current settings so they can be restored. Needs administrator.",
                |ui| {
                    ui.add_enabled_ui(!busy && running && matches!(usable, Some(Ok(()))), |ui| {
                        if small_button(ui, if self.web.windows_dns { "Apply again…" } else { "Set up…" }).clicked() {
                            self.web.dns_confirm = Some(DnsChange::Apply);
                        }
                    });
                    if backup {
                        ui.add_enabled_ui(!busy, |ui| {
                            if small_button(ui, "Restore previous DNS…").clicked() {
                                self.web.dns_confirm = Some(DnsChange::Restore);
                            }
                        });
                    }
                },
            );
            if let Some(Err(e)) = &usable {
                small(ui, format!("{e:#}"));
            } else if !running {
                small(ui, "Turn the filter on first.");
            }
            setting_toggle(
                ui,
                &mut self.web.dns_fallback,
                "Keep a fallback DNS server",
                "Recommended. Your previous DNS server stays second in line, so the internet keeps working when Phalanx is closed. Without it, nothing resolves unless Phalanx runs, but no lookup can slip past the filter.",
            );
            match self.web.dns_confirm {
                Some(change) if !busy => {
                    let (title, text) = match change {
                        DnsChange::Apply => (
                            "Point Windows' DNS at the Phalanx filter?",
                            if self.web.dns_fallback {
                                "Every connected adapter will use 127.0.0.1 and ::1 (Phalanx), with its current first server as a fallback. The current settings are saved first. Windows asks for administrator permission."
                            } else {
                                "Every connected adapter will use only 127.0.0.1 and ::1 (Phalanx). If Phalanx is not running, websites will not load until you restore. The current settings are saved first. Windows asks for administrator permission."
                            },
                        ),
                        DnsChange::Restore => ("Restore the DNS settings saved before?", "Each adapter goes back to exactly what it used before (automatic from the router, or the servers it had). Windows asks for administrator permission."),
                    };
                    ui.add_space(6.0);
                    notice(ui, if change == DnsChange::Apply && !self.web.dns_fallback { theme().red } else { theme().amber }, &format!("{title} {text}"));
                    ui.horizontal(|ui| {
                        if primary_button(ui, "Run as administrator").clicked() {
                            self.web.dns_confirm = None;
                            start_dns_change = Some(change);
                        }
                        if secondary_button(ui, "Cancel").clicked() {
                            self.web.dns_confirm = None;
                        }
                    });
                }
                _ if busy => {
                    ui.horizontal(|ui| {
                        spinner(ui);
                        muted(ui, "Waiting for the administrator command (approve the Windows prompt)…");
                    });
                }
                _ => {}
            }
        });
        if let Some(change) = start_dns_change {
            self.start_dns_change(change);
        }
        if apply_upstream {
            let entries: Vec<String> = self.web.upstream_input.split([',', ' ']).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect();
            let bad: Vec<&String> = entries.iter().filter(|s| web_config::parse_resolver(s).is_none()).collect();
            if bad.is_empty() {
                self.web.config.dns_upstream = entries;
            } else {
                self.notify(format!("Not a resolver address: {}", bad.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")), false);
            }
        }
    }

    fn web_events_card(&mut self, ui: &mut Ui) {
        card(ui, |ui| {
            section_title(ui, "Recent blocks");
            if self.web.events.is_empty() {
                small(ui, "Nothing blocked yet.");
            }
            for e in self.web.events.iter().take(30) {
                let color = if e.action == "blocked" { theme().red } else { theme().amber };
                ui.horizontal(|ui| {
                    status_dot(ui, color, 3.5);
                    ui.label(RichText::new(short_time(&e.time)).size(12.0).color(theme().muted));
                    let source = if e.source == "dns" { "DNS" } else { "browser" };
                    ui.label(RichText::new(format!("{} ({source})", e.action)).size(12.0).color(color));
                    truncated(ui, e.target.clone(), theme().text, 13.0);
                });
                truncated(ui, format!("{} · {} · {}", e.threat, e.category, e.list), theme().muted, 12.0);
            }
        });
    }
}
