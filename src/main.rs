use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use threat_scanner::engine::{Engine, EngineConfig};
use threat_scanner::quarantine::Quarantine;
use threat_scanner::scan::{self, ScanEvent, ScanOptions};
use threat_scanner::store::Store;
use threat_scanner::system::{self, Performance};
use threat_scanner::posture::{self, Check, Status};
use threat_scanner::rtp::{self, Origin, RiskyOutcome, RtpConfig, RtpEvent};
use threat_scanner::{ai, update, web, Category};

/// Phalanx: on-demand threat scanner (hash blocklist, YARA rules, PE heuristics).
#[derive(Parser)]
#[command(name = "phalanx-cli", version)]
struct Cli {
    /// Where the history database and quarantine live.
    /// Defaults to %LOCALAPPDATA%\threat-scanner (or ~/.threat-scanner).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// For development: the pipe of a `phalanx-service --console` run (as
    /// PHALANX_PIPE, which an elevated copy does not inherit).
    #[arg(long, global = true, hide = true)]
    pipe: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan files or folders.
    Scan(ScanArgs),
    /// Real-time protection: scan new files in folders as they arrive and,
    /// with --programs, programs as they start (Ctrl+C to stop).
    Watch(WatchArgs),
    /// Show recent scans.
    History {
        #[arg(long, default_value_t = 20)]
        limit: u32,
        /// Only scans of this kind (quick, custom, watch, process, cli).
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show recent detections.
    Detections {
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Per-month totals.
    Summary {
        #[arg(long)]
        json: bool,
    },
    /// List, restore or delete quarantined files.
    #[command(subcommand)]
    Quarantine(QuarantineCommand),
    /// Show loaded signatures and data locations.
    Info(SignatureArgs),
    /// Download new signatures and web rules from the public feeds (only
    /// feeds that changed since the last update are downloaded).
    Update {
        /// Download every feed again, even if unchanged.
        #[arg(long)]
        force: bool,
        /// Only report which feeds have new data (exit code 1 if any).
        #[arg(long, conflicts_with = "force")]
        check: bool,
        /// Save a free abuse.ch Auth-Key (https://auth.abuse.ch/), encrypted
        /// for this Windows user, for MalwareBazaar, ThreatFox and URLhaus.
        /// Without one those feeds are skipped. `none` removes it.
        #[arg(long, value_name = "KEY", conflicts_with_all = ["force", "check"])]
        set_key: Option<String>,
    },
    /// Look for what infostealers and their loaders leave behind: start-up
    /// entries, tasks, services, browser shortcuts and policies, proxy and
    /// hosts-file changes (read-only).
    Audit {
        /// Also read Microsoft Defender's exclusions (asks for administrator).
        #[arg(long)]
        exclusions: bool,
        /// List entries with nothing wrong too.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        signatures: SignatureArgs,
    },
    /// Check each browser profile's hardening: updates, Safe Browsing, the
    /// JavaScript optimizer, secure DNS, Browser Guard, saved passwords (read-only).
    Browsers {
        /// Do not ask the public version feeds for the newest versions.
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        json: bool,
    },
    /// Check Windows security and privacy settings (read-only).
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Ask Google Gemini whether a file looks safe. Needs GEMINI_API_KEY.
    /// Scripts are sent as text; binaries only as locally extracted facts.
    Inspect(InspectArgs),
    /// Web protection: block malicious sites, connect browsers, and find
    /// malicious browser extensions.
    #[command(subcommand)]
    Web(WebCommand),
    /// The protection service (install, remove, start and stop need
    /// administrator rights).
    #[command(subcommand)]
    Service(ServiceCommand),
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Install the service (phalanx-service.exe next to this program) and
    /// start it; an existing installation is updated.
    Install,
    /// Stop and remove the service.
    Uninstall,
    Start,
    Stop,
    /// Whether the service is installed and running, and who it thinks you
    /// are (exit code 1 if it is not running).
    Status,
    /// Bring your data from before the service (settings, history,
    /// quarantine, web lists, signatures) into the service's folder, once.
    /// Needs administrator rights.
    Migrate {
        /// The folder to bring over. Default: %LOCALAPPDATA%\threat-scanner.
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// Scans as the service keeps them, newest first, filtered and searched.
    History {
        #[arg(long, default_value_t = 20)]
        limit: u32,
        /// Text in what was scanned, or in a finding's file or threat name.
        #[arg(long)]
        search: Option<String>,
        /// Only this kind (quick, full, custom, watch, process, command,
        /// sideload); repeat for several.
        #[arg(long = "kind")]
        kinds: Vec<String>,
        /// Only scans that found something.
        #[arg(long)]
        threats_only: bool,
        /// Only the last this many days.
        #[arg(long)]
        days: Option<u32>,
        /// Start below this scan number (shown at the end of a full page).
        #[arg(long)]
        before: Option<i64>,
    },
    /// The protection settings, as the service keeps them (JSON).
    Settings,
    /// Where real-time protection is: signatures loaded, folders watched,
    /// and whether programs are seen through process events (JSON).
    Protection,
    /// Scan files or folders in the service, showing its progress.
    Scan {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Recorded in history.
        #[arg(long, default_value = "custom")]
        kind: String,
    },
    /// Print what the service reports (detections, scans, protection
    /// starting and stopping) as it happens, one JSON object a line.
    Events,
    /// What the service's Run-box reader sees in every user's registry
    /// (diagnostics; administrator).
    RunBox,
    /// Block, unblock, allow or stop allowing one site everywhere.
    /// Unblocking and allowing need administrator rights.
    Site {
        #[arg(value_enum)]
        change: SiteChangeArg,
        site: String,
    },
    /// Turn ad and tracker blocking on or off (off needs administrator rights).
    Ads {
        #[arg(value_enum)]
        state: OnOff,
    },
    /// Download new signatures and web rules in the service now, showing
    /// its progress.
    Update {
        /// Download every feed again, even if unchanged.
        #[arg(long)]
        force: bool,
    },
    /// Save the abuse.ch Auth-Key in the service (administrator).
    AuthKey {
        key: Option<String>,
        /// Remove the saved key.
        #[arg(long, conflicts_with_all = ["key", "from_app"])]
        remove: bool,
        /// Use the key saved in the app (Settings > Signatures), so it never
        /// has to be typed or shown.
        #[arg(long, conflicts_with = "key")]
        from_app: bool,
    },
    /// The web protection settings and whether the DNS filter runs.
    Web,
    /// Replace the protection settings with these (JSON, hex-encoded, as
    /// the app passes them when a change needs approval).
    SetSettings {
        #[arg(long)]
        json: String,
    },
    /// Replace the web settings with these (JSON, hex-encoded).
    SetWebSettings {
        #[arg(long)]
        json: String,
    },
    /// Put a quarantined file back (administrator).
    Restore {
        id: String,
        /// Overwrite a file now at the original place.
        #[arg(long)]
        force: bool,
    },
    /// Delete a quarantined file for good (administrator).
    DeleteQuarantined { id: String },
    /// Quarantine a file no scan detected (administrator).
    Quarantine {
        path: PathBuf,
        #[arg(long, default_value = "Quarantined.ByUser")]
        threat: String,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum SiteChangeArg {
    Block,
    Unblock,
    Allow,
    Unallow,
}

#[derive(Subcommand)]
enum WebCommand {
    /// Check sites, URLs or IP addresses against the web rules.
    Check {
        #[arg(required = true)]
        targets: Vec<String>,
        /// Also look the names up and check the addresses they resolve to.
        #[arg(long)]
        resolve: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show web protection settings, rule counts and your lists.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Block matches, only report them, or turn browser checks off.
    Mode { mode: ModeArg },
    /// Turn ad and tracker blocking on or off (browser and DNS filter).
    Ads { state: OnOff },
    /// Always allow a site (name, URL or CIDR range).
    Allow { site: String },
    /// Always block a site (name, URL or CIDR range).
    Block { site: String },
    /// Remove a site from your allow, block and browser-exclusion lists.
    Forget { site: String },
    /// Recent blocks and report-only matches.
    Events {
        #[arg(long, default_value_t = 30)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Run the DNS filter and block-page server until Ctrl+C. Point
    /// Windows' DNS server at the listen address to use it.
    Serve {
        /// Address:port to listen on (default from settings: 127.0.0.1:53).
        #[arg(long)]
        listen: Option<String>,
        /// Resolver to forward to (repeatable; default: this PC's resolvers).
        #[arg(long = "upstream", value_name = "IP[:PORT]")]
        upstream: Vec<String>,
        /// Loopback address blocked names resolve to.
        #[arg(long)]
        sinkhole: Option<std::net::Ipv4Addr>,
        /// Block-page server port.
        #[arg(long)]
        port: Option<u16>,
        /// Log matches without blocking them.
        #[arg(long)]
        report_only: bool,
    },
    /// Register the browser connector for this user (Chrome, Edge, Brave,
    /// Chromium, Firefox) and write the Browser Guard extension's files.
    Connect,
    /// Unregister the browser connector.
    Disconnect,
    /// Scan browser profiles for malicious or risky extensions and hijacked
    /// search/start-page settings.
    Extensions {
        /// List every extension, not only flagged ones.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Remove an extension from a browser profile (browser must be closed).
    /// A backup is kept; undo with `restore-extension`.
    RemoveExtension {
        /// Browser name as shown by `extensions` (e.g. "Google Chrome").
        #[arg(long)]
        browser: String,
        /// Profile folder (e.g. Default, "Profile 1").
        #[arg(long, default_value = "Default")]
        profile: String,
        id: String,
    },
    /// Put back an extension removed by `remove-extension`.
    RestoreExtension { backup: PathBuf },
    /// Put back the Windows DNS settings saved when the DNS filter was set up
    /// (asks for administrator). The uninstaller runs this. A backup is only
    /// used while Windows still points at the filter; otherwise it is stale
    /// and discarded.
    RestoreDns {
        /// Only say whether there is anything to put back: exit code 0 if
        /// Windows uses the filter, 1 if not.
        #[arg(long)]
        check: bool,
    },
    /// Serve the browser connector on stdin/stdout (browsers start this).
    #[command(hide = true)]
    NativeHost,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum OnOff {
    On,
    Off,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ModeArg {
    Block,
    ReportOnly,
    Off,
}

#[derive(Args)]
struct InspectArgs {
    file: PathBuf,
    /// Gemini model name.
    #[arg(long, default_value = ai::DEFAULT_MODEL)]
    model: String,
    /// Most text sent, in KiB.
    #[arg(long, default_value_t = ai::DEFAULT_MAX_TEXT_KB)]
    max_text_kb: u32,
    /// Do not send the file's text, only its facts and local scan result.
    #[arg(long)]
    no_text: bool,
    /// Show what would be sent and stop.
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    signatures: SignatureArgs,
}

#[derive(Args)]
struct SignatureArgs {
    /// Extra YARA rule file or folder (repeatable).
    #[arg(long = "rules", value_name = "PATH")]
    rules: Vec<PathBuf>,
    /// Extra hash blocklist file (repeatable).
    #[arg(long = "hashes", value_name = "FILE")]
    hashes: Vec<PathBuf>,
    /// Disable PE heuristics.
    #[arg(long)]
    no_heuristics: bool,
    /// Ignore downloaded signatures (use only built-in and --rules/--hashes).
    #[arg(long)]
    no_feeds: bool,
}

#[derive(Args)]
struct ScanArgs {
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    #[command(flatten)]
    signatures: SignatureArgs,
    /// Quarantine malware, PUP and hacktool detections.
    #[arg(long)]
    quarantine: bool,
    /// Also quarantine heuristic/suspicious detections (implies --quarantine).
    #[arg(long)]
    quarantine_suspicious: bool,
    /// Skip files larger than this many MiB (programs padded past it are
    /// still scanned without the padding).
    #[arg(long, default_value_t = 100)]
    max_size_mb: u64,
    /// Don't look inside ZIP and 7z archives.
    #[arg(long)]
    no_archives: bool,
    /// Print a JSON report instead of text.
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    load: LoadArgs,
}

#[derive(Args)]
struct LoadArgs {
    /// How hard to work: low-impact (few threads, background priority),
    /// balanced, or fast (all cores, normal priority).
    #[arg(long, value_enum, default_value = "balanced")]
    performance: PerformanceArg,
    /// Override the number of scanning threads.
    #[arg(long)]
    threads: Option<usize>,
    /// Folder or file never to scan (repeatable).
    #[arg(long = "exclude", value_name = "PATH")]
    exclude: Vec<PathBuf>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum PerformanceArg {
    LowImpact,
    Balanced,
    Fast,
}

impl LoadArgs {
    fn level(&self) -> Performance {
        match self.performance {
            PerformanceArg::LowImpact => Performance::LowImpact,
            PerformanceArg::Balanced => Performance::Balanced,
            PerformanceArg::Fast => Performance::Fast,
        }
    }
    fn threads(&self) -> usize {
        self.threads.unwrap_or_else(|| system::worker_threads(self.level())).max(1)
    }
}

#[derive(Args)]
struct WatchArgs {
    /// Folders to watch, e.g. your Downloads folder.
    #[arg(required_unless_present = "programs")]
    folders: Vec<PathBuf>,
    /// Also scan every program as it starts (Windows), and stop it if it is
    /// malware (PUPs and hacking tools are only reported).
    #[arg(long)]
    programs: bool,
    /// With --programs, only report detected programs; never stop them.
    #[arg(long, requires = "programs")]
    report_only: bool,
    /// Report rule and heuristic findings even on validly signed files.
    #[arg(long)]
    no_trust_signed: bool,
    /// Don't look inside ZIP and 7z archives.
    #[arg(long)]
    no_archives: bool,
    /// Don't check drives that appear (mounted disk images, USB drives).
    #[arg(long)]
    no_new_drives: bool,
    #[command(flatten)]
    signatures: SignatureArgs,
    /// Quarantine malware, PUP and hacktool detections.
    #[arg(long)]
    quarantine: bool,
    /// Show a desktop notification for each detection and each new program or script.
    #[arg(long)]
    notify: bool,
    /// Folder or file never to scan (repeatable).
    #[arg(long = "exclude", value_name = "PATH")]
    exclude: Vec<PathBuf>,
    /// Skip files larger than this many MiB.
    #[arg(long, default_value_t = 100)]
    max_size_mb: u64,
}

#[derive(Subcommand)]
enum QuarantineCommand {
    /// List quarantined files.
    List {
        /// Include items already restored.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Put a quarantined file back where it was.
    Restore {
        id: String,
        /// Overwrite a file that now exists at the original path.
        #[arg(long)]
        force: bool,
    },
    /// Permanently delete a quarantined file.
    Delete { id: String },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn data_dir(cli: &Cli) -> PathBuf {
    cli.data_dir.clone().unwrap_or_else(scan::default_data_dir)
}

fn engine(args: &SignatureArgs, dir: &Path) -> Result<Engine> {
    Engine::new(&EngineConfig {
        rule_paths: args.rules.clone(),
        hash_files: args.hashes.clone(),
        signature_dir: (!args.no_feeds).then(|| update::signature_dir(dir)),
        heuristics: !args.no_heuristics,
    })
}

fn run() -> Result<ExitCode> {
    // Browsers start the connector with their own arguments (the caller's
    // origin), not a subcommand.
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if web::native::is_host_invocation(&raw) {
        web::native::run_host(&scan::default_data_dir(), std::io::stdin().lock(), std::io::stdout().lock())?;
        return Ok(ExitCode::SUCCESS);
    }
    let cli = Cli::parse();
    if let Some(pipe) = &cli.pipe {
        // SAFETY: no other thread runs yet.
        unsafe { std::env::set_var(threat_scanner::ipc::PIPE_ENV, pipe) };
    }
    let dir = data_dir(&cli);
    let store = scan::open_store(&dir)?;

    match &cli.command {
        Command::Scan(args) => scan(args, &dir, &store),
        Command::History { limit, kind, json } => {
            let rows = store.recent_scans(*limit, kind.as_deref())?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for r in rows {
                    let state = match (&r.finished_at, r.cancelled) {
                        (None, _) => "  INCOMPLETE",
                        (_, true) => "  CANCELLED",
                        _ => "",
                    };
                    let took = r.elapsed_ms.map(|ms| format!("{:.1}s", ms as f64 / 1000.0)).unwrap_or_else(|| "?".into());
                    println!(
                        "#{} {} scan  {}  took {took}  {} thread(s){state}",
                        r.id, r.kind, r.started_at, r.threads
                    );
                    println!(
                        "    {} files ({:.1} MiB), {} skipped, {} errors, {} threats, {} quarantined",
                        r.files_scanned,
                        r.bytes_scanned as f64 / 1_048_576.0,
                        r.files_skipped,
                        r.errors,
                        r.detections,
                        r.quarantined
                    );
                    println!(
                        "    signatures: {}  targets: {}",
                        r.signatures.as_deref().unwrap_or("built-in only"),
                        r.targets
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Watch(args) => watch(args, &dir),
        Command::Detections { limit, json } => {
            let rows = store.recent_detections(*limit)?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for r in rows {
                    println!(
                        "{}  [{}] {} via {} (scan {}) -> {}\n    {}",
                        r.detected_at, r.category, r.threat, r.source, r.scan_id, r.action, r.path
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Summary { json } => {
            let rows = store.monthly_summary()?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                println!(
                    "{:<8}  {:>6}  {:>10}  {:>14}  {:>11}",
                    "month", "scans", "files", "infected files", "quarantined"
                );
                for r in rows {
                    println!(
                        "{:<8}  {:>6}  {:>10}  {:>14}  {:>11}",
                        r.month, r.scans, r.files_scanned, r.detections, r.quarantined
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Quarantine(cmd) => {
            let q = Quarantine::new(scan::quarantine_dir(&dir), &store)?;
            match cmd {
                QuarantineCommand::List { all, json } => {
                    let rows = store.quarantine_items(*all)?;
                    if *json {
                        println!("{}", serde_json::to_string_pretty(&rows)?);
                    } else if rows.is_empty() {
                        println!("Quarantine is empty.");
                    } else {
                        for r in rows {
                            let restored = r
                                .restored_at
                                .map(|t| format!("  (restored {t})"))
                                .unwrap_or_default();
                            println!(
                                "{}  {}  {} bytes{restored}\n    {}",
                                r.id, r.threat, r.size, r.original_path
                            );
                        }
                    }
                }
                QuarantineCommand::Restore { id, force } => {
                    let path = q.restore(id, *force)?;
                    println!("Restored {}", path.display());
                }
                QuarantineCommand::Delete { id } => {
                    q.delete(id)?;
                    println!("Deleted {id}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Info(args) => {
            let engine = engine(args, &dir)?;
            println!("YARA rules:   {}", engine.rule_count());
            println!("Known hashes: {}", engine.hash_count());
            println!("Heuristics:   {}", if args.no_heuristics { "off" } else { "on" });
            let mut web_config = web::WebConfig::load(&dir)?;
            web_config.use_feeds &= !args.no_feeds;
            let counts = web_config.load_rules(&dir)?.counts();
            println!(
                "Web rules:    {} ({} domains, {} URLs, {} networks, {} ports)",
                counts.blocking(),
                counts.domains,
                counts.urls,
                counts.networks,
                counts.ports
            );
            println!("Data folder:  {}", dir.display());
            let manifest = update::load_manifest(&update::signature_dir(&dir));
            println!(
                "Signatures:   {}",
                manifest
                    .last_success()
                    .map(|t| format!("updated {t}"))
                    .unwrap_or_else(|| "never updated (run `threat-scanner update`)".into())
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Audit { exclusions, all, json, signatures } => {
            let engine = engine(signatures, &dir)?;
            let work = dir.join("audit");
            let ex = if *exclusions {
                match threat_scanner::audit::read_defender_exclusions(&work)? {
                    Some(ex) => Some(ex),
                    None => {
                        eprintln!("Administrator prompt declined: Defender exclusions were not checked.");
                        None
                    }
                }
            } else {
                None
            };
            let report = threat_scanner::audit::run(Some(&engine), ex.as_ref(), &work);
            if *json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                use threat_scanner::audit::Severity;
                for it in report.items.iter().filter(|i| *all || i.severity > Severity::Info) {
                    println!("[{}] {}: {}", it.severity.label(), it.kind.label(), it.title);
                    println!("    where:   {}", it.location);
                    if !it.command.is_empty() {
                        println!("    runs:    {}", it.command);
                    }
                    match &it.signature {
                        threat_scanner::audit::Signature::Signed { signer } => println!("    signed:  {signer}"),
                        threat_scanner::audit::Signature::Unsigned => println!("    signed:  no"),
                        threat_scanner::audit::Signature::Invalid { status } => println!("    signed:  INVALID ({status})"),
                        threat_scanner::audit::Signature::Unknown => {}
                    }
                    for r in &it.reasons {
                        println!("    why:     {r}");
                    }
                }
                for e in &report.errors {
                    eprintln!("warning: {e}");
                }
                println!(
                    "\n{} high, {} to review, {} low, {} fine ({} items, {:.1}s){}",
                    report.count(Severity::High),
                    report.count(Severity::Medium),
                    report.count(Severity::Low),
                    report.count(Severity::Info),
                    report.items.len(),
                    report.elapsed_ms as f64 / 1000.0,
                    if *exclusions { "" } else { ". Add --exclusions to also check Defender's exclusions (needs administrator)." }
                );
            }
            Ok(if report.count(threat_scanner::audit::Severity::High) > 0 { ExitCode::from(1) } else { ExitCode::SUCCESS })
        }
        Command::Browsers { offline, json } => {
            // The service's DNS filter, else this user's (before 0.5).
            let machine = threat_scanner::service::data::machine_data_dir();
            let filter_in_use = web::windows_dns::filter_in_use(&machine) || web::windows_dns::filter_in_use(&dir);
            let report = web::hardening::check(!offline, filter_in_use);
            if *json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for v in &report.versions {
                    print_checks(&format!("{} {}", v.browser, v.installed.as_deref().unwrap_or("")), std::slice::from_ref(&v.check), false);
                }
                for p in &report.profiles {
                    println!();
                    print_checks(&format!("{} / {}", p.browser, p.profile), &p.checks, false);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Status { json } => {
            let defender = posture::read_defender_state();
            let security = posture::security_checks(&defender);
            let privacy = posture::privacy_checks();
            if *json {
                let out = serde_json::json!({
                    "security": { "score": posture::score(&security), "checks": security },
                    "privacy": { "score": posture::score(&privacy), "checks": privacy },
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                print_checks("Windows protection", &security, false);
                println!();
                print_checks("Privacy", &privacy, true);
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Inspect(args) => inspect(args, &dir),
        Command::Web(cmd) => web_command(cmd, &dir),
        Command::Service(cmd) => service_command(cmd),
        Command::Update { force, check, set_key } => {
            let sig_dir = update::signature_dir(&dir);
            if let Some(key) = set_key {
                let remove = key.eq_ignore_ascii_case("none");
                update::save_auth_key(&sig_dir, (!remove).then_some(key.as_str()))?;
                println!("{}", if remove { "abuse.ch Auth-Key removed." } else { "abuse.ch Auth-Key saved. Run `phalanx-cli update` to download its feeds." });
                return Ok(ExitCode::SUCCESS);
            }
            if *check {
                let result = update::check_for_updates(&sig_dir);
                for name in &result.changed {
                    println!("new data: {name}");
                }
                for name in &result.failed {
                    println!("could not check: {name}");
                }
                if result.changed.is_empty() && result.failed.is_empty() {
                    println!("All signatures are up to date.");
                }
                return Ok(if result.changed.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) });
            }
            let manifest = update::update_all(&sig_dir, *force, &mut |step| eprintln!("{step}"))?;
            for s in &manifest.sources {
                let state = if s.ok { "ok  " } else if s.skipped { "skip" } else { "FAIL" };
                println!("{state} {}: {}", s.name, s.message);
            }
            if manifest.sources.iter().any(|s| s.skipped) {
                println!("Get a free abuse.ch Auth-Key at {} and save it with `phalanx-cli update --set-key <KEY>`.", update::AUTH_KEY_PORTAL);
            }
            if !manifest.installed_anything() && !manifest.sources.iter().any(|s| s.failed()) {
                println!("Everything was already up to date.");
                return Ok(ExitCode::SUCCESS);
            }
            // Load once so problems surface now and the compiled-rule cache is warm.
            let engine = Engine::new(&EngineConfig {
                signature_dir: Some(sig_dir),
                ..Default::default()
            })?;
            println!(
                "Loaded {} YARA rules and {} known-bad hashes.",
                engine.rule_count(),
                engine.hash_count()
            );
            Ok(if !manifest.sources.iter().any(|s| s.failed()) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
    }
}

fn scan(args: &ScanArgs, dir: &Path, store: &Store) -> Result<ExitCode> {
    let engine = engine(&args.signatures, dir)?;
    let mut options = ScanOptions::new(args.paths.clone(), "cli");
    options.max_size_bytes = args.max_size_mb.saturating_mul(1024 * 1024);
    options.quarantine_floor = if args.quarantine_suspicious {
        Some(Category::Suspicious)
    } else if args.quarantine {
        Some(Category::Pup)
    } else {
        None
    };
    options.exclude = [&args.signatures.rules[..], &args.signatures.hashes[..], &args.load.exclude[..]].concat();
    options.threads = args.load.threads();
    options.background = args.load.level().background();
    options.signatures = signatures_label(&args.signatures, dir);
    options.archives = !args.no_archives;
    let json = args.json;
    let mut on_event = |event: ScanEvent<'_>| {
        if let (ScanEvent::Detection(file), false) = (event, json) {
            println!("[{}] {}  {}", file.worst().category, file.worst().threat, file.path);
            for f in &file.findings {
                println!("    {:<9} {}", f.source.as_str(), f.details);
            }
            println!("    action: {}", file.action);
        }
    };
    let report = scan::run(&engine, store, dir, &options, &AtomicBool::new(false), &mut on_event)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for e in &report.errors {
            eprintln!("warning: {e}");
        }
        println!(
            "\nScan #{} finished in {:.1}s on {} thread(s): {} files ({:.1} MiB), {} infected, {} skipped, {} errors",
            report.scan_id,
            report.elapsed_ms as f64 / 1000.0,
            report.threads,
            report.stats.files_scanned,
            report.stats.bytes_scanned as f64 / 1_048_576.0,
            report.stats.detections,
            report.stats.files_skipped,
            report.stats.errors
        );
    }
    Ok(if report.infected.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// When the downloaded signatures in use were last updated (for history).
fn signatures_label(args: &SignatureArgs, dir: &Path) -> Option<String> {
    if args.no_feeds {
        return None;
    }
    update::load_manifest(&update::signature_dir(dir))
        .last_success()
        .map(str::to_string)
}

fn watch(args: &WatchArgs, dir: &Path) -> Result<ExitCode> {
    let engine = std::sync::Arc::new(engine(&args.signatures, dir)?);
    let mut config = RtpConfig::new(args.folders.clone());
    config.exclude = [&args.signatures.rules[..], &args.signatures.hashes[..], &args.exclude[..]].concat();
    config.max_size_bytes = args.max_size_mb.saturating_mul(1024 * 1024);
    config.quarantine_floor = args.quarantine.then_some(Category::Pup);
    config.signatures = signatures_label(&args.signatures, dir);
    config.process_protection = args.programs;
    config.stop_running_threats = !args.report_only;
    config.trust_signed = !args.no_trust_signed;
    config.scan_archives = !args.no_archives;
    config.scan_new_drives = !args.no_new_drives;
    let notify = args.notify;
    let _handle = rtp::start(engine, dir.to_path_buf(), config, move |event| match event {
        RtpEvent::Started { watching, failed, programs } => {
            let programs = if programs { " and programs as they start" } else { "" };
            println!("Watching {watching} folder(s){programs}. Press Ctrl+C to stop.");
            for (folder, e) in failed {
                eprintln!("warning: cannot watch {} yet ({e}); retrying", folder.display());
            }
        }
        RtpEvent::FolderLost { folder, reason } => eprintln!("warning: stopped watching {} ({reason}); retrying", folder.display()),
        RtpEvent::FolderRestored { folder } => println!("watching {} again; checking recent files", folder.display()),
        RtpEvent::FolderRescan { folder } => println!("many changes at once in {}; rescanning recent files", folder.display()),
        RtpEvent::Detection { report, processes } | RtpEvent::Blocked { report, processes } => {
            let worst = report.worst();
            println!("[{}] {}  {}
    action: {}", worst.category, worst.threat, report.path, report.action);
            for p in &processes {
                match &p.stopped {
                    Some(Ok(())) => println!("    stopped {} (pid {})", p.name, p.pid),
                    Some(Err(e)) => println!("    could not stop {} (pid {}): {e}", p.name, p.pid),
                    None => println!("    left running: {} (pid {})", p.name, p.pid),
                }
            }
            if notify {
                system::notify(&format!("Threat detected: {}", worst.threat), &report.path);
            }
        }
        RtpEvent::Scanned { origin, report } => {
            let what = match origin {
                Origin::Folder => "new file(s)",
                Origin::Program => "program(s)",
            };
            println!("scanned {} {what}, {} threat(s)", report.stats.files_scanned, report.infected.len());
        }
        RtpEvent::RiskyFile { path, risk, origin } => {
            let from = origin.as_ref().and_then(|o| o.host()).map(|h| format!(" from {h}")).unwrap_or_default();
            println!("new {}{from}: {}", risk.kind.label(), path.display());
            if let Some(d) = &risk.disguise {
                println!("    disguised: {d}");
            }
            if notify {
                system::notify(&format!("New {} in a watched folder", risk.kind.label()), &path.display().to_string());
            }
        }
        RtpEvent::RiskyChecked { path, outcome } => match outcome {
            RiskyOutcome::NoThreatFound => println!("    no known threats: {}", path.display()),
            RiskyOutcome::NotScanned(reason) => println!("    not scanned ({reason}): {}", path.display()),
            RiskyOutcome::Threat(_) => {}
        },
        RtpEvent::ProgramWatch { events: true, .. } => println!("programs are seen through Windows' process events"),
        RtpEvent::ProgramWatch { events: false, reason } => {
            let reason = reason.map(|r| format!(" ({r})")).unwrap_or_default();
            println!("programs are found by reading the process list twice a second{reason}");
        }
        RtpEvent::SideLoad(hit) => {
            println!("[possible DLL side-loading] {} (pid {})", hit.headline(), hit.pid);
            println!("    program: {}{}", hit.image.display(), hit.signer.map(|s| format!(", signed by {s}")).unwrap_or_default());
            println!("    report-only: nothing was stopped; the DLL is scanned");
        }
        RtpEvent::Command(hit) => {
            let at = match (hit.source, hit.pid) {
                (rtp::CommandSource::RunBox, _) => "Run box".to_string(),
                (_, Some(pid)) => format!("{} (pid {pid})", hit.program),
                _ => hit.program.clone(),
            };
            println!("[suspicious command, {:?}] {at}: {}", hit.confidence(), hit.command);
            for m in &hit.matches {
                println!("    {}: {}", m.rule, m.reason);
            }
            if let Some(script) = &hit.script {
                println!("    decoded: {script}");
            }
            println!("    report-only: nothing was stopped");
            if notify && hit.confidence() == threat_scanner::cmdline::Confidence::High {
                system::notify(&format!("Suspicious command: {at}"), hit.headline());
            }
        }
        RtpEvent::DriveAdded { root, files } => println!("new drive {}: checking {files} file(s) near its top", root.display()),
        RtpEvent::Restarting { error, retry_in } => {
            eprintln!("warning: {error}; restarting protection in {} s", retry_in.as_secs())
        }
        RtpEvent::Error(e) => eprintln!("warning: {e}"),
    })?;
    loop {
        std::thread::park();
    }
}

fn print_checks(title: &str, checks: &[Check], privacy: bool) {
    match posture::score(checks) {
        Some(s) => println!("{title}: {} ({}%, {} scored, {} unknown)", posture::level(s.percent), s.percent, s.scored, s.unknown),
        None => println!("{title}: could not be assessed"),
    }
    for c in checks {
        let state = match (c.status, privacy) {
            (Status::Good, false) => "ON     ",
            (Status::Good, true) => "PRIVATE",
            (Status::Attention, _) => "REVIEW ",
            (Status::Risk, false) => "OFF    ",
            (Status::Risk, true) => "SHARING",
            (Status::Info, _) => "info   ",
            (Status::Unknown, _) => "unknown",
        };
        println!("  {state}  {}: {}", c.title, c.detail);
        if let Some(toggle) = c.toggle {
            let protective = c.status != Status::Good;
            let page = if privacy { "Privacy" } else { "Protection" };
            println!("           the Phalanx app can switch this ({page} page): {}", toggle.label(protective));
        }
        if let Some(fix) = &c.fix {
            println!("           fix (as administrator): {}", fix.command);
        }
    }
}

fn inspect(args: &InspectArgs, dir: &Path) -> Result<ExitCode> {
    let engine = engine(&args.signatures, dir)?;
    let evidence = ai::collect(&args.file, Some(&engine), args.max_text_kb, !args.no_text)?;
    if args.dry_run {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&evidence)?);
        } else {
            println!("Would send to Gemini ({}):", args.model);
            for line in evidence.sent_summary() {
                println!("  - {line}");
            }
        }
        return Ok(ExitCode::SUCCESS);
    }
    let api_key = std::env::var("GEMINI_API_KEY").unwrap_or_default();
    if api_key.trim().is_empty() {
        anyhow::bail!("set the GEMINI_API_KEY environment variable (get a key at https://aistudio.google.com/apikey)");
    }
    let config = ai::GeminiConfig { api_key, model: args.model.clone(), timeout: std::time::Duration::from_secs(180) };
    let report = ai::inspect(&config, &evidence)?;
    let a = &report.assessment;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}  ({} confidence)  {}", a.verdict.label().to_uppercase(), a.confidence, args.file.display());
        println!("\n{}", a.summary);
        if a.manipulation_attempt {
            println!("\nWARNING: the file contains text trying to influence the verdict.");
        }
        for b in &a.behaviors {
            println!("\n  [{}] {}\n      {}", b.severity, b.title, b.evidence);
        }
        if !a.recommendation.is_empty() {
            println!("\nWhat to do: {}", a.recommendation);
        }
        if let Some(f) = evidence.local_findings.as_ref().filter(|f| !f.is_empty()) {
            println!("\nLocal scanner: {} match(es), worst {}", f.len(), f[0].threat);
        }
        println!("\n{} · {} ms. AI verdicts are advisory and can be wrong.", report.model, report.elapsed_ms);
    }
    Ok(match a.verdict {
        ai::Verdict::Safe => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    })
}

#[cfg(windows)]
fn service_command(cmd: &ServiceCommand) -> Result<ExitCode> {
    use threat_scanner::ipc;
    use threat_scanner::service::manage::{self, State};
    let connect = || ipc::Client::connect().map_err(|e| anyhow::anyhow!(ipc::describe(&e)));
    match cmd {
        ServiceCommand::Install => {
            let exe = std::env::current_exe()?.with_file_name("phalanx-service.exe");
            if !exe.is_file() {
                anyhow::bail!("{} is missing; it is installed next to phalanx-cli.exe", exe.display());
            }
            manage::install(&exe)?;
            println!("The Phalanx service is installed and running ({}).", exe.display());
        }
        ServiceCommand::Uninstall => {
            manage::uninstall()?;
            println!("The Phalanx service is removed.");
        }
        ServiceCommand::Start => {
            manage::start()?;
            println!("The Phalanx service is starting.");
        }
        ServiceCommand::Stop => {
            manage::stop(std::time::Duration::from_secs(20))?;
            println!("The Phalanx service is stopped.");
        }
        ServiceCommand::Migrate { from } => {
            let from = from.clone().unwrap_or_else(scan::default_data_dir);
            // The key is encrypted for this user; the service (SYSTEM) cannot
            // read the copied file, so it travels decrypted.
            let auth_key = update::auth_key(&update::signature_dir(&from)).ok().flatten();
            let reply = ipc::Client::connect().map_err(|e| anyhow::anyhow!(ipc::describe(&e)))?.call(ipc::Request::Migrate { from: from.clone(), auth_key })?;
            if reply.needs_approval {
                anyhow::bail!("migrating needs administrator rights: run this from a terminal opened as administrator");
            }
            let done: ipc::replies::Migrate = reply.into_result()?;
            println!("Brought over from {}:", done.from.display());
            println!("    settings:   {}", if done.settings { "yes" } else { "none found" });
            println!("    history:    {} scan(s)", done.scans);
            println!("    quarantine: {} record(s), {} file(s)", done.quarantined, done.files);
            println!("    other:      {} file(s) (web lists, DNS backup, signatures)", done.copied);
            println!("The old folder was left as it was.");
        }
        ServiceCommand::History { limit, search, kinds, threats_only, days, before } => {
            let mut client = ipc::Client::connect().map_err(|e| anyhow::anyhow!(ipc::describe(&e)))?;
            let since = days.map(|d| (chrono::Local::now() - chrono::Duration::days(d.into())).to_rfc3339_opts(chrono::SecondsFormat::Secs, false));
            let query = threat_scanner::store::HistoryQuery {
                before: *before,
                limit: *limit,
                kinds: kinds.clone(),
                threats_only: *threats_only,
                text: search.clone(),
                since,
            };
            let page: ipc::replies::History = client.call(ipc::Request::History { query })?.into_result()?;
            if page.scans.is_empty() {
                println!("No scans match.");
            }
            for s in &page.scans {
                println!("#{:<5} {:<8} {}  {} file(s), {} detection(s)  {}", s.id, s.kind, s.started_at, s.files_scanned, s.detections, s.targets);
            }
            if let Some(next) = page.next {
                println!("More: add --before {next}");
            }
        }
        ServiceCommand::Scan { paths, kind } => {
            let connect = || ipc::Client::connect().map_err(|e| anyhow::anyhow!(ipc::describe(&e)));
            // Events on a connection of their own (see `Request::Subscribe`).
            let mut events = connect()?;
            events.call(ipc::Request::Subscribe)?;
            // Absolute, as the service does not share this working folder;
            // not canonical, which on Windows means `\\?\C:\…` paths.
            let paths: Vec<PathBuf> = paths.iter().map(|p| std::path::absolute(p).unwrap_or_else(|_| p.clone())).collect();
            let started: ipc::replies::Scan = connect()?.call(ipc::Request::Scan { paths, kind: kind.clone() })?.into_result()?;
            let job = started.job;
            println!("Scanning in the service (job {job})…");
            loop {
                let ipc::ServerMessage::Event { event } = events.next_message()? else { continue };
                if event["job"].as_u64() != Some(job) {
                    continue;
                }
                match event["type"].as_str() {
                    Some("scan-progress") => eprint!("\r  {} file(s), {} detection(s)   ", event["files"], event["detections"]),
                    Some("scan-detection") => {
                        let report = &event["report"];
                        eprintln!("\r  [{}] {}  {}", report["findings"][0]["category"].as_str().unwrap_or(""), report["findings"][0]["threat"].as_str().unwrap_or(""), report["path"].as_str().unwrap_or(""));
                    }
                    Some("scan-finished") => {
                        let r = &event["report"];
                        eprintln!();
                        println!("Done: {} file(s), {} skipped, {} detection(s), {} quarantined (scan {}).", r["files_scanned"], r["files_skipped"], r["detections"], r["quarantined"], r["scan_id"]);
                        return Ok(if r["detections"].as_i64().unwrap_or(0) > 0 { ExitCode::from(1) } else { ExitCode::SUCCESS });
                    }
                    Some("scan-failed") => anyhow::bail!("the scan failed: {}", event["error"].as_str().unwrap_or("")),
                    _ => {}
                }
            }
        }
        ServiceCommand::RunBox => {
            let reply = ipc::Client::connect().map_err(|e| anyhow::anyhow!(ipc::describe(&e)))?.call(ipc::Request::RunBoxView)?;
            if reply.needs_approval {
                anyhow::bail!("this shows every user's Run-box history, so it needs administrator rights");
            }
            let view: ipc::replies::RunBoxView = reply.into_result()?;
            println!("{}", serde_json::to_string_pretty(&view)?);
        }
        ServiceCommand::Site { change, site } => {
            use threat_scanner::web::SiteChange;
            let change = match change {
                SiteChangeArg::Block => SiteChange::Block,
                SiteChangeArg::Unblock => SiteChange::Unblock,
                SiteChangeArg::Allow => SiteChange::Allow,
                SiteChangeArg::Unallow => SiteChange::Unallow,
            };
            let reply = connect()?.call(ipc::Request::ChangeSite { change, site: site.clone() })?;
            if reply.needs_approval {
                anyhow::bail!("{}: run this from a terminal opened as administrator", reply.error.unwrap_or_default());
            }
            let done: ipc::replies::ChangeSite = reply.into_result()?;
            println!("Done: {}", done.site);
        }
        ServiceCommand::Ads { state } => {
            let mut client = connect()?;
            let mut settings: ipc::replies::GetWebSettings = client.call(ipc::Request::GetWebSettings)?.into_result()?;
            settings.block_ads = matches!(state, OnOff::On);
            let reply = client.call(ipc::Request::SetWebSettings { settings })?;
            if reply.needs_approval {
                anyhow::bail!("{}: run this from a terminal opened as administrator", reply.error.unwrap_or_default());
            }
            let _: threat_scanner::web::WebConfig = reply.into_result()?;
            println!("Ad and tracker blocking is {}.", if matches!(state, OnOff::On) { "on" } else { "off" });
        }
        ServiceCommand::Update { force } => {
            let mut events = connect()?;
            events.call(ipc::Request::Subscribe)?;
            let reply = connect()?.call(ipc::Request::UpdateSignatures { force: *force })?;
            let _: serde_json::Value = reply.into_result()?;
            loop {
                let ipc::ServerMessage::Event { event } = events.next_message()? else { continue };
                match event["type"].as_str() {
                    Some("update-progress") => println!("  {}", event["step"].as_str().unwrap_or("")),
                    Some("update-finished") => {
                        let failed: Vec<&str> = event["failed"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
                        println!("Done: {}.", if event["installed"].as_bool() == Some(true) { "new signatures are in use" } else { "nothing new" });
                        if !failed.is_empty() {
                            println!("Failed: {}", failed.join(", "));
                        }
                        return Ok(ExitCode::SUCCESS);
                    }
                    Some("update-failed") => anyhow::bail!("the update failed: {}", event["error"].as_str().unwrap_or("")),
                    _ => {}
                }
            }
        }
        ServiceCommand::AuthKey { key, remove, from_app } => {
            let key = match (remove, from_app) {
                (true, _) => None,
                (_, true) => Some(
                    update::auth_key(&update::signature_dir(&scan::default_data_dir()))?
                        .ok_or_else(|| anyhow::anyhow!("the app has no abuse.ch Auth-Key saved"))?,
                ),
                _ => Some(key.clone().ok_or_else(|| anyhow::anyhow!("give the key, --from-app or --remove"))?),
            };
            let reply = connect()?.call(ipc::Request::SetAuthKey { key: key.clone() })?;
            if reply.needs_approval {
                anyhow::bail!("saving the key needs administrator rights: run this from a terminal opened as administrator");
            }
            let _: serde_json::Value = reply.into_result()?;
            println!("{}", if key.is_some() { "The abuse.ch Auth-Key is saved in the service." } else { "The abuse.ch Auth-Key is removed." });
        }
        ServiceCommand::SetSettings { json } => {
            let settings = serde_json::from_slice(&hex::decode(json.trim())?)?;
            let _: serde_json::Value = approved(connect()?.call(ipc::Request::SetSettings { settings })?)?;
            println!("The protection settings are saved.");
        }
        ServiceCommand::SetWebSettings { json } => {
            let settings = serde_json::from_slice(&hex::decode(json.trim())?)?;
            let _: serde_json::Value = approved(connect()?.call(ipc::Request::SetWebSettings { settings })?)?;
            println!("The web settings are saved.");
        }
        ServiceCommand::Restore { id, force } => {
            let path: ipc::replies::Restore = approved(connect()?.call(ipc::Request::Restore { item: id.clone(), force: *force })?)?;
            println!("Restored to {}.", path.display());
        }
        ServiceCommand::DeleteQuarantined { id } => {
            let _: serde_json::Value = approved(connect()?.call(ipc::Request::DeleteQuarantined { item: id.clone() })?)?;
            println!("Deleted {id} for good.");
        }
        ServiceCommand::Quarantine { path, threat } => {
            let path = std::path::absolute(path).unwrap_or_else(|_| path.clone());
            let id: ipc::replies::QuarantineFile = approved(connect()?.call(ipc::Request::QuarantineFile { path, threat: threat.clone() })?)?;
            println!("Quarantined ({id}).");
        }
        ServiceCommand::Web => {
            let mut client = connect()?;
            let settings: serde_json::Value = client.call(ipc::Request::GetWebSettings)?.into_result()?;
            let status: serde_json::Value = client.call(ipc::Request::WebStatus)?.into_result()?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "status": status, "settings": settings }))?);
        }
        ServiceCommand::Events => {
            let mut events = ipc::Client::connect().map_err(|e| anyhow::anyhow!(ipc::describe(&e)))?;
            events.call(ipc::Request::Subscribe)?;
            eprintln!("Listening to the service. Press Ctrl+C to stop.");
            loop {
                if let ipc::ServerMessage::Event { event } = events.next_message()? {
                    println!("{event}");
                }
            }
        }
        ServiceCommand::Protection => {
            let mut client = ipc::Client::connect().map_err(|e| anyhow::anyhow!(ipc::describe(&e)))?;
            let status: ipc::replies::ProtectionStatus = client.call(ipc::Request::ProtectionStatus)?.into_result()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        ServiceCommand::Settings => {
            let mut client = ipc::Client::connect().map_err(|e| anyhow::anyhow!(ipc::describe(&e)))?;
            let settings: ipc::replies::GetSettings = client.call(ipc::Request::GetSettings)?.into_result()?;
            println!("{}", serde_json::to_string_pretty(&settings)?);
        }
        ServiceCommand::Status => {
            let state = manage::state()?;
            println!("Service: {}", state.label());
            if state != State::Running {
                return Ok(ExitCode::from(1));
            }
            match ipc::status_within(std::time::Duration::from_secs(3)) {
                Ok(status) => {
                    println!("Version: {} (process {})", status.version, status.pid);
                    println!("Data:    {}", status.data_dir.display());
                    let rights = if status.caller.admin { "administrator (elevated)" } else { "standard: changes that weaken protection need approval" };
                    println!("You:     {}, {rights}", status.caller.user);
                }
                Err(e) => {
                    println!("Pipe:    {e}");
                    return Ok(ExitCode::from(1));
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The result of a reply, or that it needs an administrator.
#[cfg(windows)]
fn approved<T: serde::de::DeserializeOwned>(reply: threat_scanner::ipc::Reply) -> Result<T> {
    if reply.needs_approval {
        anyhow::bail!("{}: run this from a terminal opened as administrator", reply.error.unwrap_or_default());
    }
    Ok(reply.into_result()?)
}

#[cfg(not(windows))]
fn service_command(_cmd: &ServiceCommand) -> Result<ExitCode> {
    anyhow::bail!("the protection service is Windows only")
}

fn web_command(cmd: &WebCommand, dir: &Path) -> Result<ExitCode> {
    use web::config::{windows_uses_filter, Mode};
    use web::extensions::{self, KnownBad};
    let load_config = || web::WebConfig::load(dir);
    let save = |config: &web::WebConfig| config.save(dir);
    match cmd {
        WebCommand::Check { targets, resolve, json } => {
            let rules = load_config()?.load_rules(dir)?;
            let mut results = Vec::new();
            for target in targets {
                let mut verdict = rules.classify_url(target);
                let mut addresses = Vec::new();
                let host = web::url::WebAddress::parse(target).map(|a| a.host).filter(|h| h.parse::<std::net::IpAddr>().is_err());
                if let (true, false, Some(host)) = (*resolve, verdict.blocks(), host) {
                    use std::net::ToSocketAddrs;
                    addresses = (host.as_str(), 80).to_socket_addrs().map(|a| a.map(|s| s.ip()).collect()).unwrap_or_default();
                    let answers: Vec<_> = addresses.iter().map(|ip| web::rules::Answer::Address(*ip)).collect();
                    let dns = rules.classify_dns(&host, &answers);
                    if dns.blocks() || verdict.code == web::VerdictCode::Clean {
                        verdict = dns;
                    }
                }
                results.push((target.clone(), verdict, addresses));
            }
            let blocked = results.iter().any(|(_, v, _)| v.blocks());
            if *json {
                let out: Vec<_> = results
                    .iter()
                    .map(|(t, v, a)| serde_json::json!({ "target": t, "block": v.blocks(), "verdict": v, "resolved": a }))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                for (target, verdict, addresses) in &results {
                    println!("{target}\n    {}", verdict.describe());
                    if !addresses.is_empty() {
                        let list: Vec<String> = addresses.iter().map(ToString::to_string).collect();
                        println!("    resolves to {}", list.join(", "));
                    }
                }
            }
            Ok(if blocked { ExitCode::from(1) } else { ExitCode::SUCCESS })
        }
        WebCommand::Status { json } => {
            let config = load_config()?;
            let counts = config.load_rules(dir)?.counts();
            let browsers = web::native::status(dir);
            let dns_in_use = config.dns_listen_addr().is_ok_and(|l| windows_uses_filter(&l));
            if *json {
                let out = serde_json::json!({
                    "config": config,
                    "rules": counts,
                    "browsers": browsers,
                    "windows_dns_uses_filter": dns_in_use,
                    "upstreams": config.upstreams(),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(ExitCode::SUCCESS);
            }
            let mode = match (config.enabled, config.mode) {
                (false, _) => "off",
                (true, Mode::Block) => "blocking",
                (true, Mode::ReportOnly) => "report only",
            };
            println!("Browser checks: {mode}");
            println!(
                "Rules:          {} blocking ({} domains, {} URLs, {} networks, {} ports){}",
                counts.blocking(),
                counts.domains,
                counts.urls,
                counts.networks,
                counts.ports,
                if config.use_feeds { "" } else { ", feeds off" }
            );
            println!(
                "Ad blocking:    {}",
                match (config.block_ads, counts.ads) {
                    (false, _) => "off".to_string(),
                    (true, 0) => "on, but the ad list is not downloaded yet (run `phalanx-cli update`)".to_string(),
                    (true, n) => format!("on ({n} ad and tracker names)"),
                }
            );
            println!("Browsers:");
            for b in &browsers {
                println!("    {:<22} {}", b.browser, b.describe());
            }
            println!(
                "DNS filter:     {} on {}; Windows DNS {} it",
                if config.dns_filter { "on in the app" } else { "off" },
                config.dns_listen,
                if dns_in_use { "uses" } else { "does not use" }
            );
            let upstreams: Vec<String> = config.upstreams().iter().map(ToString::to_string).collect();
            println!("Forwards to:    {}", upstreams.join(", "));
            for (label, list) in [
                ("Allowed", &config.user_allow),
                ("Blocked", &config.user_block),
                ("Excluded by browser", &config.extension_exclusions),
            ] {
                if !list.is_empty() {
                    println!("{label}: {}", list.join(", "));
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        WebCommand::Mode { mode } => {
            let mut config = load_config()?;
            (config.enabled, config.mode) = match mode {
                ModeArg::Block => (true, Mode::Block),
                ModeArg::ReportOnly => (true, Mode::ReportOnly),
                ModeArg::Off => (false, config.mode),
            };
            save(&config)?;
            let state = match mode {
                ModeArg::Block => "blocking",
                ModeArg::ReportOnly => "reporting only",
                ModeArg::Off => "off in the browser",
            };
            println!("Web protection is now {state}.");
            Ok(ExitCode::SUCCESS)
        }
        WebCommand::Ads { state } => {
            let mut config = load_config()?;
            config.block_ads = matches!(state, OnOff::On);
            save(&config)?;
            if !config.block_ads {
                println!("Ad and tracker blocking is now off.");
            } else if web::config::ads_file(dir).is_file() {
                println!("Ad and tracker blocking is now on.");
            } else {
                println!("Ad and tracker blocking is now on. Run `phalanx-cli update` to download the ad list.");
            }
            Ok(ExitCode::SUCCESS)
        }
        WebCommand::Allow { site } | WebCommand::Block { site } => {
            let mut config = load_config()?;
            let allow = matches!(cmd, WebCommand::Allow { .. });
            let entry = if allow { config.allow(site) } else { config.block(site) };
            let Some(entry) = entry else { anyhow::bail!("`{site}` is not a site, URL or CIDR range") };
            save(&config)?;
            println!("{} {entry}", if allow { "Allowed" } else { "Blocked" });
            Ok(ExitCode::SUCCESS)
        }
        WebCommand::Forget { site } => {
            let mut config = load_config()?;
            if config.forget(site) {
                save(&config)?;
                println!("Removed {site} from your lists");
            } else {
                println!("{site} is not on your lists");
            }
            Ok(ExitCode::SUCCESS)
        }
        WebCommand::Events { limit, json } => {
            let events = web::events::recent(dir, *limit);
            if *json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else if events.is_empty() {
                println!("No web protection events yet.");
            } else {
                for e in events {
                    println!(
                        "{}  {} {} ({}) {}\n    [{}] {} via {}",
                        e.time, e.source, e.action, e.code, e.target, e.category, e.threat, e.list
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        WebCommand::Serve { listen, upstream, sinkhole, port, report_only } => {
            web_serve(dir, listen.as_deref(), upstream, *sinkhole, *port, *report_only)
        }
        WebCommand::Connect => {
            let exe = web::native::host_exe()?;
            let browsers = web::native::install(dir, &exe)?;
            println!("Browser connector registered for this user ({}).", exe.display());
            for b in browsers {
                println!("    {:<22} {}", b.browser, if b.current { "ok" } else { "FAILED" });
            }
            let ext = web::native::extension_dir(dir);
            println!("\nNow add the Phalanx Browser Guard extension to each browser:");
            println!("  1. Open chrome://extensions (Edge: edge://extensions, Brave: brave://extensions).");
            println!("  2. Turn on Developer mode, choose \"Load unpacked\" and pick:\n       {}", ext.display());
            let firefox = web::native::firefox_extension_dir(dir);
            println!("  Firefox: about:debugging > This Firefox > Load Temporary Add-on > {}", firefox.join("manifest.json").display());
            println!("The extension's icon shows \"!\" when it cannot reach Phalanx.");
            Ok(ExitCode::SUCCESS)
        }
        WebCommand::Disconnect => {
            web::native::uninstall()?;
            println!("Browser connector unregistered. Remove the extension from your browsers too.");
            Ok(ExitCode::SUCCESS)
        }
        WebCommand::Extensions { all, json } => {
            let rules = load_config()?.load_rules(dir)?;
            let report = extensions::scan(Some(&rules), &KnownBad::load(Some(&update::signature_dir(dir))));
            if *json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                let browsers = if report.browsers.is_empty() { "no Chromium browsers found".to_string() } else { report.browsers.join(", ") };
                println!("Checked {} extension(s) in {} profile(s) of: {browsers}", report.extensions.len(), report.profiles);
                for e in report.extensions.iter().filter(|e| *all || e.rating() != "ok") {
                    println!(
                        "\n[{}] {} {} ({})\n    {} / {} · id {} · risk {}/100 · {}{}",
                        e.rating().to_uppercase(),
                        e.name,
                        e.version,
                        e.threat.as_deref().unwrap_or("no known threat"),
                        e.browser,
                        e.profile_name,
                        e.id,
                        e.score,
                        e.install_source,
                        if e.enabled { "" } else { " · disabled" }
                    );
                    for r in &e.reasons {
                        println!("    - {r}");
                    }
                    if e.rating() != "ok" {
                        println!(
                            "    remove: phalanx-cli web remove-extension --browser \"{}\" --profile \"{}\" {}",
                            e.browser, e.profile, e.id
                        );
                    }
                }
                for s in &report.settings {
                    let label = if s.blocked { "THREAT" } else { "REVIEW" };
                    println!("\n[{label}] {} / {}: {} {}\n    {}", s.browser, s.profile_name, s.setting, s.value, s.reason);
                }
                for e in &report.errors {
                    eprintln!("warning: {e}");
                }
                if report.flagged().count() + report.settings.len() == 0 {
                    println!("Nothing needs your attention.");
                }
            }
            let threats = report.flagged().any(|e| e.category.is_some()) || report.settings.iter().any(|s| s.blocked);
            Ok(if threats { ExitCode::from(1) } else { ExitCode::SUCCESS })
        }
        WebCommand::RemoveExtension { browser, profile, id } => {
            let installed = extensions::browsers();
            let Some(found) = installed.iter().find(|b| b.name.eq_ignore_ascii_case(browser)) else {
                let names: Vec<&str> = installed.iter().map(|b| b.name.as_str()).collect();
                anyhow::bail!("no browser named `{browser}` (found: {})", names.join(", "));
            };
            let backup = extensions::remove_extension(found, profile, id, &dir.join("browser-backups"))?;
            println!("Removed {id} from {} ({profile}).\nBackup: {}", found.name, backup.display());
            println!("If it comes back, browser sync, a policy or another program is reinstalling it.");
            Ok(ExitCode::SUCCESS)
        }
        WebCommand::RestoreExtension { backup } => {
            println!("{}", extensions::restore_extension(backup)?);
            Ok(ExitCode::SUCCESS)
        }
        WebCommand::RestoreDns { check } => {
            // Since 0.5 the backup is kept in the service's folder.
            let machine = threat_scanner::service::data::machine_data_dir();
            let dir = if web::windows_dns::has_backup(&machine) { machine.as_path() } else { dir };
            let nothing = if *check { ExitCode::from(1) } else { ExitCode::SUCCESS };
            if !web::windows_dns::has_backup(dir) {
                println!("Phalanx did not change Windows' DNS settings; nothing to restore.");
                return Ok(nothing);
            }
            if !web::windows_dns::filter_in_use(dir) {
                let _ = std::fs::remove_file(web::windows_dns::backup_path(dir));
                println!("Windows does not use Phalanx's DNS filter, so there is nothing to put back; the old backup was discarded.");
                return Ok(nothing);
            }
            if *check {
                println!("Windows uses Phalanx's DNS filter; restore-dns puts the previous settings back.");
                return Ok(ExitCode::SUCCESS);
            }
            match web::windows_dns::restore(dir)? {
                system::Elevated::Exited(0) => {
                    println!("Windows' previous DNS settings are back.");
                    Ok(ExitCode::SUCCESS)
                }
                system::Elevated::Exited(code) => anyhow::bail!("restoring the DNS settings failed (exit code {code})"),
                system::Elevated::Declined => {
                    eprintln!("Cancelled at the administrator prompt; Windows still uses Phalanx's DNS filter.");
                    Ok(ExitCode::from(2))
                }
            }
        }
        WebCommand::NativeHost => {
            web::native::run_host(dir, std::io::stdin().lock(), std::io::stdout().lock())?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Runs the DNS filter and block-page server in the foreground, reloading
/// rules when the settings or downloaded feeds change.
fn web_serve(
    dir: &Path,
    listen: Option<&str>,
    upstream: &[String],
    sinkhole: Option<std::net::Ipv4Addr>,
    port: Option<u16>,
    report_only: bool,
) -> Result<ExitCode> {
    use std::sync::{Arc, RwLock};
    use web::config::Mode;
    let mut config = web::WebConfig::load(dir)?;
    if let Some(l) = listen {
        config.dns_listen = l.to_string();
    }
    if !upstream.is_empty() {
        config.dns_upstream = upstream.to_vec();
    }
    config.sinkhole = sinkhole.unwrap_or(config.sinkhole);
    config.block_page_port = port.unwrap_or(config.block_page_port);
    if report_only {
        config.mode = Mode::ReportOnly;
    }
    let rules: web::SharedRules = Arc::new(RwLock::new(Arc::new(config.load_rules(dir)?)));
    let cache = Arc::new(web::cache::RedirectionCache::new());
    let page_addr = std::net::SocketAddr::new(config.sinkhole.into(), config.block_page_port);
    let page = web::blockpage::BlockPageServer::start(page_addr, cache.clone())?;
    let filter = web::dnsfilter::DnsFilter::start(
        web::dnsfilter::FilterConfig {
            listen: config.dns_listen_addr()?,
            upstreams: config.upstreams(),
            sinkhole: config.sinkhole,
            mode: config.mode,
            data_dir: Some(dir.to_path_buf()),
        },
        rules.clone(),
        cache,
        Some(Box::new(|e: &web::events::WebEvent| {
            println!("{} {} [{}] {} ({})", e.action, e.target, e.category, e.threat, e.list);
        })),
    )?;
    let upstreams: Vec<String> = config.upstreams().iter().map(ToString::to_string).collect();
    println!(
        "DNS filter on {} (forwarding to {}), block page on {}.",
        filter.local_addr(),
        upstreams.join(", "),
        page.local_addr()
    );
    if let Some(v6) = filter.local_addr_v6() {
        println!("Also serving IPv6 lookups on {v6}.");
    }
    if !web::config::windows_uses_filter(&filter.local_addr()) {
        println!("Windows does not use it yet: set your network adapter's DNS server to {}.", filter.local_addr().ip());
    }
    let blocking = if config.mode == Mode::Block { "Blocking." } else { "Report-only: nothing is blocked." };
    println!("{blocking} Press Ctrl+C to stop.");

    let stamp = || {
        let modified = |p: PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        (
            modified(web::WebConfig::path(dir)),
            modified(update::signature_dir(dir).join(web::config::FEED_FILE)),
            modified(web::config::ads_file(dir)),
        )
    };
    let mut seen = stamp();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let now = stamp();
        if now == seen {
            continue;
        }
        seen = now;
        match web::WebConfig::load(dir).and_then(|c| c.load_rules(dir)) {
            Ok(new) => {
                *rules.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(new);
                println!("Rules reloaded.");
            }
            Err(e) => eprintln!("warning: keeping previous rules: {e:#}"),
        }
    }
}
