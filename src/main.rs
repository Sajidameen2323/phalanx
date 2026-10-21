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
    /// Skip files larger than this many MiB.
    #[arg(long, default_value_t = 100)]
    max_size_mb: u64,
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
    /// Report heuristic findings even on validly signed files.
    #[arg(long)]
    no_trust_signed: bool,
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
            let report = web::hardening::check(!offline);
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
        Command::Update { force, check } => {
            let sig_dir = update::signature_dir(&dir);
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
                println!("{} {}: {}", if s.ok { "ok  " } else { "FAIL" }, s.name, s.message);
            }
            if !manifest.installed_anything() && manifest.sources.iter().all(|s| s.ok) {
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
            Ok(if manifest.sources.iter().all(|s| s.ok) {
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
            println!("  Firefox: about:debugging > This Firefox > Load Temporary Add-on > {}", ext.join("manifest.json").display());
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
