use super::*;

#[test]
fn messages_are_one_json_object_per_line() {
    let line = serde_json::to_string(&ClientMessage { id: 7, request: Request::Status }).unwrap();
    assert_eq!(line, r#"{"id":7,"op":"status"}"#);
    let refused = serde_json::to_string(&ServerMessage::Reply(Reply::needs_approval(3))).unwrap();
    let back: ServerMessage = serde_json::from_str(&refused).unwrap();
    assert_eq!(back, ServerMessage::Reply(Reply::needs_approval(3)));
    assert!(refused.contains(r#""kind":"reply""#) && refused.contains(r#""needs_approval":true"#), "{refused}");
    let ok = serde_json::to_string(&ServerMessage::Reply(Reply::ok(1, serde_json::json!("pong")))).unwrap();
    assert!(!ok.contains("needs_approval") && !ok.contains("error"), "{ok}");
}

#[test]
fn every_request_reads_back_as_sent() {
    use crate::service::settings::ProtectionSettings;
    for request in [
        Request::Ping,
        Request::Stop,
        Request::GetSettings,
        Request::SetSettings { settings: ProtectionSettings { exclusions: vec![r"D:\VMs".into()], ..Default::default() } },
        Request::RecentScans { limit: 10, kind: Some("quick".into()) },
        Request::RecentScans { limit: 5, kind: None },
        Request::History {
            query: crate::store::HistoryQuery {
                before: Some(41),
                limit: 50,
                kinds: vec!["watch".into(), "process".into()],
                threats_only: true,
                text: Some("invoice".into()),
                since: Some("2026-10-01T00:00:00+05:30".into()),
            },
        },
        Request::HistoryInfo,
        Request::ScanDetails { scan: 3 },
        Request::RecentDetections { limit: 20 },
        Request::MonthlySummary,
        Request::Quarantine { include_restored: true },
        Request::Restore { item: "a".into(), force: false },
        Request::DeleteQuarantined { item: "a".into() },
        Request::Migrate { from: r"C:\Users\me\AppData\Local\threat-scanner".into(), auth_key: Some("0123abcd".into()) },
        Request::ChangeSite { change: crate::web::SiteChange::Allow, site: "https://example.test/".into() },
        Request::UpdateSignatures { force: true },
    ] {
        let line = serde_json::to_string(&ClientMessage { id: 9, request: request.clone() }).unwrap();
        let back: Result<ClientMessage, _> = serde_json::from_str(&line);
        assert_eq!(back.as_ref().map(|m| &m.request).ok(), Some(&request), "{line}: {back:?}");
    }
}

/// Events are internally tagged, which buffers their fields: a field serde
/// cannot buffer (a `u128`) makes the event unreadable, and the app drops it.
#[test]
fn every_event_reads_back_as_sent() {
    use crate::scan::{FileReport, ScanReport};
    let file = || FileReport { path: r"C:\Users\me\Downloads\a.exe".into(), sha256: "ab".repeat(32), findings: Vec::new(), action: "reported".into() };
    let report = ScanReport {
        scan_id: 7,
        elapsed_ms: 1_234,
        cancelled: true,
        threads: 2,
        stats: Default::default(),
        infected: vec![file()],
        errors: vec!["locked".into()],
    };
    for event in [
        Event::ScanProgress { job: 1, files: 10, bytes: 2048, detections: 0, path: r"C:\x".into() },
        Event::ScanDetection { job: 1, report: file() },
        Event::ScanFinished { job: 1, report },
        Event::ScanFailed { job: 1, error: "gone".into() },
        Event::SettingsChanged { settings: Default::default() },
        Event::WebSettingsChanged { settings: Default::default() },
        Event::UpdateFinished { installed: true, last_success: None, failed: vec!["URLhaus".into()] },
    ] {
        let sent = serde_json::to_value(&event).unwrap();
        let back = serde_json::from_value::<Event>(sent.clone());
        assert!(back.as_ref().is_ok_and(|b| serde_json::to_value(b).unwrap() == sent), "{sent}: {back:?}");
    }
}

#[test]
fn weakening_needs_an_administrator() {
    let user = Caller { user: "PC\\me".into(), sid: "S-1-5-21-1".into(), admin: false };
    let admin = Caller { admin: true, ..user.clone() };
    assert!(user.may(&Request::Status) && user.may(&Request::Ping));
    assert!(!user.may(&Request::Stop));
    assert!(admin.may(&Request::Stop));
}

#[cfg(windows)]
mod live {
    use super::super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A data folder whose settings keep real-time protection off: tests must
    /// not watch this PC's Downloads folders and programs.
    fn quiet(dir: &std::path::Path) -> &std::path::Path {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("settings.json"), r#"{"watch_enabled": false}"#).unwrap();
        dir
    }

    fn test_data_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("phalanx-ipc-test-{}", std::process::id()));
        quiet(&dir);
        dir
    }

    fn private_pipe() -> String {
        static N: AtomicUsize = AtomicUsize::new(0);
        format!(r"\\.\pipe\phalanx-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed))
    }

    /// The live tests run the server as the user, who owns the pipe and so
    /// has every right: a client asking for more than users are granted
    /// would pass them and fail against the real service.
    #[test]
    fn users_are_granted_exactly_what_the_client_asks_for() {
        use crate::ipc::pipe::{CLIENT_ACCESS, SDDL};
        let ace = SDDL.split("(A;;").find(|ace| ace.ends_with(";;;IU)")).expect("an ACE for interactive users");
        let mask = u32::from_str_radix(ace.trim_start_matches("0x").split(';').next().unwrap(), 16).unwrap();
        assert_eq!(mask, CLIENT_ACCESS);
        assert_eq!(CLIENT_ACCESS & 0x4, 0, "users must not create pipe instances");
    }

    /// Whether this test process runs elevated, by Windows' own account.
    fn elevated() -> bool {
        unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
    }

    #[test]
    fn the_service_answers_and_knows_who_asks() {
        let name = private_pipe();
        let running = crate::service::start(&name, &test_data_dir()).unwrap();

        let mut client = Client::connect_to(&name, false).unwrap();
        assert_eq!(client.call(Request::Ping).unwrap().result, serde_json::json!("pong"));
        let status = client.status().unwrap();
        assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(status.pid, std::process::id());
        assert!(status.caller.sid.starts_with("S-1-5-"), "{:?}", status.caller);
        let me = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
        assert!(status.caller.user.to_lowercase().ends_with(&me), "{:?}", status.caller);
        assert_eq!(status.caller.admin, elevated(), "admin means elevated, not just in the Administrators group");

        // Several clients at once.
        let mut second = Client::connect_to(&name, false).unwrap();
        assert!(second.call(Request::Ping).unwrap().ok);
        assert!(client.call(Request::Ping).unwrap().ok);

        // Stopping weakens protection: refused unless elevated.
        let reply = client.call(Request::Stop).unwrap();
        if elevated() {
            assert!(reply.ok && running.stop_requested(std::time::Duration::from_secs(2)));
        } else {
            assert!(!reply.ok && reply.needs_approval, "{reply:?}");
            assert!(!running.stop_requested(std::time::Duration::from_millis(300)));
        }
        running.stop();
    }

    #[test]
    fn the_pipe_name_cannot_be_taken_or_faked() {
        let name = private_pipe();
        let running = crate::service::start(&name, &test_data_dir()).unwrap();
        // A second server on the same name is refused, not shared.
        assert!(crate::service::start(&name, &test_data_dir()).is_err());
        // This server runs as the user, not as a service in session 0: a
        // client that wants the real service refuses it.
        let err = Client::connect_to(&name, true).err().expect("not a service");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        running.stop();
        // Gone: the client says so plainly.
        let err = Client::connect_to(&name, false).err().expect("stopped");
        assert_eq!(describe(&err), "the protection service is not running");
    }

    #[test]
    fn settings_history_and_quarantine_go_through_the_service() {
        use crate::service::settings::ProtectionSettings;
        use crate::store::{ScanMeta, ScanRow};
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        {
            let store = crate::scan::open_store(dir).unwrap();
            let id = store.begin_scan(&ScanMeta { kind: "quick", targets: r"C:\Users", threads: 2, signatures: None }).unwrap();
            store.finish_scan(id, &Default::default(), 10, false).unwrap();
        }
        let name = private_pipe();
        let running = crate::service::start(&name, quiet(dir)).unwrap();
        let mut client = Client::connect_to(&name, false).unwrap();
        let admin = elevated();

        let settings: ProtectionSettings = client.call(Request::GetSettings).unwrap().into_result().unwrap();
        assert_eq!(settings, ProtectionSettings { watch_enabled: false, ..Default::default() });
        // Stronger: anyone.
        let stronger = ProtectionSettings { auto_quarantine: true, ..settings.clone() };
        assert!(client.call(Request::SetSettings { settings: stronger.clone() }).unwrap().ok);
        assert_eq!(ProtectionSettings::load(dir).unwrap(), stronger, "saved in the service's folder");
        // Weaker: an administrator, and the reply says why.
        let weaker = ProtectionSettings { program_protection: false, ..stronger.clone() };
        let reply = client.call(Request::SetSettings { settings: weaker }).unwrap();
        if admin {
            assert!(reply.ok);
        } else {
            assert!(reply.needs_approval, "{reply:?}");
            assert!(reply.error.as_deref().unwrap().contains("turns off scanning programs as they start"), "{reply:?}");
            assert_eq!(ProtectionSettings::load(dir).unwrap(), stronger, "unchanged");
        }

        // History and quarantine: anyone may look.
        let scans: Vec<ScanRow> = client.call(Request::RecentScans { limit: 10, kind: None }).unwrap().into_result().unwrap();
        assert_eq!((scans.len(), scans[0].kind.as_str(), scans[0].threads), (1, "quick", 2));
        let details: serde_json::Value = client.call(Request::ScanDetails { scan: scans[0].id }).unwrap().into_result().unwrap();
        assert_eq!(details, serde_json::json!({ "detections": [], "errors": [] }));
        let items: Vec<crate::store::QuarantineRow> = client.call(Request::Quarantine { include_restored: true }).unwrap().into_result().unwrap();
        assert!(items.is_empty());

        // Restoring, deleting and migrating need an administrator.
        if !admin {
            for request in [
                Request::Restore { item: "x".into(), force: false },
                Request::DeleteQuarantined { item: "x".into() },
                Request::Migrate { from: dir.join("elsewhere"), auth_key: None },
            ] {
                assert!(client.call(request).unwrap().needs_approval);
            }
        }
        running.stop();
    }

    /// Events from a subscribed connection, on a thread, so a test can wait
    /// for one with a time limit.
    fn subscribe(name: &str) -> std::sync::mpsc::Receiver<serde_json::Value> {
        let mut events = Client::connect_to(name, false).unwrap();
        assert!(events.call(Request::Subscribe).unwrap().ok);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            while let Ok(message) = events.next_message() {
                if let ServerMessage::Event { event } = message && tx.send(event).is_err() {
                    break;
                }
            }
        });
        rx
    }

    /// Waits up to 30 s for an event that `wanted` accepts.
    fn wait_for(events: &std::sync::mpsc::Receiver<serde_json::Value>, wanted: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut seen = Vec::new();
        while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
            match events.recv_timeout(left) {
                Ok(event) if wanted(&event) => return event,
                Ok(event) => seen.push(event["type"].clone()),
                Err(_) => break,
            }
        }
        panic!("no such event within 30 s; saw {seen:?}");
    }

    #[test]
    fn protection_and_scans_run_in_the_service() {
        use crate::service::settings::ProtectionSettings;
        let marker = "threat-scanner-test-marker-7f3a".to_ascii_uppercase();
        let tmp = tempfile::tempdir().unwrap();
        let (dir, watched, elsewhere) = (tmp.path().join("data"), tmp.path().join("downloads"), tmp.path().join("elsewhere"));
        for d in [&dir, &watched, &elsewhere] {
            std::fs::create_dir_all(d).unwrap();
        }
        // Real-time protection on, for this folder only.
        let settings = ProtectionSettings {
            watch_folders: vec![watched.clone()],
            program_protection: false,
            scan_new_drives: false,
            ..Default::default()
        };
        settings.save(&dir).unwrap();
        let name = private_pipe();
        let events = subscribe_after_start(&name, &dir);

        // Protection may have started before this client subscribed: ask.
        let mut client = Client::connect_to(&name, false).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let status: ProtectionStatus = client.call(Request::ProtectionStatus).unwrap().into_result().unwrap();
            if status.watching {
                assert!(status.engine.is_some_and(|(rules, _)| rules > 0), "{status:?}");
                break;
            }
            assert!(std::time::Instant::now() < deadline, "protection did not start: {status:?}");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        std::fs::write(watched.join("invoice.txt"), format!("x {marker} y")).unwrap();
        let found = wait_for(&events, |e| e["type"] == "detection");
        assert!(found["report"]["path"].as_str().unwrap().ends_with("invoice.txt"), "{found}");
        assert_eq!(found["report"]["findings"][0]["threat"], "Test.ThreatScanner.Marker");

        // A scan asked for through the pipe.
        let bad = elsewhere.join("setup.txt");
        std::fs::write(&bad, format!("x {marker} y")).unwrap();
        let started: serde_json::Value = client.call(Request::Scan { paths: vec![elsewhere.clone()], kind: "custom".into() }).unwrap().into_result().unwrap();
        let job = started["job"].clone();
        let finished = wait_for(&events, |e| e["type"] == "scan-finished" && e["job"] == job);
        assert_eq!(finished["report"]["infected"].as_array().unwrap().len(), 1, "{finished}");
        let scan_id = finished["report"]["scan_id"].as_i64().unwrap();
        // History's "Show details" for it.
        let details: ScanDetails = client.call(Request::ScanDetails { scan: scan_id }).unwrap().into_result().unwrap();
        assert!(details.detections.len() == 1 && details.detections[0].path.ends_with("setup.txt"), "{details:?}");

        // Only what the service detected can be quarantined, once.
        let not_detected = client.call(Request::QuarantineDetection { scan: scan_id, path: elsewhere.join("other.txt") }).unwrap();
        assert!(!not_detected.ok && not_detected.error.as_deref().unwrap().contains("reported no threat"), "{not_detected:?}");
        assert!(client.call(Request::QuarantineDetection { scan: scan_id, path: bad.clone() }).unwrap().ok);
        assert!(!bad.exists());
        let again = client.call(Request::QuarantineDetection { scan: scan_id, path: bad.clone() }).unwrap();
        assert!(again.error.as_deref().unwrap().contains("already quarantined"), "{again:?}");
        let items: Vec<crate::store::QuarantineRow> = client.call(Request::Quarantine { include_restored: false }).unwrap().into_result().unwrap();
        assert_eq!(items.len(), 1);
        assert!(client.call(Request::Scan { paths: vec![tmp.path().join("missing")], kind: "custom".into() }).unwrap().error.is_some());
    }

    /// Starts the service (kept running until the test process ends: its
    /// threads stop with it) and subscribes before protection starts.
    fn subscribe_after_start(name: &str, dir: &std::path::Path) -> std::sync::mpsc::Receiver<serde_json::Value> {
        let running = crate::service::start(name, dir).unwrap();
        let events = subscribe(name);
        std::mem::forget(running);
        events
    }

    /// A free local port (bound, then released).
    fn free_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    #[test]
    fn web_protection_goes_through_the_service() {
        use crate::web::{Mode, SiteChange, WebConfig};
        let tmp = tempfile::tempdir().unwrap();
        let dir = quiet(tmp.path());
        let name = private_pipe();
        let running = crate::service::start(&name, dir).unwrap();
        let mut client = Client::connect_to(&name, false).unwrap();
        let admin = elevated();

        let settings: WebConfig = client.call(Request::GetWebSettings).unwrap().into_result().unwrap();
        assert_eq!(settings, WebConfig::default());

        // Blocking a site strengthens: anyone, and it is saved where the service keeps it.
        let blocked: serde_json::Value = client
            .call(Request::ChangeSite { change: SiteChange::Block, site: "https://www.bad.test/x".into() })
            .unwrap()
            .into_result()
            .unwrap();
        assert_eq!(blocked["site"], "www.bad.test");
        assert_eq!(WebConfig::load(dir).unwrap().user_block, ["www.bad.test"]);

        // Allowing, unblocking and reporting only weaken: an administrator.
        if !admin {
            let allow = client.call(Request::ChangeSite { change: SiteChange::Allow, site: "shady.test".into() }).unwrap();
            assert!(allow.needs_approval && allow.error.as_deref().unwrap().contains("allows shady.test"), "{allow:?}");
            let unblock = client.call(Request::ChangeSite { change: SiteChange::Unblock, site: "www.bad.test".into() }).unwrap();
            assert!(unblock.needs_approval, "{unblock:?}");
            let report = WebConfig { mode: Mode::ReportOnly, ..WebConfig::load(dir).unwrap() };
            let reply = client.call(Request::SetWebSettings { settings: report }).unwrap();
            assert!(reply.needs_approval && reply.error.as_deref().unwrap().contains("only reports"), "{reply:?}");
            assert_eq!(WebConfig::load(dir).unwrap().user_block, ["www.bad.test"], "unchanged");
            assert!(client.call(Request::SetAuthKey { key: Some("0123abcd".into()) }).unwrap().needs_approval);
        }

        // Turning the DNS filter on strengthens; the service runs it.
        let (dns, page) = (free_port(), free_port());
        let on = WebConfig {
            dns_filter: true,
            dns_listen: format!("127.0.0.1:{dns}"),
            dns_upstream: vec!["192.0.2.1".into()],
            sinkhole: std::net::Ipv4Addr::LOCALHOST,
            block_page_port: page,
            ..WebConfig::load(dir).unwrap()
        };
        if admin {
            assert!(client.call(Request::SetWebSettings { settings: on }).unwrap().ok);
        } else {
            // Moving where it listens weakens, so start it as the service would at start.
            on.save(dir).unwrap();
            drop(client);
            running.stop();
            let running = crate::service::start(&name, dir).unwrap();
            client = Client::connect_to(&name, false).unwrap();
            std::mem::forget(running);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let status = loop {
            let status: crate::service::web::WebStatus = client.call(Request::WebStatus).unwrap().into_result().unwrap();
            if status.dns_filter || std::time::Instant::now() > deadline {
                break status;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        assert!(status.dns_filter && status.rules > 0 && status.error.is_none(), "{status:?}");
        assert!(std::net::UdpSocket::bind(format!("127.0.0.1:{dns}")).is_err(), "the service's DNS filter holds the port");
    }
}
