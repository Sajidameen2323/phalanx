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
        Request::ScanDetails { scan: 3 },
        Request::RecentDetections { limit: 20 },
        Request::MonthlySummary,
        Request::Quarantine { include_restored: true },
        Request::Restore { item: "a".into(), force: false },
        Request::DeleteQuarantined { item: "a".into() },
        Request::Migrate { from: r"C:\Users\me\AppData\Local\threat-scanner".into() },
    ] {
        let line = serde_json::to_string(&ClientMessage { id: 9, request: request.clone() }).unwrap();
        let back: Result<ClientMessage, _> = serde_json::from_str(&line);
        assert_eq!(back.as_ref().map(|m| &m.request).ok(), Some(&request), "{line}: {back:?}");
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

    fn test_data_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("phalanx-ipc-test-{}", std::process::id()))
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
        let running = crate::service::start(&name, dir).unwrap();
        let mut client = Client::connect_to(&name, false).unwrap();
        let admin = elevated();

        let settings: ProtectionSettings = client.call(Request::GetSettings).unwrap().into_result().unwrap();
        assert_eq!(settings, ProtectionSettings::default());
        // Stronger: anyone.
        let stronger = ProtectionSettings { auto_quarantine: true, ..settings.clone() };
        assert!(client.call(Request::SetSettings { settings: stronger.clone() }).unwrap().ok);
        assert_eq!(ProtectionSettings::load(dir).unwrap(), stronger, "saved in the service's folder");
        // Weaker: an administrator, and the reply says why.
        let weaker = ProtectionSettings { watch_enabled: false, ..stronger.clone() };
        let reply = client.call(Request::SetSettings { settings: weaker }).unwrap();
        if admin {
            assert!(reply.ok);
        } else {
            assert!(reply.needs_approval, "{reply:?}");
            assert!(reply.error.as_deref().unwrap().contains("turns off real-time protection"), "{reply:?}");
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
                Request::Migrate { from: dir.join("elsewhere") },
            ] {
                assert!(client.call(request).unwrap().needs_approval);
            }
        }
        running.stop();
    }
}
