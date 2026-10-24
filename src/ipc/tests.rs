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
        let running = crate::service::start(&name).unwrap();

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
        let running = crate::service::start(&name).unwrap();
        // A second server on the same name is refused, not shared.
        assert!(crate::service::start(&name).is_err());
        // This server runs as the user, not as a service in session 0: a
        // client that wants the real service refuses it.
        let err = Client::connect_to(&name, true).err().expect("not a service");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        running.stop();
        // Gone: the client says so plainly.
        let err = Client::connect_to(&name, false).err().expect("stopped");
        assert_eq!(describe(&err), "the protection service is not running");
    }
}
