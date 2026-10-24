//! `phalanx-service.exe`: the protection service, run by Windows' service
//! manager as LocalSystem. `--console` runs it in this terminal instead (for
//! development), optionally on another pipe name with `--pipe NAME`.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--console") {
        let pipe = args.iter().position(|a| a == "--pipe").and_then(|i| args.get(i + 1)).cloned();
        return console(pipe.as_deref().unwrap_or(threat_scanner::ipc::PIPE_NAME));
    }
    match windows_service::service_dispatcher::start(threat_scanner::service::SERVICE_NAME, ffi_service_main) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("phalanx-service runs as a Windows service (install it with `phalanx-cli service install`).");
            eprintln!("To run it in this terminal instead: phalanx-service --console [--pipe NAME]");
            std::process::ExitCode::from(2)
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("phalanx-service is Windows only");
    std::process::exit(2);
}

#[cfg(windows)]
fn console(pipe: &str) -> std::process::ExitCode {
    let running = match threat_scanner::service::start(pipe) {
        Ok(running) => running,
        Err(e) => {
            eprintln!("could not start on {pipe}: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    println!("Phalanx service running in this terminal on {pipe}. Press Ctrl+C to stop.");
    while !running.stop_requested(std::time::Duration::from_secs(1)) {}
    println!("Stopping: an administrator asked.");
    running.stop();
    std::process::ExitCode::SUCCESS
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    // A failure here ends the service with an error code; Windows' recovery
    // options restart it.
    let _ = run_service();
}

#[cfg(windows)]
fn run_service() -> windows_service::Result<()> {
    use std::time::Duration;
    use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let (tx, rx) = std::sync::mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(threat_scanner::service::SERVICE_NAME, handler)?;
    let report = |state, accept, exit: u32, wait: u64| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(exit),
            checkpoint: 0,
            wait_hint: Duration::from_secs(wait),
            process_id: None,
        })
    };
    report(ServiceState::StartPending, ServiceControlAccept::empty(), 0, 10)?;
    let running = match threat_scanner::service::start(threat_scanner::ipc::PIPE_NAME) {
        Ok(running) => running,
        Err(e) => {
            // Another process holds the pipe name: refuse rather than share it.
            let code = e.raw_os_error().unwrap_or(1) as u32;
            return report(ServiceState::Stopped, ServiceControlAccept::empty(), code, 0);
        }
    };
    report(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0, 0)?;
    loop {
        if rx.recv_timeout(Duration::from_millis(500)).is_ok() || running.stop_requested(Duration::ZERO) {
            break;
        }
    }
    report(ServiceState::StopPending, ServiceControlAccept::empty(), 0, 10)?;
    running.stop();
    report(ServiceState::Stopped, ServiceControlAccept::empty(), 0, 0)
}
