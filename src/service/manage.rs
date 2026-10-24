//! Installing, starting, stopping and removing the service in Windows'
//! service manager. Everything but [`state`] needs administrator rights.

use super::{DESCRIPTION, DISPLAY_NAME, SERVICE_NAME};
use anyhow::{anyhow, Context, Result};
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
    ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

/// The service as Windows sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    NotInstalled,
    Stopped,
    Starting,
    Running,
    Stopping,
    /// Paused, continuing or pausing (Phalanx does not pause; shown as is).
    Other,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            State::NotInstalled => "not installed",
            State::Stopped => "stopped",
            State::Starting => "starting",
            State::Running => "running",
            State::Stopping => "stopping",
            State::Other => "paused",
        }
    }
}

fn os_error(e: &windows_service::Error) -> Option<i32> {
    match e {
        windows_service::Error::Winapi(io) => io.raw_os_error(),
        _ => None,
    }
}

/// Explains an error from the service manager in plain words.
fn explain(e: windows_service::Error, doing: &str) -> anyhow::Error {
    match os_error(&e) {
        Some(ERROR_ACCESS_DENIED) => anyhow!("{doing} needs administrator rights: run this from a terminal opened as administrator"),
        Some(ERROR_SERVICE_DOES_NOT_EXIST) => anyhow!("the Phalanx service is not installed"),
        _ => anyhow::Error::new(e).context(doing.to_string()),
    }
}

/// The service's state. Any user may ask.
pub fn state() -> Result<State> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(|e| explain(e, "reading the service list"))?;
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) => service,
        Err(e) if os_error(&e) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(State::NotInstalled),
        Err(e) => return Err(explain(e, "reading the service's state")),
    };
    let status = service.query_status().map_err(|e| explain(e, "reading the service's state"))?;
    Ok(match status.current_state {
        ServiceState::Stopped => State::Stopped,
        ServiceState::StartPending => State::Starting,
        ServiceState::Running => State::Running,
        ServiceState::StopPending => State::Stopping,
        _ => State::Other,
    })
}

/// Installs the service to run `executable` as LocalSystem at startup, and
/// starts it. An existing installation is updated (an upgrade) instead.
/// Windows restarts it three times after a crash, then once a day.
pub fn install(executable: &Path) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .map_err(|e| explain(e, "installing the service"))?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable.to_path_buf(),
        launch_arguments: Vec::new(),
        dependencies: Vec::new(),
        // LocalSystem.
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(existing) => {
            existing.change_config(&info).map_err(|e| explain(e, "updating the service"))?;
            existing
        }
        Err(e) if os_error(&e) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
            manager.create_service(&info, access).map_err(|e| explain(e, "installing the service"))?
        }
        Err(e) => return Err(explain(e, "installing the service")),
    };
    service.set_description(DESCRIPTION).map_err(|e| explain(e, "describing the service"))?;
    let restart = ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) };
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart; 3]),
        })
        .map_err(|e| explain(e, "setting the service to restart after a failure"))?;
    // Also restart when it stops with an error, not only when it crashes.
    service.set_failure_actions_on_non_crash_failures(true).map_err(|e| explain(e, "setting the service to restart after a failure"))?;
    if service.query_status().ok().map(|s| s.current_state) != Some(ServiceState::Running) {
        service.start::<&str>(&[]).map_err(|e| explain(e, "starting the service"))?;
    }
    Ok(())
}

pub fn start() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(|e| explain(e, "starting the service"))?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START).map_err(|e| explain(e, "starting the service"))?;
    service.start::<&str>(&[]).map_err(|e| explain(e, "starting the service"))
}

/// Stops the service and waits up to `timeout` for it to stop.
pub fn stop(timeout: Duration) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(|e| explain(e, "stopping the service"))?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)
        .map_err(|e| explain(e, "stopping the service"))?;
    if service.query_status().ok().map(|s| s.current_state) == Some(ServiceState::Stopped) {
        return Ok(());
    }
    service.stop().map_err(|e| explain(e, "stopping the service"))?;
    let until = Instant::now() + timeout;
    while Instant::now() < until {
        if service.query_status().ok().map(|s| s.current_state) == Some(ServiceState::Stopped) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(anyhow!("the service did not stop within {} seconds", timeout.as_secs()))
}

/// Stops and removes the service. Not installed is not an error.
pub fn uninstall() -> Result<()> {
    match state()? {
        State::NotInstalled => return Ok(()),
        State::Stopped => {}
        _ => stop(Duration::from_secs(20))?,
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(|e| explain(e, "removing the service"))?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE).map_err(|e| explain(e, "removing the service"))?;
    service.delete().map_err(|e| explain(e, "removing the service")).context("removing the service")
}
