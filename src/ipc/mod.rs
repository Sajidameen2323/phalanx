//! The protection service's named pipe: what the app, the CLI and the
//! browser connector say to the service, and who may say it.
//!
//! One JSON message per line in each direction. A client sends
//! [`ClientMessage`]s (a request and an id); the service answers each with a
//! [`ServerMessage::Reply`] carrying the same id, and may send
//! [`ServerMessage::Event`]s at any time.
//!
//! Every request is authorised by who asks, read from the caller's own token
//! (see [`Caller`]): anyone signed in may look and strengthen protection;
//! weakening it needs an elevated administrator, which a program running as
//! the user cannot become without the user approving Windows' UAC prompt.
//! A request refused for that reason comes back with `needs_approval`.

#[cfg(windows)]
mod pipe;

use crate::risk::{DownloadOrigin, RiskyFile};
use crate::rtp::{CommandHit, Origin, ProcessHit, RiskyOutcome, RtpEvent};
use crate::scan::{FileReport, ScanReport};
use crate::service::settings::ProtectionSettings;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::io::{self, BufRead, BufReader, Write};
use std::time::Duration;

/// The service's pipe.
pub const PIPE_NAME: &str = r"\\.\pipe\Phalanx";

/// What a client asks of the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    /// Is the service there?
    Ping,
    /// What the service is and who it thinks is asking.
    Status,
    /// Stop the service (it is restarted only by Windows or an administrator).
    Stop,
    /// The protection settings.
    GetSettings,
    /// Replace the protection settings. Anyone may strengthen them; a
    /// change that weakens them needs an administrator.
    SetSettings { settings: ProtectionSettings },
    /// Recent scans, newest first; `kind` limits them to one kind.
    RecentScans {
        limit: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<String>,
    },
    /// A scan's detections and errors. (Fields are not called `id`: that is
    /// the message's own.)
    ScanDetails { scan: i64 },
    RecentDetections { limit: u32 },
    /// Totals per month.
    MonthlySummary,
    /// Quarantined files (and, with `include_restored`, restored ones).
    Quarantine {
        #[serde(default)]
        include_restored: bool,
    },
    /// Put a quarantined file back where it was.
    Restore {
        item: String,
        #[serde(default)]
        force: bool,
    },
    /// Delete a quarantined file for good.
    DeleteQuarantined { item: String },
    /// Bring a user's data from before the service (once).
    Migrate { from: PathBuf },
    /// Send this connection every [`Event`] from now on. It then only
    /// carries events: send requests on another connection.
    Subscribe,
    /// Where protection is now ([`ProtectionStatus`]): for a client that
    /// connects after the events that said so.
    ProtectionStatus,
    /// What the Run-box reader sees in every user's registry (diagnostics;
    /// administrators only, since it shows other users' Run-box history).
    RunBoxView,
    /// Scan files or folders; the reply carries a job number, and progress
    /// arrives as events. `kind` is recorded in history (`quick`, `full`…).
    Scan { paths: Vec<PathBuf>, kind: String },
    /// Stop a scan started with `Scan`.
    CancelScan { job: u64 },
    /// Quarantine a file a scan reported (but did not quarantine). Only a
    /// file the service itself detected, recorded in its history and
    /// unchanged since, is moved.
    QuarantineDetection { scan: i64, path: PathBuf },
}

/// What the service reports to subscribed clients: real-time protection
/// as it works, and the progress of scans.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Event {
    /// Signatures loaded; protection starts (again) with them.
    EngineReady { rules: usize, hashes: usize },
    /// Signatures could not be loaded; nothing is scanned until they are.
    EngineFailed { error: String },
    ProtectionStarted { watching: usize, failed: Vec<(PathBuf, String)>, programs: bool },
    /// Real-time protection was turned off in the settings.
    ProtectionOff,
    FolderLost { folder: PathBuf, reason: String },
    FolderRestored { folder: PathBuf },
    FolderRescan { folder: PathBuf },
    /// A threat; `repeat` when a program already detected started again.
    Detection { report: FileReport, processes: Vec<ProcessHit>, repeat: bool },
    Scanned { origin: Origin, files: i64, threats: usize },
    RiskyFile { path: PathBuf, risk: RiskyFile, origin: Option<DownloadOrigin> },
    RiskyChecked { path: PathBuf, outcome: RiskyOutcome },
    Command { hit: CommandHit },
    DriveAdded { root: PathBuf, files: usize },
    Restarting { error: String, retry_in_secs: u64 },
    ProtectionError { message: String },
    ScanProgress { job: u64, files: i64, bytes: i64, detections: i64, path: PathBuf },
    ScanDetection { job: u64, report: FileReport },
    ScanFinished { job: u64, report: ScanReport },
    ScanFailed { job: u64, error: String },
}

impl From<RtpEvent> for Event {
    fn from(event: RtpEvent) -> Self {
        match event {
            RtpEvent::Started { watching, failed, programs } => Event::ProtectionStarted { watching, failed, programs },
            RtpEvent::FolderLost { folder, reason } => Event::FolderLost { folder, reason },
            RtpEvent::FolderRestored { folder } => Event::FolderRestored { folder },
            RtpEvent::FolderRescan { folder } => Event::FolderRescan { folder },
            RtpEvent::Detection { report, processes } => Event::Detection { report, processes, repeat: false },
            RtpEvent::Blocked { report, processes } => Event::Detection { report, processes, repeat: true },
            RtpEvent::Scanned { origin, report } => Event::Scanned { origin, files: report.stats.files_scanned, threats: report.infected.len() },
            RtpEvent::RiskyFile { path, risk, origin } => Event::RiskyFile { path, risk, origin },
            RtpEvent::RiskyChecked { path, outcome } => Event::RiskyChecked { path, outcome },
            RtpEvent::Command(hit) => Event::Command { hit },
            RtpEvent::DriveAdded { root, files } => Event::DriveAdded { root, files },
            RtpEvent::Restarting { error, retry_in } => Event::Restarting { error, retry_in_secs: retry_in.as_secs() },
            RtpEvent::Error(message) => Event::ProtectionError { message },
        }
    }
}

/// Who may make a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allowed {
    /// Any signed-in user: looking, and making protection stronger.
    Anyone,
    /// An elevated administrator: anything that makes protection weaker.
    Administrator,
}

impl Request {
    /// Who may make the request. `SetSettings` is let through here; the
    /// service then asks for an administrator if the change weakens
    /// protection.
    pub fn allowed(&self) -> Allowed {
        match self {
            Request::Ping
            | Request::Status
            | Request::GetSettings
            | Request::SetSettings { .. }
            | Request::RecentScans { .. }
            | Request::ScanDetails { .. }
            | Request::RecentDetections { .. }
            | Request::MonthlySummary
            | Request::Quarantine { .. }
            | Request::Subscribe
            | Request::ProtectionStatus
            | Request::Scan { .. }
            | Request::CancelScan { .. }
            | Request::QuarantineDetection { .. } => Allowed::Anyone,
            Request::Stop | Request::Restore { .. } | Request::DeleteQuarantined { .. } | Request::Migrate { .. } | Request::RunBoxView => {
                Allowed::Administrator
            }
        }
    }
}

/// A request and the id its reply will carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientMessage {
    pub id: u64,
    #[serde(flatten)]
    pub request: Request,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ServerMessage {
    Reply(Reply),
    /// Something happened (a detection, scan progress); sent to every client.
    Event { event: Value },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    pub id: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub result: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Refused because it needs an administrator's approval.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub needs_approval: bool,
}

impl Reply {
    pub fn ok(id: u64, result: Value) -> Self {
        Self { id, ok: true, result, error: None, needs_approval: false }
    }

    pub fn error(id: u64, error: impl Into<String>) -> Self {
        Self { id, ok: false, result: Value::Null, error: Some(error.into()), needs_approval: false }
    }

    pub fn needs_approval(id: u64) -> Self {
        Self { needs_approval: true, ..Self::error(id, "this weakens protection, so it needs an administrator's approval") }
    }

    /// Refused because the change weakens protection in these ways.
    pub fn needs_approval_because(id: u64, reasons: &[String]) -> Self {
        Self { needs_approval: true, ..Self::error(id, format!("this weakens protection ({}), so it needs an administrator's approval", reasons.join("; "))) }
    }

    /// The result as `T`, or the service's error.
    pub fn into_result<T: serde::de::DeserializeOwned>(self) -> io::Result<T> {
        if !self.ok {
            return Err(io::Error::other(self.error.unwrap_or_else(|| "the service refused".into())));
        }
        serde_json::from_value(self.result).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Who is on the other end of a connection, from their token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caller {
    /// `DOMAIN\user`, or the SID when the name cannot be looked up.
    pub user: String,
    pub sid: String,
    /// Running elevated as an administrator (a member of Administrators
    /// whose token is not the filtered, UAC-limited one).
    pub admin: bool,
}

impl Caller {
    pub fn may(&self, request: &Request) -> bool {
        match request.allowed() {
            Allowed::Anyone => true,
            Allowed::Administrator => self.admin,
        }
    }
}

/// The reply to `Status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub pid: u32,
    /// Unix time the service started.
    pub started: u64,
    /// Who the service thinks asked.
    pub caller: Caller,
    /// Where the service keeps its data.
    pub data_dir: PathBuf,
}

/// The reply to `ProtectionStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionStatus {
    /// Signatures loaded: rules and known hashes.
    pub engine: Option<(usize, usize)>,
    /// Real-time protection is watching (it has started).
    pub watching: bool,
    /// Scans running now.
    pub scans: usize,
}

/// The pipe server, as the service runs it.
#[cfg(windows)]
pub use pipe::{Connection, Server};

/// A connection to the service.
pub struct Client {
    reader: BufReader<std::fs::File>,
    writer: std::fs::File,
    next_id: u64,
}

impl Client {
    /// Connects to the service's pipe and checks that the server really is a
    /// service (it runs in session 0, where programs running as the user
    /// cannot create anything), so another program holding the name first
    /// cannot pose as it.
    pub fn connect() -> io::Result<Self> {
        Self::connect_to(PIPE_NAME, true)
    }

    /// Connects to `name`; `service_only` as in [`Client::connect`]. Tests
    /// and `--console` runs use a private name with `service_only` off.
    pub fn connect_to(name: &str, service_only: bool) -> io::Result<Self> {
        #[cfg(windows)]
        {
            let file = pipe::open_client(name, Duration::from_secs(2), service_only)?;
            Ok(Self { reader: BufReader::new(file.try_clone()?), writer: file, next_id: 1 })
        }
        #[cfg(not(windows))]
        {
            let _ = (name, service_only);
            Err(io::Error::new(io::ErrorKind::Unsupported, "the protection service is Windows only"))
        }
    }

    /// Sends `request` and waits for its reply, skipping events. Ids start
    /// at 1; the service answers a request it cannot read with id 0.
    pub fn call(&mut self, request: Request) -> io::Result<Reply> {
        let id = self.next_id;
        self.next_id += 1;
        let mut line = serde_json::to_string(&ClientMessage { id, request })?;
        line.push('\n');
        self.writer.write_all(line.as_bytes())?;
        loop {
            match self.next_message()? {
                ServerMessage::Reply(reply) if reply.id == id => return Ok(reply),
                // Id 0: the service could not read the request at all.
                ServerMessage::Reply(reply) if reply.id == 0 => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, reply.error.unwrap_or_default()))
                }
                _ => continue,
            }
        }
    }

    /// The next message from the service (blocks).
    pub fn next_message(&mut self) -> io::Result<ServerMessage> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the service closed the connection"));
        }
        serde_json::from_str(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// The service's status, or why it could not be had.
    pub fn status(&mut self) -> io::Result<Status> {
        self.call(Request::Status)?.into_result()
    }
}

/// The service's status within `timeout`, on a helper thread so a hung
/// service never blocks the caller. `Err` says why not (not installed,
/// stopped, not answering).
pub fn status_within(timeout: Duration) -> Result<Status, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = std::thread::Builder::new().name("service-status".into()).spawn(move || {
        let _ = tx.send(Client::connect().and_then(|mut c| c.status()).map_err(|e| describe(&e)));
    });
    rx.recv_timeout(timeout).unwrap_or_else(|_| Err("the protection service is not answering".into()))
}

/// Why the service could not be reached, in plain words.
pub fn describe(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::NotFound => "the protection service is not running".into(),
        io::ErrorKind::PermissionDenied => "Windows denied access to the protection service".into(),
        _ => format!("could not reach the protection service: {error}"),
    }
}

#[cfg(test)]
mod tests;
