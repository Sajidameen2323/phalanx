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

use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    pub fn allowed(&self) -> Allowed {
        match self {
            Request::Ping | Request::Status => Allowed::Anyone,
            Request::Stop => Allowed::Administrator,
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

    /// Sends `request` and waits for its reply, skipping events.
    pub fn call(&mut self, request: Request) -> io::Result<Reply> {
        let id = self.next_id;
        self.next_id += 1;
        let mut line = serde_json::to_string(&ClientMessage { id, request })?;
        line.push('\n');
        self.writer.write_all(line.as_bytes())?;
        loop {
            match self.next_message()? {
                ServerMessage::Reply(reply) if reply.id == id => return Ok(reply),
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
        let reply = self.call(Request::Status)?;
        if !reply.ok {
            return Err(io::Error::other(reply.error.unwrap_or_default()));
        }
        serde_json::from_value(reply.result).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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
