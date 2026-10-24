//! Named-pipe plumbing: the server's pipe and its permissions, who a client
//! is, and the client's check that the server is a service.

use super::Caller;
use std::fs::File;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::sync::Mutex;
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, LookupAccountSidW, RevertToSelf, TokenUser, WinBuiltinAdministratorsSid,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeServerSessionId, ImpersonateNamedPipeClient, WaitNamedPipeW, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

/// What a client opens the pipe with, and all that users are granted:
/// FILE_GENERIC_READ | FILE_WRITE_DATA. Not FILE_GENERIC_WRITE, which also
/// holds FILE_CREATE_PIPE_INSTANCE: with it, a program running as a user
/// could add its own instance of the pipe and answer other clients.
pub(super) const CLIENT_ACCESS: u32 = 0x0012_0089 | 0x0002;

/// Who may use the pipe. SYSTEM, administrators and the pipe's owner (the
/// service; the user in `--console` runs and tests): everything. Interactive
/// users (signed in at the PC or by Remote Desktop): [`CLIENT_ACCESS`].
pub(super) const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12008b;;;IU)";
const BUFFER: u32 = 64 * 1024;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

struct Owned(HANDLE);
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// The service's end of the pipe.
pub struct Server {
    name: Vec<u16>,
    descriptor: PSECURITY_DESCRIPTOR,
    /// The first instance, made by [`Server::bind`] and used by the first
    /// [`Server::accept`].
    pending: Mutex<Option<HANDLE>>,
}

// The descriptor is only read after creation; handles move between threads.
unsafe impl Send for Server {}
unsafe impl Sync for Server {}

impl Server {
    /// Creates the pipe. Fails if another process already holds the name,
    /// rather than sharing it.
    pub fn bind(name: &str) -> io::Result<Self> {
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: valid NUL-terminated SDDL; the descriptor is freed in Drop.
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(SDDL).as_ptr(), SDDL_REVISION_1, &mut descriptor, std::ptr::null_mut()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let server = Self { name: wide(name), descriptor, pending: Mutex::new(None) };
        let first = server.instance(true)?;
        *server.pending.lock().unwrap_or_else(|p| p.into_inner()) = Some(first);
        Ok(server)
    }

    fn instance(&self, first: bool) -> io::Result<HANDLE> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor,
            bInheritHandle: 0,
        };
        let open_mode = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        // SAFETY: valid name and attributes for the duration of the call.
        let handle = unsafe { CreateNamedPipeW(self.name.as_ptr(), open_mode, pipe_mode, PIPE_UNLIMITED_INSTANCES, BUFFER, BUFFER, 0, &attributes) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(handle)
    }

    /// Waits for the next client.
    pub fn accept(&self) -> io::Result<Connection> {
        let pending = self.pending.lock().unwrap_or_else(|p| p.into_inner()).take();
        let handle = match pending {
            Some(handle) => handle,
            None => self.instance(false)?,
        };
        // SAFETY: a pipe handle we own; a client that connected before this
        // call reports ERROR_PIPE_CONNECTED, which is success.
        if unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) } == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                unsafe { CloseHandle(handle) };
                return Err(e);
            }
        }
        // SAFETY: the handle is ours and now owned by the File.
        Ok(Connection { file: unsafe { File::from_raw_handle(handle as _) } })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(handle) = self.pending.lock().unwrap_or_else(|p| p.into_inner()).take() {
            unsafe { CloseHandle(handle) };
        }
        unsafe { LocalFree(self.descriptor as _) };
    }
}

/// One client's connection.
pub struct Connection {
    pub file: File,
}

impl Connection {
    /// Who the client is, from their token. Call after reading from the pipe.
    pub fn caller(&self) -> io::Result<Caller> {
        let pipe = self.file.as_raw_handle() as HANDLE;
        // SAFETY: impersonation is always ended with RevertToSelf below,
        // before anything else runs on this thread.
        let token = unsafe {
            if ImpersonateNamedPipeClient(pipe) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut token: HANDLE = std::ptr::null_mut();
            let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token);
            let error = io::Error::last_os_error();
            RevertToSelf();
            if opened == 0 {
                return Err(error);
            }
            Owned(token)
        };
        token_caller(token.0)
    }
}

/// A token's user and whether it is an elevated administrator.
fn token_caller(token: HANDLE) -> io::Result<Caller> {
    unsafe {
        let mut admins = [0u8; 68];
        let mut size = admins.len() as u32;
        if CreateWellKnownSid(WinBuiltinAdministratorsSid, std::ptr::null_mut(), admins.as_mut_ptr().cast(), &mut size) == 0 {
            return Err(io::Error::last_os_error());
        }
        // A UAC-filtered token holds Administrators as deny-only: not a member.
        let mut member = 0;
        if CheckTokenMembership(token, admins.as_mut_ptr().cast(), &mut member) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u64; 64];
        let mut needed = 0;
        if GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), (buffer.len() * 8) as u32, &mut needed) == 0 {
            return Err(io::Error::last_os_error());
        }
        let sid = (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid;
        let mut text: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut text) == 0 {
            return Err(io::Error::last_os_error());
        }
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let sid_text = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text as _);
        let (mut name, mut domain) = ([0u16; 256], [0u16; 256]);
        let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
        let mut kind: SID_NAME_USE = 0;
        let user = if LookupAccountSidW(std::ptr::null(), sid, name.as_mut_ptr(), &mut name_len, domain.as_mut_ptr(), &mut domain_len, &mut kind) != 0 {
            let name = String::from_utf16_lossy(&name[..name_len as usize]);
            let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
            if domain.is_empty() { name } else { format!("{domain}\\{name}") }
        } else {
            sid_text.clone()
        };
        Ok(Caller { user, sid: sid_text, admin: member != 0 })
    }
}

/// Opens the client end of `name`, waiting up to `timeout` while every
/// instance is busy. With `service_only`, the server must run in session 0,
/// where only services run.
pub fn open_client(name: &str, timeout: Duration, service_only: bool) -> io::Result<File> {
    let deadline = std::time::Instant::now() + timeout;
    let file = loop {
        // Identification only: the service can see who we are, but nothing
        // posing as it can act as us.
        match std::fs::OpenOptions::new().access_mode(CLIENT_ACCESS).security_qos_flags(SECURITY_IDENTIFICATION).open(name) {
            Ok(file) => break file,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                // SAFETY: valid NUL-terminated name.
                if left.is_zero() || unsafe { WaitNamedPipeW(wide(name).as_ptr(), left.as_millis().max(1) as u32) } == 0 {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "the protection service is busy"));
                }
            }
            Err(e) => return Err(e),
        }
    };
    if service_only {
        let mut session = u32::MAX;
        // SAFETY: valid pipe handle and out-pointer.
        let ok = unsafe { GetNamedPipeServerSessionId(file.as_raw_handle() as HANDLE, &mut session) } != 0;
        if !ok || session != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the program answering on Phalanx's pipe is not the Phalanx service"));
        }
    }
    Ok(file)
}
