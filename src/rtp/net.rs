//! A process's open internet connections, from Windows' TCP table
//! (`GetExtendedTcpTable`, the API behind `Get-NetTCPConnection`). Read when
//! a program is caught at browser data, before it is stopped, so the alert
//! can say where the data may have gone.

use std::net::SocketAddr;

/// The remote ends of `pid`'s established TCP connections, leaving out
/// connections within this PC. Empty if the table cannot be read.
pub fn connections(pid: u32) -> Vec<SocketAddr> {
    let mut found: Vec<SocketAddr> = imp::established().into_iter().filter(|(owner, remote)| *owner == pid && !remote.ip().is_loopback()).map(|(_, remote)| remote).collect();
    found.sort();
    found.dedup();
    found
}

#[cfg(windows)]
mod imp {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCP_STATE_ESTAB, TCP_TABLE_OWNER_PID_CONNECTIONS,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    /// Owning process and remote end of every established connection.
    pub fn established() -> Vec<(u32, SocketAddr)> {
        let mut out = Vec::new();
        if let Some(table) = table(AF_INET as u32) {
            for row in rows::<MIB_TCPROW_OWNER_PID>(&table) {
                if row.dwState == MIB_TCP_STATE_ESTAB as u32 {
                    // Addresses and ports are in network byte order.
                    let ip = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
                    out.push((row.dwOwningPid, SocketAddr::new(ip.into(), port(row.dwRemotePort))));
                }
            }
        }
        if let Some(table) = table(AF_INET6 as u32) {
            for row in rows::<MIB_TCP6ROW_OWNER_PID>(&table) {
                if row.dwState == MIB_TCP_STATE_ESTAB as u32 {
                    let ip = Ipv6Addr::from(row.ucRemoteAddr);
                    let ip = ip.to_ipv4_mapped().map_or(ip.into(), Into::into);
                    out.push((row.dwOwningPid, SocketAddr::new(ip, port(row.dwRemotePort))));
                }
            }
        }
        out
    }

    fn port(raw: u32) -> u16 {
        u16::from_be(raw as u16)
    }

    /// The table for one address family: a row count, then the rows. Kept
    /// as u64s so the rows are aligned.
    fn table(family: u32) -> Option<Vec<u64>> {
        let mut size = 0u32;
        for _ in 0..4 {
            let mut buf = vec![0u64; (size as usize).div_ceil(8).max(1)];
            let mut len = (buf.len() * 8) as u32;
            // SAFETY: `buf` holds `len` writable bytes.
            let status = unsafe { GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut len, 0, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) };
            match status {
                NO_ERROR => return Some(buf),
                // Connections came and went; ask again with the new size.
                ERROR_INSUFFICIENT_BUFFER => size = len + 4096,
                _ => return None,
            }
        }
        None
    }

    fn rows<T: Copy>(table: &[u64]) -> Vec<T> {
        let bytes = table.len() * 8;
        let count = (table[0] & 0xFFFF_FFFF) as usize;
        // The rows start after the count, at their own alignment.
        let start = std::mem::align_of::<T>().max(4);
        let fits = bytes.saturating_sub(start) / std::mem::size_of::<T>();
        // SAFETY: `start` is within `table`, aligned for `T` (the buffer is
        // 8-aligned), and `count.min(fits)` rows fit after it.
        unsafe {
            let first = (table.as_ptr() as *const u8).add(start) as *const T;
            std::slice::from_raw_parts(first, count.min(fits)).to_vec()
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn established() -> Vec<(u32, std::net::SocketAddr)> {
        Vec::new()
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn finds_this_process_s_connections() {
        // A connection within this PC is in the table but left out.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _server = listener.accept().unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(imp::established().iter().any(|(pid, remote)| *pid == std::process::id() && *remote == addr), "the loopback connection is listed");
        assert!(connections(std::process::id()).iter().all(|r| !r.ip().is_loopback()));
    }
}
