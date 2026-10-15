//! Just enough URL handling for web protection: split an address into scheme,
//! host and port, normalise it for rule lookups, and percent-encode query
//! parameters for block-page links.

use std::net::IpAddr;

/// The parts of a web address that rules look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAddress {
    /// Lowercase scheme, `http` when the input had none.
    pub scheme: String,
    /// Lowercase host name without a trailing dot, or an IP address
    /// (IPv6 without brackets).
    pub host: String,
    /// The explicit port, if it differs from the scheme's default.
    pub port: Option<u16>,
    /// Path and query (never empty: at least `/`), without the fragment.
    pub path: String,
}

impl WebAddress {
    /// Parses `https://user@Host.example:8443/a?b#c`, `host.example/path`,
    /// `1.2.3.4:80` or `[::1]:8080`. Returns `None` for anything without a
    /// usable host.
    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        let (scheme, rest) = match input.find("://") {
            Some(i) => (input[..i].to_ascii_lowercase(), &input[i + 3..]),
            None => ("http".to_string(), input),
        };
        if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
            return None;
        }
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            let close = stripped.find(']')?;
            let port = stripped[close + 1..].strip_prefix(':');
            (&stripped[..close], port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        let port = match port {
            None | Some("") => None,
            Some(p) => Some(p.parse::<u16>().ok()?),
        };
        let host = normalize_host(host)?;
        let port = port.filter(|p| Some(*p) != default_port(&scheme));
        let tail = tail.split('#').next().unwrap_or("");
        let path = match tail {
            "" => "/".to_string(),
            t if t.starts_with('?') => format!("/{t}"),
            t => t.to_string(),
        };
        Some(Self { scheme, host, port, path })
    }

    /// The host as an IP address, when it is one.
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }

    /// Canonical text used to match `url` rules.
    pub fn normalized(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        match self.port {
            Some(p) => format!("{}://{host}:{p}{}", self.scheme, self.path),
            None => format!("{}://{host}{}", self.scheme, self.path),
        }
    }

    /// The same address without its query string, if it had one.
    pub fn without_query(&self) -> Option<String> {
        let (path, _) = self.path.split_once('?')?;
        let mut copy = self.clone();
        copy.path = if path.is_empty() { "/".into() } else { path.to_string() };
        Some(copy.normalized())
    }
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        "ftp" => Some(21),
        _ => None,
    }
}

/// Lowercases a host name and drops a trailing dot. Rejects empty names and
/// names with characters that never appear in a host.
pub fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || !host.chars().all(|c| c.is_ascii_alphanumeric() || "-._:".contains(c))
    {
        return None;
    }
    Some(host)
}

/// Percent-encodes everything except unreserved characters (RFC 3986), for
/// use inside a query parameter.
pub fn encode_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Decodes `%XX` escapes and `+` (as a space) from a query parameter.
pub fn decode_component(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi * 16 + lo) as u8);
                        i += 3;
                        continue;
                    }
                    _ => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Splits `a=1&b=2` into decoded pairs.
pub fn query_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (decode_component(k), decode_component(v)),
            None => (decode_component(p), String::new()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_forms() {
        let a = WebAddress::parse("HTTPS://user:pw@Bad.Example.:443/x?y=1#frag").unwrap();
        assert_eq!((a.scheme.as_str(), a.host.as_str(), a.port, a.path.as_str()), ("https", "bad.example", None, "/x?y=1"));
        assert_eq!(a.normalized(), "https://bad.example/x?y=1");
        assert_eq!(a.without_query().as_deref(), Some("https://bad.example/x"));

        let b = WebAddress::parse("bad.example").unwrap();
        assert_eq!(b.normalized(), "http://bad.example/");
        let c = WebAddress::parse("http://1.2.3.4:4444").unwrap();
        assert_eq!((c.port, c.ip()), (Some(4444), Some("1.2.3.4".parse().unwrap())));
        let d = WebAddress::parse("http://[2001:db8::1]:8080/a").unwrap();
        assert_eq!(d.host, "2001:db8::1");
        assert_eq!(d.normalized(), "http://[2001:db8::1]:8080/a");
        assert_eq!(WebAddress::parse("http://ok.example?q").unwrap().path, "/?q");

        assert!(WebAddress::parse("http://").is_none());
        assert!(WebAddress::parse("http://bad host/").is_none());
        assert!(WebAddress::parse("http://x.example:99999/").is_none());
    }

    #[test]
    fn query_encoding_round_trips() {
        let original = "http://bad.example/a b?c=d&e=ü";
        let encoded = encode_component(original);
        assert!(!encoded.contains(['/', '?', '&', ' ', '=']));
        assert_eq!(decode_component(&encoded), original);
        assert_eq!(query_pairs("a=1&b=x%20y&c"), [("a".into(), "1".into()), ("b".into(), "x y".into()), ("c".into(), String::new())]);
        assert_eq!(decode_component("100%"), "100%");
    }
}
