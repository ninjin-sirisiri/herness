//! Validation and normalization of user-supplied provider endpoints.
//!
//! Only `http` and `https` endpoints are accepted. `https` is always accepted.
//! Plain `http` is accepted automatically only for loopback hosts; a remote
//! plain-HTTP endpoint requires the caller to record an explicit danger
//! acknowledgment in [`super::ConnectionSettings`]. The stored URL is
//! normalized (lowercase scheme and host, default port removed, no query or
//! fragment) so later request routing cannot reinterpret it.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use super::error::EndpointViolation;

/// HTTP transport scheme accepted for a provider endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpScheme {
    /// Plain HTTP. Remote hosts require an explicit danger acknowledgment.
    Http,
    /// TLS-protected HTTP.
    Https,
}

impl HttpScheme {
    /// Lowercase scheme name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// Default port for the scheme.
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("http") {
            Some(Self::Http)
        } else if value.eq_ignore_ascii_case("https") {
            Some(Self::Https)
        } else {
            None
        }
    }
}

impl fmt::Display for HttpScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated, normalized provider endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    scheme: HttpScheme,
    host: Host,
    port: Option<u16>,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Host {
    Name(String),
    Ip(IpAddr),
}

impl Endpoint {
    /// Parses an endpoint URL.
    ///
    /// This validates the URL shape only. The remote plain-HTTP danger
    /// acknowledgment is enforced when a [`super::ConnectionSettings`] is
    /// created.
    pub fn parse(raw: &str) -> Result<Self, EndpointViolation> {
        if raw.chars().any(char::is_control) {
            return Err(EndpointViolation::ControlCharacter);
        }
        let input = raw.trim();
        if input.is_empty() {
            return Err(EndpointViolation::Empty);
        }
        if input.chars().any(char::is_whitespace) {
            return Err(EndpointViolation::Whitespace);
        }

        let Some((scheme_raw, rest)) = input.split_once("://") else {
            if let Some((prefix, _)) = input.split_once(':')
                && HttpScheme::parse(prefix).is_none()
                && valid_scheme(prefix)
            {
                return Err(EndpointViolation::UnsupportedScheme {
                    scheme: sanitize_scheme(prefix),
                });
            }
            return Err(EndpointViolation::MissingScheme);
        };
        let scheme =
            HttpScheme::parse(scheme_raw).ok_or_else(|| EndpointViolation::UnsupportedScheme {
                scheme: sanitize_scheme(scheme_raw),
            })?;
        if rest.is_empty() {
            return Err(EndpointViolation::MissingHost);
        }

        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let remainder = &rest[authority_end..];
        if authority.is_empty() {
            return Err(EndpointViolation::MissingHost);
        }
        if authority.contains('@') {
            return Err(EndpointViolation::UserInfoNotAllowed);
        }

        let (host, port) = parse_authority(authority)?;
        let path = parse_path(remainder)?;
        let port = port.filter(|port| *port != scheme.default_port());

        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    /// Parses only the origin of an absolute HTTP(S) URL.
    ///
    /// Path, query, and fragment are ignored because they do not participate
    /// in origin comparison. User information and unsupported schemes are
    /// still rejected.
    pub(crate) fn parse_origin(raw: &str) -> Result<Self, EndpointViolation> {
        if raw.chars().any(char::is_control) {
            return Err(EndpointViolation::ControlCharacter);
        }
        let input = raw.trim();
        if input.is_empty() {
            return Err(EndpointViolation::Empty);
        }
        if input.chars().any(char::is_whitespace) {
            return Err(EndpointViolation::Whitespace);
        }
        let Some((scheme_raw, rest)) = input.split_once("://") else {
            return Err(EndpointViolation::MissingScheme);
        };
        let scheme =
            HttpScheme::parse(scheme_raw).ok_or_else(|| EndpointViolation::UnsupportedScheme {
                scheme: sanitize_scheme(scheme_raw),
            })?;
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.is_empty() {
            return Err(EndpointViolation::MissingHost);
        }
        if authority.contains('@') {
            return Err(EndpointViolation::UserInfoNotAllowed);
        }
        let (host, port) = parse_authority(authority)?;
        Ok(Self {
            scheme,
            host,
            port: port.filter(|port| *port != scheme.default_port()),
            path: "/".to_owned(),
        })
    }

    /// Transport scheme.
    pub const fn scheme(&self) -> HttpScheme {
        self.scheme
    }

    /// Normalized host without brackets.
    pub fn host(&self) -> String {
        match &self.host {
            Host::Name(name) => name.clone(),
            Host::Ip(ip) => ip.to_string(),
        }
    }

    /// Explicit port if it differs from the scheme default.
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// Port used for requests and origin comparison.
    pub const fn effective_port(&self) -> u16 {
        match self.port {
            Some(port) => port,
            None => self.scheme.default_port(),
        }
    }

    /// Normalized path. Always begins with `/`, and has no trailing slash
    /// except for the root path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether this endpoint points at the local machine.
    pub fn is_loopback(&self) -> bool {
        match &self.host {
            Host::Name(name) => name == "localhost",
            Host::Ip(ip) => ip.is_loopback(),
        }
    }

    /// Whether plain HTTP is used for a non-loopback host.
    pub fn requires_insecure_remote_http_ack(&self) -> bool {
        matches!(self.scheme, HttpScheme::Http) && !self.is_loopback()
    }

    /// Normalized endpoint URL safe to store and display.
    pub fn as_url(&self) -> String {
        let host = match &self.host {
            Host::Name(name) => name.clone(),
            Host::Ip(IpAddr::V4(ip)) => ip.to_string(),
            Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]"),
        };
        match self.port {
            Some(port) => format!("{}://{host}:{port}{}", self.scheme, self.path),
            None => format!("{}://{host}{}", self.scheme, self.path),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_url())
    }
}

impl Serialize for Endpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_url())
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

fn valid_scheme(raw: &str) -> bool {
    !raw.is_empty()
        && raw
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '-' | '.'))
}

fn sanitize_scheme(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .take(16)
        .filter(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '-' | '.'))
        .collect();
    if sanitized.is_empty() {
        "unknown".to_owned()
    } else {
        sanitized
    }
}

fn parse_authority(authority: &str) -> Result<(Host, Option<u16>), EndpointViolation> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or(EndpointViolation::InvalidHost)?;
        let ip: Ipv6Addr = host.parse().map_err(|_| EndpointViolation::InvalidHost)?;
        let port = match after {
            "" => None,
            value => {
                let port = value
                    .strip_prefix(':')
                    .ok_or(EndpointViolation::InvalidHost)?;
                Some(parse_port(port)?)
            }
        };
        return Ok((Host::Ip(IpAddr::V6(ip)), port));
    }

    let (host_raw, port_raw) = match authority.rfind(':') {
        Some(index) if authority[..index].contains(':') => {
            // A bare IPv6 address must be bracketed so the port is unambiguous.
            return Err(EndpointViolation::InvalidHost);
        }
        Some(index) => (&authority[..index], Some(&authority[index + 1..])),
        None => (authority, None),
    };
    if host_raw.is_empty() {
        return Err(EndpointViolation::MissingHost);
    }
    if !host_raw.is_ascii() {
        return Err(EndpointViolation::InvalidHost);
    }

    let port = match port_raw {
        Some(value) => Some(parse_port(value)?),
        None => None,
    };
    let host = normalize_host(host_raw)?;
    Ok((host, port))
}

fn parse_port(value: &str) -> Result<u16, EndpointViolation> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(EndpointViolation::InvalidPort);
    }
    let port: u16 = value.parse().map_err(|_| EndpointViolation::InvalidPort)?;
    if port == 0 {
        return Err(EndpointViolation::InvalidPort);
    }
    Ok(port)
}

fn normalize_host(raw: &str) -> Result<Host, EndpointViolation> {
    let host = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
    if host.is_empty() {
        return Err(EndpointViolation::MissingHost);
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(Host::Ip(IpAddr::V4(ip)));
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        // Numeric-looking names must be real IPv4 addresses. Otherwise a
        // malformed address could be surprised by DNS resolution later.
        return Err(EndpointViolation::InvalidHost);
    }
    let valid = host.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    });
    if !valid {
        return Err(EndpointViolation::InvalidHost);
    }
    Ok(Host::Name(host))
}

fn parse_path(remainder: &str) -> Result<String, EndpointViolation> {
    if remainder.contains('?') {
        return Err(EndpointViolation::QueryNotAllowed);
    }
    if remainder.contains('#') {
        return Err(EndpointViolation::FragmentNotAllowed);
    }
    let mut path = remainder.to_owned();
    if path.is_empty() {
        path.push('/');
    }
    while path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_normalized_and_default_port_is_removed() {
        let endpoint = Endpoint::parse("HTTPS://API.Example.COM:443/v1/").unwrap();
        assert_eq!(endpoint.as_url(), "https://api.example.com/v1");
        assert_eq!(endpoint.scheme(), HttpScheme::Https);
        assert_eq!(endpoint.host(), "api.example.com");
        assert_eq!(endpoint.port(), None);
        assert_eq!(endpoint.effective_port(), 443);
    }

    #[test]
    fn loopback_plain_http_is_accepted_and_remote_plain_http_needs_ack() {
        for value in [
            "http://127.0.0.1:8080",
            "http://127.9.8.7/v1",
            "http://[::1]:11434/v1",
            "http://localhost:3000",
        ] {
            let endpoint = Endpoint::parse(value).unwrap();
            assert!(endpoint.is_loopback(), "{value}");
            assert!(!endpoint.requires_insecure_remote_http_ack(), "{value}");
        }

        let remote = Endpoint::parse("http://api.example.com/v1").unwrap();
        assert!(!remote.is_loopback());
        assert!(remote.requires_insecure_remote_http_ack());
    }

    #[test]
    fn user_information_and_bad_shapes_are_rejected() {
        assert_eq!(
            Endpoint::parse("http://user:pass@example.com").unwrap_err(),
            EndpointViolation::UserInfoNotAllowed
        );
        assert_eq!(
            Endpoint::parse("ftp://example.com").unwrap_err(),
            EndpointViolation::UnsupportedScheme {
                scheme: "ftp".to_owned()
            }
        );
        assert_eq!(
            Endpoint::parse("https://exa mple.com").unwrap_err(),
            EndpointViolation::Whitespace
        );
        assert_eq!(
            Endpoint::parse("https://example.com/path?token=1").unwrap_err(),
            EndpointViolation::QueryNotAllowed
        );
        assert_eq!(
            Endpoint::parse("https://example.com/path#fragment").unwrap_err(),
            EndpointViolation::FragmentNotAllowed
        );
        assert_eq!(
            Endpoint::parse("http://example.com:0").unwrap_err(),
            EndpointViolation::InvalidPort
        );
    }

    #[test]
    fn numeric_hosts_must_be_valid_ipv4() {
        assert_eq!(
            Endpoint::parse("http://999.1.1.1").unwrap_err(),
            EndpointViolation::InvalidHost
        );
        assert_eq!(
            Endpoint::parse("http://127.0.0.1").unwrap().host(),
            "127.0.0.1"
        );
    }
}
