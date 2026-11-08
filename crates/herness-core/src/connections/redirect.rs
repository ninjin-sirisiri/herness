//! Redirect handling policy for provider credentials.
//!
//! The host never forwards an `Authorization` header, cookie, or API key to a
//! different origin. A redirect is same-origin only when the scheme, host, and
//! effective port all match the request that carried the credential. Any
//! cross-origin redirect drops the header and requires the caller to resolve
//! credentials again for the new origin; it must not reuse the old lease.

use std::fmt;

use super::endpoint::{Endpoint, HttpScheme};
use super::error::EndpointViolation;

/// Canonical origin of an HTTP request.
///
/// Defaults ports are always stored explicitly, so `https://a.example` and
/// `https://a.example:443` compare equal while `http://a.example` does not.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    scheme: HttpScheme,
    host: String,
    port: u16,
}

impl Origin {
    /// Builds an origin from a validated endpoint.
    pub fn from_endpoint(endpoint: &Endpoint) -> Self {
        Self {
            scheme: endpoint.scheme(),
            host: endpoint.host(),
            port: endpoint.effective_port(),
        }
    }

    /// Parses an absolute URL into an origin. Path, query, and fragment do not
    /// participate in origin comparison.
    pub fn parse(url: &str) -> Result<Self, EndpointViolation> {
        Endpoint::parse_origin(url).map(|endpoint| Self::from_endpoint(&endpoint))
    }

    /// Transport scheme.
    pub const fn scheme(&self) -> HttpScheme {
        self.scheme
    }

    /// Normalized host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Effective port.
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// Why a redirect target must not receive the request's credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectDropReason {
    /// Scheme, host, or port differs from the request origin.
    CrossOrigin,
    /// The redirect target was not a usable absolute HTTP(S) URL.
    InvalidTarget,
}

/// Whether the credential may be attached to a redirect request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectAuthDecision {
    /// The target is the same origin; the credential may be attached.
    AttachAuthorization,
    /// The credential must be dropped. The caller must resolve credentials for
    /// the new origin before sending an authenticated request.
    DropAuthorization {
        /// Sanitized reason for dropping the header.
        reason: RedirectDropReason,
        /// Always true for a dropped credential. Kept explicit so callers cannot
        /// treat a redirect as a transparent retry with the old lease.
        requires_re_resolution: bool,
    },
}

/// Decides whether the credential used for `request` may follow a redirect to
/// `redirect_target`.
///
/// Any unparseable or non-HTTP(S) target drops the credential. This function
/// never sends credentials to a cross-origin target, including HTTPS-to-HTTP
/// downgrades and port changes.
pub fn redirect_auth_decision(request: &Origin, redirect_target: &str) -> RedirectAuthDecision {
    match Origin::parse(redirect_target) {
        Ok(target) if &target == request => RedirectAuthDecision::AttachAuthorization,
        Ok(_) => RedirectAuthDecision::DropAuthorization {
            reason: RedirectDropReason::CrossOrigin,
            requires_re_resolution: true,
        },
        Err(_) => RedirectAuthDecision::DropAuthorization {
            reason: RedirectDropReason::InvalidTarget,
            requires_re_resolution: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_origin_and_default_port_keep_the_credential() {
        let request = Origin::parse("https://api.example.com:443/v1").unwrap();
        assert_eq!(
            redirect_auth_decision(&request, "https://api.example.com/v2"),
            RedirectAuthDecision::AttachAuthorization
        );
        assert_eq!(
            redirect_auth_decision(&request, "HTTPS://API.EXAMPLE.COM:443/v2"),
            RedirectAuthDecision::AttachAuthorization
        );
        assert_eq!(
            redirect_auth_decision(&request, "https://api.example.com/v2?next=1#section"),
            RedirectAuthDecision::AttachAuthorization
        );
    }

    #[test]
    fn downgrade_port_and_host_changes_drop_the_credential() {
        let request = Origin::parse("https://api.example.com/v1").unwrap();
        for target in [
            "http://api.example.com/v2",
            "https://api.example.com:8443/v2",
            "https://other.example.com/v2",
            "https://sub.api.example.com/v2",
            "not a url",
            "file:///etc/passwd",
        ] {
            match redirect_auth_decision(&request, target) {
                RedirectAuthDecision::DropAuthorization {
                    requires_re_resolution,
                    ..
                } => assert!(requires_re_resolution, "{target}"),
                RedirectAuthDecision::AttachAuthorization => {
                    panic!("credential attached to {target}")
                }
            }
        }
    }
}
