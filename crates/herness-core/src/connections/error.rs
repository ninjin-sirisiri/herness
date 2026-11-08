//! Structured, non-secret failures for connection settings and credentials.
//!
//! Connection settings are human-owned configuration, not model or skill
//! output. Every rejection is reported with a stable kind that can be shown in
//! the settings UI and written to an event without carrying a secret or a raw
//! provider value.

use std::fmt;

use crate::contracts::connection::{ConnectionId, Provider};
use crate::contracts::errors::CredentialFailureKind;

/// Reason a user-supplied endpoint URL was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointViolation {
    /// The value was empty or whitespace-only.
    Empty,
    /// The value contained an ASCII or Unicode control character.
    ControlCharacter,
    /// The value contained an unescaped whitespace character.
    Whitespace,
    /// The value had no `scheme://` prefix.
    MissingScheme,
    /// The scheme was not `http` or `https`.
    UnsupportedScheme {
        /// Sanitized scheme taken from the input. Only ASCII letters, digits,
        /// and `+`, `-`, `.` are retained.
        scheme: String,
    },
    /// The authority had no host.
    MissingHost,
    /// The host was not a valid DNS name, IPv4 address, or bracketed IPv6
    /// address.
    InvalidHost,
    /// The authority contained user information (`user:password@`).
    UserInfoNotAllowed,
    /// The port was empty, non-numeric, zero, or outside `1..=65535`.
    InvalidPort,
    /// A base endpoint must not carry a query string.
    QueryNotAllowed,
    /// A base endpoint must not carry a fragment.
    FragmentNotAllowed,
}

impl fmt::Display for EndpointViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("must not be empty"),
            Self::ControlCharacter => f.write_str("must not contain control characters"),
            Self::Whitespace => f.write_str("must not contain whitespace"),
            Self::MissingScheme => f.write_str("must include an http:// or https:// scheme"),
            Self::UnsupportedScheme { scheme } => {
                write!(f, "unsupported scheme {scheme:?}; expected http or https")
            }
            Self::MissingHost => f.write_str("must include a host"),
            Self::InvalidHost => f.write_str("host is not a valid DNS name or IP address"),
            Self::UserInfoNotAllowed => {
                f.write_str("must not include user information before the host")
            }
            Self::InvalidPort => f.write_str("port must be between 1 and 65535"),
            Self::QueryNotAllowed => f.write_str("base endpoint must not include a query string"),
            Self::FragmentNotAllowed => f.write_str("base endpoint must not include a fragment"),
        }
    }
}

/// Structured failure while creating or looking up connection settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// The selected model was empty after trimming.
    EmptyModel,
    /// An OpenAI-compatible connection requires an explicit endpoint.
    EndpointRequired,
    /// Only an OpenAI-compatible connection may carry a custom endpoint.
    EndpointNotAllowed {
        /// Provider that rejected the endpoint.
        provider: Provider,
    },
    /// The endpoint URL failed validation.
    InvalidEndpoint {
        /// Validation failure.
        violation: EndpointViolation,
    },
    /// Remote plain HTTP was requested without recording the danger
    /// acknowledgment.
    RemoteHttpRequiresAcknowledgment,
    /// The authentication method is not supported by the provider.
    AuthMethodNotSupported {
        /// Selected provider.
        provider: Provider,
        /// Selected authentication method.
        auth_method: crate::contracts::connection::AuthMethod,
    },
    /// The connection id is not registered.
    UnknownConnection {
        /// Missing connection id.
        connection: ConnectionId,
    },
    /// The connection id is already registered.
    DuplicateConnection {
        /// Duplicate connection id.
        connection: ConnectionId,
    },
    /// A stored credential reference did not match the connection settings
    /// that carried it.
    CredentialReferenceMismatch,
    /// A vault account key was empty, too long, or contained control
    /// characters.
    InvalidVaultAccount,
    /// The connection registry could not be read or written because its
    /// internal lock was poisoned. The host must report this rather than invent
    /// settings.
    RegistryUnavailable,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyModel => f.write_str("model must not be empty"),
            Self::EndpointRequired => {
                f.write_str("an OpenAI-compatible connection requires an endpoint")
            }
            Self::EndpointNotAllowed { provider } => write!(
                f,
                "provider {provider} does not accept a custom endpoint; use an OpenAI-compatible connection"
            ),
            Self::InvalidEndpoint { violation } => write!(f, "invalid endpoint: {violation}"),
            Self::RemoteHttpRequiresAcknowledgment => {
                f.write_str("remote plain HTTP requires an explicit danger acknowledgment")
            }
            Self::AuthMethodNotSupported {
                provider,
                auth_method,
            } => write!(
                f,
                "authentication method {auth_method:?} is not supported by provider {provider}"
            ),
            Self::UnknownConnection { connection } => {
                write!(f, "connection {connection} is not registered")
            }
            Self::DuplicateConnection { connection } => {
                write!(f, "connection {connection} is already registered")
            }
            Self::CredentialReferenceMismatch => {
                f.write_str("stored credential reference does not match the connection")
            }
            Self::InvalidVaultAccount => f.write_str("invalid credential vault account key"),
            Self::RegistryUnavailable => f.write_str("connection registry is unavailable"),
        }
    }
}

impl std::error::Error for ConnectionError {}

/// Failure reported by a credential vault implementation.
///
/// A vault maps its operating-system result to one of these kinds. A failure
/// must never be handled by writing the secret to an ordinary file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultFailure {
    /// The operating system refused access to the item.
    Denied,
    /// The keychain (or equivalent vault) is locked.
    Locked,
    /// The vault is not reachable.
    Unavailable,
    /// An existing item could not be updated.
    UpdateFailed,
    /// An item already exists and the vault refused a duplicate.
    DuplicateItem,
    /// The requested item does not exist.
    MissingItem,
    /// The stored item could not be decoded by the vault.
    InvalidData,
}

impl VaultFailure {
    /// Maps the vault failure to the public, sanitized credential kind.
    pub const fn credential_failure_kind(self) -> CredentialFailureKind {
        match self {
            Self::Denied => CredentialFailureKind::KeychainDenied,
            Self::Locked => CredentialFailureKind::KeychainLocked,
            Self::Unavailable => CredentialFailureKind::KeychainUnavailable,
            Self::UpdateFailed => CredentialFailureKind::KeychainWriteFailed,
            Self::DuplicateItem => CredentialFailureKind::KeychainDuplicateItem,
            Self::MissingItem => CredentialFailureKind::KeychainItemMissing,
            Self::InvalidData => CredentialFailureKind::InvalidCredentialData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_vault_failure_maps_to_a_distinct_structured_kind() {
        let cases = [
            (VaultFailure::Denied, CredentialFailureKind::KeychainDenied),
            (VaultFailure::Locked, CredentialFailureKind::KeychainLocked),
            (
                VaultFailure::Unavailable,
                CredentialFailureKind::KeychainUnavailable,
            ),
            (
                VaultFailure::UpdateFailed,
                CredentialFailureKind::KeychainWriteFailed,
            ),
            (
                VaultFailure::DuplicateItem,
                CredentialFailureKind::KeychainDuplicateItem,
            ),
            (
                VaultFailure::MissingItem,
                CredentialFailureKind::KeychainItemMissing,
            ),
            (
                VaultFailure::InvalidData,
                CredentialFailureKind::InvalidCredentialData,
            ),
        ];
        for (failure, expected) in cases {
            assert_eq!(failure.credential_failure_kind(), expected);
        }
    }
}
