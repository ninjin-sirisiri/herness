//! Credential resolution port.
//!
//! Secret material is available only through [`ResolvedCredential`], which is
//! neither serializable nor printable in cleartext. Public connection views and
//! every event use [`crate::contracts::connection::ConnectionInfo`] instead.

use std::fmt;

use crate::contracts::connection::ConnectionId;
use crate::contracts::errors::{ArgumentViolation, CoreError};

/// Non-secret availability of a connection credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialAvailability {
    /// A credential is present and can be resolved.
    Available,
    /// A human login is required.
    LoginRequired,
    /// No usable credential exists.
    Unavailable,
}

/// Kind of secret material returned by the credential port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    /// Provider API key.
    ApiKey,
    /// OAuth access token or token set.
    OAuthToken,
}

/// A secret string that redacts itself from debug output.
///
/// This type deliberately implements neither `Serialize`, `Display`, `Clone`,
/// nor equality.
pub struct SecretString(String);

impl SecretString {
    /// Wraps non-empty secret material.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.is_empty() {
            return Err(CoreError::InvalidValue {
                field: "credential".to_owned(),
                violation: ArgumentViolation::Empty,
            });
        }
        Ok(Self(value))
    }

    /// Exposes the secret. Call only inside a credential or engine adapter and
    /// never copy the result into logs, events, checkpoints, or errors.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

/// A resolved credential lease. The value is redacted from debug output and
/// cannot be cloned or compared.
pub struct ResolvedCredential {
    kind: CredentialKind,
    secret: SecretString,
}

impl ResolvedCredential {
    /// Creates a resolved credential.
    pub const fn new(kind: CredentialKind, secret: SecretString) -> Self {
        Self { kind, secret }
    }

    /// Credential kind.
    pub const fn kind(&self) -> CredentialKind {
        self.kind
    }

    /// Exposes the secret to an adapter under the same rules as
    /// [`SecretString::expose_secret`].
    pub fn expose_secret(&self) -> &str {
        self.secret.expose_secret()
    }
}

impl fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("kind", &self.kind)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Port implemented by the Keychain-backed credential service.
pub trait CredentialPort {
    /// Reports non-secret credential availability.
    fn availability(&self, connection: &ConnectionId) -> Result<CredentialAvailability, CoreError>;

    /// Resolves the current credential for one request.
    fn resolve(&self, connection: &ConnectionId) -> Result<ResolvedCredential, CoreError>;
}
