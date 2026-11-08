//! Sanitized failures for the ChatGPT OAuth flow.
//!
//! No variant carries an authorization code, token, ID token, raw provider
//! body, or authorization URL. Variants are stable, structured values suitable
//! for display and for recording without redaction machinery.

use std::fmt;

use herness_core::{ConnectionId, CredentialFailureKind};

/// Transport failure reported by a token endpoint adapter.
///
/// The real transport maps HTTP and provider errors to these kinds and never
/// forwards a response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenTransportError {
    /// The authorization code was rejected. A fresh authorization is required.
    InvalidGrant,
    /// The provider could not be reached or the connection failed.
    Network,
    /// The provider refused the request.
    Rejected,
    /// The provider returned a response that could not be interpreted.
    InvalidResponse,
    /// No transport is connected.
    Unavailable,
    /// Revocation was not confirmed.
    RevocationUnconfirmed,
}

impl fmt::Display for TokenTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGrant => f.write_str("authorization grant was rejected"),
            Self::Network => f.write_str("token endpoint could not be reached"),
            Self::Rejected => f.write_str("token endpoint refused the request"),
            Self::InvalidResponse => f.write_str("token endpoint returned an invalid response"),
            Self::Unavailable => f.write_str("token transport is not available"),
            Self::RevocationUnconfirmed => f.write_str("remote revocation was not confirmed"),
        }
    }
}

/// Failure while retrieving or parsing provider JWKS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwksError {
    /// The JWKS source is not connected.
    Unavailable,
    /// The source returned malformed JSON or unsupported key material.
    Malformed,
    /// No key was usable for the token's algorithm.
    NoUsableKey,
}

impl fmt::Display for JwksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("JWKS source is not available"),
            Self::Malformed => f.write_str("JWKS response is malformed"),
            Self::NoUsableKey => f.write_str("no usable verification key was found"),
        }
    }
}

/// Why an ID token failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdTokenFailure {
    /// The token was not three base64url segments or its header/claims were not
    /// valid JSON.
    Malformed,
    /// The header algorithm is not supported.
    UnsupportedAlgorithm,
    /// No JWKS key matched the token's key ID or algorithm.
    NoMatchingKey,
    /// Signature verification failed.
    Signature,
    /// The issuer did not match the configured OpenAI issuer.
    Issuer,
    /// The audience did not contain the issued client ID.
    Audience,
    /// The token is expired at the checked time.
    Expired,
    /// The issued-at time is implausibly far in the future.
    NotYetValid,
    /// The nonce did not match this authorization attempt.
    Nonce,
    /// The subject was missing or empty.
    MissingSubject,
}

impl fmt::Display for IdTokenFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("ID token is malformed"),
            Self::UnsupportedAlgorithm => f.write_str("ID token algorithm is not supported"),
            Self::NoMatchingKey => f.write_str("ID token key is not present in JWKS"),
            Self::Signature => f.write_str("ID token signature is invalid"),
            Self::Issuer => f.write_str("ID token issuer does not match"),
            Self::Audience => f.write_str("ID token audience does not match the issued client"),
            Self::Expired => f.write_str("ID token is expired"),
            Self::NotYetValid => f.write_str("ID token issued-at time is in the future"),
            Self::Nonce => f.write_str("ID token nonce does not match this attempt"),
            Self::MissingSubject => f.write_str("ID token subject is missing"),
        }
    }
}

/// Why host-id loading or persistence failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostIdError {
    /// The store could not be read.
    ReadFailed,
    /// The store could not be written.
    WriteFailed,
    /// A stored value was not an accepted host-id format.
    InvalidStoredValue,
}

impl fmt::Display for HostIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadFailed => f.write_str("host ID could not be read"),
            Self::WriteFailed => f.write_str("host ID could not be persisted"),
            Self::InvalidStoredValue => f.write_str("stored host ID is not a supported value"),
        }
    }
}

/// Malformed or unacceptable loopback callback request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackViolation {
    /// The request was not a `GET` for the fixed callback path.
    WrongRequest,
    /// The query string could not be parsed.
    MalformedQuery,
    /// The authorization server returned an error other than `access_denied`.
    AuthorizationError,
}

impl fmt::Display for CallbackViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongRequest => f.write_str("callback request was not a valid GET"),
            Self::MalformedQuery => f.write_str("callback query was malformed"),
            Self::AuthorizationError => f.write_str("authorization server returned an error"),
        }
    }
}

/// Why a terms-gate policy does not permit ChatGPT login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermsGateReason {
    /// The app has not made a license/distribution decision yet.
    LicenseUndecided,
    /// The app would be published or distributed beyond the local host.
    PublishedOrDistributed,
    /// The app would be offered commercially.
    PaidOffering,
    /// The app would run as a remotely hosted service.
    RemoteHosted,
    /// The applicable conditions could not be confirmed.
    ConditionsUnconfirmed,
}

impl fmt::Display for TermsGateReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LicenseUndecided => f.write_str("license and distribution decision is open"),
            Self::PublishedOrDistributed => f.write_str("published distribution is not approved"),
            Self::PaidOffering => f.write_str("commercial offering is not approved"),
            Self::RemoteHosted => f.write_str("remote hosting is not approved"),
            Self::ConditionsUnconfirmed => f.write_str("applicable terms are not confirmed"),
        }
    }
}

/// Structured, non-secret failure of the ChatGPT login flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The selected connection is not an OpenAI ChatGPT-login connection.
    NotChatGptConnection {
        /// Connection that was selected.
        connection: ConnectionId,
    },
    /// The saved account registration does not exist for this connection.
    AccountNotFound {
        /// Connection that was selected.
        connection: ConnectionId,
    },
    /// An account selector was empty or malformed.
    InvalidAccountReference,
    /// The terms gate does not permit a login attempt.
    TermsGateClosed {
        /// Why the gate is closed.
        reason: TermsGateReason,
    },
    /// A new-registration attempt has no configured application name.
    AgentNameRequired,
    /// Cryptographic randomness could not be generated.
    RandomUnavailable,
    /// The loopback callback listener could not bind `127.0.0.1`.
    LoopbackBindFailed,
    /// An issued client ID was empty, dynamic, or malformed.
    InvalidIssuedClientId,
    /// A new-registration callback did not contain the issued client ID.
    MissingIssuedClientId,
    /// A callback client ID did not match the pending registration.
    ClientMismatch,
    /// A reauthorization attempt had no saved issued client ID.
    RegistrationRequired,
    /// Another attempt is already pending for this connection.
    AttemptInProgress,
    /// The attempt was already completed or cancelled.
    AttemptConsumed,
    /// A second callback for the same attempt was rejected.
    CallbackReplay,
    /// No callback arrived before the deadline.
    CallbackTimeout,
    /// The attempt was cancelled by the host or human.
    Cancelled,
    /// The loopback callback request was malformed.
    InvalidCallback {
        /// Sanitized violation.
        violation: CallbackViolation,
    },
    /// The state did not match the pending attempt.
    StateMismatch,
    /// The authorization server reported `access_denied`.
    AccessDenied,
    /// The callback contained no authorization code.
    MissingCode,
    /// The token response contained no ID token.
    MissingIdToken,
    /// The token response was otherwise invalid.
    InvalidTokenResponse,
    /// The ID token failed cryptographic or claim validation.
    IdToken {
        /// Sanitized validation failure.
        failure: IdTokenFailure,
    },
    /// The refreshed token set no longer includes plan usage.
    PlanScopeMissing,
    /// A returning account's verified identity changed.
    AccountMismatch,
    /// Token exchange, refresh, or revocation failed.
    Transport {
        /// Sanitized transport failure.
        failure: TokenTransportError,
    },
    /// JWKS retrieval or parsing failed.
    Jwks {
        /// Sanitized JWKS failure.
        failure: JwksError,
    },
    /// The credential vault rejected a read, write, or delete.
    Vault {
        /// Sanitized credential failure.
        failure: CredentialFailureKind,
    },
    /// The connection registry could not be read or updated.
    SettingsUnavailable,
    /// The host ID could not be loaded or persisted.
    HostId {
        /// Sanitized host-id failure.
        failure: HostIdError,
    },
    /// The browser could not be opened.
    BrowserUnavailable,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotChatGptConnection { connection } => {
                write!(
                    f,
                    "connection {connection} is not a ChatGPT-login connection"
                )
            }
            Self::AccountNotFound { connection } => {
                write!(
                    f,
                    "no saved ChatGPT account was found for connection {connection}"
                )
            }
            Self::InvalidAccountReference => f.write_str("ChatGPT account selector is invalid"),
            Self::TermsGateClosed { reason } => {
                write!(f, "ChatGPT login is not permitted: {reason}")
            }
            Self::AgentNameRequired => {
                f.write_str("ChatGPT registration requires a configured application name")
            }
            Self::RandomUnavailable => f.write_str("secure randomness is unavailable"),
            Self::LoopbackBindFailed => f.write_str("loopback callback listener could not bind"),
            Self::InvalidIssuedClientId => f.write_str("issued ChatGPT client ID is invalid"),
            Self::MissingIssuedClientId => {
                f.write_str("new ChatGPT registration did not return an issued client ID")
            }
            Self::ClientMismatch => {
                f.write_str("callback client ID does not match the pending registration")
            }
            Self::RegistrationRequired => {
                f.write_str("a saved issued client ID is required for reauthorization")
            }
            Self::AttemptInProgress => f.write_str("another ChatGPT login attempt is pending"),
            Self::AttemptConsumed => f.write_str("ChatGPT login attempt is already consumed"),
            Self::CallbackReplay => f.write_str("duplicate ChatGPT callback was rejected"),
            Self::CallbackTimeout => f.write_str("ChatGPT callback timed out"),
            Self::Cancelled => f.write_str("ChatGPT login attempt was cancelled"),
            Self::InvalidCallback { violation } => {
                write!(f, "invalid ChatGPT callback: {violation}")
            }
            Self::StateMismatch => f.write_str("ChatGPT callback state does not match"),
            Self::AccessDenied => f.write_str("ChatGPT authorization was declined"),
            Self::MissingCode => f.write_str("ChatGPT callback did not include a code"),
            Self::MissingIdToken => f.write_str("token response did not include an ID token"),
            Self::InvalidTokenResponse => f.write_str("token response is invalid"),
            Self::IdToken { failure } => write!(f, "ID token validation failed: {failure}"),
            Self::PlanScopeMissing => f.write_str("ChatGPT plan usage scope was not granted"),
            Self::AccountMismatch => {
                f.write_str("ChatGPT account identity does not match the selected account")
            }
            Self::Transport { failure } => write!(f, "token transport failed: {failure}"),
            Self::Jwks { failure } => write!(f, "JWKS retrieval failed: {failure}"),
            Self::Vault { failure } => write!(f, "credential vault failed: {failure:?}"),
            Self::SettingsUnavailable => f.write_str("connection settings are unavailable"),
            Self::HostId { failure } => write!(f, "host ID failed: {failure}"),
            Self::BrowserUnavailable => f.write_str("system browser could not be opened"),
        }
    }
}

impl std::error::Error for AuthError {}
