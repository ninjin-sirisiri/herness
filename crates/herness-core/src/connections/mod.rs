//! Non-secret connection settings and the macOS Keychain credential boundary.
//!
//! This module owns:
//!
//! * validated HTTP(S) endpoints and remote plain-HTTP acknowledgment,
//! * redirect origin policy that never forwards credentials cross-origin,
//! * non-secret connection settings and a human-only settings registry,
//! * a write-only credential save API, a resolver used by the engine,
//! * per-connection refresh serialization and no-fallback resolution,
//! * redaction helpers for logs, diagnostics, and synthetic errors.
//!
//! The dependency direction stays host-owned: `herness-core` defines the
//! boundaries, while the desktop crate provides the macOS Keychain adapter.

mod credential;
mod endpoint;
mod error;
mod redact;
mod redirect;
mod registry;

pub use crate::contracts::connection::ConnectionCapabilityDeclaration;
pub use credential::{
    CHATGPT_DYNAMIC_AGENT_CLIENT, CHATGPT_PLAN_SCOPE, CREDENTIAL_FORMAT_VERSION, ConnectionState,
    CredentialAdmin, CredentialBroker, CredentialMaterial, CredentialRef, CredentialRefresher,
    CredentialService, CredentialVault, CredentialWriter, OAuthTokenSet, OAuthTokenSetDetails,
    VAULT_SERVICE, VaultAccount,
};
pub use endpoint::{Endpoint, HttpScheme};
pub use error::{ConnectionError, EndpointViolation, VaultFailure};
pub use redact::{
    MAX_REDACTED_URL_CHARS, REDACTED, redact_error, redact_header, redact_headers,
    redact_known_secrets, redact_url,
};
pub use redirect::{Origin, RedirectAuthDecision, RedirectDropReason, redirect_auth_decision};
pub use registry::{
    AssessmentGateway, ConnectionAdmin, ConnectionDirectory, ConnectionSettings, InsecureRemoteHttp,
};
