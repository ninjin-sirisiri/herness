//! Official ChatGPT OAuth flow and terms gate.
//!
//! The module is independent of the legacy pi OAuth helper. It defines the
//! exact public-client flow confirmed on 2026-11-08. Task 8 validated the flow
//! with injected token/JWKS boundaries; Task 13 adds
//! [`https::HttpsTokenTransport`] and [`https::DiscoveryJwksSource`] for the
//! separately approved real connection. The asymmetric key material and the
//! loopback callback listener remain local: no code here contacts OpenAI unless
//! the trusted host selects the local/unpublished terms gate and the Phase B
//! runbook invokes a real login or controller check.

pub mod error;
pub mod host_id;
pub mod https;
pub mod jwk;
pub mod jwt;
pub mod listener;
pub mod pkce;
pub mod registry;
pub mod service;
pub mod transport;
pub mod types;

pub use error::{
    AuthError, CallbackViolation, HostIdError, IdTokenFailure, JwksError, TermsGateReason,
    TokenTransportError,
};
pub use host_id::{FileHostIdStore, HostId, HostIdManager, HostIdStore, MemoryHostIdStore};
pub use https::{
    AuthHttp, AuthHttpConfig, DISCOVERY_URL, DiscoveryJwksSource, HttpsTokenTransport,
    official_auth_components,
};
pub use jwk::{Jwk, JwkSet, JwksSource, StaticJwks};
pub use listener::{AuthorizationCallback, CallbackListener};
pub use registry::{AccountDirectory, InMemoryAccountDirectory};
pub use service::{
    AuthorizationUrl, BrowserOpener, ChatGptAuth, ChatGptAuthConfig, ClientRegistration,
    PendingAuthorization, SignInMode, SignInOutcome, SignInRequest, SignOutOutcome,
};
pub use transport::{
    RefreshRequest, RemoteRevokeStatus, RevokeRequest, TokenExchangeRequest, TokenResponse,
    TokenResponseParts, TokenTransport,
};
pub use types::{
    AUTHORIZATION_ENDPOINT, AuthRequiredReason, CALLBACK_PATH, CLOCK_SKEW_MILLIS, ChatGptAccount,
    ChatGptAccountRef, ChatGptAuthState, Clock, FixedClock, IDENTITY_SCOPES, ISSUER,
    IssuedClientId, PLAN_SCOPES, REQUESTED_SCOPES, RESOURCE, SystemClock, TOKEN_ENDPOINT,
    TermsConfirmation, TermsGate, VerifiedIdentity,
};
