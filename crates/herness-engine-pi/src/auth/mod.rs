//! Official ChatGPT OAuth flow and terms gate.
//!
//! The module is independent of the legacy pi OAuth helper. It defines the
//! exact public-client flow confirmed on 2026-11-08, but stays mock-only: token
//! exchange and JWKS retrieval are injected traits, and no code here contacts an
//! OpenAI host. The only network operation is a local `127.0.0.1` loopback
//! listener for the authorization callback.

pub mod error;
pub mod host_id;
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
