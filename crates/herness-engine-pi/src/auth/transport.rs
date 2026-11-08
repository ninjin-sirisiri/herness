//! Injectable token endpoint and revocation boundary.
//!
//! Task 8 defines the exact request shape and validates responses. It does not
//! implement an HTTP client and never contacts an OpenAI host. Task 9 supplies
//! the real transport; tests supply scripted responses.

use std::fmt;

use herness_core::SecretString;

use super::error::TokenTransportError;

/// Authorization-code exchange request.
pub struct TokenExchangeRequest {
    /// Issued client ID. Never `dynamic_agent_client`.
    client_id: String,
    /// Authorization code from the loopback callback.
    code: String,
    /// PKCE verifier generated for this attempt.
    code_verifier: String,
    /// Exact callback URI used in the authorization request.
    redirect_uri: String,
    /// Requested resource.
    resource: String,
}

impl TokenExchangeRequest {
    /// Builds a form-encoded `authorization_code` grant request.
    pub fn new(
        client_id: impl Into<String>,
        code: impl Into<String>,
        code_verifier: impl Into<String>,
        redirect_uri: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            code: code.into(),
            code_verifier: code_verifier.into(),
            redirect_uri: redirect_uri.into(),
            resource: resource.into(),
        }
    }

    /// Issued client ID.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Authorization code. Never log.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// PKCE verifier. Never log.
    pub fn code_verifier(&self) -> &str {
        &self.code_verifier
    }

    /// Exact redirect URI.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Requested resource.
    pub fn resource(&self) -> &str {
        &self.resource
    }
}

impl fmt::Debug for TokenExchangeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenExchangeRequest")
            .field("client_id", &self.client_id)
            .field("code", &"[REDACTED]")
            .field("code_verifier", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("resource", &self.resource)
            .finish()
    }
}

/// Refresh-token grant request.
pub struct RefreshRequest {
    client_id: String,
    refresh_token: String,
    resource: String,
}

impl RefreshRequest {
    /// Builds a refresh request for the issued client saved with the token set.
    pub fn new(
        client_id: impl Into<String>,
        refresh_token: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            refresh_token: refresh_token.into(),
            resource: resource.into(),
        }
    }

    /// Issued client ID.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Refresh token. Never log.
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    /// Requested resource.
    pub fn resource(&self) -> &str {
        &self.resource
    }
}

impl fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshRequest")
            .field("client_id", &self.client_id)
            .field("refresh_token", &"[REDACTED]")
            .field("resource", &self.resource)
            .finish()
    }
}

/// Revocation request for a renewable session.
pub struct RevokeRequest {
    client_id: String,
    refresh_token: String,
}

impl RevokeRequest {
    /// Builds a refresh-token revocation request.
    pub fn new(client_id: impl Into<String>, refresh_token: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            refresh_token: refresh_token.into(),
        }
    }

    /// Issued client ID.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Refresh token. Never log.
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }
}

impl fmt::Debug for RevokeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevokeRequest")
            .field("client_id", &self.client_id)
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
}

/// Token endpoint response fields used by the flow.
pub struct TokenResponse {
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    id_token: Option<SecretString>,
    expires_in: u64,
    scope: Option<String>,
}

impl TokenResponse {
    /// Creates a response. Access token must be non-empty and `expires_in` must
    /// be positive.
    pub fn new(
        access_token: &str,
        refresh_token: Option<&str>,
        id_token: Option<&str>,
        expires_in: u64,
        scope: Option<&str>,
    ) -> Result<Self, TokenTransportError> {
        let access_token =
            SecretString::new(access_token).map_err(|_| TokenTransportError::InvalidResponse)?;
        if expires_in == 0 {
            return Err(TokenTransportError::InvalidResponse);
        }
        let refresh_token = match refresh_token {
            Some(value) => {
                Some(SecretString::new(value).map_err(|_| TokenTransportError::InvalidResponse)?)
            }
            None => None,
        };
        let id_token = match id_token {
            Some(value) => {
                Some(SecretString::new(value).map_err(|_| TokenTransportError::InvalidResponse)?)
            }
            None => None,
        };
        let scope = match scope {
            Some(value) if value.trim().is_empty() => None,
            Some(value) => Some(value.to_owned()),
            None => None,
        };
        Ok(Self {
            access_token,
            refresh_token,
            id_token,
            expires_in,
            scope,
        })
    }

    /// Access token. Never log.
    pub fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    /// Rotated refresh token, if returned.
    pub fn refresh_token(&self) -> Option<&SecretString> {
        self.refresh_token.as_ref()
    }

    /// ID token, if returned.
    pub fn id_token(&self) -> Option<&SecretString> {
        self.id_token.as_ref()
    }

    /// Access-token lifetime in seconds.
    pub const fn expires_in(&self) -> u64 {
        self.expires_in
    }

    /// Space-separated granted scope, if returned.
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// Parses the scope string into individual scopes.
    pub fn scopes(&self) -> Vec<String> {
        self.scope
            .as_deref()
            .map(|value| {
                value
                    .split_whitespace()
                    .filter(|scope| !scope.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Consumes the response into its secret parts.
    pub fn into_parts(self) -> TokenResponseParts {
        TokenResponseParts {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            id_token: self.id_token,
            expires_in: self.expires_in,
            scope: self.scope,
        }
    }
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Consumed token response fields.
pub struct TokenResponseParts {
    /// Access token.
    pub access_token: SecretString,
    /// Rotated refresh token.
    pub refresh_token: Option<SecretString>,
    /// ID token.
    pub id_token: Option<SecretString>,
    /// Lifetime in seconds.
    pub expires_in: u64,
    /// Space-separated granted scope.
    pub scope: Option<String>,
}

/// Token endpoint adapter.
pub trait TokenTransport: Send + Sync {
    /// Exchanges an authorization code using a form-encoded
    /// `authorization_code` grant.
    fn exchange(
        &self,
        request: &TokenExchangeRequest,
    ) -> Result<TokenResponse, TokenTransportError>;

    /// Refreshes a token set using a form-encoded `refresh_token` grant.
    fn refresh(&self, request: &RefreshRequest) -> Result<TokenResponse, TokenTransportError>;

    /// Requests remote session revocation. Task 8 never reports this as
    /// confirmed.
    fn revoke(&self, request: &RevokeRequest) -> Result<(), TokenTransportError>;
}

/// What Task 8 can honestly report about remote revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteRevokeStatus {
    /// No refresh token was available, so revocation was not attempted.
    NotAttempted,
    /// A revocation request was sent or scripted but provider-side revocation
    /// cannot be confirmed by this build.
    RequestAcceptedUnverified,
    /// The revocation request failed. Local credentials were still cleared.
    FailedUnverified,
}

impl RemoteRevokeStatus {
    /// Task 8 never confirms provider-side revocation.
    pub const fn is_confirmed(self) -> bool {
        false
    }
}
