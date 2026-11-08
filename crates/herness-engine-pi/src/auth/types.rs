//! Confirmed constants and non-secret account types for the official ChatGPT
//! OAuth flow.

use std::fmt;

use herness_core::{CHATGPT_DYNAMIC_AGENT_CLIENT, ConnectionId, Timestamp, VaultAccount};

use super::error::{AuthError, TermsGateReason};

/// Authorization endpoint confirmed from the official Sign in with ChatGPT
/// documentation on 2026-11-08.
pub const AUTHORIZATION_ENDPOINT: &str = "https://auth.openai.com/api/accounts/authorize";
/// Token endpoint confirmed on 2026-11-08.
pub const TOKEN_ENDPOINT: &str = "https://auth.openai.com/api/accounts/oauth/token";
/// OpenID issuer expected in a validated ID token.
pub const ISSUER: &str = "https://auth.openai.com";
/// Resource requested by authorization, exchange, and refresh.
pub const RESOURCE: &str = "https://api.openai.com/v1";
/// Fixed loopback callback path. Only the port may vary between attempts.
pub const CALLBACK_PATH: &str = "/auth/callback";
/// Identity scopes.
pub const IDENTITY_SCOPES: [&str; 3] = ["openid", "profile", "email"];
/// ChatGPT plan usage scopes.
pub const PLAN_SCOPES: [&str; 3] = [
    "offline_access",
    "resource.invoke",
    "chatgpt.tokens.use.direct",
];
/// Full scope list requested on initial registration and reauthorization.
pub const REQUESTED_SCOPES: [&str; 6] = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "resource.invoke",
    "chatgpt.tokens.use.direct",
];
/// Clock skew accepted for ID-token expiry and issued-at checks.
pub const CLOCK_SKEW_MILLIS: u64 = 60_000;

/// Terms gate for ChatGPT plan usage.
///
/// The official overview describes this flow for open-source and locally hosted
/// apps, and directs paid or remotely hosted apps to an interest form. herness
/// is locally hosted and unpublished, but it has no license or distribution
/// decision. The only permitted state in this task is therefore local,
/// unpublished, non-commercial use while development continues. Publication,
/// commercial offering, or remote hosting must stay closed until a human makes
/// the required decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermsGate {
    /// Local, unpublished, non-commercial development use only.
    LocalUnpublishedUse,
    /// Login is not permitted for the recorded reason.
    Closed(TermsGateReason),
}

impl TermsGate {
    /// Whether this gate permits a login attempt.
    pub const fn permits_login(self) -> bool {
        matches!(self, Self::LocalUnpublishedUse)
    }

    /// Recorded reason when the gate is closed.
    pub const fn reason(self) -> Option<TermsGateReason> {
        match self {
            Self::LocalUnpublishedUse => None,
            Self::Closed(reason) => Some(reason),
        }
    }
}

/// Confirmation record written by Task 8's research gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TermsConfirmation {
    /// Date the official pages were re-read.
    pub confirmed_on: &'static str,
    /// Gate selected for this build.
    pub gate: TermsGate,
}

impl TermsConfirmation {
    /// Confirmation recorded on 2026-11-08 for local, unpublished use.
    pub const fn local_unpublished() -> Self {
        Self {
            confirmed_on: "2026-11-08",
            gate: TermsGate::LocalUnpublishedUse,
        }
    }
}

/// An issued ChatGPT client ID.
///
/// `dynamic_agent_client` is the registration entrypoint only. It is never a
/// valid issued client ID.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IssuedClientId(String);

impl IssuedClientId {
    /// Validates an issued client ID returned by registration.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthError> {
        let value = value.into();
        if value == CHATGPT_DYNAMIC_AGENT_CLIENT
            || value.is_empty()
            || value.len() > 96
            || value.chars().any(char::is_control)
            || value
                .chars()
                .any(|character| character.is_whitespace() || !is_client_id_char(character))
        {
            return Err(AuthError::InvalidIssuedClientId);
        }
        Ok(Self(value))
    }

    /// Client ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IssuedClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuedClientId(")?;
        f.write_str(&self.0)?;
        f.write_str(")")
    }
}

impl fmt::Display for IssuedClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_client_id_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
}

/// Non-secret identity verified from an ID token.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// Token issuer.
    pub issuer: String,
    /// Account subject (`sub`).
    pub subject: String,
    /// Email claim, if present.
    pub email: Option<String>,
}

impl fmt::Debug for VerifiedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedIdentity")
            .field("issuer", &self.issuer)
            .field("subject", &"[REDACTED]")
            .field("email", &self.email.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// One saved ChatGPT account registration.
///
/// The `client_id` and `subject` pair separates registrations. The vault account
/// is derived from both so two accounts never overwrite each other's secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct ChatGptAccount {
    connection: ConnectionId,
    client_id: IssuedClientId,
    subject: String,
    email: Option<String>,
    vault_account: VaultAccount,
}

impl ChatGptAccount {
    /// Builds a registration from a validated identity and issued client ID.
    pub fn new(
        connection: ConnectionId,
        client_id: IssuedClientId,
        identity: &VerifiedIdentity,
        email: Option<String>,
    ) -> Result<Self, AuthError> {
        let vault_account =
            VaultAccount::for_chatgpt_account(connection, client_id.as_str(), &identity.subject)
                .map_err(|_| AuthError::InvalidIssuedClientId)?;
        Ok(Self {
            connection,
            client_id,
            subject: identity.subject.clone(),
            email: email.or_else(|| identity.email.clone()),
            vault_account,
        })
    }

    /// Connection this registration belongs to.
    pub const fn connection(&self) -> ConnectionId {
        self.connection
    }

    /// Issued client ID.
    pub fn client_id(&self) -> &IssuedClientId {
        &self.client_id
    }

    /// Verified ID-token subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Email hint, if the ID token carried one.
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Account-scoped vault key.
    pub fn vault_account(&self) -> &VaultAccount {
        &self.vault_account
    }

    /// Non-secret reference used to select this account for reauthorization or
    /// sign-out.
    pub fn reference(&self) -> ChatGptAccountRef {
        ChatGptAccountRef {
            client_id: self.client_id.clone(),
            subject: self.subject.clone(),
        }
    }
}

impl fmt::Debug for ChatGptAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatGptAccount")
            .field("connection", &self.connection)
            .field("client_id", &self.client_id)
            .field("subject", &"[REDACTED]")
            .field("email", &self.email.as_ref().map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
}

/// Stable non-secret selector for a saved account.
#[derive(Clone, PartialEq, Eq)]
pub struct ChatGptAccountRef {
    client_id: IssuedClientId,
    subject: String,
}

impl ChatGptAccountRef {
    /// Creates a selector from an issued client ID and verified subject.
    pub fn new(client_id: IssuedClientId, subject: impl Into<String>) -> Result<Self, AuthError> {
        let subject = subject.into();
        if subject.is_empty() || subject.chars().any(char::is_control) {
            return Err(AuthError::InvalidAccountReference);
        }
        Ok(Self { client_id, subject })
    }

    /// Issued client ID.
    pub fn client_id(&self) -> &IssuedClientId {
        &self.client_id
    }

    /// Verified subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

impl fmt::Debug for ChatGptAccountRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatGptAccountRef")
            .field("client_id", &self.client_id)
            .field("subject", &"[REDACTED]")
            .finish()
    }
}

/// Non-secret state of a ChatGPT connection for the settings and engine
/// boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatGptAuthState {
    /// No account is selected or no credential is stored.
    LoginRequired,
    /// A selected account is usable for ChatGPT plan inference.
    Available {
        /// Selected account, when it is one of the saved registrations.
        account: Option<ChatGptAccount>,
    },
    /// An account was authenticated but lacks the plan-usage scope.
    AuthenticatedWithoutPlan {
        /// Account that lacks the scope.
        account: ChatGptAccount,
    },
    /// A selected credential is expired and needs a fresh login or refresh.
    AuthRequired {
        /// Selected account, when known.
        account: Option<ChatGptAccount>,
        /// Sanitized reason.
        reason: AuthRequiredReason,
    },
    /// The selected credential cannot be used.
    Unavailable {
        /// Sanitized reason.
        reason: AuthRequiredReason,
    },
}

/// Reason a ChatGPT connection needs human action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRequiredReason {
    /// Access token is expired.
    Expired,
    /// Plan usage scope is missing.
    PlanScopeMissing,
    /// The vault could not be read.
    VaultUnavailable,
    /// The stored credential could not be decoded.
    InvalidCredentialData,
}

/// Wall clock used for token expiry and ID-token validation.
pub trait Clock: Send + Sync {
    /// Current time.
    fn now(&self) -> Timestamp;
}

/// System clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// Deterministic clock for tests and replayable hosts.
#[derive(Debug)]
pub struct FixedClock {
    now: std::sync::Mutex<Timestamp>,
}

impl FixedClock {
    /// Creates a clock at one timestamp.
    pub fn new(now: Timestamp) -> Self {
        Self {
            now: std::sync::Mutex::new(now),
        }
    }

    /// Replaces the current timestamp.
    pub fn set(&self, now: Timestamp) {
        *self
            .now
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = now;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        *self
            .now
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
