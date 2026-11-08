//! Host-owned model request, usage, and stop/deadline contracts.
//!
//! An external model request is identified by a host-owned [`RequestId`] and
//! one [`AttemptId`]. The pre-send gate records its intent, checks consent,
//! budget, deadline, and stop state, and only then may the request be sent.
//! Terminal observations carry the real model identifier, a sanitized failure
//! kind, and token usage. Missing usage is [`TokenCount::Unknown`], never zero.

use std::fmt;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::contracts::connection::ConnectionId;
use crate::contracts::errors::{ArgumentViolation, CoreError, ProviderFailureKind};
use crate::contracts::events::EventSubject;
use crate::contracts::ids::ProjectScope;
use crate::contracts::ids::{AttemptId, RequestId};

/// Reason a run stop was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The user requested the stop.
    UserRequest,
    /// The application is shutting down.
    ApplicationQuit,
    /// Policy or approval requires the run to stop.
    Policy,
}

/// Immutable stop/deadline snapshot checked before side effects and sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StopDeadlineControl {
    stop_reason: Option<StopReason>,
    deadline_reached: bool,
}

impl StopDeadlineControl {
    /// Work may proceed.
    pub const fn proceed() -> Self {
        Self {
            stop_reason: None,
            deadline_reached: false,
        }
    }

    /// A stop was requested for `reason`.
    pub const fn stopped(reason: StopReason) -> Self {
        Self {
            stop_reason: Some(reason),
            deadline_reached: false,
        }
    }

    /// The run deadline has been reached.
    pub const fn deadline() -> Self {
        Self {
            stop_reason: None,
            deadline_reached: true,
        }
    }

    /// Requested stop reason, if a stop was requested.
    pub const fn stop_reason(self) -> Option<StopReason> {
        self.stop_reason
    }

    /// Whether the deadline has been reached.
    pub const fn is_deadline_reached(self) -> bool {
        self.deadline_reached
    }

    /// Whether a send may start under this control snapshot.
    pub const fn permits_send(self) -> bool {
        self.stop_reason.is_none() && !self.deadline_reached
    }
}

/// Stable host-owned label for the purpose of one model request.
///
/// The label is open because later phases own their concrete purposes. It is
/// validated, non-empty, and never contains credential material.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestPurpose(String);

impl RequestPurpose {
    /// Creates a non-empty purpose label.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CoreError> {
        let trimmed = value.as_ref().trim();
        if trimmed.is_empty() {
            return Err(CoreError::InvalidValue {
                field: "requestPurpose".to_owned(),
                violation: ArgumentViolation::Empty,
            });
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Borrows the label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for RequestPurpose {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RequestPurpose {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Real model identifier reported by the provider for one completed request.
///
/// This is the returned model, not an alias selected by the user. It never
/// contains provider response bodies or credentials.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModelId(String);

impl ModelId {
    /// Creates a non-empty model identifier.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CoreError> {
        let trimmed = value.as_ref().trim();
        if trimmed.is_empty() {
            return Err(CoreError::InvalidValue {
                field: "modelId".to_owned(),
                violation: ArgumentViolation::Empty,
            });
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Borrows the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ModelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for ModelId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ModelId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// One reported token count.
///
/// A provider that did not report a count yields [`TokenCount::Unknown`].
/// Zero is only used when the provider actually reported zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenCount {
    /// The provider reported this count.
    Known(u64),
    /// The count was missing or could not be attributed.
    Unknown,
}

impl TokenCount {
    /// Creates a reported count.
    pub const fn known(value: u64) -> Self {
        Self::Known(value)
    }

    /// A missing count.
    pub const fn unknown() -> Self {
        Self::Unknown
    }

    /// Returns the reported count, if one exists.
    pub const fn reported(self) -> Option<u64> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown => None,
        }
    }

    /// Whether the count is unknown.
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// Token usage for one model request.
///
/// Any field the provider did not report remains unknown. Missing usage is
/// never converted to zero and opaque SDK checkpoints are not parsed to fill
/// it in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenUsage {
    input_tokens: TokenCount,
    output_tokens: TokenCount,
    cache_read_tokens: TokenCount,
    cache_write_tokens: TokenCount,
}

impl TokenUsage {
    /// Usage with every field unknown.
    pub const fn unknown() -> Self {
        Self {
            input_tokens: TokenCount::Unknown,
            output_tokens: TokenCount::Unknown,
            cache_read_tokens: TokenCount::Unknown,
            cache_write_tokens: TokenCount::Unknown,
        }
    }

    /// Creates usage from four independently reported counts.
    pub const fn new(
        input_tokens: TokenCount,
        output_tokens: TokenCount,
        cache_read_tokens: TokenCount,
        cache_write_tokens: TokenCount,
    ) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_write_tokens,
        }
    }

    /// Reported input count.
    pub const fn input_tokens(self) -> TokenCount {
        self.input_tokens
    }

    /// Reported output count.
    pub const fn output_tokens(self) -> TokenCount {
        self.output_tokens
    }

    /// Reported cache-read count.
    pub const fn cache_read_tokens(self) -> TokenCount {
        self.cache_read_tokens
    }

    /// Reported cache-write count.
    pub const fn cache_write_tokens(self) -> TokenCount {
        self.cache_write_tokens
    }

    /// Whether every field is unknown.
    pub const fn is_unknown(self) -> bool {
        self.input_tokens.is_unknown()
            && self.output_tokens.is_unknown()
            && self.cache_read_tokens.is_unknown()
            && self.cache_write_tokens.is_unknown()
    }
}

impl Default for TokenUsage {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Terminal state of one model request attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestOutcome {
    /// Connection or gate work failed before any bytes were sent.
    PreflightFailed,
    /// Sending started; the terminal outcome is not yet known.
    SendStarted,
    /// The provider completed the request.
    Completed,
    /// The request was cancelled.
    Cancelled,
    /// The request may have been sent but its result cannot be determined.
    SendResultUnknown,
}

/// What the host intends to send before the gate admits it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestGateIntent {
    request_id: RequestId,
    attempt_id: AttemptId,
    connection: ConnectionId,
    purpose: RequestPurpose,
    subject: EventSubject,
    control: StopDeadlineControl,
}

impl RequestGateIntent {
    /// Creates an intent whose request, attempt, and subject share one project.
    pub fn new(
        request_id: RequestId,
        attempt_id: AttemptId,
        connection: ConnectionId,
        purpose: RequestPurpose,
        subject: EventSubject,
        control: StopDeadlineControl,
    ) -> Result<Self, CoreError> {
        let project = subject.project_id();
        ProjectScope::new(project).verify(&request_id)?;
        ProjectScope::new(project).verify(&attempt_id)?;
        Ok(Self {
            request_id,
            attempt_id,
            connection,
            purpose,
            subject,
            control,
        })
    }

    /// Host-owned request identifier.
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Attempt identifier for this request.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Connection the request would use.
    pub const fn connection(&self) -> ConnectionId {
        self.connection
    }

    /// Host-owned purpose label.
    pub fn purpose(&self) -> &RequestPurpose {
        &self.purpose
    }

    /// Run or host activity reference.
    pub const fn subject(&self) -> &EventSubject {
        &self.subject
    }

    /// Stop/deadline snapshot captured with the intent.
    pub const fn control(&self) -> StopDeadlineControl {
        self.control
    }
}

/// Why a pre-send gate refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestGateRefusal {
    /// Disclosure consent for this scope is absent or stale.
    ConsentRequired,
    /// Budget or price information does not permit the request.
    BudgetUnavailable,
    /// The request deadline has been reached.
    DeadlineReached,
    /// A stop was requested.
    Stopped,
    /// The gate itself is unavailable.
    Unavailable,
}

/// Outcome of a pre-send gate check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RequestGateOutcome {
    /// The intent was durably recorded and the request may be sent.
    Admit,
    /// The request must not be sent.
    Refuse {
        /// Structured refusal reason.
        reason: RequestGateRefusal,
    },
}

/// One terminal observation of a model request attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelRequestObservation {
    request_id: RequestId,
    attempt_id: AttemptId,
    outcome: RequestOutcome,
    failure: Option<ProviderFailureKind>,
    model_id: Option<ModelId>,
    usage: TokenUsage,
}

impl ModelRequestObservation {
    /// Creates a validated terminal observation.
    pub fn new(
        request_id: RequestId,
        attempt_id: AttemptId,
        outcome: RequestOutcome,
        failure: Option<ProviderFailureKind>,
        model_id: Option<ModelId>,
        usage: TokenUsage,
    ) -> Result<Self, CoreError> {
        let project = request_id.project_id();
        ProjectScope::new(project).verify(&attempt_id)?;
        if outcome == RequestOutcome::PreflightFailed && failure.is_none() {
            return Err(CoreError::InvalidValue {
                field: "failure".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: "a preflight failure requires a sanitized failure kind".to_owned(),
                },
            });
        }
        if outcome == RequestOutcome::PreflightFailed && !usage.is_unknown() {
            return Err(CoreError::InvalidValue {
                field: "usage".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: "a preflight failure cannot report token usage".to_owned(),
                },
            });
        }
        Ok(Self {
            request_id,
            attempt_id,
            outcome,
            failure,
            model_id,
            usage,
        })
    }

    /// Request this observation belongs to.
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Attempt this observation describes.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Terminal outcome.
    pub const fn outcome(&self) -> RequestOutcome {
        self.outcome
    }

    /// Sanitized provider failure kind, when one exists.
    pub const fn failure(&self) -> Option<ProviderFailureKind> {
        self.failure
    }

    /// Real model identifier reported by the provider, when available.
    pub fn model_id(&self) -> Option<&ModelId> {
        self.model_id.as_ref()
    }

    /// Reported usage; missing counts stay unknown.
    pub const fn usage(&self) -> TokenUsage {
        self.usage
    }
}

impl<'de> Deserialize<'de> for ModelRequestObservation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            request_id: RequestId,
            attempt_id: AttemptId,
            outcome: RequestOutcome,
            #[serde(default)]
            failure: Option<ProviderFailureKind>,
            #[serde(default)]
            model_id: Option<ModelId>,
            #[serde(default)]
            usage: TokenUsage,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.request_id,
            wire.attempt_id,
            wire.outcome,
            wire.failure,
            wire.model_id,
            wire.usage,
        )
        .map_err(de::Error::custom)
    }
}
