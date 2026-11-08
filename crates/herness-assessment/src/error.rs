//! Sanitized failures for assessment requests.
//!
//! These values are safe to display, log, or persist. They never carry an API
//! key, authorization header, request body, provider URL with credentials, or
//! raw provider response body.

use std::fmt;
use std::time::Duration;

/// Stable category of an assessment transport failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssessmentErrorKind {
    /// The request value was empty, malformed, or not an object.
    InvalidRequest,
    /// A payload declared `tools` or `tool_choice`; assessment is tool-less.
    ToolUseNotAllowed,
    /// An image was supplied as a URL instead of caller-provided bytes.
    ExternalImageUrl,
    /// The connection does not accept a required input modality.
    UnsupportedModality,
    /// The profile requires provider-native structured output that the
    /// connection or route cannot provide.
    StructuredOutputUnavailable,
    /// A caller-supplied evidence document is missing, duplicated, or outside
    /// the exact evidence set of the request.
    InvalidEvidence,
    /// The evidence required for an assessment would exceed the provider's
    /// known input limits. Evidence is never truncated into a passing answer.
    InputTooLarge,
    /// An evidence document belongs to another project.
    CrossProjectReference,
    /// The request, profile, and connection do not describe the same fixed
    /// assessment profile.
    ProfileBindingMismatch,
    /// The connection is not registered.
    UnknownConnection,
    /// The connection settings or endpoint class cannot serve assessment.
    CapabilityMismatch,
    /// The request model does not match the selected connection's model.
    ModelMismatch,
    /// The credential could not be resolved or had the wrong kind.
    CredentialUnavailable,
    /// The provider rejected the credential (HTTP 401/403).
    AuthenticationFailed,
    /// The provider returned HTTP 429.
    RateLimited,
    /// The provider returned a server-side failure.
    ServerFailure,
    /// The provider rejected the request with a non-retryable status.
    RequestRejected,
    /// The connection failed before any request bytes could be sent.
    ConnectionFailed,
    /// A timeout or network failure may have occurred after sending.
    SendResultUnknown,
    /// The caller cancelled the request before a response completed.
    Cancelled,
    /// A redirect target was on another origin and would not receive the
    /// credential.
    CrossOriginRedirect,
    /// A same-origin redirect was returned; redirects are never followed.
    NoRedirectFollowing,
    /// The response was empty, malformed, or not usable.
    InvalidResponse,
    /// The response body exceeded the transport limit.
    ResponseTooLarge,
    /// `Retry-After` did not fit inside the remaining run deadline.
    RetryAfterBeyondDeadline,
    /// The remaining run deadline was reached before or during the request.
    DeadlineReached,
    /// The test-only endpoint configuration or internal runtime is invalid.
    InvalidConfiguration,
    /// An internal runtime or transport setup failed.
    Internal,
}

/// One sanitized assessment transport failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssessmentError {
    kind: AssessmentErrorKind,
    attempts: u8,
    status: Option<u16>,
    retry_after: Option<Duration>,
    retry_exhausted: bool,
}

impl AssessmentError {
    /// Creates an error without an HTTP status.
    pub(crate) const fn new(kind: AssessmentErrorKind) -> Self {
        Self {
            kind,
            attempts: 0,
            status: None,
            retry_after: None,
            retry_exhausted: false,
        }
    }

    /// Creates a sanitized invalid-configuration error.
    pub(crate) const fn invalid_configuration() -> Self {
        Self::new(AssessmentErrorKind::InvalidConfiguration)
    }

    /// Attaches the HTTP status that caused the failure.
    pub(crate) const fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// Attaches a parsed `Retry-After` duration.
    pub(crate) const fn with_retry_after(mut self, retry_after: Option<Duration>) -> Self {
        self.retry_after = retry_after;
        self
    }

    /// Records how many HTTP attempts were performed.
    pub(crate) const fn with_attempts(mut self, attempts: u8) -> Self {
        self.attempts = attempts;
        self
    }

    /// Marks a retryable failure whose retry budget is exhausted.
    pub(crate) const fn exhausted(mut self) -> Self {
        self.retry_exhausted = true;
        self
    }

    /// Failure category.
    pub const fn kind(self) -> AssessmentErrorKind {
        self.kind
    }

    /// Number of HTTP attempts that were performed for this request.
    pub const fn attempts(self) -> u8 {
        self.attempts
    }

    /// HTTP status, when one was received.
    pub const fn status(self) -> Option<u16> {
        self.status
    }

    /// Parsed `Retry-After` duration, when the provider supplied one.
    pub const fn retry_after(self) -> Option<Duration> {
        self.retry_after
    }

    /// Whether the failure was retryable and the retry budget is exhausted.
    pub const fn is_retry_exhausted(self) -> bool {
        self.retry_exhausted
    }

    /// Whether the same connection may be retried for this failure.
    ///
    /// Only rate limits, transient server failures, and connection failures
    /// that happened before any request bytes could be sent are retryable. A
    /// timeout or ambiguous send, authentication failure, invalid response,
    /// redirect, refusal, or low-confidence verdict is never retried here.
    pub const fn is_retryable(self) -> bool {
        match self.kind {
            AssessmentErrorKind::RateLimited => true,
            AssessmentErrorKind::ConnectionFailed => true,
            AssessmentErrorKind::ServerFailure => {
                matches!(self.status, Some(500 | 502 | 503 | 504 | 529))
            }
            _ => false,
        }
    }
}

impl fmt::Display for AssessmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            AssessmentErrorKind::InvalidRequest => "assessment request is invalid",
            AssessmentErrorKind::ToolUseNotAllowed => {
                "assessment requests must not declare tools or tool_choice"
            }
            AssessmentErrorKind::ExternalImageUrl => {
                "assessment images must be caller-provided bytes, not URLs"
            }
            AssessmentErrorKind::UnsupportedModality => {
                "the connection does not accept a required assessment input modality"
            }
            AssessmentErrorKind::StructuredOutputUnavailable => {
                "the connection cannot provide the required structured assessment output"
            }
            AssessmentErrorKind::InvalidEvidence => {
                "the supplied evidence does not match the assessment request"
            }
            AssessmentErrorKind::InputTooLarge => {
                "the assessment evidence exceeds the provider's accepted input limits"
            }
            AssessmentErrorKind::CrossProjectReference => {
                "the supplied evidence belongs to another project"
            }
            AssessmentErrorKind::ProfileBindingMismatch => {
                "the assessment request, profile, and connection do not match"
            }
            AssessmentErrorKind::UnknownConnection => "the assessment connection is not registered",
            AssessmentErrorKind::CapabilityMismatch => {
                "the connection cannot serve this assessment request"
            }
            AssessmentErrorKind::ModelMismatch => {
                "the request model does not match the selected connection"
            }
            AssessmentErrorKind::CredentialUnavailable => {
                "the assessment credential is unavailable"
            }
            AssessmentErrorKind::AuthenticationFailed => "the assessment credential was rejected",
            AssessmentErrorKind::RateLimited => "the assessment provider rate-limited the request",
            AssessmentErrorKind::ServerFailure => "the assessment provider failed",
            AssessmentErrorKind::RequestRejected => "the assessment provider rejected the request",
            AssessmentErrorKind::ConnectionFailed => {
                "the assessment connection failed before sending"
            }
            AssessmentErrorKind::SendResultUnknown => {
                "the assessment send result is unknown after transmission"
            }
            AssessmentErrorKind::Cancelled => "the assessment request was cancelled",
            AssessmentErrorKind::CrossOriginRedirect => {
                "the assessment provider redirected to another origin"
            }
            AssessmentErrorKind::NoRedirectFollowing => {
                "the assessment provider returned a redirect; redirects are not followed"
            }
            AssessmentErrorKind::InvalidResponse => "the assessment response was invalid",
            AssessmentErrorKind::ResponseTooLarge => "the assessment response was too large",
            AssessmentErrorKind::RetryAfterBeyondDeadline => {
                "Retry-After does not fit inside the remaining run deadline"
            }
            AssessmentErrorKind::DeadlineReached => {
                "the remaining run deadline was reached before the assessment completed"
            }
            AssessmentErrorKind::InvalidConfiguration => {
                "the assessment transport configuration is invalid"
            }
            AssessmentErrorKind::Internal => "the assessment transport is unavailable",
        };
        f.write_str(message)?;
        if let Some(status) = self.status {
            write!(f, " (HTTP {status})")?;
        }
        Ok(())
    }
}

impl std::error::Error for AssessmentError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_rate_limits_transient_5xx_and_pre_send_connections_are_retryable() {
        assert!(
            AssessmentError::new(AssessmentErrorKind::RateLimited)
                .with_status(429)
                .is_retryable()
        );
        for status in [500, 502, 503, 504, 529] {
            assert!(
                AssessmentError::new(AssessmentErrorKind::ServerFailure)
                    .with_status(status)
                    .is_retryable(),
                "{status}"
            );
        }
        for status in [501, 505] {
            assert!(
                !AssessmentError::new(AssessmentErrorKind::ServerFailure)
                    .with_status(status)
                    .is_retryable(),
                "{status}"
            );
        }
        assert!(AssessmentError::new(AssessmentErrorKind::ConnectionFailed).is_retryable());
        for kind in [
            AssessmentErrorKind::SendResultUnknown,
            AssessmentErrorKind::AuthenticationFailed,
            AssessmentErrorKind::InvalidResponse,
            AssessmentErrorKind::InvalidEvidence,
            AssessmentErrorKind::InputTooLarge,
            AssessmentErrorKind::Cancelled,
            AssessmentErrorKind::CrossOriginRedirect,
        ] {
            assert!(!AssessmentError::new(kind).is_retryable(), "{kind:?}");
        }
    }
}
