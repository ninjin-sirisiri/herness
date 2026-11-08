//! Internal error translation for the pi engine adapter.
//!
//! Nothing here exposes a pi type. Every public failure is a sanitized
//! [`CoreError`]; raw SDK and provider messages are only used to decide a
//! stable failure kind and never copied into a contract value, event, or
//! checkpoint.

use herness_core::{CoreError, EngineFailureKind, ProviderFailureKind};

/// Longest provider-free detail copied into a model-facing tool failure.
const MAX_DETAIL_CHARS: usize = 512;

/// A checkpoint could not be produced, parsed, or restored.
pub(crate) fn checkpoint_unavailable() -> CoreError {
    CoreError::EngineUnavailable {
        failure: EngineFailureKind::CheckpointUnavailable,
    }
}

/// The engine itself is not available or could not interpret SDK output.
pub(crate) fn engine_unavailable() -> CoreError {
    CoreError::EngineUnavailable {
        failure: EngineFailureKind::Unavailable,
    }
}

/// The engine returned data that this adapter cannot interpret.
pub(crate) fn engine_invalid_response() -> CoreError {
    CoreError::EngineUnavailable {
        failure: EngineFailureKind::InvalidResponse,
    }
}

/// A provider request failed without exposing its response body.
pub(crate) fn provider_failure(
    provider: herness_core::Provider,
    failure: ProviderFailureKind,
) -> CoreError {
    CoreError::ProviderFailure { provider, failure }
}

/// Maps an HTTP status to a sanitized provider failure kind.
pub(crate) fn provider_status_failure(status: u16) -> ProviderFailureKind {
    match status {
        401 | 403 => ProviderFailureKind::Authentication,
        408 | 425 | 429 => ProviderFailureKind::RateLimited,
        500..=599 => ProviderFailureKind::Network,
        _ => ProviderFailureKind::InvalidResponse,
    }
}

/// A short, sanitized tool failure detail suitable for a model-facing result.
pub(crate) fn sanitized_detail(error: &CoreError) -> String {
    let mut text = error.to_string();
    if text.chars().count() > MAX_DETAIL_CHARS {
        text = text.chars().take(MAX_DETAIL_CHARS).collect();
        text.push('…');
    }
    text
}
