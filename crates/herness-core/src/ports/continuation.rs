//! Conversation-preserving continuation and input-correspondence port.
//!
//! The host runtime that owns run lifecycle implements this boundary. A build
//! without an implementation returns an explicit unsupported error instead of
//! pretending that a continuation started or that an input completed.

use crate::contracts::errors::{CoreError, PortFeature};
use crate::contracts::ids::InputId;
use crate::contracts::input::{ContinuationRequest, InputProgress};

/// Starts a new run that continues a previous conversation.
///
/// The caller must already have checked that the previous run is stable, that
/// no unresolved operation or managed process remains, and that the same
/// agent/session can preserve the conversation. An implementation must not
/// re-send prior input or reuse prior approvals.
pub trait ContinuationPort {
    /// Starts the continuation described by `request`.
    ///
    /// The implementation owns creation of the new run's tools, checkpoints,
    /// and events. Returning success without starting the run is not allowed.
    fn continue_run(&mut self, request: &ContinuationRequest) -> Result<(), CoreError> {
        let _ = request;
        Err(CoreError::UnsupportedPortFeature {
            feature: PortFeature::Continuation,
        })
    }

    /// Returns the latest acceptance/start/completion progress for an input.
    ///
    /// An idle observation alone is not completion. Callers use this value to
    /// decide whether they can associate idle with a completed submission.
    fn input_progress(&self, input: &InputId) -> Result<Option<InputProgress>, CoreError> {
        let _ = input;
        Err(CoreError::UnsupportedPortFeature {
            feature: PortFeature::InputCorrespondence,
        })
    }
}
