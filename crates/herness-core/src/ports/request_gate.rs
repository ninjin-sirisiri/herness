//! Pre-send model request gate and stop/deadline control ports.
//!
//! The host-owned gate is injected so H1 alone does not need H2 types. A build
//! that has no gate implementation must return
//! [`CoreError::UnsupportedPortFeature`] rather than admitting a request.

use crate::contracts::errors::{CoreError, PortFeature};
use crate::contracts::ids::RunId;
use crate::contracts::request::{
    ModelRequestObservation, RequestGateIntent, RequestGateOutcome, StopDeadlineControl,
};

/// Gate and observation boundary for every external model request.
///
/// Implementations must durably record the intent before returning
/// [`RequestGateOutcome::Admit`]. A refusal, an error, or a missing
/// implementation means the request must not be sent. The gate must also
/// refuse when stop or deadline control does not permit a send.
pub trait ModelRequestGatePort {
    /// Checks consent, budget, stop, and deadline, then durably records the
    /// intent. Only [`RequestGateOutcome::Admit`] permits sending.
    fn admit(&mut self, intent: &RequestGateIntent) -> Result<RequestGateOutcome, CoreError> {
        let _ = intent;
        Err(CoreError::UnsupportedPortFeature {
            feature: PortFeature::RequestGate,
        })
    }

    /// Records a terminal request observation and its reported usage.
    ///
    /// Missing usage is recorded as unknown, never as zero. Observing an
    /// attempt more than once must be handled by the implementation without
    /// duplicating a send.
    fn observe(&mut self, observation: &ModelRequestObservation) -> Result<(), CoreError> {
        let _ = observation;
        Err(CoreError::UnsupportedPortFeature {
            feature: PortFeature::RequestObservation,
        })
    }
}

/// Reads the current stop and deadline snapshot for a run.
///
/// Host tool execution and model sends check this snapshot immediately before
/// a side effect. The default implementation reports that the capability is
/// unavailable, so an adapter cannot mistake an unimplemented control for
/// permission to proceed.
pub trait StopDeadlinePort {
    /// Returns the current control snapshot for `run`.
    fn control(&self, run: &RunId) -> Result<StopDeadlineControl, CoreError> {
        let _ = run;
        Err(CoreError::UnsupportedPortFeature {
            feature: PortFeature::StopDeadlineControl,
        })
    }
}
