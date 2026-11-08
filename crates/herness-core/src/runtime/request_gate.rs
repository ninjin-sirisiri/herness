//! Default store-backed model-request gate.
//!
//! The gate is injected into the engine adapter as a
//! [`ModelRequestGatePort`]. It persists the host-owned intent before admitting
//! a request and persists every observation through the same store port. A
//! build whose store does not implement the request rows cannot admit a send.
//!
//! Consent policy and budget accounting are H2 responsibilities. This H1
//! implementation enforces the stop/deadline snapshot it receives and refuses
//! to send when the durable intent cannot be recorded.

use std::sync::{Arc, Mutex};

use crate::contracts::errors::CoreError;
use crate::contracts::request::{
    ModelRequestObservation, RequestGateIntent, RequestGateOutcome, RequestGateRefusal,
};
use crate::contracts::time::Timestamp;
use crate::ports::request_gate::ModelRequestGatePort;
use crate::ports::store::StorePort;

/// Store-backed gate for every external model request.
pub struct StoreModelRequestGate<S: StorePort> {
    store: Arc<Mutex<S>>,
}

impl<S: StorePort> StoreModelRequestGate<S> {
    /// Creates a gate over the same store handle used by the host runtime.
    pub fn new(store: Arc<Mutex<S>>) -> Self {
        Self { store }
    }

    fn store(&self) -> std::sync::MutexGuard<'_, S> {
        self.store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<S: StorePort> ModelRequestGatePort for StoreModelRequestGate<S> {
    fn admit(&mut self, intent: &RequestGateIntent) -> Result<RequestGateOutcome, CoreError> {
        let control = intent.control();
        if let Some(_reason) = control.stop_reason() {
            return Ok(RequestGateOutcome::Refuse {
                reason: RequestGateRefusal::Stopped,
            });
        }
        if control.is_deadline_reached() {
            return Ok(RequestGateOutcome::Refuse {
                reason: RequestGateRefusal::DeadlineReached,
            });
        }
        self.store()
            .record_model_request(intent.clone(), Timestamp::now())?;
        Ok(RequestGateOutcome::Admit)
    }

    fn observe(&mut self, observation: &ModelRequestObservation) -> Result<(), CoreError> {
        self.store()
            .record_model_request_observation(observation.clone(), Timestamp::now())
    }
}
