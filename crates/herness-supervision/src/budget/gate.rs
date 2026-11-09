//! Budget-aware adapter for the H1 [`ModelRequestGatePort`] path.
//!
//! The gate does not change H1's [`RequestGateIntent`] shape. It checks the
//! captured stop/deadline snapshot, asks a host-supplied estimator for a
//! conservative price, then lets the ledger commit the intent and reservation
//! in one durable operation. Only `Admit` permits a send.

use herness_core::contracts::{
    CoreError, IdKind, ModelRequestObservation, RequestGateIntent, RequestGateOutcome,
    RequestGateRefusal, RequestOutcome, StoreFailureKind,
};
use herness_core::ports::request_gate::ModelRequestGatePort;

use crate::budget::BudgetClockState;
use crate::budget::ledger::{BudgetClockPort, BudgetLedger, MoneySettlement};
use crate::budget::{Money, RequestBudgetEstimate};
use crate::error::SupervisionError;
use crate::ports::BudgetStorePort;

/// Host-supplied conservative request pricing.
///
/// `estimate` runs before any send under a money cap. `settled_amount` may
/// return a locally computed actual amount for a completed request; returning
/// `None` keeps the reservation unresolved instead of guessing zero.
pub trait RequestBudgetEstimator {
    /// Conservative estimate for one request, or `None` when no local price is
    /// available.
    fn estimate(&self, intent: &RequestGateIntent) -> Option<RequestBudgetEstimate>;

    /// Locally computed actual amount for a completed observation.
    fn settled_amount(&self, observation: &ModelRequestObservation) -> Option<Money> {
        let _ = observation;
        None
    }
}

impl<F> RequestBudgetEstimator for F
where
    F: Fn(&RequestGateIntent) -> Option<RequestBudgetEstimate>,
{
    fn estimate(&self, intent: &RequestGateIntent) -> Option<RequestBudgetEstimate> {
        self(intent)
    }
}

/// Budget-aware gate over one supervision ledger.
pub struct BudgetRequestGate<S: BudgetStorePort, C: BudgetClockPort, E: RequestBudgetEstimator> {
    ledger: BudgetLedger<S, C>,
    estimator: E,
}

impl<S: BudgetStorePort, C: BudgetClockPort, E: RequestBudgetEstimator> BudgetRequestGate<S, C, E> {
    /// Creates a gate over the ledger's supervision target.
    pub fn new(ledger: BudgetLedger<S, C>, estimator: E) -> Self {
        Self { ledger, estimator }
    }

    /// Borrows the ledger.
    pub const fn ledger(&self) -> &BudgetLedger<S, C> {
        &self.ledger
    }

    /// Mutable ledger access for state transitions outside a request.
    pub const fn ledger_mut(&mut self) -> &mut BudgetLedger<S, C> {
        &mut self.ledger
    }

    /// Returns the settlement implied by one observation.
    fn settlement_for(&self, observation: &ModelRequestObservation) -> MoneySettlement {
        match observation.outcome() {
            RequestOutcome::PreflightFailed => MoneySettlement::NotSent,
            RequestOutcome::SendStarted => MoneySettlement::Sent,
            RequestOutcome::Completed => {
                if observation.usage().is_unknown() {
                    MoneySettlement::Unresolved
                } else {
                    match self.estimator.settled_amount(observation) {
                        Some(actual) => MoneySettlement::Completed { actual },
                        None => MoneySettlement::Unresolved,
                    }
                }
            }
            RequestOutcome::Cancelled | RequestOutcome::SendResultUnknown => {
                MoneySettlement::Unresolved
            }
        }
    }
}

impl<S: BudgetStorePort, C: BudgetClockPort, E: RequestBudgetEstimator> ModelRequestGatePort
    for BudgetRequestGate<S, C, E>
{
    fn admit(&mut self, intent: &RequestGateIntent) -> Result<RequestGateOutcome, CoreError> {
        let control = intent.control();
        if control.stop_reason().is_some() {
            return Ok(RequestGateOutcome::Refuse {
                reason: RequestGateRefusal::Stopped,
            });
        }
        if control.is_deadline_reached() {
            return Ok(RequestGateOutcome::Refuse {
                reason: RequestGateRefusal::DeadlineReached,
            });
        }
        let estimate = self.estimator.estimate(intent);
        match self.ledger.admit_request(intent, estimate.as_ref()) {
            Ok(()) => Ok(RequestGateOutcome::Admit),
            Err(error) => match admission_refusal(&error) {
                Some(reason) => Ok(RequestGateOutcome::Refuse { reason }),
                None => Err(core_error(error)),
            },
        }
    }

    fn observe(&mut self, observation: &ModelRequestObservation) -> Result<(), CoreError> {
        let settlement = self.settlement_for(observation);
        self.ledger
            .observe_request(observation, settlement)
            .map_err(core_error)
    }
}

fn admission_refusal(error: &SupervisionError) -> Option<RequestGateRefusal> {
    match error {
        SupervisionError::BudgetLimitReached { .. }
        | SupervisionError::BudgetPriceUnavailable { .. } => {
            Some(RequestGateRefusal::BudgetUnavailable)
        }
        SupervisionError::BudgetInactive { state } => {
            if matches!(state, BudgetClockState::AppStopped) {
                Some(RequestGateRefusal::Stopped)
            } else {
                Some(RequestGateRefusal::BudgetUnavailable)
            }
        }
        _ => None,
    }
}

fn core_error(error: SupervisionError) -> CoreError {
    match error {
        SupervisionError::CrossProjectReference {
            expected, found, ..
        } => CoreError::CrossProjectReference {
            id_kind: IdKind::Project,
            expected,
            found,
        },
        SupervisionError::RevisionConflict { .. }
        | SupervisionError::BudgetReservationConflict { .. }
        | SupervisionError::UnknownBudgetReservation { .. } => CoreError::StoreUnavailable {
            failure: StoreFailureKind::Conflict,
        },
        _ => CoreError::StoreUnavailable {
            failure: StoreFailureKind::Unavailable,
        },
    }
}
