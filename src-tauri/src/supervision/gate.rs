//! Supervision-aware H1 model-request gate.
//!
//! The gate is installed on the single Pi engine. A request whose subject
//! belongs to a supervised run is admitted through that target's durable
//! `BudgetLedger` (which records the request intent and any money reservation in
//! one transaction). Everything else keeps the existing store-backed H1
//! behavior. There is no second ledger and no provider fallback.

use herness_core::contracts::{
    CoreError, EventSubject, ModelRequestObservation, ProjectId, RequestGateIntent,
    RequestGateOutcome,
};
use herness_core::ports::ModelRequestGatePort;
use herness_core::{OperationId, RunId, StoreFailureKind, StorePort, Timestamp};
use herness_supervision::budget::gate::{BudgetRequestGate, RequestBudgetEstimator};
use herness_supervision::budget::ledger::BudgetLedger;
use herness_supervision::{SupervisionError, SupervisionId};

use crate::supervision::plan::load_plan;
use crate::supervision::store::{HostBudgetClock, StoreHandle};

/// Estimator used when no local price table is configured.
///
/// A money-capped policy therefore refuses a request instead of guessing a
/// price. Time/run accounting does not depend on this value.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoPriceEstimator;

impl RequestBudgetEstimator for NoPriceEstimator {
    fn estimate(
        &self,
        _intent: &RequestGateIntent,
    ) -> Option<herness_supervision::RequestBudgetEstimate> {
        None
    }

    fn settled_amount(
        &self,
        _observation: &ModelRequestObservation,
    ) -> Option<herness_supervision::Money> {
        None
    }
}

/// One gate over the single store.
#[derive(Clone)]
pub struct SupervisionAwareGate {
    store: StoreHandle,
}

impl SupervisionAwareGate {
    /// Creates the gate over the shared store handle.
    pub const fn new(store: StoreHandle) -> Self {
        Self { store }
    }

    /// Returns a boxed handle for `PiEngine::set_request_gate`.
    pub fn boxed(&self) -> Box<dyn ModelRequestGatePort + Send> {
        Box::new(self.clone())
    }

    fn supervision_for(&self, subject: &EventSubject) -> Option<(ProjectId, SupervisionId)> {
        let project = subject.project_id();
        let run = self.run_for(subject)?;
        let records = self
            .store
            .lock()
            .supervision_records_for_project(&project)
            .ok()?;
        records
            .into_iter()
            .find(|record| record.run_group().contains(&run))
            .map(|record| (project, record.supervision_id()))
    }

    fn run_for(&self, subject: &EventSubject) -> Option<RunId> {
        if let Some(run) = subject.run() {
            return Some(run.run_id());
        }
        let activity = subject.host_activity()?;
        // Permission-evaluation intents use the operation's local UUID as the
        // activity ID. If a durable intent exists, resolve its run; otherwise
        // the request keeps the non-supervised store path.
        let operation =
            OperationId::from_parts(subject.project_id(), activity.activity_id().local_id());
        let record = self.store.lock().operation(&operation).ok()??;
        Some(record.intent().operation().run_id())
    }

    fn plan(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Option<crate::supervision::plan::StoredPlan> {
        load_plan(&self.store, project, supervision)
    }

    fn ledger(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<Option<BudgetLedger<StoreHandle, HostBudgetClock>>, SupervisionError> {
        let Some(plan) = self.plan(project, supervision) else {
            return Ok(None);
        };
        Ok(Some(BudgetLedger::open(
            self.store.clone(),
            project,
            supervision,
            plan.budget.policy()?,
            plan.budget_version,
            HostBudgetClock::new(),
        )?))
    }
}

impl ModelRequestGatePort for SupervisionAwareGate {
    fn admit(&mut self, intent: &RequestGateIntent) -> Result<RequestGateOutcome, CoreError> {
        let control = intent.control();
        if control.stop_reason().is_some() {
            return Ok(RequestGateOutcome::Refuse {
                reason: herness_core::RequestGateRefusal::Stopped,
            });
        }
        if control.is_deadline_reached() {
            return Ok(RequestGateOutcome::Refuse {
                reason: herness_core::RequestGateRefusal::DeadlineReached,
            });
        }
        if let Some((project, supervision)) = self.supervision_for(intent.subject()) {
            let ledger = match self.ledger(project, supervision) {
                Ok(Some(ledger)) => ledger,
                Ok(None) | Err(_) => {
                    // A supervised run without a durable plan/policy is not
                    // allowed to fall back to an unbudgeted request.
                    return Ok(RequestGateOutcome::Refuse {
                        reason: herness_core::RequestGateRefusal::BudgetUnavailable,
                    });
                }
            };
            let mut gate = BudgetRequestGate::new(ledger, NoPriceEstimator);
            return gate.admit(intent);
        }
        store_admit(&mut self.store, intent)
    }

    fn observe(&mut self, observation: &ModelRequestObservation) -> Result<(), CoreError> {
        let attempt = observation.attempt_id();
        let Some(record) = self.store.lock().model_request(&attempt).ok().flatten() else {
            return store_observe(&mut self.store, observation);
        };
        let Some((project, supervision)) = self.supervision_for(record.intent().subject()) else {
            return store_observe(&mut self.store, observation);
        };
        let ledger = match self.ledger(project, supervision) {
            Ok(Some(ledger)) => ledger,
            Ok(None) | Err(_) => {
                return Err(CoreError::StoreUnavailable {
                    failure: StoreFailureKind::Unavailable,
                });
            }
        };
        let mut gate = BudgetRequestGate::new(ledger, NoPriceEstimator);
        gate.observe(observation)
    }
}

fn store_admit(
    store: &mut StoreHandle,
    intent: &RequestGateIntent,
) -> Result<RequestGateOutcome, CoreError> {
    store
        .record_model_request(intent.clone(), Timestamp::now())
        .map_err(|_| CoreError::StoreUnavailable {
            failure: StoreFailureKind::Unavailable,
        })?;
    Ok(RequestGateOutcome::Admit)
}

fn store_observe(
    store: &mut StoreHandle,
    observation: &ModelRequestObservation,
) -> Result<(), CoreError> {
    store
        .record_model_request_observation(observation.clone(), Timestamp::now())
        .map_err(|_| CoreError::StoreUnavailable {
            failure: StoreFailureKind::Unavailable,
        })
}
