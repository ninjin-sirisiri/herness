//! Production permission-evaluator composition.
//!
//! H1 is created with one shared `PermissionEvaluatorPort`. This module keeps a
//! dynamic state behind that port: when a project has a verified permission
//! profile and a current permission-purpose consent, the router builds the real
//! Task 14 `PermissionEvaluator` on demand. A supervised operation uses that
//! target's durable `BudgetLedger`; a normal-chat operation uses the existing
//! store-backed request path with the Task 14 run-scoped request limit. Without
//! a verified profile the evaluator reports unavailable, so H1 automatic mode
//! waits for a human instead of allowing or silently substituting a model.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::{Arc, Mutex, MutexGuard};

use herness_assessment::{
    AssessmentTransport, PermissionBudgetScope, PermissionEvaluator, PermissionEvaluatorConfig,
    SharedModelRequestGate, TransportControl,
};
use herness_core::{
    CoreError, EvaluationFailureKind, EvaluationRequest, EvaluatorAvailability, PermissionDecision,
    PermissionEvaluatorPort, ProjectId, RunId, SharedPermissionEvaluator,
};
use herness_supervision::budget::gate::BudgetRequestGate;
use herness_supervision::budget::ledger::BudgetLedger;
use herness_supervision::{
    DisclosureConsent, DisclosureDataKind, ProfilePurpose, ProviderOrigin, SupervisionError,
    SupervisionId, TargetVersion,
};

use crate::supervision::assessment::AssessmentHost;
use crate::supervision::gate::{NoPriceEstimator, SupervisionAwareGate};
use crate::supervision::plan::{ConfigStore, ConfiguredProfile, load_plan};
use crate::supervision::store::{HostBudgetClock, StoreHandle};

/// One prepared permission profile/consent pair.
#[derive(Debug, Clone)]
struct PermissionConfig {
    profile: herness_supervision::ProfileEntry,
    consent: DisclosureConsent,
    origin: ProviderOrigin,
    target_version: TargetVersion,
}

#[derive(Default)]
struct PermissionState {
    projects: BTreeMap<ProjectId, PermissionConfig>,
    evaluators: BTreeMap<(ProjectId, Option<SupervisionId>), PermissionEvaluator>,
}

/// Shared runtime handle installed into H1 at application startup.
#[derive(Clone)]
pub struct PermissionRuntime {
    state: Arc<Mutex<PermissionState>>,
    assessment: AssessmentHost,
    evaluator: SharedPermissionEvaluator,
}

impl PermissionRuntime {
    /// Creates the dynamic evaluator and the shared port H1 receives.
    pub fn new(store: StoreHandle, assessment: AssessmentHost) -> Self {
        let state = Arc::new(Mutex::new(PermissionState::default()));
        let evaluator = SharedPermissionEvaluator::new(Box::new(HostPermissionEvaluator {
            state: Arc::clone(&state),
            store: store.clone(),
            assessment: assessment.clone(),
        }));
        Self {
            state,
            assessment,
            evaluator,
        }
    }

    /// Shared H1 port. It is the same instance the runtime and engine receive.
    pub fn evaluator(&self) -> SharedPermissionEvaluator {
        self.evaluator.clone()
    }

    /// Whether any project currently has a usable permission profile/consent.
    pub fn available(&self) -> bool {
        !self.lock().projects.is_empty()
    }

    /// Whether one project currently has a usable permission profile/consent.
    pub fn available_for(&self, project: ProjectId) -> bool {
        self.lock().projects.contains_key(&project)
    }

    /// Rebuilds the permission configuration for one project.
    ///
    /// A missing, unverified, revoked, origin-mismatched, or non-text consent
    /// makes the project explicitly unavailable. Existing cached evaluators for
    /// the project are discarded so a change cannot reuse old policy/consent.
    pub fn refresh(&self, config: &ConfigStore, project: ProjectId) {
        let prepared = prepare_config(&self.assessment, &config.get(project));
        let mut state = self.lock();
        state.evaluators.retain(|(cached, _), _| *cached != project);
        match prepared {
            Some(prepared) => {
                state.projects.insert(project, prepared);
            }
            None => {
                state.projects.remove(&project);
            }
        }
    }

    /// Invalidates one target's cached evaluator after a budget/policy change.
    pub fn invalidate_supervision(&self, project: ProjectId, supervision: SupervisionId) {
        self.lock()
            .evaluators
            .retain(|(cached_project, cached_supervision), _| {
                *cached_project != project || *cached_supervision != Some(supervision)
            });
    }

    fn lock(&self) -> MutexGuard<'_, PermissionState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn prepare_config(
    assessment: &AssessmentHost,
    config: &crate::supervision::plan::ProjectConfig,
) -> Option<PermissionConfig> {
    let ConfiguredProfile { profile, verified } = config.profile(ProfilePurpose::Permission)?;
    if !*verified || profile.purpose() != ProfilePurpose::Permission {
        return None;
    }
    let consent = config.consent(ProfilePurpose::Permission)?;
    if consent.require_granted().is_err() {
        return None;
    }
    if !consent
        .scope()
        .data_kinds()
        .contains(&DisclosureDataKind::Text)
    {
        return None;
    }
    let origin = assessment.origin_for(profile.connection()).ok()?;
    if consent.origin() != &origin {
        return None;
    }
    let entry = assessment.entry(profile).ok()?;
    if entry.validate().is_err() {
        return None;
    }
    Some(PermissionConfig {
        profile: entry,
        consent: consent.clone(),
        origin,
        target_version: consent.target_scope_version(),
    })
}

struct HostPermissionEvaluator {
    state: Arc<Mutex<PermissionState>>,
    store: StoreHandle,
    assessment: AssessmentHost,
}

impl HostPermissionEvaluator {
    fn state(&self) -> MutexGuard<'_, PermissionState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn supervision_for(&self, project: ProjectId, run: RunId) -> Option<SupervisionId> {
        let records = self
            .store
            .lock()
            .supervision_records_for_project(&project)
            .ok()?;
        records
            .into_iter()
            .find(|record| record.run_group().contains(&run))
            .map(|record| record.supervision_id())
    }

    fn build(
        &self,
        project: ProjectId,
        supervision: Option<SupervisionId>,
        config: &PermissionConfig,
    ) -> Result<PermissionEvaluator, CoreError> {
        let transport = AssessmentTransport::new(
            Arc::clone(&self.assessment.credentials),
            self.assessment.directory.clone(),
            self.assessment.endpoints.clone(),
        )
        .map_err(|_| CoreError::PermissionEvaluationFailed {
            failure: EvaluationFailureKind::Unavailable,
        })?;
        let mut remaining = None;
        let gate = match supervision {
            Some(supervision) => {
                let plan = load_plan(&self.store, project, supervision).ok_or(
                    CoreError::PermissionEvaluationFailed {
                        failure: EvaluationFailureKind::Unavailable,
                    },
                )?;
                let policy = plan.budget.policy().map_err(supervision_error)?;
                let mut ledger = BudgetLedger::open(
                    self.store.clone(),
                    project,
                    supervision,
                    policy,
                    plan.budget_version,
                    HostBudgetClock::new(),
                )
                .map_err(supervision_error)?;
                remaining = ledger
                    .remaining_active_seconds()
                    .ok()
                    .map(std::time::Duration::from_secs);
                SharedModelRequestGate::new(Box::new(BudgetRequestGate::new(
                    ledger,
                    NoPriceEstimator,
                )))
            }
            None => {
                SharedModelRequestGate::new(Box::new(SupervisionAwareGate::new(self.store.clone())))
            }
        };
        let control = remaining.map_or_else(TransportControl::default, |remaining| {
            TransportControl::default().with_remaining(remaining)
        });
        let config_builder = PermissionEvaluatorConfig::new(
            config.profile.clone(),
            Some(config.consent.clone()),
            config.origin.clone(),
            config.target_version,
            transport,
        )
        .with_budget_gate(gate)
        .with_budget_scope(match supervision {
            Some(_) => PermissionBudgetScope::Supervised,
            None => PermissionBudgetScope::RunScoped { max_requests: 1 },
        })
        .with_transport_control(control)
        .with_data_kinds(config.consent.scope().data_kinds().clone());
        PermissionEvaluator::new(config_builder).map_err(|_| {
            CoreError::PermissionEvaluationFailed {
                failure: EvaluationFailureKind::Unavailable,
            }
        })
    }
}

fn supervision_error(error: SupervisionError) -> CoreError {
    let _ = error;
    CoreError::PermissionEvaluationFailed {
        failure: EvaluationFailureKind::Unavailable,
    }
}

impl PermissionEvaluatorPort for HostPermissionEvaluator {
    fn availability(&self) -> EvaluatorAvailability {
        let Ok(state) = self.state.try_lock() else {
            return EvaluatorAvailability::Unavailable;
        };
        if state.projects.is_empty() {
            EvaluatorAvailability::Unavailable
        } else {
            EvaluatorAvailability::Available
        }
    }

    fn evaluate(&mut self, request: &EvaluationRequest) -> Result<PermissionDecision, CoreError> {
        let project = request.operation().project_id();
        let run = request.operation().run_id();
        let supervision = self.supervision_for(project, run);
        let mut state = self.state();
        let Some(config) = state.projects.get(&project).cloned() else {
            return Err(CoreError::PermissionEvaluationFailed {
                failure: EvaluationFailureKind::Unavailable,
            });
        };
        let key = (project, supervision);
        if let Entry::Vacant(entry) = state.evaluators.entry(key) {
            let evaluator = self.build(project, supervision, &config)?;
            entry.insert(evaluator);
        }
        state
            .evaluators
            .get_mut(&key)
            .ok_or(CoreError::PermissionEvaluationFailed {
                failure: EvaluationFailureKind::Unavailable,
            })?
            .evaluate(request)
    }
}
