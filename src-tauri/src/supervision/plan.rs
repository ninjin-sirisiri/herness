//! Durable supervision plan and per-purpose host configuration.
//!
//! A supervision record stores the fixed versions, state, evidence references,
//! and command journal. The full approved condition content, execution scope,
//! profile, consent, and budget policy are kept in this host-owned plan so a
//! restarted process can rebuild the exact supervisor contract without
//! inferring approval from prose.

use std::collections::{BTreeMap, BTreeSet};

use herness_core::contracts::{AgentId, ModelId, ProjectId, SessionId};
use herness_core::{CoreError, Timestamp};
use herness_supervision::{
    ApprovalActor, AssessmentProfile, BudgetPolicy, Condition, ConditionId, ConditionSet,
    ConditionVersion, ConsentId, ConsentState, DisclosureConsent, DisclosureDataKind,
    DisclosureScope, ExecutionScope, Money, MoneyCap, OwnerApprovalSource, OwnerRef, PriceVersion,
    ProfilePurpose, ProviderOrigin, RequiredCheck, RunGroup, SupervisionContract, SupervisionError,
    SupervisionId, SupervisionRecord, SupervisionSubject, TargetScope, TargetVersion,
    VerificationOperation,
};
use serde::{Deserialize, Serialize};

use crate::supervision::runtime::ChildIdentity;
use crate::supervision::store::StoreHandle;

/// One host-minted confirmation of a human action.
///
/// The fields are private and there is no public constructor. A Tauri command
/// minted one only after `guard::verify` accepted the trusted main window. A
/// model tool cannot reach this crate boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanConfirmation {
    kind: ConfirmationKind,
    nonce: uuid::Uuid,
}

/// Which human action a confirmation covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationKind {
    /// Create a supervision target.
    Create,
    /// Start the first run.
    Start,
    /// Stop or cancel.
    Stop,
    /// Resume from a human-waiting or stopped state.
    Resume,
    /// Reassess the current target.
    Reassess,
    /// Change conditions, profile, consent, or budget.
    Change,
    /// Configure a per-purpose profile.
    Profile,
    /// Grant or revoke per-purpose consent.
    Consent,
}

impl HumanConfirmation {
    pub(crate) fn new(kind: ConfirmationKind) -> Self {
        Self {
            kind,
            nonce: uuid::Uuid::new_v4(),
        }
    }

    /// Confirmation kind.
    pub const fn kind(&self) -> ConfirmationKind {
        self.kind
    }
}

/// Who is requesting a create/change operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum RequestActor {
    /// A human using the trusted main window.
    Human,
    /// An already-approved H3/H4 owner.
    ApprovedOwner {
        /// Owner reference that must match the subject owner.
        owner: OwnerRef,
        /// Phase-owned approval source.
        source: OwnerApprovalSource,
    },
    /// A model proposal. Always rejected.
    Model,
}

impl RequestActor {
    /// Converts to the H2 approval actor.
    pub fn approval_actor(&self) -> ApprovalActor {
        match self {
            Self::Human => ApprovalActor::Human,
            Self::ApprovedOwner { owner, source } => ApprovalActor::ApprovedOwner {
                owner: owner.clone(),
                source: *source,
            },
            Self::Model => ApprovalActor::Model,
        }
    }
}

/// One UI/condition input for a required shell check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckInput {
    /// Exact command run in the project root.
    pub command: String,
    /// What the check verifies.
    pub description: String,
}

/// One completion condition proposed by a human or approved owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConditionInput {
    /// Short condition title.
    pub title: String,
    /// Per-condition rubric used by a semantic assessment.
    pub rubric: String,
    /// Required checks for this condition.
    #[serde(default)]
    pub checks: Vec<CheckInput>,
}

/// Finite budget input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BudgetInput {
    /// Cumulative active seconds.
    pub active_seconds: u64,
    /// Additional runs after the first.
    pub additional_runs: u32,
    /// Optional finite USD cap in micro-dollars.
    #[serde(default)]
    pub money_limit_micros: Option<u64>,
    /// Price version required when a money cap is supplied.
    #[serde(default)]
    pub price_version: Option<String>,
}

impl BudgetInput {
    /// Builds the validated finite policy.
    pub fn policy(&self) -> Result<BudgetPolicy, SupervisionError> {
        let money_cap = match self.money_limit_micros {
            Some(limit) => {
                let price_version =
                    self.price_version
                        .as_deref()
                        .ok_or(SupervisionError::BudgetInvalid {
                            field: "budget.priceVersion".to_owned(),
                            detail: "a money cap requires a price version".to_owned(),
                        })?;
                Some(MoneyCap::new(
                    Money::from_micros(limit),
                    PriceVersion::new(price_version)?,
                )?)
            }
            None => None,
        };
        BudgetPolicy::new(self.active_seconds, self.additional_runs, money_cap)
    }

    /// Serialized budget snapshot used by the durable plan.
    pub fn snapshot(&self) -> Result<BudgetSnapshot, SupervisionError> {
        let policy = self.policy()?;
        Ok(BudgetSnapshot::from_policy(&policy))
    }
}

/// Serializable budget policy snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BudgetSnapshot {
    active_seconds: u64,
    additional_runs: u32,
    money_cap: Option<MoneyCap>,
}

impl BudgetSnapshot {
    /// Captures an already-validated policy.
    pub fn from_policy(policy: &BudgetPolicy) -> Self {
        Self {
            active_seconds: policy.active_seconds(),
            additional_runs: policy.additional_runs(),
            money_cap: policy.money_cap().cloned(),
        }
    }

    /// Rebuilds a validated policy.
    pub fn policy(&self) -> Result<BudgetPolicy, SupervisionError> {
        BudgetPolicy::new(
            self.active_seconds,
            self.additional_runs,
            self.money_cap.clone(),
        )
    }
}

/// Durable plan for one supervision target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoredPlan {
    /// Human or approved-owner actor used to build the contract.
    pub actor: RequestActor,
    /// Subject owner.
    pub owner: OwnerRef,
    /// Child identity allocated at create time.
    pub child: ChildIdentity,
    /// Approved execution scope.
    pub execution_scope: ExecutionScope,
    /// Approved conditions and checks.
    pub conditions: ConditionSet,
    /// Approved target scope.
    pub evidence_target: TargetScope,
    /// Fixed assessment profile.
    pub profile: AssessmentProfile,
    /// Fixed disclosure consent.
    pub consent: DisclosureConsent,
    /// Finite budget policy.
    pub budget: BudgetSnapshot,
    /// Durable budget policy version.
    pub budget_version: u64,
    /// Exact approved contract at create/change time.
    pub contract: SupervisionContract,
}

impl StoredPlan {
    /// Returns the exact contract approved at create/change time.
    ///
    /// The record versions must still match. Live approval/consent validity is
    /// checked separately by the controller before a run or assessment.
    pub fn contract(
        &self,
        record: &SupervisionRecord,
        _now: Timestamp,
    ) -> Result<SupervisionContract, SupervisionError> {
        if self.conditions.condition_version() != record.condition_version()
            || self.contract.conditions().condition_version() != record.condition_version()
        {
            return Err(SupervisionError::InvalidValue {
                field: "plan.conditions".to_owned(),
                detail: "the stored condition content does not match the record version".to_owned(),
            });
        }
        if self.profile.binding() != record.profile() || self.contract.profile() != record.profile()
        {
            return Err(SupervisionError::ProfileUnavailable {
                reason: herness_supervision::ProfileUnavailable::VersionMismatch {
                    bound: record.profile().version().get(),
                    configured: self.profile.version().get(),
                },
            });
        }
        if self.consent.binding() != record.consent() || self.contract.consent() != record.consent()
        {
            return Err(SupervisionError::ConsentBlocked {
                reason: herness_supervision::ConsentBlock::VersionMismatch,
            });
        }
        if self.evidence_target.version() != record.target_version()
            || self.contract.evidence_target().version() != record.target_version()
        {
            return Err(SupervisionError::InvalidValue {
                field: "plan.target".to_owned(),
                detail: "the stored target scope does not match the record version".to_owned(),
            });
        }
        Ok(self.contract.clone())
    }

    /// Rebuilds and stores the exact contract after an explicit change.
    ///
    /// This enforces a current approved condition set and granted consent. It
    /// is used before a change is committed, so an invalid change fails before
    /// the record mutation.
    pub fn rebuild_contract(
        &mut self,
        record: &SupervisionRecord,
        now: Timestamp,
    ) -> Result<(), SupervisionError> {
        let subject = SupervisionSubject::new(
            record.project_id(),
            record.supervision_id(),
            self.child.agent_id,
            self.child.session_id,
            self.owner.clone(),
        )?;
        self.contract = SupervisionContract::new(
            self.actor.approval_actor(),
            subject,
            self.execution_scope.clone(),
            RunGroup::new(herness_supervision::RunGroupId::new(record.project_id())),
            self.conditions.clone(),
            self.evidence_target.clone(),
            &self.profile,
            &self.consent,
            self.budget.policy()?,
            now,
        )?;
        Ok(())
    }

    /// Updates the condition content and version after an explicit change.
    pub fn set_conditions(&mut self, conditions: ConditionSet) {
        self.conditions = conditions;
    }

    /// Updates the profile after an explicit change.
    pub fn set_profile(&mut self, profile: AssessmentProfile) {
        self.profile = profile;
    }

    /// Updates the consent after an explicit change.
    pub fn set_consent(&mut self, consent: DisclosureConsent) {
        self.consent = consent;
    }

    /// Updates the budget policy and version after an explicit change.
    pub fn set_budget(&mut self, budget: BudgetPolicy, version: u64) {
        self.budget = BudgetSnapshot::from_policy(&budget);
        self.budget_version = version;
    }
}

/// One configured profile and its verification state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfiguredProfile {
    /// Exact profile value.
    pub profile: AssessmentProfile,
    /// Whether a human/acceptance step verified the real route. This build
    /// never claims verification for a newly configured profile.
    pub verified: bool,
}

/// Per-project profiles and consents for all three assessment purposes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectConfig {
    /// Purpose-keyed profiles.
    pub profiles: BTreeMap<ProfilePurpose, ConfiguredProfile>,
    /// Purpose-keyed consent records.
    pub consents: BTreeMap<ProfilePurpose, DisclosureConsent>,
}

impl ProjectConfig {
    /// Current profile for one purpose.
    pub fn profile(&self, purpose: ProfilePurpose) -> Option<&ConfiguredProfile> {
        self.profiles.get(&purpose)
    }

    /// Current consent for one purpose.
    pub fn consent(&self, purpose: ProfilePurpose) -> Option<&DisclosureConsent> {
        self.consents.get(&purpose)
    }

    /// Replaces the profile for a purpose.
    pub fn set_profile(&mut self, profile: AssessmentProfile, verified: bool) {
        self.profiles
            .insert(profile.purpose(), ConfiguredProfile { profile, verified });
    }

    /// Replaces the consent for a purpose.
    pub fn set_consent(&mut self, consent: DisclosureConsent) {
        self.consents.insert(consent.purpose(), consent);
    }

    /// Removes the consent for a purpose.
    pub fn clear_consent(&mut self, purpose: ProfilePurpose) {
        self.consents.remove(&purpose);
    }
}

/// Shared in-memory per-project configuration with durable host-state copies.
#[derive(Clone, Default)]
pub struct ConfigStore {
    inner: std::sync::Arc<std::sync::Mutex<BTreeMap<ProjectId, ProjectConfig>>>,
}

impl ConfigStore {
    /// Creates an empty configuration store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads one project's configuration.
    pub fn get(&self, project: ProjectId) -> ProjectConfig {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&project)
            .cloned()
            .unwrap_or_default()
    }

    /// Replaces one project's configuration.
    pub fn set(&self, project: ProjectId, config: ProjectConfig) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(project, config);
    }

    /// Restores one project's configuration from host state.
    pub fn restore(&self, store: &StoreHandle, project: ProjectId) {
        let key = config_key(project);
        let Ok(Some(bytes)) = store.lock().load_host_state(&key) else {
            return;
        };
        if let Ok(config) = serde_json::from_slice::<ProjectConfig>(&bytes) {
            self.set(project, config);
        }
    }

    /// Persists one project's configuration.
    pub fn persist(&self, store: &StoreHandle, project: ProjectId) -> Result<(), SupervisionError> {
        let config = self.get(project);
        let bytes =
            serde_json::to_vec(&config).map_err(|error| SupervisionError::StorageFailure {
                detail: format!("could not encode the supervision configuration: {error}"),
            })?;
        store
            .lock()
            .save_host_state(&config_key(project), &bytes)
            .map_err(|error| SupervisionError::StorageFailure {
                detail: error.to_string(),
            })
    }
}

fn config_key(project: ProjectId) -> String {
    format!("h2.supervision.config:{project}")
}

fn plan_key(project: ProjectId, supervision: SupervisionId) -> String {
    format!("h2.supervision.plan:{project}:{supervision}")
}

/// Loads one durable plan from host state.
pub fn load_plan(
    store: &StoreHandle,
    project: ProjectId,
    supervision: SupervisionId,
) -> Option<StoredPlan> {
    let bytes = store
        .lock()
        .load_host_state(&plan_key(project, supervision))
        .ok()??;
    serde_json::from_slice(&bytes).ok()
}

/// Persists one durable plan.
pub fn save_plan(
    store: &StoreHandle,
    project: ProjectId,
    supervision: SupervisionId,
    plan: &StoredPlan,
) -> Result<(), SupervisionError> {
    let bytes = serde_json::to_vec(plan).map_err(|error| SupervisionError::StorageFailure {
        detail: format!("could not encode the supervision plan: {error}"),
    })?;
    store
        .lock()
        .save_host_state(&plan_key(project, supervision), &bytes)
        .map_err(|error| SupervisionError::StorageFailure {
            detail: error.to_string(),
        })
}

/// Builds an approved condition set from human input.
pub fn build_conditions(
    project: ProjectId,
    version: ConditionVersion,
    actor: &RequestActor,
    inputs: &[ConditionInput],
    now: Timestamp,
) -> Result<ConditionSet, SupervisionError> {
    if inputs.is_empty() {
        return Err(SupervisionError::InvalidValue {
            field: "conditions".to_owned(),
            detail: "at least one completion condition is required".to_owned(),
        });
    }
    let mut conditions = Vec::new();
    let mut checks = Vec::new();
    for input in inputs {
        let condition_id = ConditionId::new(project);
        let mut check_ids = Vec::new();
        for check in &input.checks {
            let check_id = herness_supervision::CheckId::new(project);
            let operation = VerificationOperation::command(&check.command)?;
            checks.push(RequiredCheck::new(
                check_id,
                condition_id,
                operation,
                &check.description,
            )?);
            check_ids.push(check_id);
        }
        conditions.push(Condition::new(
            condition_id,
            &input.title,
            &input.rubric,
            check_ids,
            herness_supervision::ConditionOrigin::Human,
        )?);
    }
    let mut set = ConditionSet::new(project, version, conditions, checks)?;
    let basis = approval_basis(actor, now)?;
    let approval =
        herness_supervision::ConditionApproval::new(project, basis, version, set.digest().clone())?;
    set.approve(actor.approval_actor(), approval, now)?;
    Ok(set)
}

fn approval_basis(
    actor: &RequestActor,
    now: Timestamp,
) -> Result<herness_supervision::ApprovalBasis, SupervisionError> {
    match actor {
        RequestActor::Human => Ok(herness_supervision::ApprovalBasis::ExplicitHuman {
            approved_at: now,
            expires_at: None,
        }),
        RequestActor::ApprovedOwner { owner, source } => {
            if !owner.is_approved_owner() {
                return Err(SupervisionError::ApprovalRejected {
                    reason: herness_supervision::ApprovalRejection::OwnerNotApproved,
                });
            }
            Ok(herness_supervision::ApprovalBasis::InheritedOwner {
                owner: owner.clone(),
                source: *source,
                approved_at: now,
                expires_at: None,
            })
        }
        RequestActor::Model => Err(SupervisionError::ModelCannotApproveOrChange {
            action: "create completion conditions".to_owned(),
        }),
    }
}

/// Builds one bounded disclosure scope.
#[allow(clippy::too_many_arguments)]
pub fn build_consent(
    actor: &RequestActor,
    project: ProjectId,
    purpose: ProfilePurpose,
    origin: ProviderOrigin,
    data_kinds: BTreeSet<DisclosureDataKind>,
    targets: Vec<String>,
    target_version: TargetVersion,
    now: Timestamp,
) -> Result<DisclosureConsent, SupervisionError> {
    match actor {
        RequestActor::Human => {}
        RequestActor::ApprovedOwner { .. } => {
            return Err(SupervisionError::ApprovalRejected {
                reason: herness_supervision::ApprovalRejection::ActorMismatch,
            });
        }
        RequestActor::Model => {
            return Err(SupervisionError::ModelCannotApproveOrChange {
                action: "grant disclosure consent".to_owned(),
            });
        }
    }
    let scope = DisclosureScope::new(purpose, data_kinds, targets, target_version)?;
    DisclosureConsent::grant(
        ApprovalActor::Human,
        ConsentId::new(project),
        origin,
        scope,
        now,
    )
}

/// Extracts the granted target version, if the consent is usable.
pub fn consent_target_version(consent: &DisclosureConsent) -> Option<TargetVersion> {
    matches!(consent.state(), ConsentState::Granted { .. })
        .then_some(consent.target_scope_version())
}

/// Converts a connection model name into a `ModelId`.
pub fn model_id(model: &str) -> Result<ModelId, SupervisionError> {
    ModelId::new(model).map_err(|error| SupervisionError::InvalidValue {
        field: "profile.model".to_owned(),
        detail: core_error(error),
    })
}

fn core_error(error: CoreError) -> String {
    error.to_string()
}

/// Child agent and session for a plan.
pub const fn plan_child(plan: &StoredPlan) -> (AgentId, SessionId) {
    (plan.child.agent_id, plan.child.session_id)
}
