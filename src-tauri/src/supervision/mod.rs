//! Library-level H2 supervision composition for the desktop host.
//!
//! This module is the only place that connects the H2 supervisor to the real
//! H1 runtime, the one SQLite store, the durable budget ledger, the
//! per-purpose profile/consent registry, and the real required-check gateway.
//! It contains no Tauri window types and is exercised directly by the
//! `herness-supervision-tests` desktop suite.

pub mod assessment;
pub mod checks;
pub mod gate;
pub mod permission;
pub mod plan;
pub mod runtime;
pub mod store;
pub mod workspace;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use herness_core::{ProjectId, Timestamp};
use herness_supervision::budget::ledger::{BudgetClockPort, BudgetLedger};
use herness_supervision::operations::{
    HumanOperation, OperationPorts, OwnerSupersessionRequest, SupervisionChange,
    SupervisionOperationRequest, ensure_owner_supersedable, execute_operation,
    execute_owner_supersession,
};
use herness_supervision::owner_launch::{
    HostOwnerAuthority, OwnerApprovalRegistryPort, OwnerLaunchBinding, authorize_owner_launch,
};
use herness_supervision::ports::{
    BudgetStorePort, ClockPort, EvidenceStorePort, SupervisionStorePort,
};
use herness_supervision::recovery::RecoveryService;
use herness_supervision::supervisor::{
    ConditionAssessmentPort, OwnerNotificationPort, RequiredCheckPort, Supervisor,
    SupervisorNotification, SupervisorPorts, TickOutcome, TickRequest,
};
use herness_supervision::{
    ApprovalActor, ApprovalBasis, BudgetUsage, ConditionApproval, ConditionVersion,
    ConsentBinding, ConsentState, DisclosureDataKind, HumanAction, ProfileBinding, ProfilePurpose,
    ProviderOrigin, SupervisionCommand, SupervisionError, SupervisionId, SupervisionRecord,
    SupervisionRequestId, SupervisionState, TargetReadSet, TargetVersion, WorkPacket,
};
use serde::Serialize;

pub use plan::{
    BudgetInput, CheckInput, ConditionInput, ConfirmationKind, HumanConfirmation, ProjectConfig,
    RequestActor as PlanRequestActor, StoredPlan,
};

use assessment::{AssessmentHost, build_profile};
use checks::HostCheckPort;
use permission::PermissionRuntime;
use plan::{
    BudgetSnapshot, ConfigStore, PLAN_FORMAT_VERSION, PendingPlan, build_conditions, load_pending_plan,
    load_plan, plan_child, save_pending_plan, save_plan,
};
use runtime::DesktopSupervisionRuntime;
use store::{HostBudgetClock, HostClock, StoreHandle};

/// Shared tick interval for host-owned supervision progress.
pub const PUMP_INTERVAL: Duration = Duration::from_millis(200);

/// One queued owner notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationView {
    /// Stable notification ID.
    pub notification_id: String,
    /// Committed revision.
    pub revision: u64,
    /// State after the commit.
    pub state: String,
    /// Structured reason after the commit.
    pub reason: serde_json::Value,
    /// Conditions still unmet.
    pub unmet_conditions: Vec<String>,
    /// When the notification was created.
    pub observed_at: Timestamp,
}

/// One profile/consent status shown for a purpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PurposeStatusView {
    /// Purpose label.
    pub purpose: String,
    /// Whether any profile/consent is configured.
    pub configured: bool,
    /// Whether the profile passed a real acceptance step.
    pub verified: bool,
    /// Profile identifier.
    pub profile_id: Option<String>,
    /// Provider label.
    pub provider: Option<String>,
    /// Connection identifier.
    pub connection: Option<String>,
    /// Model alias.
    pub model: Option<String>,
    /// Consent state (`granted`/`revoked`/`unset`).
    pub consent_state: String,
    /// Consent version.
    pub consent_version: Option<u64>,
    /// Provider origin.
    pub origin: Option<String>,
    /// Approved data kinds.
    pub data_kinds: Vec<String>,
    /// Approved target scope.
    pub targets: Vec<String>,
    /// Approved target version.
    pub target_scope_version: Option<u64>,
}

/// One condition with its checks and approval state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConditionView {
    /// Condition identifier.
    pub condition_id: String,
    /// Title.
    pub title: String,
    /// Rubric.
    pub rubric: String,
    /// Required checks.
    pub checks: Vec<CheckView>,
    /// Whether the exact set is approved.
    pub approved: bool,
}

/// One required check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckView {
    /// Check identifier.
    pub check_id: String,
    /// Exact operation text.
    pub operation: String,
    /// Description.
    pub description: String,
}

/// One bounded budget view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetView {
    /// Policy version.
    pub policy_version: u64,
    /// Cumulative active seconds.
    pub active_seconds: u64,
    /// Additional runs.
    pub additional_runs: u32,
    /// Money cap in micro-dollars.
    pub money_limit_micros: Option<u64>,
    /// Price version when a cap exists.
    pub price_version: Option<String>,
    /// Effective usage.
    pub usage: BudgetUsage,
    /// Remaining active seconds.
    pub remaining_active_seconds: u64,
    /// Number of unresolved money charges.
    pub unresolved_charges: usize,
}

/// One evidence summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceView {
    /// Evidence identifier.
    pub evidence_id: String,
    /// Check identifier.
    pub check_id: Option<String>,
    /// Condition identifier.
    pub condition_id: Option<String>,
    /// Result status.
    pub status: String,
    /// Exact operation.
    pub operation: String,
    /// Observed result detail.
    pub outcome: String,
    /// Acquisition sequence.
    pub sequence: u64,
    /// Observation time.
    pub observed_at: Timestamp,
}

/// One recovery summary. Every field is read-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryView {
    /// Current stored revision.
    pub revision: u64,
    /// Stored state.
    pub state: String,
    /// Structured stored reason.
    pub reason: serde_json::Value,
    /// Disposition label.
    pub disposition: String,
    /// Whether an explicit resume/reassess may proceed.
    pub resumable: bool,
    /// Unresolved request attempts.
    pub unresolved_requests: Vec<serde_json::Value>,
    /// Terminal observations kept only as history.
    pub history_only_requests: Vec<serde_json::Value>,
    /// Unresolved H1 operations.
    pub unresolved_operations: Vec<serde_json::Value>,
    /// Managed processes.
    pub managed_processes: Vec<serde_json::Value>,
    /// Checkpoint state.
    pub checkpoint: String,
    /// H1 process/restored mode.
    pub recovery_mode: Option<String>,
    /// Budget facts.
    pub budget: serde_json::Value,
    /// Version mismatches.
    pub version_mismatches: Vec<serde_json::Value>,
    /// Block reasons.
    pub block_reasons: Vec<serde_json::Value>,
    /// Required human actions.
    pub required_actions: Vec<String>,
    /// Whether a stored completion is related to newer content.
    pub stale_completion: bool,
    /// Read-only side-effect counters.
    pub side_effects: serde_json::Value,
    /// Whether a stale-completion notification was delivered.
    pub notified: bool,
}

/// Complete non-secret view of one supervision target.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupervisionView {
    /// Project.
    pub project_id: ProjectId,
    /// Supervision target.
    pub supervision_id: SupervisionId,
    /// Current revision.
    pub revision: u64,
    /// State label.
    pub state: String,
    /// Structured reason.
    pub reason: serde_json::Value,
    /// Fixed condition version.
    pub condition_version: u64,
    /// Fixed target version.
    pub target_version: u64,
    /// Fixed profile binding.
    pub profile: ProfileBinding,
    /// Fixed consent binding.
    pub consent: ConsentBinding,
    /// Conditions and checks.
    pub conditions: Vec<ConditionView>,
    /// Conditions not currently met.
    pub unmet_conditions: Vec<String>,
    /// Runs in start order.
    pub run_group: Vec<String>,
    /// Applied decision count.
    pub applied_decisions: usize,
    /// History-only decision count.
    pub invalidated_decisions: usize,
    /// Completion snapshot, if completed.
    pub completion: Option<serde_json::Value>,
    /// Related-input stale marker, if any.
    pub completion_stale: Option<serde_json::Value>,
    /// Budget view.
    pub budget: Option<BudgetView>,
    /// Evidence summaries.
    pub evidence: Vec<EvidenceView>,
    /// Per-purpose profile and consent statuses.
    pub purposes: Vec<PurposeStatusView>,
    /// Queued owner notifications for this target.
    pub notifications: Vec<NotificationView>,
    /// Whether the durable host plan is available and matches the record.
    pub plan_available: bool,
    /// Pending assessment request metadata, never hidden reasoning.
    pub pending_assessment: Option<serde_json::Value>,
}

/// Create request from a trusted human operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSupervisionRequest {
    /// Project that owns the child.
    pub project: ProjectId,
    /// Connection used by the child agent.
    pub connection: herness_core::ConnectionId,
    /// Initial instruction for the first run.
    pub instructions: String,
    /// Human-confirmed conditions.
    pub conditions: Vec<ConditionInput>,
    /// Bounded read set.
    pub read_set: Vec<String>,
    /// Bounded write paths.
    #[serde(default)]
    pub write_paths: Vec<String>,
    /// Whether shell tools are inside the execution scope.
    #[serde(default)]
    pub allow_shell: bool,
    /// Initial condition version.
    #[serde(default)]
    pub condition_version: Option<u64>,
    /// Target version.
    #[serde(default)]
    pub target_version: Option<u64>,
    /// Finite budget.
    #[serde(default)]
    pub budget: Option<BudgetInput>,
}

/// Explicit change request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeSupervisionRequest {
    /// New conditions, when changed.
    #[serde(default)]
    pub conditions: Option<Vec<ConditionInput>>,
    /// New condition version, required with conditions.
    #[serde(default)]
    pub condition_version: Option<u64>,
    /// Purpose whose configured profile should be adopted.
    #[serde(default)]
    pub profile_purpose: Option<ProfilePurpose>,
    /// Purpose whose configured consent should be adopted.
    #[serde(default)]
    pub consent_purpose: Option<ProfilePurpose>,
    /// New finite budget policy.
    #[serde(default)]
    pub budget: Option<BudgetInput>,
}

/// Host-only approved-owner generation replacement request.
///
/// This is not an IPC payload: the entry point also requires a
/// [`HostOwnerAuthority`] minted from the current owner registry, so a model or
/// a serializable owner kind alone cannot invoke it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupersedeSupervisionRequest {
    /// Host-owned idempotent request ID.
    pub request_id: SupervisionRequestId,
    /// Target whose generation is replaced.
    pub supervision_id: SupervisionId,
    /// Revision the owner last observed.
    pub expected_revision: u64,
    /// Strictly newer approved target version.
    pub target_version: TargetVersion,
    /// Replacement condition inputs when the approved conditions changed.
    pub conditions: Option<Vec<ConditionInput>>,
    /// Replacement condition version, required with `conditions`.
    pub condition_version: Option<u64>,
    /// Purpose whose configured profile should be adopted.
    pub profile_purpose: Option<ProfilePurpose>,
    /// Purpose whose configured consent should be adopted.
    pub consent_purpose: Option<ProfilePurpose>,
    /// Replacement finite budget policy when it legitimately changed.
    pub budget: Option<BudgetInput>,
    /// Current H3/H4-owned settings or approval version.
    pub settings_version: u64,
    /// Current H3/H4 job identity.
    pub job_id: String,
}

/// One host-owned supervision composition.
pub struct SupervisionHost {
    store: StoreHandle,
    plans: runtime::PlanMap,
    config: ConfigStore,
    connections: AssessmentHost,
    assessment: Box<dyn ConditionAssessmentPort + Send>,
    checks: CheckMode,
    permission: PermissionRuntime,
    active: Mutex<BTreeSet<(ProjectId, SupervisionId)>>,
    last_tick: Mutex<BTreeMap<(ProjectId, SupervisionId), Instant>>,
    restored: Mutex<BTreeSet<(ProjectId, SupervisionId)>>,
    notifications: Arc<Mutex<VecDeque<NotificationView>>>,
    clock: HostClock,
}

pub(crate) enum CheckMode {
    Real,
    Injected(Box<dyn RequiredCheckPort + Send>),
}

/// One replacement plan, its exact contract, and the registry binding it needs.
struct BuiltSupersession {
    plan: StoredPlan,
    contract: herness_supervision::SupervisionContract,
    binding: OwnerLaunchBinding,
}

impl SupervisionHost {
    /// Creates the production composition.
    pub fn new(
        store: StoreHandle,
        connections: AssessmentHost,
        assessment: Box<dyn ConditionAssessmentPort + Send>,
    ) -> Self {
        let permission = PermissionRuntime::new(store.clone(), connections.clone());
        Self::with_config(
            store,
            ConfigStore::new(),
            connections,
            assessment,
            CheckMode::Real,
            permission,
        )
    }

    /// Creates a test composition with an injected required-check port.
    pub fn with_injected_checks(
        store: StoreHandle,
        connections: AssessmentHost,
        assessment: Box<dyn ConditionAssessmentPort + Send>,
        checks: Box<dyn RequiredCheckPort + Send>,
    ) -> Self {
        let permission = PermissionRuntime::new(store.clone(), connections.clone());
        Self::with_config(
            store,
            ConfigStore::new(),
            connections,
            assessment,
            CheckMode::Injected(checks),
            permission,
        )
    }

    /// Creates a composition with an explicitly shared per-project config.
    pub(crate) fn with_config(
        store: StoreHandle,
        config: ConfigStore,
        connections: AssessmentHost,
        assessment: Box<dyn ConditionAssessmentPort + Send>,
        checks: CheckMode,
        permission: PermissionRuntime,
    ) -> Self {
        Self {
            store,
            plans: Arc::new(Mutex::new(BTreeMap::new())),
            config,
            connections,
            assessment,
            checks,
            permission,
            active: Mutex::new(BTreeSet::new()),
            last_tick: Mutex::new(BTreeMap::new()),
            restored: Mutex::new(BTreeSet::new()),
            notifications: Arc::new(Mutex::new(VecDeque::new())),
            clock: HostClock,
        }
    }

    /// Production constructor with the evaluator shared with H1.
    pub(crate) fn with_permission(
        store: StoreHandle,
        config: ConfigStore,
        connections: AssessmentHost,
        assessment: Box<dyn ConditionAssessmentPort + Send>,
        checks: CheckMode,
        permission: PermissionRuntime,
    ) -> Self {
        Self::with_config(store, config, connections, assessment, checks, permission)
    }

    /// Test-only composition with an explicit config and check boundary.
    ///
    /// This does not create a Tauri window or a provider transport. It is
    /// public so the black-box desktop test can share the real store and
    /// recovery facts with scripted H1 boundaries.
    pub fn with_config_for_test(
        store: StoreHandle,
        config: ConfigStore,
        connections: AssessmentHost,
        assessment: Box<dyn ConditionAssessmentPort + Send>,
        checks: Box<dyn RequiredCheckPort + Send>,
    ) -> Self {
        let permission = PermissionRuntime::new(store.clone(), connections.clone());
        Self::with_config(
            store,
            config,
            connections,
            assessment,
            CheckMode::Injected(checks),
            permission,
        )
    }

    /// Shared durable plan map used by the runtime adapter and tests.
    pub fn plans(&self) -> runtime::PlanMap {
        Arc::clone(&self.plans)
    }

    /// Shared configuration registry.
    pub fn config(&self) -> ConfigStore {
        self.config.clone()
    }

    /// Shared dynamic permission evaluator installed into H1.
    pub fn permission(&self) -> &PermissionRuntime {
        &self.permission
    }

    /// Whether any project has a verified permission profile and consent.
    pub fn permission_available(&self) -> bool {
        self.permission.available()
    }

    /// Whether one project has a verified permission profile and consent.
    pub fn permission_available_for(&self, project: ProjectId) -> bool {
        self.permission.available_for(project)
    }

    /// Mints a host-owned human confirmation. Only the trusted command layer
    /// calls this after verifying the main window source.
    pub fn confirm(&self, kind: ConfirmationKind) -> HumanConfirmation {
        HumanConfirmation::new(kind)
    }

    fn require_confirmation(
        &self,
        actor: &plan::RequestActor,
        confirmation: Option<HumanConfirmation>,
        kind: ConfirmationKind,
    ) -> Result<(), SupervisionError> {
        match actor {
            plan::RequestActor::Human => {
                let confirmation = confirmation.ok_or(SupervisionError::Unsupported {
                    feature: "human confirmation is required".to_owned(),
                })?;
                if confirmation.kind() != kind {
                    return Err(SupervisionError::Unsupported {
                        feature: "human confirmation does not match the operation".to_owned(),
                    });
                }
                Ok(())
            }
            plan::RequestActor::ApprovedOwner { owner, .. } => {
                if !owner.is_approved_owner() {
                    return Err(SupervisionError::ApprovalRejected {
                        reason: herness_supervision::ApprovalRejection::OwnerNotApproved,
                    });
                }
                Ok(())
            }
            plan::RequestActor::Model => Err(SupervisionError::ModelCannotApproveOrChange {
                action: "perform a supervision operation".to_owned(),
            }),
        }
    }

    /// Restores durable plans and per-project profile/consent configuration.
    pub fn restore(&self, projects: &[ProjectId]) {
        for project in projects {
            self.config.restore(&self.store, *project);
            self.permission.refresh(&self.config, *project);
            let records = self
                .store
                .lock()
                .supervision_records_for_project(project)
                .unwrap_or_default();
            for record in records {
                // Restore only reloads durable state. A target loaded by this
                // process is never started automatically; an explicit human
                // start (or a fresh owner launch after a new creation) may
                // proceed.
                self.set_restored(*project, record.supervision_id(), true);
                if let Err(error) = self.promote_pending_plan(*project, record.supervision_id()) {
                    eprintln!(
                        "SUPERVISION_PENDING_PLAN_ERROR: {project} {}: {error}",
                        record.supervision_id()
                    );
                }
                match load_plan(&self.store, *project, record.supervision_id()) {
                    Ok(Some(plan)) => {
                        self.plans
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .insert((*project, record.supervision_id()), plan);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        // Restore never fabricates a plan. A legacy or damaged
                        // record stays unavailable until a human recreates it;
                        // start/continue/resume surface the explicit error.
                        eprintln!(
                            "SUPERVISION_PLAN_RESTORE_ERROR: {project} {}: {error}",
                            record.supervision_id()
                        );
                    }
                }
            }
        }
    }

    /// Creates one supervision target from human-confirmed conditions.
    pub fn create(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        actor: plan::RequestActor,
        request: CreateSupervisionRequest,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<SupervisionView, SupervisionError> {
        self.require_confirmation(&actor, confirmation, ConfirmationKind::Create)?;
        if request.instructions.trim().is_empty() {
            return Err(SupervisionError::InvalidValue {
                field: "instructions".to_owned(),
                detail: "the first instruction must not be empty".to_owned(),
            });
        }
        let project = request.project;
        let _ = runtime.project_path(project)?;
        let config = self.config.get(project);
        let Some(profile) = config.profile(ProfilePurpose::Completion) else {
            return Err(SupervisionError::ProfileUnavailable {
                reason: herness_supervision::ProfileUnavailable::Unset {
                    purpose: ProfilePurpose::Completion,
                },
            });
        };
        let Some(consent) = config.consent(ProfilePurpose::Completion) else {
            return Err(SupervisionError::ConsentBlocked {
                reason: herness_supervision::ConsentBlock::Revoked,
            });
        };
        let target_version = TargetVersion::new(request.target_version.unwrap_or(1))?;
        if consent.target_scope_version() != target_version {
            return Err(SupervisionError::ConsentBlocked {
                reason: herness_supervision::ConsentBlock::TargetScopeChanged,
            });
        }
        let expected_origin = self.connections.origin_for(profile.profile.connection())?;
        if consent.origin() != &expected_origin {
            return Err(SupervisionError::ConsentBlocked {
                reason: herness_supervision::ConsentBlock::DifferentOrigin,
            });
        }
        if !consent
            .scope()
            .data_kinds()
            .contains(&DisclosureDataKind::Text)
        {
            return Err(SupervisionError::ConsentBlocked {
                reason: herness_supervision::ConsentBlock::ScopeExpanded {
                    added: vec![DisclosureDataKind::Text],
                },
            });
        }
        let condition_version = ConditionVersion::new(request.condition_version.unwrap_or(1))?;
        let now = self.clock.now();
        let conditions =
            build_conditions(project, condition_version, &actor, &request.conditions, now)?;
        let execution_scope = herness_supervision::ExecutionScope::new(
            project,
            request.read_set.clone(),
            request.write_paths.clone(),
            request.allow_shell,
        )?;
        let workspace = workspace::ProjectWorkspace::new(runtime.project_path(project)?);
        let manifest = herness_supervision::freshness::capture_manifest(
            &workspace,
            project,
            target_version,
            herness_supervision::TargetReadSet::Declared(request.read_set.clone()),
        )?;
        let evidence_target = manifest.target_scope()?;
        let budget = match request.budget {
            Some(budget) => budget.policy()?,
            None => herness_supervision::BudgetPolicy::h2_default(),
        };
        let child = runtime.create_child(project, request.connection, &execution_scope)?;
        let supervision_id = SupervisionId::new(project);
        let owner = match &actor {
            plan::RequestActor::Human => herness_supervision::OwnerRef::new(
                herness_supervision::OwnerKind::Human,
                "trusted-main",
            )?,
            plan::RequestActor::ApprovedOwner { owner, .. } => owner.clone(),
            plan::RequestActor::Model => {
                return Err(SupervisionError::ModelCannotApproveOrChange {
                    action: "create a supervision target".to_owned(),
                });
            }
        };
        let subject = herness_supervision::SupervisionSubject::new(
            project,
            supervision_id,
            child.agent_id,
            child.session_id,
            owner.clone(),
        )?;
        let run_group =
            herness_supervision::RunGroup::new(herness_supervision::RunGroupId::new(project));
        let packet = WorkPacket::new(
            1,
            &request.instructions,
            project,
            &evidence_target,
            execution_scope.clone(),
            conditions.condition_version(),
            profile.profile.binding(),
            consent.binding(),
            1,
            budget.clone(),
        )?;
        let contract = herness_supervision::SupervisionContract::new(
            actor.approval_actor(),
            subject,
            execution_scope.clone(),
            run_group,
            conditions.clone(),
            evidence_target.clone(),
            &profile.profile,
            consent,
            budget.clone(),
            packet.clone(),
            now,
        )?;
        let plan = StoredPlan {
            format_version: PLAN_FORMAT_VERSION,
            actor: actor.clone(),
            owner,
            child,
            execution_scope,
            conditions,
            evidence_target,
            profile: profile.profile.clone(),
            consent: consent.clone(),
            budget: BudgetSnapshot::from_policy(&budget),
            budget_version: 1,
            packet,
            contract: contract.clone(),
        };
        save_plan(&self.store, project, supervision_id, &plan)?;
        let record = SupervisionRecord::new(&contract);
        self.store
            .compare_and_swap(project, supervision_id, None, &record)?;
        self.plans
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert((project, supervision_id), plan);
        self.set_restored(project, supervision_id, false);
        self.view(project, supervision_id)
    }

    /// Configures one purpose-specific profile. New profiles are unverified.
    pub fn configure_profile(
        &self,
        actor: plan::RequestActor,
        project: ProjectId,
        purpose: ProfilePurpose,
        connection: herness_core::ConnectionId,
        model: &str,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<PurposeStatusView, SupervisionError> {
        self.require_confirmation(&actor, confirmation, ConfirmationKind::Profile)?;
        if !matches!(actor, plan::RequestActor::Human) {
            return Err(SupervisionError::ModelCannotApproveOrChange {
                action: "configure an assessment profile".to_owned(),
            });
        }
        let configured = build_profile(&self.connections, project, purpose, connection, model)?;
        let mut config = self.config.get(project);
        config.set_profile(configured.profile.clone(), false);
        self.config.set(project, config);
        self.config.persist(&self.store, project)?;
        self.permission.refresh(&self.config, project);
        Ok(self.purpose_status(project, purpose))
    }

    /// Grants per-purpose disclosure consent after an explicit human action.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_consent(
        &self,
        actor: plan::RequestActor,
        project: ProjectId,
        purpose: ProfilePurpose,
        origin: ProviderOrigin,
        data_kinds: BTreeSet<DisclosureDataKind>,
        targets: Vec<String>,
        target_version: TargetVersion,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<PurposeStatusView, SupervisionError> {
        self.require_confirmation(&actor, confirmation, ConfirmationKind::Consent)?;
        let mut config = self.config.get(project);
        if let Some(profile) = config.profile(purpose) {
            let expected = self.connections.origin_for(profile.profile.connection())?;
            if expected != origin {
                return Err(SupervisionError::ConsentBlocked {
                    reason: herness_supervision::ConsentBlock::DifferentOrigin,
                });
            }
        }
        let consent = plan::build_consent(
            &actor,
            project,
            purpose,
            origin,
            data_kinds,
            targets,
            target_version,
            self.clock.now(),
        )?;
        config.set_consent(consent);
        self.config.set(project, config);
        self.config.persist(&self.store, project)?;
        self.permission.refresh(&self.config, project);
        Ok(self.purpose_status(project, purpose))
    }

    /// Host-only acceptance marker for a real, separately verified profile.
    ///
    /// This is deliberately not an IPC command. Task 17/18 acceptance can call
    /// it after recording real evidence; this build leaves every new profile
    /// unverified.
    pub fn mark_profile_verified(
        &self,
        project: ProjectId,
        purpose: ProfilePurpose,
        verified: bool,
    ) -> Result<PurposeStatusView, SupervisionError> {
        let mut config = self.config.get(project);
        let Some(existing) = config.profile(purpose).cloned() else {
            return Err(SupervisionError::ProfileUnavailable {
                reason: herness_supervision::ProfileUnavailable::Unset { purpose },
            });
        };
        config.set_profile(existing.profile, verified);
        self.config.set(project, config);
        self.config.persist(&self.store, project)?;
        self.permission.refresh(&self.config, project);
        Ok(self.purpose_status(project, purpose))
    }

    /// Revokes one purpose-specific consent. Already sent content is not
    /// recalled.
    pub fn revoke_consent(
        &self,
        actor: plan::RequestActor,
        project: ProjectId,
        purpose: ProfilePurpose,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<PurposeStatusView, SupervisionError> {
        self.require_confirmation(&actor, confirmation, ConfirmationKind::Consent)?;
        if !matches!(actor, plan::RequestActor::Human) {
            return Err(SupervisionError::ModelCannotApproveOrChange {
                action: "revoke disclosure consent".to_owned(),
            });
        }
        let mut config = self.config.get(project);
        let Some(consent) = config.consent(purpose).cloned() else {
            return Err(SupervisionError::ConsentBlocked {
                reason: herness_supervision::ConsentBlock::Revoked,
            });
        };
        let revoked =
            consent.revoke(herness_supervision::ApprovalActor::Human, self.clock.now())?;
        config.set_consent(revoked);
        self.config.set(project, config);
        self.config.persist(&self.store, project)?;
        self.permission.refresh(&self.config, project);
        Ok(self.purpose_status(project, purpose))
    }

    /// Explicitly starts the first run of a ready target.
    pub fn start(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        project: ProjectId,
        supervision: SupervisionId,
        request_id: SupervisionRequestId,
        expected_revision: u64,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<SupervisionView, SupervisionError> {
        self.require_human_confirmation(confirmation, ConfirmationKind::Start)?;
        if let Some(recorded) = self.store.command_result(request_id)? {
            if recorded.supervision_id() != supervision
                || recorded.command() != SupervisionCommand::Reassess
            {
                return Err(SupervisionError::DuplicateRequestConflict {
                    request: request_id.to_string(),
                    recorded: recorded.command().as_str().to_owned(),
                    supplied: SupervisionCommand::Start.as_str().to_owned(),
                });
            }
            return self.view(project, supervision);
        }
        let record = self.load(project, supervision)?;
        if record.revision() != expected_revision {
            return Err(SupervisionError::RevisionConflict {
                expected: expected_revision,
                found: record.revision(),
            });
        }
        if record.state() != SupervisionState::Ready {
            return Err(SupervisionError::InvalidValue {
                field: "state".to_owned(),
                detail: format!("start requires ready, found {}", record.state().as_str()),
            });
        }
        self.set_active(project, supervision, true);
        if let Err(error) = self.tick_one(runtime, project, supervision, request_id) {
            self.set_active(project, supervision, false);
            return Err(error);
        }
        self.set_restored(project, supervision, false);
        self.view(project, supervision)
    }

    /// Builds the exact target binding an H3/H4 owner must have approved before
    /// the automatic first start.
    ///
    /// The opaque settings version and job ID come from the owner phase. All
    /// other constraints are read from the stored approved contract, so the
    /// owner cannot request a weaker condition set, scope, profile, consent, or
    /// budget than H2 recorded.
    pub fn owner_launch_binding(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
        settings_version: u64,
        job_id: &str,
    ) -> Result<OwnerLaunchBinding, SupervisionError> {
        let record = self.load(project, supervision)?;
        let plan = self.plan(project, supervision)?;
        let contract = plan.contract(&record, self.clock.now())?;
        OwnerLaunchBinding::from_contract(
            &contract,
            plan.budget_version,
            settings_version,
            job_id,
        )
    }

    /// Starts the first run of a ready target using a host-minted approved-owner
    /// authority.
    ///
    /// This path never accepts a `RequestActor` or `OwnerKind`: the
    /// non-serializable [`HostOwnerAuthority`] can only come from
    /// `authorize_owner_launch` after the current registry matched. A human
    /// start still requires `HumanConfirmation`; a target loaded by `restore`,
    /// an already-started target, and any non-ready target are refused without
    /// a run.
    pub fn start_approved_owner(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        authority: HostOwnerAuthority,
        request_id: SupervisionRequestId,
        expected_revision: u64,
    ) -> Result<SupervisionView, SupervisionError> {
        let project = authority.project_id();
        let supervision = authority.supervision_id();
        request_id.validate_in(project)?;
        // A duplicate host request returns the already recorded result even if
        // the target has since moved past ready. It never starts a second run.
        if let Some(recorded) = self.store.command_result(request_id)? {
            if recorded.project_id() != project
                || recorded.supervision_id() != supervision
                || recorded.command() != SupervisionCommand::Reassess
            {
                return Err(SupervisionError::DuplicateRequestConflict {
                    request: request_id.to_string(),
                    recorded: recorded.command().as_str().to_owned(),
                    supplied: SupervisionCommand::Start.as_str().to_owned(),
                });
            }
            return self.view(project, supervision);
        }
        let record = self.load(project, supervision)?;
        if record.revision() != expected_revision {
            return Err(SupervisionError::RevisionConflict {
                expected: expected_revision,
                found: record.revision(),
            });
        }
        if self.is_restored(project, supervision) {
            return Err(SupervisionError::OwnerLaunchRejected {
                reason: herness_supervision::OwnerLaunchRejection::RestoredTarget,
            });
        }
        if !record.run_group().runs().is_empty() || record.supervisor().current_run().is_some() {
            return Err(SupervisionError::OwnerLaunchRejected {
                reason: herness_supervision::OwnerLaunchRejection::AlreadyStarted,
            });
        }
        if record.state() != SupervisionState::Ready {
            return Err(SupervisionError::OwnerLaunchRejected {
                reason: herness_supervision::OwnerLaunchRejection::TargetNotReady {
                    found: record.state(),
                },
            });
        }
        let plan = self.plan(project, supervision)?;
        let contract = plan.contract(&record, self.clock.now())?;
        authority.ensure_contract_binding(&contract, plan.budget_version)?;
        self.set_active(project, supervision, true);
        if let Err(error) = self.tick_one(runtime, project, supervision, request_id) {
            self.set_active(project, supervision, false);
            return Err(error);
        }
        self.set_restored(project, supervision, false);
        self.view(project, supervision)
    }

    /// Builds the exact replacement binding an H3/H4 owner must currently have
    /// approved before replacing a stale generation.
    ///
    /// This is the request side only. It does not mutate the target, and the
    /// returned value is not an authority.
    pub fn owner_supersession_binding(
        &self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        request: &SupersedeSupervisionRequest,
    ) -> Result<OwnerLaunchBinding, SupervisionError> {
        let project = request.request_id.project_id();
        request.request_id.validate_in(project)?;
        let record = self.load(project, request.supervision_id)?;
        let plan = self.plan(project, request.supervision_id)?;
        Ok(self
            .build_supersession_plan(runtime, &record, &plan, request)?
            .binding)
    }

    /// Replaces a stale generation in the same target using a host-minted
    /// approved-owner authority.
    ///
    /// The current run is stopped and confirmed before the target version,
    /// work packet, approval basis, and invalidation history change. The
    /// record, command result, and budget ledger are preserved; the method
    /// starts at most one new run in the same target. Every human stop, human
    /// wait, stagnation, budget, recovery, unconfirmed-stop, cancel, and
    /// completed latch is refused without a mutation. A target loaded by
    /// `restore` is refused so a restart cannot auto-resume authoring.
    pub fn supersede_approved_owner(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        registry: &dyn OwnerApprovalRegistryPort,
        authority: HostOwnerAuthority,
        request: SupersedeSupervisionRequest,
    ) -> Result<SupervisionView, SupervisionError> {
        let project = request.request_id.project_id();
        let supervision = request.supervision_id;
        request.request_id.validate_in(project)?;
        if authority.project_id() != project || authority.supervision_id() != supervision {
            return Err(SupervisionError::OwnerSupersessionRejected {
                reason: herness_supervision::OwnerSupersessionRejection::TargetMismatch,
            });
        }
        // A crash after the atomic record/command commit but before the plan
        // promotion is repaired before any duplicate is answered.
        self.promote_pending_plan(project, supervision)?;
        // A duplicate request returns its recorded result before any load,
        // stop, budget change, snapshot capture, or second run.
        if let Some(recorded) = self.store.command_result(request.request_id)? {
            if recorded.project_id() != project
                || recorded.supervision_id() != supervision
                || recorded.command() != SupervisionCommand::Supersede
            {
                return Err(SupervisionError::DuplicateRequestConflict {
                    request: request.request_id.to_string(),
                    recorded: recorded.command().as_str().to_owned(),
                    supplied: SupervisionCommand::Supersede.as_str().to_owned(),
                });
            }
            return self.view(project, supervision);
        }
        if self.is_restored(project, supervision) {
            return Err(SupervisionError::OwnerSupersessionRejected {
                reason: herness_supervision::OwnerSupersessionRejection::RestoredTarget,
            });
        }
        let record = self.load(project, supervision)?;
        if record.revision() != request.expected_revision {
            return Err(SupervisionError::RevisionConflict {
                expected: request.expected_revision,
                found: record.revision(),
            });
        }
        let plan = self.plan(project, supervision)?;
        let now = self.clock.now();
        let current_contract = plan.contract(&record, now)?;
        // The host-only token proves the caller is still looking at the
        // approved current generation. The replacement is then checked again
        // against the current registry below.
        authority.ensure_contract_binding(&current_contract, plan.budget_version)?;
        ensure_owner_supersedable(&record)?;

        let built = self.build_supersession_plan(runtime, &record, &plan, &request)?;
        let new_authority = authorize_owner_launch(registry, &built.binding, now)?;
        new_authority.ensure_contract_binding(&built.contract, built.plan.budget_version)?;

        save_pending_plan(
            &self.store,
            project,
            supervision,
            &PendingPlan {
                record_revision: record.revision().saturating_add(1),
                request_id: request.request_id,
                plan: built.plan.clone(),
            },
        )?;

        let operation = OwnerSupersessionRequest::new(
            request.request_id,
            supervision,
            request.expected_revision,
            built.contract.clone(),
        )?;
        let mut ledger = self.ledger(project, supervision, &plan)?;
        let mut facts = self.store.clone();
        let result = execute_owner_supersession(
            OperationPorts {
                store: &mut facts,
                runtime,
                budget: &mut ledger,
                clock: &self.clock,
            },
            &current_contract,
            plan.budget_version,
            operation,
            new_authority,
        )?;
        if result.duplicate() {
            self.promote_pending_plan(project, supervision)?;
            return self.view(project, supervision);
        }
        self.promote_pending_plan(project, supervision)?;

        self.set_active(project, supervision, true);
        let request_id = SupervisionRequestId::new(project);
        if let Err(error) = self.tick_one(runtime, project, supervision, request_id) {
            self.set_active(project, supervision, false);
            return Err(error);
        }
        self.view(project, supervision)
    }

    /// Builds the replacement plan and the exact registry binding it needs.
    fn build_supersession_plan(
        &self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        record: &SupervisionRecord,
        current_plan: &StoredPlan,
        request: &SupersedeSupervisionRequest,
    ) -> Result<BuiltSupersession, SupervisionError> {
        let project = record.project_id();
        let (owner, source) = match &current_plan.actor {
            plan::RequestActor::ApprovedOwner { owner, source } => (owner.clone(), *source),
            _ => {
                return Err(SupervisionError::OwnerLaunchRejected {
                    reason: herness_supervision::OwnerLaunchRejection::OwnerNotApproved,
                });
            }
        };
        let now = self.clock.now();
        let conditions = match request.conditions.as_ref() {
            Some(inputs) => {
                let version = ConditionVersion::new(
                    request
                        .condition_version
                        .unwrap_or_else(|| record.condition_version().get().saturating_add(1)),
                )?;
                build_conditions(project, version, &current_plan.actor, inputs, now)?
            }
            None => {
                if request.condition_version.is_some() {
                    return Err(SupervisionError::InvalidValue {
                        field: "conditionVersion".to_owned(),
                        detail: "a condition version requires replacement condition inputs"
                            .to_owned(),
                    });
                }
                let mut set = current_plan.conditions.clone();
                let approval = ConditionApproval::new(
                    project,
                    ApprovalBasis::InheritedOwner {
                        owner: owner.clone(),
                        source,
                        approved_at: now,
                        expires_at: None,
                    },
                    set.condition_version(),
                    set.digest().clone(),
                )?;
                set.approve(
                    ApprovalActor::ApprovedOwner {
                        owner: owner.clone(),
                        source,
                    },
                    approval,
                    now,
                )?;
                set
            }
        };
        let config = self.config.get(project);
        let profile = match request.profile_purpose {
            Some(purpose) => config
                .profile(purpose)
                .map(|profile| profile.profile.clone())
                .ok_or(SupervisionError::ProfileUnavailable {
                    reason: herness_supervision::ProfileUnavailable::Unset { purpose },
                })?,
            None => current_plan.profile.clone(),
        };
        let consent = match request.consent_purpose {
            Some(purpose) => {
                let consent =
                    config
                        .consent(purpose)
                        .cloned()
                        .ok_or(SupervisionError::ConsentBlocked {
                            reason: herness_supervision::ConsentBlock::Revoked,
                        })?;
                consent.require_granted()?;
                consent
            }
            None => current_plan.consent.clone(),
        };
        let budget = match request.budget.as_ref() {
            Some(input) => input.policy()?,
            None => current_plan.budget.policy()?,
        };
        let budget_version = if request.budget.is_some() {
            current_plan.budget_version.saturating_add(1)
        } else {
            current_plan.budget_version
        };
        let workspace = workspace::ProjectWorkspace::new(runtime.project_path(project)?);
        let manifest = herness_supervision::freshness::capture_manifest(
            &workspace,
            project,
            request.target_version,
            TargetReadSet::Declared(current_plan.evidence_target.read_set().to_vec()),
        )?;
        let evidence_target = manifest.target_scope()?;

        let mut next = current_plan.clone();
        next.conditions = conditions;
        next.profile = profile;
        next.consent = consent;
        next.evidence_target = evidence_target;
        next.budget = BudgetSnapshot::from_policy(&budget);
        next.budget_version = budget_version;
        next.rebuild_contract(record, now)?;
        let binding = OwnerLaunchBinding::from_contract(
            &next.contract,
            next.budget_version,
            request.settings_version,
            &request.job_id,
        )?;
        Ok(BuiltSupersession {
            contract: next.contract.clone(),
            plan: next,
            binding,
        })
    }

    /// Promotes a staged replacement plan only when the exact `Supersede`
    /// command committed at the staged revision.
    ///
    /// A crash before that commit, or any other command at the same revision,
    /// leaves the canonical plan untouched. Promotion is idempotent.
    fn promote_pending_plan(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<bool, SupervisionError> {
        let pending = match load_pending_plan(&self.store, project, supervision) {
            Ok(Some(pending)) => pending,
            Ok(None) => return Ok(false),
            Err(error) => {
                eprintln!(
                    "SUPERVISION_PENDING_PLAN_ERROR: {project} {supervision}: {error}"
                );
                return Ok(false);
            }
        };
        let Some(record) = self.store.load(project, supervision)? else {
            return Ok(false);
        };
        if record.revision() != pending.record_revision {
            return Ok(false);
        }
        let Some(recorded) = self.store.command_result(pending.request_id)? else {
            return Ok(false);
        };
        if recorded.project_id() != project
            || recorded.supervision_id() != supervision
            || recorded.command() != SupervisionCommand::Supersede
            || recorded.revision() != pending.record_revision
        {
            return Ok(false);
        }
        save_plan(&self.store, project, supervision, &pending.plan)?;
        self.plans
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert((project, supervision), pending.plan);
        Ok(true)
    }

    /// Stops or cancels one target through the H1 cooperative stop path.
    pub fn stop(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        request: SupervisionOperationRequest,
        cancel: bool,
        expected_policy_version: u64,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<SupervisionView, SupervisionError> {
        self.require_human_confirmation(confirmation, ConfirmationKind::Stop)?;
        let project = request.project_id();
        let supervision = request.supervision_id();
        let plan = self.plan(project, supervision)?;
        let contract = plan.contract(&self.load(project, supervision)?, self.clock.now())?;
        let mut ledger = self.ledger(project, supervision, &plan)?;
        let mut facts = self.store.clone();
        let adapter = runtime;
        let result = execute_operation(
            OperationPorts {
                store: &mut facts,
                runtime: adapter,
                budget: &mut ledger,
                clock: &self.clock,
            },
            &contract,
            expected_policy_version,
            request,
        )?;
        self.set_active(project, supervision, false);
        if cancel {
            // Cancel is only a label on the recorded operation; the recorded
            // state and reason are authoritative.
            let _ = result;
        }
        self.view(project, supervision)
    }

    /// Resumes a stopped/waiting target after the recovery gate.
    pub fn resume(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        request: SupervisionOperationRequest,
        expected_policy_version: u64,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<SupervisionView, SupervisionError> {
        self.require_human_confirmation(confirmation, ConfirmationKind::Resume)?;
        let project = request.project_id();
        let supervision = request.supervision_id();
        let result = self.execute_human_operation(runtime, request, expected_policy_version)?;
        if result.duplicate() {
            return self.view(project, supervision);
        }
        self.set_active(project, supervision, true);
        let request_id = SupervisionRequestId::new(project);
        if let Err(error) = self.tick_one(runtime, project, supervision, request_id) {
            self.set_active(project, supervision, false);
            return Err(error);
        }
        self.view(project, supervision)
    }

    /// Reassesses from fresh or reused evidence without replaying an old run.
    pub fn reassess(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        request: SupervisionOperationRequest,
        expected_policy_version: u64,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<SupervisionView, SupervisionError> {
        self.require_human_confirmation(confirmation, ConfirmationKind::Reassess)?;
        let project = request.project_id();
        let supervision = request.supervision_id();
        let result = self.execute_human_operation(runtime, request, expected_policy_version)?;
        if result.duplicate() {
            return self.view(project, supervision);
        }
        self.set_active(project, supervision, true);
        let request_id = SupervisionRequestId::new(project);
        if let Err(error) = self.tick_one(runtime, project, supervision, request_id) {
            self.set_active(project, supervision, false);
            return Err(error);
        }
        self.view(project, supervision)
    }

    /// Changes approved conditions, profile, consent, or budget explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn change(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        project: ProjectId,
        supervision: SupervisionId,
        request_id: SupervisionRequestId,
        expected_revision: u64,
        actor: plan::RequestActor,
        change: ChangeSupervisionRequest,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<SupervisionView, SupervisionError> {
        self.require_confirmation(&actor, confirmation, ConfirmationKind::Change)?;
        let base = self.load(project, supervision)?;
        if base.revision() != expected_revision {
            return Err(SupervisionError::RevisionConflict {
                expected: expected_revision,
                found: base.revision(),
            });
        }
        let plan = self.plan(project, supervision)?;
        let now = self.clock.now();
        let config = self.config.get(project);

        let mut prospective = plan.clone();
        let mut changes: Vec<SupervisionChange> = Vec::new();
        if let Some(conditions) = change.conditions.as_ref() {
            let version = ConditionVersion::new(
                change
                    .condition_version
                    .unwrap_or_else(|| base.condition_version().get().saturating_add(1)),
            )?;
            let set = build_conditions(project, version, &actor, conditions, now)?;
            prospective.set_conditions(set.clone());
            changes.push(SupervisionChange::Conditions(set));
        }
        if let Some(purpose) = change.profile_purpose {
            let Some(profile) = config.profile(purpose) else {
                return Err(SupervisionError::ProfileUnavailable {
                    reason: herness_supervision::ProfileUnavailable::Unset { purpose },
                });
            };
            prospective.set_profile(profile.profile.clone());
            changes.push(SupervisionChange::Profile(profile.profile.binding()));
        }
        if let Some(purpose) = change.consent_purpose {
            let Some(consent) = config.consent(purpose).cloned() else {
                return Err(SupervisionError::ConsentBlocked {
                    reason: herness_supervision::ConsentBlock::Revoked,
                });
            };
            consent.require_granted()?;
            prospective.set_consent(consent.clone());
            changes.push(SupervisionChange::Consent(consent.binding()));
        }
        if let Some(budget) = change.budget.as_ref() {
            let policy = budget.policy()?;
            let version = plan.budget_version.saturating_add(1);
            prospective.set_budget(policy.clone(), version);
            changes.push(SupervisionChange::Budget {
                policy,
                policy_version: version,
            });
        }
        if changes.is_empty() {
            return Err(SupervisionError::InvalidValue {
                field: "change".to_owned(),
                detail: "no condition, profile, consent, or budget change was supplied".to_owned(),
            });
        }
        // Validate the complete prospective contract before any durable
        // mutation. This includes the current conditions approval, granted
        // consent, profile/consent purpose match, and target version binding.
        prospective.rebuild_contract(&base, now)?;

        let mut active_plan = plan;
        let mut current = base;
        let mut next_request = Some(request_id);
        for change in changes {
            let contract = active_plan.contract(&current, now)?;
            let mut ledger = self.ledger(project, supervision, &active_plan)?;
            let operation = SupervisionOperationRequest::new(
                next_request
                    .take()
                    .unwrap_or_else(|| SupervisionRequestId::new(project)),
                supervision,
                HumanOperation::Change(change.clone()),
                current.revision(),
            )?;
            let mut facts = self.store.clone();
            let result = execute_operation(
                OperationPorts {
                    store: &mut facts,
                    runtime,
                    budget: &mut ledger,
                    clock: &self.clock,
                },
                &contract,
                active_plan.budget_version,
                operation,
            )?;
            if result.duplicate() {
                return self.view(project, supervision);
            }
            let budget_changed = matches!(change, SupervisionChange::Budget { .. });
            match change {
                SupervisionChange::Conditions(set) => active_plan.set_conditions(set),
                SupervisionChange::Profile(binding) => {
                    let profile = config.profile(binding.purpose()).ok_or(
                        SupervisionError::ProfileUnavailable {
                            reason: herness_supervision::ProfileUnavailable::Unset {
                                purpose: binding.purpose(),
                            },
                        },
                    )?;
                    active_plan.set_profile(profile.profile.clone());
                }
                SupervisionChange::Consent(binding) => {
                    let consent = config.consent(binding.purpose()).cloned().ok_or(
                        SupervisionError::ConsentBlocked {
                            reason: herness_supervision::ConsentBlock::Revoked,
                        },
                    )?;
                    active_plan.set_consent(consent);
                }
                SupervisionChange::Budget {
                    policy,
                    policy_version,
                } => active_plan.set_budget(policy, policy_version),
                SupervisionChange::Target(_) => {
                    return Err(SupervisionError::Unsupported {
                        feature: "target changes are not exposed by this UI".to_owned(),
                    });
                }
            }
            current = self.load(project, supervision)?;
            active_plan.rebuild_contract(&current, now)?;
            save_plan(&self.store, project, supervision, &active_plan)?;
            self.plans
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert((project, supervision), active_plan.clone());
            if budget_changed {
                self.permission.invalidate_supervision(project, supervision);
            }
        }
        self.set_active(project, supervision, false);
        self.view(project, supervision)
    }
    fn execute_human_operation(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        request: SupervisionOperationRequest,
        expected_policy_version: u64,
    ) -> Result<herness_supervision::operations::OperationResult, SupervisionError> {
        let project = request.project_id();
        let supervision = request.supervision_id();
        let plan = self.plan(project, supervision)?;
        let contract = plan.contract(&self.load(project, supervision)?, self.clock.now())?;
        let mut ledger = self.ledger(project, supervision, &plan)?;
        let mut facts = self.store.clone();
        execute_operation(
            OperationPorts {
                store: &mut facts,
                runtime,
                budget: &mut ledger,
                clock: &self.clock,
            },
            &contract,
            expected_policy_version,
            request,
        )
    }

    /// Reads a saved view. Restore/reopen never starts or sends anything.
    pub fn get(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<SupervisionView, SupervisionError> {
        self.view(project, supervision)
    }

    /// Lists every saved target for a project.
    pub fn list(&self, project: ProjectId) -> Result<Vec<SupervisionView>, SupervisionError> {
        let records = self
            .store
            .lock()
            .supervision_records_for_project(&project)
            .map_err(|error| SupervisionError::StorageFailure {
                detail: error.to_string(),
            })?;
        records
            .into_iter()
            .map(|record| self.view(project, record.supervision_id()))
            .collect()
    }

    /// Reads the durable recovery report. This sends and starts nothing.
    pub fn recovery(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<RecoveryView, SupervisionError> {
        let record = self.load(project, supervision)?;
        let plan = self.plan(project, supervision)?;
        let contract = plan.contract(&record, self.clock.now())?;
        let mut ledger = self.ledger(project, supervision, &plan)?;
        let mut facts = self.store.clone();
        let report = RecoveryService::new(&mut facts, runtime, &mut ledger, &self.clock)
            .recover(&contract, plan.budget_version)?;
        Ok(recovery_view(&report))
    }

    /// Host-owned pump: advances only explicitly started/resumed targets, for
    /// every project, at a bounded interval.
    pub fn pump(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        projects: &[ProjectId],
    ) -> Result<usize, SupervisionError> {
        let keys = {
            let active = self
                .active
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            active
                .iter()
                .filter(|(project, _)| projects.contains(project))
                .copied()
                .collect::<Vec<_>>()
        };
        let mut advanced = 0;
        for (project, supervision) in keys {
            let last = self
                .last_tick
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&(project, supervision))
                .copied();
            if last.is_some_and(|last| last.elapsed() < PUMP_INTERVAL) {
                continue;
            }
            let record = match self.load(project, supervision) {
                Ok(record) => record,
                Err(_) => {
                    self.set_active(project, supervision, false);
                    continue;
                }
            };
            if matches!(
                record.state(),
                SupervisionState::WaitingHuman
                    | SupervisionState::Stopped
                    | SupervisionState::Failed
                    | SupervisionState::Cancelled
                    | SupervisionState::Completed
            ) {
                self.set_active(project, supervision, false);
                continue;
            }
            let request_id = SupervisionRequestId::new(project);
            match self.tick_one(runtime, project, supervision, request_id) {
                Ok(()) => {
                    advanced += 1;
                    self.last_tick
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert((project, supervision), Instant::now());
                }
                Err(error) => {
                    // A transient store/runtime failure is not progress. Keep
                    // the target active so the next bounded pump retries.
                    eprintln!("SUPERVISION_PUMP_ERROR: {project} {supervision}: {error}");
                }
            }
        }
        Ok(advanced)
    }

    fn tick_one(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        project: ProjectId,
        supervision: SupervisionId,
        event_id: SupervisionRequestId,
    ) -> Result<(), SupervisionError> {
        event_id.validate_in(project)?;
        let record = self.load(project, supervision)?;
        if matches!(
            record.state(),
            SupervisionState::WaitingHuman
                | SupervisionState::Stopped
                | SupervisionState::Failed
                | SupervisionState::Cancelled
                | SupervisionState::Completed
        ) {
            return Ok(());
        }
        let Some(plan) = self.stored_plan(project, supervision)? else {
            return self.force_waiting(runtime, &record, HumanAction::ReconcileRecovery);
        };
        let now = self.clock.now();
        if plan.conditions.require_approval(now).is_err() {
            return self.force_waiting(runtime, &record, HumanAction::ConfirmConditions);
        }
        if plan.consent.require_granted().is_err() {
            return self.force_waiting(runtime, &record, HumanAction::GrantDisclosureConsent);
        }
        if plan.consent.target_scope_version() != record.target_version() {
            return self.force_waiting(runtime, &record, HumanAction::GrantDisclosureConsent);
        }
        let live_consent = self
            .config
            .get(project)
            .consent(record.consent().purpose())
            .cloned();
        if live_consent.is_none_or(|consent| {
            consent.binding() != record.consent()
                || consent.target_scope_version() != record.target_version()
                || consent.require_granted().is_err()
        }) {
            return self.force_waiting(runtime, &record, HumanAction::GrantDisclosureConsent);
        }
        let contract = match plan.contract(&record, now) {
            Ok(contract) => contract,
            Err(_) => {
                return self.force_waiting(runtime, &record, HumanAction::ReconcileRecovery);
            }
        };
        let tick = TickRequest::new(event_id, contract)?;
        let mut store = self.store.clone();
        let mut evidence = self.store.clone();
        let mut ledger = self.ledger(project, supervision, &plan)?;
        let mut notifications = HostNotifications {
            queue: Arc::clone(&self.notifications),
        };
        let result = match &mut self.checks {
            CheckMode::Real => {
                let root = runtime.project_path(project)?;
                let (agent, session) = plan_child(&plan);
                let mut check_port = HostCheckPort::new(
                    self.store.clone(),
                    agent,
                    session,
                    root,
                    runtime.shared_policy(),
                    "supervision required check",
                );
                Supervisor::new(SupervisorPorts {
                    runtime,
                    checks: &mut check_port,
                    assessment: &mut *self.assessment,
                    evidence: &mut evidence,
                    store: &mut store,
                    budget: &mut ledger,
                    clock: &self.clock,
                    notifications: &mut notifications,
                })
                .tick(tick)
            }
            CheckMode::Injected(checks) => Supervisor::new(SupervisorPorts {
                runtime,
                checks: &mut **checks,
                assessment: &mut *self.assessment,
                evidence: &mut evidence,
                store: &mut store,
                budget: &mut ledger,
                clock: &self.clock,
                notifications: &mut notifications,
            })
            .tick(tick),
        };
        match result {
            Ok(report) => {
                if matches!(
                    report.outcome(),
                    TickOutcome::Stopped
                        | TickOutcome::Failed
                        | TickOutcome::Completed
                        | TickOutcome::WaitingHuman
                ) {
                    self.set_active(project, supervision, false);
                }
                Ok(())
            }
            Err(SupervisionError::RevisionConflict { .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn force_waiting(
        &mut self,
        _runtime: &mut dyn DesktopSupervisionRuntime,
        record: &SupervisionRecord,
        action: HumanAction,
    ) -> Result<(), SupervisionError> {
        if record.state() == SupervisionState::WaitingHuman {
            return Ok(());
        }
        let project = record.project_id();
        let supervision = record.supervision_id();
        let request = herness_supervision::SupervisionRequest::new(
            SupervisionRequestId::new(project),
            supervision,
            SupervisionCommand::Reassess,
            record.revision(),
        )?;
        let mut store = self.store.clone();
        herness_supervision::execute_command(&mut store, request, |current| {
            let mut next = current.clone();
            next.wait_for_human(action)?;
            Ok(next)
        })?;
        self.set_active(project, supervision, false);
        Ok(())
    }

    fn load(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<SupervisionRecord, SupervisionError> {
        self.store
            .load(project, supervision)?
            .ok_or(SupervisionError::UnknownSupervision)
    }

    fn plan(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<StoredPlan, SupervisionError> {
        self.stored_plan(project, supervision)?
            .ok_or(SupervisionError::Unsupported {
                feature: "supervision plan is not available".to_owned(),
            })
    }

    /// Loads one plan strictly. A legacy or altered stored plan returns its
    /// explicit error instead of being treated as absent.
    fn stored_plan(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<Option<StoredPlan>, SupervisionError> {
        // Repair a crash between the atomic supersession commit and the plan
        // save before reading the canonical plan.
        self.promote_pending_plan(project, supervision)?;
        let cached = self
            .plans
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&(project, supervision))
            .cloned();
        let plan = match cached {
            Some(plan) => Some(plan),
            None => load_plan(&self.store, project, supervision)?,
        };
        if let Some(plan) = &plan {
            plan.verify()?;
            if plan.packet.project_id() != project {
                return Err(SupervisionError::CrossProjectReference {
                    id_kind: "supervision plan".to_owned(),
                    expected: project,
                    found: plan.packet.project_id(),
                });
            }
        }
        Ok(plan)
    }

    /// Read-only plan for views. Decode/verification errors leave the target
    /// without plan detail; they never substitute a fabricated plan.
    fn plan_opt(&self, project: ProjectId, supervision: SupervisionId) -> Option<StoredPlan> {
        self.stored_plan(project, supervision).ok().flatten()
    }

    fn ledger(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
        plan: &StoredPlan,
    ) -> Result<BudgetLedger<StoreHandle, HostBudgetClock>, SupervisionError> {
        BudgetLedger::open(
            self.store.clone(),
            project,
            supervision,
            plan.budget.policy()?,
            plan.budget_version,
            HostBudgetClock::new(),
        )
    }

    fn require_human_confirmation(
        &self,
        confirmation: Option<HumanConfirmation>,
        kind: ConfirmationKind,
    ) -> Result<(), SupervisionError> {
        let confirmation = confirmation.ok_or(SupervisionError::Unsupported {
            feature: "human confirmation is required".to_owned(),
        })?;
        if confirmation.kind() != kind {
            return Err(SupervisionError::Unsupported {
                feature: "human confirmation does not match the operation".to_owned(),
            });
        }
        Ok(())
    }

    fn set_active(&self, project: ProjectId, supervision: SupervisionId, active: bool) {
        let mut set = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if active {
            set.insert((project, supervision));
        } else {
            set.remove(&(project, supervision));
        }
        if !active {
            self.last_tick
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&(project, supervision));
        }
    }

    fn set_restored(&self, project: ProjectId, supervision: SupervisionId, restored: bool) {
        let mut set = self
            .restored
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if restored {
            set.insert((project, supervision));
        } else {
            set.remove(&(project, supervision));
        }
    }

    fn is_restored(&self, project: ProjectId, supervision: SupervisionId) -> bool {
        self.restored
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&(project, supervision))
    }

    fn view(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<SupervisionView, SupervisionError> {
        let record = self.load(project, supervision)?;
        let plan = self.plan_opt(project, supervision);
        let evidence = self
            .store
            .list_for_supervision(project, supervision)?
            .into_iter()
            .map(|record| EvidenceView {
                evidence_id: record.id().to_string(),
                check_id: record.check_id().map(|id| id.to_string()),
                condition_id: record.condition_id().map(|id| id.to_string()),
                status: record.status().as_str().to_owned(),
                operation: record.operation().as_str().to_owned(),
                outcome: record.outcome().detail().to_owned(),
                sequence: record.sequence(),
                observed_at: record.observed_at(),
            })
            .collect();
        let conditions = plan
            .as_ref()
            .map(|plan| {
                plan.conditions
                    .conditions()
                    .iter()
                    .map(|condition| ConditionView {
                        condition_id: condition.id().to_string(),
                        title: condition.title().to_owned(),
                        rubric: condition.rubric().to_owned(),
                        checks: plan
                            .conditions
                            .checks()
                            .iter()
                            .filter(|check| check.condition_id() == condition.id())
                            .map(|check| CheckView {
                                check_id: check.id().to_string(),
                                operation: check.operation().as_str().to_owned(),
                                description: check.description().to_owned(),
                            })
                            .collect(),
                        approved: plan.conditions.is_approved(Timestamp::now()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let budget = plan
            .as_ref()
            .and_then(|plan| self.budget_view(project, supervision, plan).ok());
        let purposes = [
            ProfilePurpose::Completion,
            ProfilePurpose::Html,
            ProfilePurpose::Permission,
        ]
        .into_iter()
        .map(|purpose| self.purpose_status(project, purpose))
        .collect();
        let notifications = self.notifications_for(project, supervision);
        Ok(SupervisionView {
            project_id: project,
            supervision_id: supervision,
            revision: record.revision(),
            state: record.state().as_str().to_owned(),
            reason: serde_json::to_value(record.reason()).unwrap_or(serde_json::Value::Null),
            condition_version: record.condition_version().get(),
            target_version: record.target_version().get(),
            profile: record.profile(),
            consent: record.consent(),
            conditions,
            unmet_conditions: record
                .unmet_conditions()
                .iter()
                .map(ToString::to_string)
                .collect(),
            run_group: record
                .run_group()
                .runs()
                .iter()
                .map(ToString::to_string)
                .collect(),
            applied_decisions: record.applied_decisions().len(),
            invalidated_decisions: record.invalidated_decisions().len(),
            completion: record
                .completion()
                .and_then(|completion| serde_json::to_value(completion).ok()),
            completion_stale: record
                .completion_stale()
                .and_then(|stale| serde_json::to_value(stale).ok()),
            budget,
            evidence,
            purposes,
            notifications,
            plan_available: plan.is_some(),
            pending_assessment: record
                .supervisor()
                .pending_assessment()
                .and_then(|pending| serde_json::to_value(pending.request()).ok()),
        })
    }

    fn budget_view(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
        plan: &StoredPlan,
    ) -> Result<BudgetView, SupervisionError> {
        let policy = plan.budget.policy()?;
        let stored = self.store.load_budget(project, supervision)?;
        let (usage, policy_version, unresolved) = match stored {
            Some(stored) => {
                let usage = stored
                    .record()
                    .effective_usage(HostBudgetClock::new().read());
                (
                    usage,
                    stored.record().policy_version(),
                    stored.record().unresolved_charges().len(),
                )
            }
            None => (BudgetUsage::empty(), plan.budget_version, 0),
        };
        Ok(BudgetView {
            policy_version,
            active_seconds: policy.active_seconds(),
            additional_runs: policy.additional_runs(),
            money_limit_micros: policy.money_cap().map(|cap| cap.limit().micros()),
            price_version: policy
                .money_cap()
                .map(|cap| cap.price_version().as_str().to_owned()),
            usage,
            remaining_active_seconds: usage.remaining_active_seconds(&policy),
            unresolved_charges: unresolved,
        })
    }

    fn purpose_status(&self, project: ProjectId, purpose: ProfilePurpose) -> PurposeStatusView {
        let config = self.config.get(project);
        let profile = config.profile(purpose);
        let consent = config.consent(purpose);
        PurposeStatusView {
            purpose: purpose.as_str().to_owned(),
            configured: profile.is_some() || consent.is_some(),
            verified: profile.is_some_and(|profile| profile.verified),
            profile_id: profile.map(|profile| profile.profile.id().to_string()),
            provider: profile.map(|profile| profile.profile.provider().as_str().to_owned()),
            connection: profile.map(|profile| profile.profile.connection().to_string()),
            model: profile.map(|profile| profile.profile.model().to_string()),
            consent_state: match consent.map(|consent| consent.state()) {
                Some(ConsentState::Granted { .. }) => "granted".to_owned(),
                Some(ConsentState::Revoked { .. }) => "revoked".to_owned(),
                None => "unset".to_owned(),
            },
            consent_version: consent.map(|consent| consent.version()),
            origin: consent.map(|consent| origin_label(consent.origin())),
            data_kinds: consent
                .map(|consent| {
                    consent
                        .scope()
                        .data_kinds()
                        .iter()
                        .map(|kind| kind.as_str().to_owned())
                        .collect()
                })
                .unwrap_or_default(),
            targets: consent
                .map(|consent| consent.scope().targets().to_vec())
                .unwrap_or_default(),
            target_scope_version: consent.map(|consent| consent.target_scope_version().get()),
        }
    }

    fn notifications_for(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Vec<NotificationView> {
        self.notifications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|notification| {
                notification
                    .notification_id
                    .starts_with(&format!("supervision:{project}:{supervision}:"))
            })
            .cloned()
            .collect()
    }
}

struct HostNotifications {
    queue: Arc<Mutex<VecDeque<NotificationView>>>,
}

impl OwnerNotificationPort for HostNotifications {
    fn notify(&mut self, notification: &SupervisorNotification) -> Result<(), SupervisionError> {
        let view = NotificationView {
            notification_id: notification.notification_id().to_owned(),
            revision: notification.revision(),
            state: notification.state().as_str().to_owned(),
            reason: serde_json::to_value(notification.reason()).unwrap_or(serde_json::Value::Null),
            unmet_conditions: notification
                .unmet_conditions()
                .iter()
                .map(ToString::to_string)
                .collect(),
            observed_at: notification.observed_at(),
        };
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !queue
            .iter()
            .any(|existing| existing.notification_id == view.notification_id)
        {
            queue.push_back(view);
        }
        Ok(())
    }
}

fn origin_label(origin: &ProviderOrigin) -> String {
    format!(
        "{}://{}:{}",
        origin.scheme().as_str(),
        origin.host(),
        origin.port()
    )
}

fn recovery_view(report: &herness_supervision::recovery::RecoveryReport) -> RecoveryView {
    RecoveryView {
        revision: report.revision(),
        state: report.state().as_str().to_owned(),
        reason: serde_json::to_value(report.reason()).unwrap_or(serde_json::Value::Null),
        disposition: serde_json::to_value(report.disposition())
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned()),
        resumable: report.resumable(),
        unresolved_requests: report
            .unresolved_requests()
            .iter()
            .map(|request| {
                serde_json::json!({
                    "attemptId": request.attempt_id().to_string(),
                    "kind": request.kind().as_str(),
                    "purpose": request.purpose(),
                })
            })
            .collect(),
        history_only_requests: report
            .history_only_requests()
            .iter()
            .map(|request| {
                serde_json::json!({
                    "attemptId": request.attempt_id().to_string(),
                    "outcome": serde_json::to_value(request.outcome()).unwrap_or(serde_json::Value::Null),
                    "reason": serde_json::to_value(request.reason()).unwrap_or(serde_json::Value::Null),
                })
            })
            .collect(),
        unresolved_operations: report
            .unresolved_operations()
            .iter()
            .map(|operation| {
                serde_json::json!({
                    "operationId": operation.operation_id(),
                    "runId": operation.run_id().to_string(),
                    "tool": operation.tool(),
                    "pending": operation.pending(),
                })
            })
            .collect(),
        managed_processes: report
            .managed_processes()
            .iter()
            .map(|process| {
                serde_json::json!({
                    "processId": process.process_id(),
                    "running": process.running(),
                    "stopConfirmed": process.stop_confirmed(),
                })
            })
            .collect(),
        checkpoint: match report.checkpoint() {
            Some(herness_supervision::RecoveryCheckpoint::Present) => "present".to_owned(),
            Some(herness_supervision::RecoveryCheckpoint::Missing) => "missing".to_owned(),
            Some(herness_supervision::RecoveryCheckpoint::Ambiguous(detail)) => {
                format!("ambiguous: {detail}")
            }
            None => "not_observed".to_owned(),
        },
        recovery_mode: report.recovery_mode().map(|mode| mode.as_str().to_owned()),
        budget: serde_json::to_value(report.budget()).unwrap_or(serde_json::Value::Null),
        version_mismatches: report
            .version_mismatches()
            .iter()
            .filter_map(|mismatch| serde_json::to_value(mismatch).ok())
            .collect(),
        block_reasons: report
            .block_reasons()
            .iter()
            .filter_map(|reason| serde_json::to_value(reason).ok())
            .collect(),
        required_actions: report
            .required_actions()
            .iter()
            .filter_map(|action| {
                serde_json::to_value(action)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
            })
            .collect(),
        stale_completion: report.stale_completion(),
        side_effects: serde_json::to_value(report.side_effects())
            .unwrap_or(serde_json::Value::Null),
        notified: report.notified(),
    }
}
