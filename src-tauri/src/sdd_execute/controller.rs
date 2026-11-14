//! The `SddTaskController` availability gate and the minimal trusted operations.
//!
//! # Availability
//!
//! [`SddTaskController::evaluate`] checks every required port for one project and
//! the current saved approval. The controller is available only when **all** of
//! them are really present. A missing port or a missing approval is reported as
//! the exact missing capability; there is no fallback implementation, no model
//! substitute, and no partial mode. Every mutating operation calls
//! [`SddTaskController::ensure_available`] first, so a UI can never reach work it
//! does not have the capability to finish.
//!
//! # What the operations do
//!
//! | Operation | Durable effect |
//! | --- | --- |
//! | preview | none: reads the plan and its specs through the pack inspector |
//! | approve-and-start | saves the human approval revision and the `ready` snapshot with its start record |
//! | pause | writes the durable `waiting_human` hold, then asks the current child to stop |
//! | cancel | writes the terminal `cancelled` state, then asks the current child to stop |
//! | resume | links at most one established commit or records the durable hold |
//! | approve-plan-revision | saves the new human revision after a confirmed stop |
//! | finish handoff | returns the durable handoff inputs and the reasons it is not ready |
//!
//! The start does **not** create a child: the saved `ready` snapshot is the start
//! intent, and the coordinator dispatches the first incomplete Task from it. That
//! is why [`crate::sdd_execute::views::SddStartView::child_started`] is always
//! `false` — the UI is never told a child exists when none does.
//!
//! Every human confirmation is minted here, after the command layer verified the
//! trusted main webview. A repository string, a report, an environment variable,
//! a receipt, an `ApprovedOwner` value, or an `H4SddTask` value cannot reach this
//! module.

use std::path::{Path, PathBuf};

use herness_core::contracts::{ConnectionId, ProjectId, Timestamp};
use herness_core::{
    AbsolutePath, ProcessSupervisor, SystemArgvLauncher, ToolchainConfig, ToolchainDetector,
};
use herness_sdd_execute::{
    AppliedRevision, ApprovalContent, ApprovalId, ApprovalInputs, ApprovalRevisionStorePort,
    BudgetConsumption, CommitAuthorization, ConflictReason, ControlRequestId, ExecutionApproval,
    ExecutionConnection, ExecutionId, ExecutionOperation, ExecutionOperationRequest,
    ExecutionOperationResult, ExecutionRevision, ExecutionSnapshot, ExecutionState, FailureDetails,
    GitIdentity, H3ApprovalBinding, HumanAction, PlanPath, PlanRevision, RecoveryReason,
    SddExecutionError, SnapshotBudget, SnapshotInput, SnapshotPlan, SnapshotWorkspace,
    StartApprovalRegistry, StartPhase, StartReceipt, StartRecord, StartRecordStorePort, StopReason,
    StopRecord, TaskApproval, TaskPhase, TaskRef, TaskSnapshot,
};
use herness_supervision::{BudgetPolicy, ConsentId, Money, MoneyCap, PriceVersion};
use serde::{Deserialize, Serialize};

use crate::host::DesktopHost;
use crate::sdd_execute::composition::{CurrentInputs, PlanRevisionRequest};
use crate::sdd_execute::plan_changes::DesktopPlanChangeGate;
use crate::sdd_execute::registry::{ApprovalDraft, PreviewFacts};
use crate::sdd_execute::views::{
    SddCapabilityReportView, SddFailureView, SddFinishBlockerView, SddFinishHandoffView,
    SddOperationView, SddPort, SddPreviewView, SddResumeView, SddSnapshotView,
    SddStartDisclosureView, SddStartView, SddSubscribeView,
};
use crate::supervision::store::StoreHandle;
use crate::supervision::{ConfirmationKind, HumanConfirmation};

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// One read-only preview request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SddPreviewRequest {
    /// Project the plan belongs to.
    pub project_id: ProjectId,
    /// Project-relative plan path.
    pub plan_path: String,
}

/// One per-Task finite limit supplied by the human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SddTaskLimitRequest {
    /// Plan-assigned Task number.
    pub number: u32,
    /// Cumulative active seconds.
    pub active_seconds: u64,
    /// Additional child runs.
    pub additional_runs: u32,
    /// Optional money cap in micro-dollars.
    #[serde(default)]
    pub money_limit_micros: Option<u64>,
    /// Price version, required with a money cap.
    #[serde(default)]
    pub price_version: Option<String>,
}

/// One approve-and-start request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SddApproveStartRequest {
    /// Project that owns the execution.
    pub project_id: ProjectId,
    /// New execution identity.
    pub execution_id: ExecutionId,
    /// Approval identity.
    pub approval_id: ApprovalId,
    /// Idempotent start request.
    pub request_id: ControlRequestId,
    /// Approval revision the human confirmed.
    pub expected_approval_revision: u64,
    /// Approved plan path.
    pub plan_path: String,
    /// Approved canonical checkout root.
    pub checkout_root: String,
    /// Approved implementation branch.
    pub branch: String,
    /// Approved integration base branch.
    pub base_branch: String,
    /// Whether an isolated worktree was approved.
    pub isolated_worktree: bool,
    /// H1 execution connection.
    pub connection: ConnectionId,
    /// Approved H3 settings record version.
    pub h3_settings_version: u64,
    /// Approved H3 capability labels.
    #[serde(default)]
    pub h3_capabilities: Vec<String>,
    /// Approved H3 consent identifiers, as their string form.
    #[serde(default)]
    pub h3_consent_ids: Vec<String>,
    /// One finite limit per Task.
    pub task_limits: Vec<SddTaskLimitRequest>,
    /// Git author name the host commits with.
    pub git_name: String,
    /// Git author email the host commits with.
    pub git_email: String,
}

impl SddApproveStartRequest {
    /// The plan-revision approval form of this request.
    pub fn plan_revision(
        &self,
        request_id: ControlRequestId,
        expected_revision: u64,
    ) -> SddPlanRevisionRequest {
        SddPlanRevisionRequest {
            project_id: self.project_id,
            execution_id: self.execution_id,
            request_id,
            expected_revision,
            approval_id: self.approval_id,
            expected_approval_revision: self.expected_approval_revision,
            start: self.clone(),
        }
    }
}

/// One plan-revision approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SddPlanRevisionRequest {
    /// Project that owns the execution.
    pub project_id: ProjectId,
    /// Execution identity.
    pub execution_id: ExecutionId,
    /// Idempotent request.
    pub request_id: ControlRequestId,
    /// Execution revision the caller observed.
    pub expected_revision: u64,
    /// Approval identity.
    pub approval_id: ApprovalId,
    /// Approval revision the human based the decision on.
    pub expected_approval_revision: u64,
    /// The new approved plan and its inputs.
    #[serde(flatten)]
    pub start: SddApproveStartRequest,
}

/// One update operation request with the mandatory request guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SddOperationRequest {
    /// Project that owns the execution.
    pub project_id: ProjectId,
    /// Execution identity.
    pub execution_id: ExecutionId,
    /// Idempotent request.
    pub request_id: ControlRequestId,
    /// Execution revision the caller observed.
    pub expected_revision: u64,
}

/// One resume request. It additionally names the approval the human based the
/// resume on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SddResumeRequest {
    /// Project that owns the execution.
    pub project_id: ProjectId,
    /// Execution identity.
    pub execution_id: ExecutionId,
    /// Idempotent request.
    pub request_id: ControlRequestId,
    /// Execution revision the caller observed.
    pub expected_revision: u64,
    /// Approval identity.
    pub approval_id: ApprovalId,
    /// Approval revision the human based the resume on.
    pub expected_approval_revision: u64,
}

/// One finish handoff request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SddFinishRequest {
    /// Project that owns the execution.
    pub project_id: ProjectId,
    /// Execution identity.
    pub execution_id: ExecutionId,
}

// ---------------------------------------------------------------------------
// The controller
// ---------------------------------------------------------------------------

/// The trusted desktop SDD Task controller.
///
/// It is a thin, capability-gated composition over the existing H4 desktop
/// modules. It owns no port of its own: every value it reads comes from the one
/// `DesktopHost`, and every durable write goes through the one store.
pub struct SddTaskController {
    capabilities: SddCapabilityReportView,
}

impl SddTaskController {
    /// Evaluates every required port for one project.
    ///
    /// `trusted_main` is `true` only when the command layer already verified the
    /// invoking webview is the single local `main` webview.
    pub fn evaluate(host: &DesktopHost, project: Option<ProjectId>, trusted_main: bool) -> Self {
        Self::evaluate_with_overrides(host, project, trusted_main, &[])
    }

    /// Evaluates the ports with explicit test overrides.
    ///
    /// This is a test boundary, not a production switch: it exists because the
    /// pack inspector and the saved approval cannot be synthesized in an ordinary
    /// desktop test without a pack checkout or a recorded approval. An override
    /// only replaces the *observed presence* of a port; it never changes what an
    /// operation does with a missing one.
    #[doc(hidden)]
    pub fn evaluate_with_overrides(
        host: &DesktopHost,
        project: Option<ProjectId>,
        trusted_main: bool,
        overrides: &[(SddPort, bool)],
    ) -> Self {
        let mut checks: Vec<(SddPort, bool, String)> = Vec::new();
        checks.push((
            SddPort::ExecutionStore,
            true,
            "the shared SQLite store holds the H4 snapshot and journals".to_owned(),
        ));

        let project_root = project.and_then(|project| {
            host.runtime()
                .project(project)
                .ok()
                .map(|view| view.path().as_path().to_path_buf())
        });
        checks.push(match &project_root {
            Some(root) if root.is_dir() => (
                SddPort::PlanSource,
                true,
                format!("the plan source reads under {}", root.display()),
            ),
            Some(root) => (
                SddPort::PlanSource,
                false,
                format!("the project root {} is not a directory", root.display()),
            ),
            None => (
                SddPort::PlanSource,
                false,
                "no project is selected, so the plan source has no root".to_owned(),
            ),
        });

        let pack = host.html_sync_services().pack_root().map(Path::to_path_buf);
        let has_python = python_executable().is_some();
        checks.push(match (&pack, has_python) {
            (Some(root), true) if root.join("scripts/plan-inspect").is_file() => (
                SddPort::PlanInspector,
                true,
                format!("the pack inspector reads {}", root.display()),
            ),
            (Some(root), true) => (
                SddPort::PlanInspector,
                false,
                format!("{} has no scripts/plan-inspect", root.display()),
            ),
            (Some(_), false) => (
                SddPort::PlanInspector,
                false,
                "no Python 3 interpreter was found for the pack inspector".to_owned(),
            ),
            (None, _) => (
                SddPort::PlanInspector,
                false,
                "no Common SDD pack root is configured (SDD_PACK_ROOT)".to_owned(),
            ),
        });

        let git = git_executable();
        checks.push(match (&git, &project_root) {
            (Some(_), Some(_)) => (
                SddPort::Workspace,
                true,
                "the Git workspace adapter is composed".to_owned(),
            ),
            (None, _) => (
                SddPort::Workspace,
                false,
                "no Git executable was found".to_owned(),
            ),
            (Some(_), None) => (
                SddPort::Workspace,
                false,
                "no project is selected".to_owned(),
            ),
        });

        checks.push((
            SddPort::ChildDispatch,
            true,
            "the H2 supervision host dispatches the one Task child".to_owned(),
        ));
        checks.push((
            SddPort::HtmlBarrier,
            true,
            "the H3 H4Barrier port reads the saved document state".to_owned(),
        ));
        checks.push((
            SddPort::HostGit,
            git.is_some(),
            if git.is_some() {
                "the H1 host Git boundary is composed".to_owned()
            } else {
                "no Git executable was found for the host commit".to_owned()
            },
        ));
        checks.push(match &project_root {
            Some(root) if root.is_dir() => (
                SddPort::ProgressLedger,
                true,
                format!("the compatibility ledger writes under {}", root.display()),
            ),
            _ => (
                SddPort::ProgressLedger,
                false,
                "no checkout is available for the ledger".to_owned(),
            ),
        });

        checks.push((
            SddPort::TrustedApproval,
            trusted_main,
            if trusted_main {
                "the caller is the trusted local main webview".to_owned()
            } else {
                "only the trusted local main webview can issue a human confirmation".to_owned()
            },
        ));

        let current = project.and_then(|project| newest_approval(host, project));
        checks.push(match &current {
            Some(approval) => (
                SddPort::CurrentApproval,
                true,
                format!(
                    "the current approval {} revision {} is saved",
                    approval.approval_id(),
                    approval.revision()
                ),
            ),
            None => (
                SddPort::CurrentApproval,
                false,
                "the project has no saved execution approval".to_owned(),
            ),
        });

        Self {
            capabilities: SddCapabilityReportView::from_checks(
                checks
                    .into_iter()
                    .map(|(port, available, detail)| {
                        match overrides.iter().find(|(candidate, _)| *candidate == port) {
                            Some((_, true)) => (
                                port,
                                true,
                                format!("a test boundary reports {port:?} present: {detail}"),
                            ),
                            Some((_, false)) => (
                                port,
                                false,
                                format!("a test boundary reports {port:?} missing: {detail}"),
                            ),
                            None => (port, available, detail),
                        }
                    })
                    .collect::<Vec<_>>(),
            ),
        }
    }

    /// The evaluated capability report.
    pub const fn capabilities(&self) -> &SddCapabilityReportView {
        &self.capabilities
    }

    /// Refuses every mutating operation when one required port is missing.
    pub fn ensure_available(&self) -> Result<(), SddFailureView> {
        if self.capabilities.available() {
            Ok(())
        } else {
            Err(SddFailureView::unavailable(
                "sdd_task_controller",
                self.capabilities.missing_line(),
            ))
        }
    }

    /// Refuses a start when a port other than the (not yet saved) approval is
    /// missing.
    ///
    /// A first start has no saved approval by definition, so the current
    /// approval is the operation's own result, not a precondition. Every other
    /// port must still be present.
    fn ensure_start_available(&self) -> Result<(), SddFailureView> {
        let blocking: Vec<&_> = self
            .capabilities
            .missing()
            .into_iter()
            .filter(|state| state.capability() != "current_approval")
            .collect();
        if blocking.is_empty() {
            return Ok(());
        }
        Err(SddFailureView::unavailable(
            "sdd_approve_and_start",
            blocking
                .iter()
                .map(|state| format!("{}: {}", state.capability(), state.detail()))
                .collect::<Vec<_>>()
                .join("; "),
        ))
    }

    // -----------------------------------------------------------------------
    // Preview
    // -----------------------------------------------------------------------

    /// Runs one side-effect-free preview.
    ///
    /// It reads the exact plan bytes and the declared spec/source snapshots and
    /// sends nothing to a model. The preview does not claim the prose matches the
    /// structured block or that the canonical spec is approved.
    pub fn preview(
        &self,
        host: &mut DesktopHost,
        request: &SddPreviewRequest,
    ) -> Result<SddPreviewView, SddFailureView> {
        // A preview needs the plan source and the inspector only; a missing saved
        // approval must not prevent a human from reading a plan.
        self.ensure_preview_available()?;
        let preview = import_preview(host, request.project_id, &request.plan_path)?;
        Ok(SddPreviewView::of(request.project_id, &preview))
    }

    fn ensure_preview_available(&self) -> Result<(), SddFailureView> {
        let blocking: Vec<&_> = self
            .capabilities
            .missing()
            .into_iter()
            .filter(|state| !matches!(state.capability(), "trusted_approval" | "current_approval"))
            .collect();
        if blocking.is_empty() {
            return Ok(());
        }
        Err(SddFailureView::unavailable(
            "sdd_preview",
            blocking
                .iter()
                .map(|state| format!("{}: {}", state.capability(), state.detail()))
                .collect::<Vec<_>>()
                .join("; "),
        ))
    }

    /// Builds the start disclosure a human confirms.
    ///
    /// It never starts anything and never writes.
    pub fn disclosure(
        &self,
        host: &mut DesktopHost,
        request: &SddApproveStartRequest,
    ) -> Result<SddStartDisclosureView, SddFailureView> {
        self.ensure_preview_available()?;
        let (_, draft) = draft_for(host, request)?;
        let content = draft.build().map_err(failure_of)?.content().clone();
        Ok(SddStartDisclosureView::from_content(
            request.execution_id,
            request.approval_id,
            request.expected_approval_revision,
            &content,
            unverified_capabilities(host, request.project_id),
        ))
    }

    // -----------------------------------------------------------------------
    // Approve and start
    // -----------------------------------------------------------------------

    /// Saves the human approval revision and the `ready` start snapshot.
    ///
    /// `confirmation` must be a `Start` confirmation minted after the trusted
    /// main-window guard accepted the call. The saved snapshot is the start
    /// intent: it records the approved plan, checkout, branch, Tasks, budgets, and
    /// applied revision, so the coordinator dispatches from durable state. A
    /// re-delivered request returns the stored result, and no second snapshot or
    /// child is created.
    pub fn approve_and_start(
        &self,
        host: &mut DesktopHost,
        request: &SddApproveStartRequest,
        confirmation: Option<&HumanConfirmation>,
    ) -> Result<SddStartView, SddFailureView> {
        ensure_operation_confirmation(confirmation, ConfirmationKind::Start)?;
        // A revoked consent, an unverified profile, or a changed baseline must
        // refuse before any preview process, approval write, or start intent.
        ensure_live_start_inputs(host, request.project_id)?;

        let (_, draft) = draft_for(host, request)?;
        let build = draft.build().map_err(failure_of)?;
        let content = build.content().clone();
        let fingerprint = start_fingerprint(request, &content)?;

        {
            let store = host.store_handle();
            let guard = store.lock();
            if let Ok(Some(record)) =
                guard.start_record(request.project_id, request.execution_id, request.request_id)
            {
                if record.fingerprint() != &fingerprint {
                    return Err(failure_ref(&SddExecutionError::DuplicateRequestConflict {
                        recorded: record.fingerprint().to_string(),
                        supplied: fingerprint.to_string(),
                    }));
                }
                return match record.phase() {
                    StartPhase::Started => {
                        let approval = guard
                            .latest_sdd_approval(request.project_id, request.approval_id)
                            .ok()
                            .flatten()
                            .ok_or_else(|| {
                                failure_ref(&SddExecutionError::ApprovalRequired {
                                    reason: herness_sdd_execute::ApprovalRequirement::StartApproval,
                                    details: FailureDetails::none().boxed(),
                                })
                            })?;
                        drop(guard);
                        let stored = load_snapshot(host, request.project_id, request.execution_id)?;
                        let disclosure = SddStartDisclosureView::of(
                            request.execution_id,
                            &approval,
                            unverified_capabilities(host, request.project_id),
                        );
                        Ok(SddStartView::new(
                            &approval,
                            true,
                            disclosure,
                            snapshot_view(host, &stored)?,
                        ))
                    }
                    StartPhase::PreparingWorkspace | StartPhase::Starting => {
                        Err(failure_ref(&SddExecutionError::RecoveryRequired {
                            reason: RecoveryReason::UnknownRequest,
                            details: FailureDetails::none().boxed(),
                        }))
                    }
                };
            }
            if let Ok(Some(_)) = guard.load_sdd_execution(request.project_id, request.execution_id)
            {
                // A snapshot already exists for this execution. Nothing is
                // overwritten by a different start request.
                return Err(failure_ref(&SddExecutionError::Conflict {
                    reason: ConflictReason::OwnershipConflict,
                    details: FailureDetails::none().boxed(),
                }));
            }
        }

        self.ensure_start_available()?;

        // The first Task's declared HTML must already be synced. The saved H3
        // state is compared here; the final barrier still re-verifies the exact
        // bytes before any commit.
        ensure_start_html(host, request.project_id, &content)?;
        // The selected checkout must be clean. It is observed read-only; nothing
        // is stashed, reset, or cleaned.
        if Path::new(request.checkout_root.trim()).exists() {
            ensure_checkout_clean(request.project_id, &request.checkout_root)?;
        }

        // 1. Record the start intent before any durable write, so a crash between
        //    the approval and the snapshot is observable instead of invisible.
        let first_task = content
            .tasks()
            .first()
            .map(TaskApproval::task)
            .ok_or_else(|| {
                failure_ref(&SddExecutionError::ApprovalRequired {
                    reason: herness_sdd_execute::ApprovalRequirement::StartApproval,
                    details: FailureDetails::none().boxed(),
                })
            })?;
        let intent = StartRecord::new(
            request.execution_id,
            request.request_id,
            request.approval_id,
            request.expected_approval_revision,
            first_task,
            fingerprint,
            StartPhase::PreparingWorkspace,
            None,
        )
        .map_err(failure_of)?;
        {
            let store = host.store_handle();
            let mut guard = store.lock();
            StartRecordStorePort::record_start(&mut *guard, &intent).map_err(failure_of)?;
        }

        // 2. Save the human approval revision. Only the trusted main window can
        //    reach this line, so the post's actor/source gate is not forgeable.
        let post = build
            .into_human_post(Timestamp::now())
            .map_err(failure_of)?;
        let approval = {
            let store = host.store_handle();
            let mut registry = StartApprovalRegistry::new(StoreRevisions(store.clone()));
            registry.post_human_approval(&post).map_err(failure_of)?
        };
        if approval.revision() != request.expected_approval_revision {
            return Err(failure_ref(&SddExecutionError::Conflict {
                reason: ConflictReason::StaleRevision,
                details: FailureDetails::none().boxed(),
            }));
        }

        // 3. Write the `ready` snapshot. It is the start intent the coordinator
        //    dispatches from.
        let snapshot = ready_snapshot(request, &content).map_err(failure_of)?;
        {
            let store = host.store_handle();
            let mut guard = store.lock();
            guard
                .compare_and_swap_execution(
                    request.project_id,
                    request.execution_id,
                    None,
                    &snapshot,
                )
                .map_err(|error| {
                    SddFailureView::of(&SddExecutionError::Unavailable {
                        feature: format!("sdd_execute.startSnapshot: {error}"),
                        details: FailureDetails::none().boxed(),
                    })
                })?;
        }

        // 4. Record the started result last, so the phase never claims more than
        //    what is durable.
        let started = intent.started(
            StartReceipt::new(format!("execution:{}", request.execution_id), true)
                .map_err(failure_of)?,
        );
        {
            let store = host.store_handle();
            let mut guard = store.lock();
            StartRecordStorePort::record_start(&mut *guard, &started).map_err(failure_of)?;
        }

        let disclosure = SddStartDisclosureView::of(
            request.execution_id,
            &approval,
            unverified_capabilities(host, request.project_id),
        );
        let stored = load_snapshot(host, request.project_id, request.execution_id)?;
        Ok(SddStartView::new(
            &approval,
            false,
            disclosure,
            snapshot_view(host, &stored)?,
        ))
    }

    // -----------------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------------

    /// Returns the saved snapshot.
    pub fn snapshot(
        &self,
        host: &DesktopHost,
        project: ProjectId,
        execution: ExecutionId,
    ) -> Result<SddSnapshotView, SddFailureView> {
        let stored = load_snapshot(host, project, execution)?;
        snapshot_view(host, &stored)
    }

    /// Returns the saved snapshot plus the reconnect sequence.
    ///
    /// `since` is the project sequence the caller last saw. The saved snapshot is
    /// the only progress input: no command result is merged into it.
    pub fn subscribe(
        &self,
        host: &DesktopHost,
        project: ProjectId,
        execution: ExecutionId,
        since: Option<u64>,
    ) -> Result<SddSubscribeView, SddFailureView> {
        let snapshot = self.snapshot(host, project, execution)?;
        Ok(SddSubscribeView::of(snapshot, since))
    }

    // -----------------------------------------------------------------------
    // Pause / cancel
    // -----------------------------------------------------------------------

    /// Stops new dispatch, sends, and commits and asks the current child to stop.
    ///
    /// The durable hold is written first, so a crash between the two leaves a
    /// recorded stop instead of an unrecorded signal.
    pub fn pause(
        &self,
        host: &mut DesktopHost,
        request: &SddOperationRequest,
        confirmation: Option<&HumanConfirmation>,
    ) -> Result<SddOperationView, SddFailureView> {
        self.ensure_available()?;
        ensure_operation_confirmation(confirmation, ConfirmationKind::Stop)?;
        let stop = StopRecord::new(StopReason::PauseRequested, Some(HumanAction::ConfirmStop))
            .map_err(failure_of)?;
        self.hold(
            host,
            request,
            ExecutionOperation::Pause,
            stop,
            ExecutionState::WaitingHuman,
        )
    }

    /// Cancels the execution terminally.
    ///
    /// Nothing is deleted: every recorded Task, commit range, no-change record,
    /// and evidence reference is retained, and the final state is `cancelled`,
    /// which is never a success.
    pub fn cancel(
        &self,
        host: &mut DesktopHost,
        request: &SddOperationRequest,
        confirmation: Option<&HumanConfirmation>,
    ) -> Result<SddOperationView, SddFailureView> {
        self.ensure_available()?;
        ensure_operation_confirmation(confirmation, ConfirmationKind::Stop)?;
        let stop = StopRecord::new(StopReason::CancelRequested, None).map_err(failure_of)?;
        self.hold(
            host,
            request,
            ExecutionOperation::Cancel,
            stop,
            ExecutionState::Cancelled,
        )
    }

    fn hold(
        &self,
        host: &mut DesktopHost,
        request: &SddOperationRequest,
        operation: ExecutionOperation,
        stop: StopRecord,
        state: ExecutionState,
    ) -> Result<SddOperationView, SddFailureView> {
        let stored = load_snapshot(host, request.project_id, request.execution_id)?;
        let store = host.store_handle();
        {
            let guard = store.lock();
            if let Ok(Some(record)) = guard.sdd_control_record(
                request.project_id,
                request.execution_id,
                request.request_id,
            ) && record.outcome().is_some()
            {
                drop(guard);
                let result = load_snapshot(host, request.project_id, request.execution_id)?;
                return Ok(SddOperationView::of(
                    operation,
                    true,
                    &result,
                    project_sequence(host, request.project_id),
                    false,
                ));
            }
        }
        if stored.revision().get() != request.expected_revision {
            return Err(failure_ref(&SddExecutionError::RevisionConflict {
                expected: ExecutionRevision::new(request.expected_revision).map_err(failure_of)?,
                found: stored.revision(),
            }));
        }
        if stored.state().is_terminal() {
            return Err(failure_ref(&SddExecutionError::Conflict {
                reason: ConflictReason::TaskNotReady,
                details: FailureDetails::none().boxed(),
            }));
        }
        let next = held_snapshot(&stored, stop, state).map_err(failure_of)?;
        let operation_request = ExecutionOperationRequest::new(
            request.project_id,
            request.execution_id,
            request.request_id,
            stored.revision(),
            operation,
        )
        .map_err(failure_of)?;
        let result = ExecutionOperationResult::new(operation, next.clone()).map_err(failure_of)?;
        let record = operation_request.recorded(result).map_err(failure_of)?;
        {
            let mut guard = store.lock();
            herness_sdd_execute::ExecutionStorePort::commit_operation(
                &mut *guard,
                request.project_id,
                request.execution_id,
                Some(stored.revision()),
                &next,
                &record,
            )
            .map_err(failure_of)?;
        }
        let child_stop = request_child_stop(host, &stored);
        let result = load_snapshot(host, request.project_id, request.execution_id)?;
        Ok(SddOperationView::of(
            operation,
            false,
            &result,
            project_sequence(host, request.project_id),
            child_stop,
        ))
    }

    // -----------------------------------------------------------------------
    // Resume
    // -----------------------------------------------------------------------

    /// Resumes after a human confirmation.
    ///
    /// The live inputs are rebuilt from the stored approval plus the live
    /// connection, profile, consents, and baseline before the core resume runs,
    /// so a revoked consent or a changed baseline refuses instead of being
    /// silently accepted.
    pub fn resume(
        &self,
        host: &mut DesktopHost,
        request: &SddResumeRequest,
        confirmation: Option<&HumanConfirmation>,
    ) -> Result<SddResumeView, SddFailureView> {
        ensure_operation_confirmation(confirmation, ConfirmationKind::Resume)?;
        let store = host.store_handle();
        let approval = store
            .lock()
            .latest_sdd_approval(request.project_id, request.approval_id)
            .ok()
            .flatten()
            .ok_or_else(|| {
                failure_ref(&SddExecutionError::ApprovalRequired {
                    reason: herness_sdd_execute::ApprovalRequirement::StartApproval,
                    details: FailureDetails::none().boxed(),
                })
            })?;
        let inputs = live_inputs(host, &approval).map_err(failure_of)?;
        let resume_request = herness_sdd_execute::ResumeRequest::new(
            request.project_id,
            request.execution_id,
            request.request_id,
            ExecutionRevision::new(request.expected_revision).map_err(failure_of)?,
            crate::sdd_execute::recovery::confirm_resume(),
            request.approval_id,
            request.expected_approval_revision,
        )
        .map_err(failure_of)?;
        let root = project_root(host, request.project_id)?;
        let mut gate = DesktopPlanChangeGate::new(request.project_id, &root, store.clone())
            .map_err(failure_of)?;
        let outcome = host
            .resume_sdd_execute(&resume_request, &inputs, Some(&mut gate))
            .map_err(|error| SddFailureView::unavailable("sdd_execute.resume", error))?;
        Ok(SddResumeView::of(&outcome))
    }

    // -----------------------------------------------------------------------
    // Approve a plan revision
    // -----------------------------------------------------------------------

    /// Saves a new human-approved plan revision after a confirmed stop.
    pub fn approve_plan_revision(
        &self,
        host: &mut DesktopHost,
        request: &SddPlanRevisionRequest,
        confirmation: Option<&HumanConfirmation>,
    ) -> Result<SddOperationView, SddFailureView> {
        ensure_operation_confirmation(confirmation, ConfirmationKind::PlanRevision)?;
        let (_, draft) = draft_for(host, &request.start)?;
        let post = draft
            .build()
            .map_err(failure_of)?
            .into_human_post(Timestamp::now())
            .map_err(failure_of)?;
        let identity = herness_sdd_execute::PlanRevisionIdentity::new(
            request.project_id,
            request.execution_id,
            request.request_id,
            ExecutionRevision::new(request.expected_revision).map_err(failure_of)?,
            request.approval_id,
            request.expected_approval_revision,
        )
        .map_err(failure_of)?;
        let plan_request = PlanRevisionRequest::new(&post, identity, confirmation.cloned());
        let outcome = {
            let store = host.store_handle();
            let mut guard = store.lock();
            crate::sdd_execute::composition::approve_plan_revision_request(
                &mut *guard,
                &plan_request,
            )
            .map_err(failure_of)?
        };
        let replayed = matches!(
            outcome,
            herness_sdd_execute::PlanRevisionOutcome::Replayed { .. }
        );
        let result = load_snapshot(host, request.project_id, request.execution_id)?;
        Ok(SddOperationView::of(
            ExecutionOperation::ApprovePlanRevision,
            replayed,
            &result,
            project_sequence(host, request.project_id),
            false,
        ))
    }

    // -----------------------------------------------------------------------
    // Finish handoff
    // -----------------------------------------------------------------------

    /// Returns the finish handoff inputs and the reasons it is not ready.
    ///
    /// This build records the durable inputs and reports the explicit blockers.
    /// The final-state evidence decision is made by the finish composition
    /// (Task 22/25); until it accepts, the view is never `ready`, so the UI cannot
    /// declare a completion the store did not establish.
    pub fn finish_handoff(
        &self,
        host: &DesktopHost,
        request: &SddFinishRequest,
    ) -> Result<SddFinishHandoffView, SddFailureView> {
        let stored = load_snapshot(host, request.project_id, request.execution_id)?;
        let final_check_ids = final_check_ids(host, &stored);
        let blockers = finish_blockers(&stored, final_check_ids.is_empty());
        Ok(SddFinishHandoffView::not_ready(
            &stored,
            final_check_ids,
            blockers,
        ))
    }
}

// ---------------------------------------------------------------------------
// Confirmation gates
// ---------------------------------------------------------------------------

/// Refuses an operation whose confirmation is missing or of another kind.
pub fn ensure_operation_confirmation(
    confirmation: Option<&HumanConfirmation>,
    kind: ConfirmationKind,
) -> Result<(), SddFailureView> {
    match confirmation {
        Some(confirmation) if confirmation.kind() == kind => Ok(()),
        _ => Err(failure_ref(&SddExecutionError::ApprovalRequired {
            reason: match kind {
                ConfirmationKind::PlanRevision => {
                    herness_sdd_execute::ApprovalRequirement::PlanRevisionApproval
                }
                ConfirmationKind::Resume => herness_sdd_execute::ApprovalRequirement::Resume,
                _ => herness_sdd_execute::ApprovalRequirement::StartApproval,
            },
            details: FailureDetails::none().boxed(),
        })),
    }
}

// ---------------------------------------------------------------------------
// Store adapters
// ---------------------------------------------------------------------------

/// The approval-revision and start-record ports over the shared store handle.
struct StoreRevisions(StoreHandle);

impl ApprovalRevisionStorePort for StoreRevisions {
    fn record_approval_revision(
        &mut self,
        approval: &ExecutionApproval,
    ) -> Result<(), SddExecutionError> {
        ApprovalRevisionStorePort::record_approval_revision(&mut *self.0.lock(), approval)
    }

    fn approval_revision(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
        revision: u64,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        ApprovalRevisionStorePort::approval_revision(
            &*self.0.lock(),
            project_id,
            approval_id,
            revision,
        )
    }

    fn latest_approval_revision(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        ApprovalRevisionStorePort::latest_approval_revision(
            &*self.0.lock(),
            project_id,
            approval_id,
        )
    }

    fn approval_revisions(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Vec<ExecutionApproval>, SddExecutionError> {
        ApprovalRevisionStorePort::approval_revisions(&*self.0.lock(), project_id, approval_id)
    }
}

impl StartRecordStorePort for StoreRevisions {
    fn start_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<StartRecord>, SddExecutionError> {
        StartRecordStorePort::start_record(&*self.0.lock(), project_id, execution_id, request_id)
    }

    fn start_record_for_task(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        task: TaskRef,
    ) -> Result<Option<StartRecord>, SddExecutionError> {
        StartRecordStorePort::start_record_for_task(&*self.0.lock(), project_id, execution_id, task)
    }

    fn record_start(&mut self, record: &StartRecord) -> Result<(), SddExecutionError> {
        StartRecordStorePort::record_start(&mut *self.0.lock(), record)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Maps one typed H4 error onto its failure view.
pub fn failure_of(error: SddExecutionError) -> SddFailureView {
    SddFailureView::of(&error)
}

/// Maps a borrowed typed H4 error onto its failure view.
pub fn failure_ref(error: &SddExecutionError) -> SddFailureView {
    SddFailureView::of(error)
}

fn python_executable() -> Option<AbsolutePath> {
    let report = ToolchainDetector::new(ToolchainConfig::from_environment()).detect();
    report.python.executable_path.clone()
}

fn git_executable() -> Option<AbsolutePath> {
    for candidate in [
        "/usr/bin/git",
        "/opt/homebrew/bin/git",
        "/usr/local/bin/git",
    ] {
        if Path::new(candidate).is_file() {
            return AbsolutePath::new(candidate).ok();
        }
    }
    None
}

fn project_root(host: &DesktopHost, project: ProjectId) -> Result<PathBuf, SddFailureView> {
    host.runtime()
        .project(project)
        .map(|view| view.path().as_path().to_path_buf())
        .map_err(|error| SddFailureView::unavailable("sdd_execute.project", error.to_string()))
}

fn project_sequence(host: &DesktopHost, project: ProjectId) -> u64 {
    host.runtime().last_sequence(project).unwrap_or(0)
}

fn newest_approval(host: &DesktopHost, project: ProjectId) -> Option<ExecutionApproval> {
    let store = host.store_handle();
    let guard = store.lock();
    let ids = guard.sdd_approval_ids(project).ok()?;
    let mut newest: Option<ExecutionApproval> = None;
    for approval_id in ids {
        let Some(approval) = guard.latest_sdd_approval(project, approval_id).ok()? else {
            continue;
        };
        let replace = newest
            .as_ref()
            .is_none_or(|current| approval.approved_at() > current.approved_at());
        if replace {
            newest = Some(approval);
        }
    }
    newest
}

fn load_snapshot(
    host: &DesktopHost,
    project: ProjectId,
    execution: ExecutionId,
) -> Result<ExecutionSnapshot, SddFailureView> {
    let store = host.store_handle();
    let loaded = store
        .lock()
        .load_sdd_execution(project, execution)
        .map_err(|_| {
            failure_ref(&SddExecutionError::RecoveryRequired {
                reason: RecoveryReason::StateUnreadable,
                details: FailureDetails::none().boxed(),
            })
        })?
        .ok_or_else(|| {
            failure_ref(&SddExecutionError::RecoveryRequired {
                reason: RecoveryReason::StateUnreadable,
                details: FailureDetails::none().boxed(),
            })
        })?;
    Ok(loaded.snapshot().clone())
}

fn git_result_unknown(
    host: &DesktopHost,
    project: ProjectId,
    execution: ExecutionId,
) -> Option<String> {
    let store = host.store_handle();
    let entries = store.lock().sdd_git_entries(project, execution).ok()?;
    let newest = entries.last()?;
    let unknown = newest.state() == herness_sdd_execute::GitJournalState::ResultUnknown
        || newest
            .outcome()
            .is_some_and(herness_sdd_execute::GitCommitOutcome::is_unknown);
    unknown.then(|| {
        format!(
            "the newest host commit journal entry for Task {} is not established",
            newest.intent().task().number().get()
        )
    })
}

fn snapshot_view(
    host: &DesktopHost,
    snapshot: &ExecutionSnapshot,
) -> Result<SddSnapshotView, SddFailureView> {
    let sequence = project_sequence(host, snapshot.project_id());
    let unknown = git_result_unknown(host, snapshot.project_id(), snapshot.execution_id());
    Ok(SddSnapshotView::of(snapshot, sequence, unknown))
}

fn import_preview(
    host: &mut DesktopHost,
    project: ProjectId,
    plan_path: &str,
) -> Result<crate::sdd_execute::pack::ImportPreview, SddFailureView> {
    let root = project_root(host, project)?;
    let pack_root = host
        .html_sync_services()
        .pack_root()
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            SddFailureView::unavailable(
                "plan_inspector",
                "no Common SDD pack root is configured (SDD_PACK_ROOT)",
            )
        })?;
    let python = python_executable().ok_or_else(|| {
        SddFailureView::unavailable("plan_inspector", "no Python 3 interpreter was found")
    })?;
    let plan = PlanPath::parse(plan_path).map_err(failure_of)?;
    let canonical = root.canonicalize().map_err(|error| {
        SddFailureView::unavailable(
            "plan_source",
            format!("the project root is unreadable: {}", error.kind()),
        )
    })?;
    let canonical_text = canonical.to_str().ok_or_else(|| {
        SddFailureView::unavailable("plan_source", "the project root is not valid UTF-8")
    })?;
    let layout = herness_sdd_execute::SourceLayout::new(canonical_text).map_err(failure_of)?;
    let inspector = crate::sdd_execute::pack::PackInspector::new(
        &pack_root,
        python,
        SystemArgvLauncher,
        ProcessSupervisor::new(),
        project,
    )
    .map_err(failure_of)?;
    let source = crate::sdd_execute::PlanFileSource::new(project, &root).map_err(failure_of)?;
    let mut importer = crate::sdd_execute::pack::PlanImporter::new(inspector, source, layout, None);
    importer.import(&plan).map_err(failure_of)
}

/// Builds the verified preview facts and the approval draft for one request.
fn draft_for(
    host: &mut DesktopHost,
    request: &SddApproveStartRequest,
) -> Result<(crate::sdd_execute::pack::ImportPreview, ApprovalDraft), SddFailureView> {
    let preview = import_preview(host, request.project_id, &request.plan_path)?;
    let layout =
        herness_sdd_execute::SourceLayout::new(preview.project_root()).map_err(failure_of)?;
    let facts = PreviewFacts::from_import(&preview, &layout).map_err(failure_of)?;
    let draft = build_draft(host, request, facts, layout)?;
    Ok((preview, draft))
}

fn build_draft(
    host: &DesktopHost,
    request: &SddApproveStartRequest,
    facts: PreviewFacts,
    layout: herness_sdd_execute::SourceLayout,
) -> Result<ApprovalDraft, SddFailureView> {
    if facts.tasks().len() != request.task_limits.len() {
        return Err(SddFailureView::invalid(
            "exactly one finite limit is required per parsed Task",
        ));
    }
    let mut budgets = Vec::with_capacity(facts.tasks().len());
    for (facts, supplied) in facts.tasks().iter().zip(&request.task_limits) {
        if facts.number() != supplied.number {
            return Err(SddFailureView::invalid(format!(
                "the limits name Task {} but the plan's Task is {}",
                supplied.number,
                facts.number()
            )));
        }
        budgets.push(budget_policy(supplied)?);
    }
    let connection = live_connection(host, request.project_id, request.connection)?;
    let h3 = H3ApprovalBinding::new(
        request.h3_settings_version,
        parse_consent_ids(&request.h3_consent_ids)?,
        request.h3_capabilities.clone(),
    )
    .map_err(failure_of)?;
    let git_identity =
        GitIdentity::new(&request.git_name, &request.git_email).map_err(failure_of)?;
    let plan_revision = next_plan_revision(host, request);
    ApprovalDraft::new(
        request.execution_id,
        request.approval_id,
        facts,
        layout,
        plan_revision,
        request.checkout_root.clone(),
        git_identity,
        request.branch.clone(),
        request.base_branch.clone(),
        request.isolated_worktree,
        connection,
        CommitAuthorization::new(true, true).map_err(failure_of)?,
        h3,
        budgets,
    )
    .map_err(failure_of)
}

fn budget_policy(limit: &SddTaskLimitRequest) -> Result<BudgetPolicy, SddFailureView> {
    let money = match (limit.money_limit_micros, limit.price_version.as_deref()) {
        (Some(micros), Some(version)) => Some(
            MoneyCap::new(
                Money::from_micros(micros),
                PriceVersion::new(version)
                    .map_err(|error| SddFailureView::invalid(error.to_string()))?,
            )
            .map_err(|error| SddFailureView::invalid(error.to_string()))?,
        ),
        (Some(_), None) => {
            return Err(SddFailureView::invalid(
                "a money cap requires its price version",
            ));
        }
        (None, _) => None,
    };
    BudgetPolicy::new(limit.active_seconds, limit.additional_runs, money)
        .map_err(|error| SddFailureView::invalid(error.to_string()))
}

fn parse_consent_ids(values: &[String]) -> Result<Vec<ConsentId>, SddFailureView> {
    values
        .iter()
        .map(|value| {
            value
                .parse::<ConsentId>()
                .map_err(|error| SddFailureView::invalid(error.to_string()))
        })
        .collect()
}

/// The live execution connection with only the consents that are granted now.
///
/// A revoked or missing consent yields an empty grant list, which the approval
/// verification refuses with `approval_required/disclosure_consent` instead of
/// silently re-using the previously approved consent.
fn live_connection(
    host: &DesktopHost,
    project: ProjectId,
    connection: ConnectionId,
) -> Result<ExecutionConnection, SddFailureView> {
    let profile = live_profile(host, project)?;
    let config = host.supervision().config().get(project);
    let consents = granted_consents(&config);
    if !consents
        .iter()
        .any(|consent| consent.purpose() == profile.purpose())
    {
        return Err(failure_ref(&SddExecutionError::ApprovalRequired {
            reason: herness_sdd_execute::ApprovalRequirement::DisclosureConsent,
            details: FailureDetails::none().boxed(),
        }));
    }
    ExecutionConnection::new(connection, profile, consents).map_err(failure_of)
}

/// Checks the live inputs a start binds, before any process or write.
///
/// A missing or revoked consent is `approval_required/disclosure_consent`; an
/// unverified profile is `approval_required/capability`. Neither falls back to a
/// previously approved value.
fn ensure_live_start_inputs(host: &DesktopHost, project: ProjectId) -> Result<(), SddFailureView> {
    let profile = live_profile(host, project)?;
    let config = host.supervision().config().get(project);
    let consents = granted_consents(&config);
    if !consents
        .iter()
        .any(|consent| consent.purpose() == profile.purpose())
    {
        return Err(failure_ref(&SddExecutionError::ApprovalRequired {
            reason: herness_sdd_execute::ApprovalRequirement::DisclosureConsent,
            details: FailureDetails::none().boxed(),
        }));
    }
    Ok(())
}

/// The current verified Completion profile of one project.
///
/// A configured-but-unverified profile is a missing capability, never a
/// fallback to a model or another provider.
fn live_profile(
    host: &DesktopHost,
    project: ProjectId,
) -> Result<herness_supervision::ProfileBinding, SddFailureView> {
    host.supervision()
        .config()
        .get(project)
        .profile(herness_supervision::ProfilePurpose::Completion)
        .filter(|profile| profile.verified)
        .map(|profile| profile.profile.binding())
        .ok_or_else(|| {
            failure_ref(&SddExecutionError::ApprovalRequired {
                reason: herness_sdd_execute::ApprovalRequirement::Capability,
                details: FailureDetails::none().boxed(),
            })
        })
}

fn granted_consents(
    config: &crate::supervision::ProjectConfig,
) -> Vec<herness_supervision::ConsentBinding> {
    let mut consents = Vec::new();
    for purpose in [
        herness_supervision::ProfilePurpose::Completion,
        herness_supervision::ProfilePurpose::Html,
    ] {
        let Some(consent) = config.consent(purpose) else {
            continue;
        };
        if !matches!(
            consent.state(),
            herness_supervision::ConsentState::Granted { .. }
        ) {
            continue;
        }
        consents.push(herness_supervision::ConsentBinding::new(
            consent.id(),
            consent.version(),
            consent.scope().purpose(),
            consent.scope().target_scope_version(),
        ));
    }
    consents
}

fn next_plan_revision(host: &DesktopHost, request: &SddApproveStartRequest) -> PlanRevision {
    let store = host.store_handle();
    let latest = store
        .lock()
        .latest_sdd_approval(request.project_id, request.approval_id)
        .ok()
        .flatten();
    latest
        .and_then(|approval| PlanRevision::new(approval.plan().plan_revision().get() + 1).ok())
        .unwrap_or(PlanRevision::INITIAL)
}

fn start_fingerprint(
    request: &SddApproveStartRequest,
    content: &ApprovalContent,
) -> Result<herness_sdd_execute::Sha256Digest, SddFailureView> {
    let value = serde_json::json!({
        "project": request.project_id.to_string(),
        "execution": request.execution_id.to_string(),
        "approval": request.approval_id.to_string(),
        "approvalRevision": request.expected_approval_revision,
        "planDigest": content.plan().digest().as_str(),
        "checkout": content.workspace().canonical_checkout_root(),
        "branch": content.workspace().branch(),
        "baseBranch": content.workspace().base_branch(),
        "isolated": content.workspace().isolated_worktree(),
        "connection": content.connection().connection_id().to_string(),
        "tasks": content
            .tasks()
            .iter()
            .map(|task| {
                serde_json::json!({
                    "number": task.task().number().get(),
                    "stableId": task.task().stable_id().to_string(),
                    "seconds": task.budget().active_seconds(),
                    "runs": task.budget().additional_runs(),
                    "checks": task.checks().len(),
                    "htmlTargets": task.html_targets(),
                })
            })
            .collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&value).map_err(|error| {
        SddFailureView::invalid(format!("could not encode the start fingerprint: {error}"))
    })?;
    Ok(herness_sdd_execute::Sha256Digest::sha256(&bytes))
}

fn ready_snapshot(
    request: &SddApproveStartRequest,
    content: &ApprovalContent,
) -> Result<ExecutionSnapshot, SddExecutionError> {
    let plan = SnapshotPlan::new(
        content.plan().plan_path().clone(),
        content.plan().digest().clone(),
        content.plan().plan_revision(),
    );
    let workspace = SnapshotWorkspace::new(
        content.workspace().canonical_checkout_root(),
        content.workspace().branch(),
        content.workspace().base_branch(),
        content.workspace().baseline().cloned(),
    )?;
    let tasks = content
        .tasks()
        .iter()
        .map(|task| {
            TaskSnapshot::new(
                task.task(),
                herness_sdd_execute::TaskProgression::Pending,
                TaskPhase::Ready,
                None,
                None,
                task.commit_policy(),
                None,
                None,
                Vec::new(),
                None,
                AppliedRevision::current(content.plan().plan_revision()),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let current_task = tasks.first().map(TaskSnapshot::task);
    ExecutionSnapshot::new(SnapshotInput {
        project_id: request.project_id,
        execution_id: request.execution_id,
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::Ready,
        plan,
        workspace,
        current_task,
        tasks,
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: AppliedRevision::current(content.plan().plan_revision()),
        final_project_sequence: None,
    })
}

fn ensure_start_html(
    host: &DesktopHost,
    project: ProjectId,
    content: &ApprovalContent,
) -> Result<(), SddFailureView> {
    let targets = content
        .tasks()
        .first()
        .map(|task| task.html_targets().to_vec())
        .unwrap_or_default();
    if targets.is_empty() {
        return Ok(());
    }
    let store = host.store_handle();
    let guard = store.lock();
    for target in targets {
        let invalid = |reason| {
            failure_ref(&SddExecutionError::HtmlNotSynced {
                reason,
                details: FailureDetails::none().boxed(),
            })
        };
        let Ok(document) = herness_html_sync::DocumentKey::new(project, target.clone()) else {
            return Err(invalid(herness_sdd_execute::HtmlSyncReason::Missing));
        };
        let Some(record) = guard
            .load_html_sync_document(project, &document)
            .ok()
            .flatten()
        else {
            return Err(invalid(herness_sdd_execute::HtmlSyncReason::Missing));
        };
        let state = record.state();
        if state.state() != herness_html_sync::H3State::Synced
            || !state.applicability().is_applicable()
        {
            return Err(invalid(herness_sdd_execute::HtmlSyncReason::Unsynced));
        }
    }
    Ok(())
}

fn ensure_checkout_clean(project: ProjectId, checkout_root: &str) -> Result<(), SddFailureView> {
    let git = git_executable()
        .ok_or_else(|| SddFailureView::unavailable("workspace", "no Git executable was found"))?;
    let mut runner = crate::sdd_execute::GitRunner::new(
        git,
        SystemArgvLauncher,
        ProcessSupervisor::new(),
        project,
    )
    .map_err(failure_of)?;
    let root = Path::new(checkout_root)
        .canonicalize()
        .map_err(|error| {
            SddFailureView::unavailable(
                "workspace",
                format!("the checkout is unreadable: {}", error.kind()),
            )
        })?
        .to_str()
        .ok_or_else(|| SddFailureView::unavailable("workspace", "the checkout is not valid UTF-8"))?
        .to_owned();
    let status = runner.status(&root).map_err(failure_of)?;
    if !status.is_clean() {
        return Err(failure_ref(&SddExecutionError::Conflict {
            reason: ConflictReason::DirtyIndex,
            details: FailureDetails::none().boxed(),
        }));
    }
    Ok(())
}

fn unverified_capabilities(host: &DesktopHost, project: ProjectId) -> Vec<String> {
    let mut missing = Vec::new();
    if host.html_sync_services().pack_root().is_none() {
        missing.push("plan_inspector: no pack root is configured".to_owned());
    }
    if python_executable().is_none() {
        missing.push("plan_inspector: no Python 3 interpreter was found".to_owned());
    }
    if git_executable().is_none() {
        missing.push("host_git: no Git executable was found".to_owned());
    }
    let config = host.supervision().config().get(project);
    for purpose in [
        herness_supervision::ProfilePurpose::Completion,
        herness_supervision::ProfilePurpose::Html,
    ] {
        match config.profile(purpose) {
            Some(profile) if !profile.verified => missing.push(format!(
                "profile.{}: configured but not verified by a real acceptance step",
                purpose.as_str()
            )),
            Some(_) => {}
            None => missing.push(format!(
                "profile.{}: no profile is configured",
                purpose.as_str()
            )),
        }
        match config.consent(purpose) {
            Some(consent)
                if matches!(
                    consent.state(),
                    herness_supervision::ConsentState::Granted { .. }
                ) => {}
            Some(_) => missing.push(format!("consent.{}: revoked", purpose.as_str())),
            None => missing.push(format!("consent.{}: not granted", purpose.as_str())),
        }
    }
    missing
}

fn held_snapshot(
    stored: &ExecutionSnapshot,
    stop: StopRecord,
    state: ExecutionState,
) -> Result<ExecutionSnapshot, SddExecutionError> {
    let mut tasks = Vec::with_capacity(stored.tasks().len());
    for task in stored.tasks() {
        let active = matches!(
            task.phase(),
            TaskPhase::Running
                | TaskPhase::WaitingHtml
                | TaskPhase::Verifying
                | TaskPhase::Committing
        );
        let (phase, task_stop) = if active && state == ExecutionState::Cancelled {
            (TaskPhase::Cancelled, None)
        } else if active {
            (TaskPhase::WaitingHuman, Some(stop))
        } else {
            (task.phase(), task.stop())
        };
        tasks.push(TaskSnapshot::new(
            task.task(),
            phase.implied_progression(),
            phase,
            task.h2_reference(),
            task.child(),
            task.commit_policy(),
            task.commit_range().cloned(),
            task.no_change().cloned(),
            task.evidence().to_vec(),
            task_stop,
            task.applied_revision(),
        )?);
    }
    ExecutionSnapshot::new(SnapshotInput {
        project_id: stored.project_id(),
        execution_id: stored.execution_id(),
        revision: stored.revision().next(),
        state,
        plan: stored.plan().clone(),
        workspace: stored.workspace().clone(),
        current_task: stored.current_task(),
        tasks,
        stop: Some(stop),
        budget: stored.budget(),
        applied_revision: stored.applied_revision(),
        final_project_sequence: stored.final_project_sequence(),
    })
}

/// Asks the current Task's H2 child to stop cooperatively.
///
/// A failure is reported to the caller and never converted into a confirmed
/// stop: the durable hold that was written first is what closes new work.
fn request_child_stop(host: &mut DesktopHost, stored: &ExecutionSnapshot) -> bool {
    let Some(task) = stored
        .tasks()
        .iter()
        .find(|task| task.h2_reference().is_some() && !task.progression().is_complete())
    else {
        return false;
    };
    let Some(h2) = task.h2_reference() else {
        return false;
    };
    let Ok(view) = host
        .supervision()
        .get(stored.project_id(), h2.supervision_id())
    else {
        return false;
    };
    let request_id = herness_supervision::SupervisionRequestId::new(stored.project_id());
    let Ok(operation) = herness_supervision::operations::SupervisionOperationRequest::new(
        request_id,
        h2.supervision_id(),
        herness_supervision::operations::HumanOperation::Stop,
        view.revision,
    ) else {
        return false;
    };
    let confirmation = host.confirm_supervision(ConfirmationKind::Stop);
    host.supervision_stop(operation, false, Some(confirmation))
        .is_ok()
}

fn final_check_ids(host: &DesktopHost, snapshot: &ExecutionSnapshot) -> Vec<String> {
    let store = host.store_handle();
    let guard = store.lock();
    let Ok(ids) = guard.sdd_approval_ids(snapshot.project_id()) else {
        return Vec::new();
    };
    for approval_id in ids {
        let Ok(Some(approval)) = guard.latest_sdd_approval(snapshot.project_id(), approval_id)
        else {
            continue;
        };
        if approval.plan().digest() == snapshot.plan().digest()
            && approval.plan().plan_revision() == snapshot.plan().approved_revision()
        {
            return approval.plan().parsed().final_check_ids().to_vec();
        }
    }
    Vec::new()
}

fn finish_blockers(
    snapshot: &ExecutionSnapshot,
    final_checks_missing: bool,
) -> Vec<SddFinishBlockerView> {
    let mut blockers = Vec::new();
    if !matches!(
        snapshot.state(),
        ExecutionState::ReadyForFinish | ExecutionState::Committing
    ) {
        blockers.push(SddFinishBlockerView::durable(
            "execution_state",
            format!(
                "the execution is {}, not a finishable state",
                snapshot.state().as_str()
            ),
        ));
    }
    for task in snapshot.tasks() {
        if task.progression() != herness_sdd_execute::TaskProgression::Complete {
            blockers.push(SddFinishBlockerView::durable(
                "task_not_complete",
                format!("Task {} is not complete", task.task().number().get()),
            ));
        }
    }
    if let Some(stop) = snapshot.stop() {
        blockers.push(SddFinishBlockerView::durable(
            "open_stop",
            format!("an open stop ({}) must be resolved", stop.reason().as_str()),
        ));
    }
    if snapshot.workspace().baseline().is_none() {
        blockers.push(SddFinishBlockerView::durable(
            "baseline_missing",
            "the execution has no fixed Branch baseline",
        ));
    }
    if snapshot.applied_revision().state() == herness_sdd_execute::AppliedRevisionState::Stale {
        blockers.push(SddFinishBlockerView::durable(
            "applied_revision_stale",
            "a newer approved plan revision exists; history is retained but the applied revision \
             is stale",
        ));
    }
    if final_checks_missing {
        blockers.push(SddFinishBlockerView::durable(
            "final_checks_unknown",
            "the approved plan's finalChecks identifiers are not readable from the current approval",
        ));
    }
    blockers.push(SddFinishBlockerView::durable(
        "final_evidence_not_verified",
        "the final-state evidence decision is owned by the finish composition; this read does not \
         declare the execution ready",
    ));
    blockers
}

/// Builds the live `ApprovalInputs` a resume and a start verification use.
pub fn live_inputs(
    host: &DesktopHost,
    approval: &ExecutionApproval,
) -> Result<ApprovalInputs, SddExecutionError> {
    let project = approval.project_id();
    let config = host.supervision().config().get(project);
    let connection = approval.connection().connection_id();
    let profile = approval.connection().profile();
    let consents = granted_consents(&config);
    let h3 = host
        .store_handle()
        .lock()
        .load_html_sync_settings(project)
        .ok()
        .flatten()
        .map(|record| {
            H3ApprovalBinding::new(
                record.settings().version(),
                Vec::new(),
                vec!["html-sync".to_owned()],
            )
        })
        .transpose()?;
    let baseline = current_baseline(host, project);
    CurrentInputs::from_approval(approval, connection, profile, consents, h3, baseline)
        .map(|inputs| inputs.inputs().clone())
}

fn current_baseline(
    host: &DesktopHost,
    project: ProjectId,
) -> Option<herness_sdd_execute::Baseline> {
    let store = host.store_handle();
    let guard = store.lock();
    let ids = guard.sdd_approval_ids(project).ok()?;
    for approval_id in ids {
        let Some(approval) = guard.latest_sdd_approval(project, approval_id).ok()? else {
            continue;
        };
        if let Some(baseline) = approval.workspace().baseline() {
            return Some(baseline.clone());
        }
    }
    None
}
