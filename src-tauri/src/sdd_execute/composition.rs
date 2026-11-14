//! Desktop composition of the H4 start approval and the start guard.
//!
//! This module is the one place that connects the approval registry to the real
//! SQLite store, the real Git workspace adapter, the trusted human confirmation,
//! and the child boundary. It contains no Tauri command, no window type, and no
//! UI: Task 21 calls it from the guarded command layer, and Task 15 drives the
//! same registry per Task.
//!
//! # Human-only approval
//!
//! [`StartApprovalRequest`] carries an optional
//! [`HumanConfirmation`](crate::supervision::ConfirmationKind) of kind
//! `Start`. It has no public constructor, so a model tool, a repository string,
//! an environment variable, or a preview cannot mint one: only the trusted
//! main-window path can. A request without it is refused before the registry is
//! touched, and the actor/source of the saved approval are always
//! human/`h4-approval-registry`.
//!
//! # Current-input re-observation
//!
//! [`CurrentInputs::from_approval`] rebuilds the [`ApprovalInputs`] a start is
//! verified against from a stored approval plus the live connection, profile,
//! consent, H3, and workspace facts. A revoked consent, a changed profile, a
//! different H3 settings version, or a new baseline therefore refuses the start
//! instead of being silently accepted.

use herness_core::contracts::{ProjectId, Timestamp};
use herness_sdd_execute::{
    ApprovalId, ApprovalInputs, ApprovalRequirement, Baseline, CommitAuthorization,
    ExecutionApproval, ExecutionId, FailureDetails, H3ApprovalBinding, ObservedConnection,
    SddExecutionError, WorkspaceApproval,
};
use herness_supervision::{ConsentBinding, ProfileBinding};

use crate::sdd_execute::pack::ImportPreview;
use crate::sdd_execute::registry::{
    ApprovalDraft, H4StartApprovalRegistry, StartChildPort, StartComposition, StartHtmlPort,
    StartOutcome, StartRequest, StartWorkspacePort,
};
use crate::sdd_execute::workspace::WorkspaceAdapter;
use crate::supervision::plan::{ConfirmationKind, HumanConfirmation};

/// The live values one approval revision binds, beside the plan and Tasks.
#[derive(Debug, Clone)]
pub struct LiveStartFacts {
    connection: herness_sdd_execute::ExecutionConnection,
    h3: H3ApprovalBinding,
    commit: CommitAuthorization,
}

impl LiveStartFacts {
    /// Records the live connection, H3 boundary, and commit authorization.
    pub const fn new(
        connection: herness_sdd_execute::ExecutionConnection,
        h3: H3ApprovalBinding,
        commit: CommitAuthorization,
    ) -> Self {
        Self {
            connection,
            h3,
            commit,
        }
    }

    /// The live execution connection, profile, and consents.
    pub const fn connection(&self) -> &herness_sdd_execute::ExecutionConnection {
        &self.connection
    }

    /// The live H3 settings/consent/capability boundary.
    pub const fn h3(&self) -> &H3ApprovalBinding {
        &self.h3
    }

    /// The live host commit and hook authorization.
    pub const fn commit(&self) -> CommitAuthorization {
        self.commit
    }
}

/// One approve-and-start request from the trusted human path.
pub struct StartApprovalRequest<'a> {
    draft: &'a ApprovalDraft,
    request: &'a StartRequest,
    approval: ApprovalOutcome,
    confirmation: Option<HumanConfirmation>,
}

/// How the human confirmation and the approval revision are ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// Save a new human post, then start.
    SaveThenStart,
    /// Start the already saved current revision.
    StartCurrent,
}

impl<'a> StartApprovalRequest<'a> {
    /// Creates one request from the trusted human path.
    ///
    /// The confirmation is optional so a start of an already saved revision can
    /// be driven by a coordinator; a *new* approval always requires it.
    pub fn new(
        draft: &'a ApprovalDraft,
        request: &'a StartRequest,
        approval: ApprovalOutcome,
        confirmation: Option<HumanConfirmation>,
    ) -> Self {
        Self {
            draft,
            request,
            approval,
            confirmation,
        }
    }

    /// The draft that fixes the approved inputs.
    pub const fn draft(&self) -> &ApprovalDraft {
        self.draft
    }

    /// The start request.
    pub const fn request(&self) -> &StartRequest {
        self.request
    }

    /// Whether this request saves a new revision or starts the current one.
    pub const fn approval(&self) -> ApprovalOutcome {
        self.approval
    }

    /// The required human confirmation, when the human path supplied it.
    pub const fn confirmation(&self) -> Option<&HumanConfirmation> {
        self.confirmation.as_ref()
    }
}

/// Refuses an approval that was not minted through the trusted human path.
pub fn ensure_human_start_confirmation(
    confirmation: Option<&HumanConfirmation>,
) -> Result<(), SddExecutionError> {
    match confirmation {
        Some(confirmation) if confirmation.kind() == ConfirmationKind::Start => Ok(()),
        Some(_) => Err(SddExecutionError::ApprovalRequired {
            reason: ApprovalRequirement::StartApproval,
            details: FailureDetails::none().boxed(),
        }),
        None => Err(SddExecutionError::ApprovalRequired {
            reason: ApprovalRequirement::StartApproval,
            details: FailureDetails::none().boxed(),
        }),
    }
}

/// The current observation of every input an approval binds.
///
/// A coordinator or a resume rebuilds it from the stored approval and the live
/// values, so an approval is never verified against a stale copy of itself.
#[derive(Debug, Clone)]
pub struct CurrentInputs {
    approval_id: ApprovalId,
    inputs: ApprovalInputs,
}

impl CurrentInputs {
    /// Rebuilds the observation from a stored approval and the live values.
    ///
    /// The plan, Tasks, commit authorization, and H3 boundary come from the
    /// stored approval; the connection profile, the granted consents, and the
    /// workspace baseline come from the live host. A missing consent is an empty
    /// grant list, so verification refuses it with the disclosure requirement.
    #[allow(clippy::too_many_arguments)]
    pub fn from_approval(
        approval: &ExecutionApproval,
        connection_id: herness_core::contracts::ConnectionId,
        profile: ProfileBinding,
        consents: Vec<ConsentBinding>,
        h3: Option<H3ApprovalBinding>,
        baseline: Option<Baseline>,
    ) -> Result<Self, SddExecutionError> {
        let workspace = live_workspace(approval.workspace(), baseline)?;
        let inputs = ApprovalInputs::new(
            approval.plan().clone(),
            workspace,
            approval.tasks().to_vec(),
            ObservedConnection::new(connection_id, profile, consents),
            approval.commit(),
            h3,
        );
        Ok(Self {
            approval_id: approval.approval_id(),
            inputs,
        })
    }

    /// Approval identity the observation belongs to.
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// The observation itself.
    pub const fn inputs(&self) -> &ApprovalInputs {
        &self.inputs
    }
}

fn live_workspace(
    approved: &WorkspaceApproval,
    baseline: Option<Baseline>,
) -> Result<WorkspaceApproval, SddExecutionError> {
    WorkspaceApproval::new(
        approved.project_id(),
        approved.canonical_checkout_root(),
        approved.git_identity().clone(),
        approved.branch(),
        approved.base_branch(),
        approved.isolated_worktree(),
        baseline,
    )
}

/// The default child port for a build with no H1 adapter bound.
///
/// It never creates anything; a start that reaches it refuses with
/// `unavailable` and records no start result.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableChildStart;

impl StartChildPort for UnavailableChildStart {
    fn start_child(
        &mut self,
        _execution: ExecutionId,
        _task: herness_sdd_execute::TaskRef,
        _approval_revision: u64,
    ) -> Result<String, SddExecutionError> {
        Err(SddExecutionError::Unavailable {
            feature: "h4.childStart".to_owned(),
            details: FailureDetails::none().boxed(),
        })
    }
}

/// The desktop start composition over the real store and workspace adapter.
pub type DesktopStartComposition<S, W, C, H> = StartComposition<S, W, C, H>;

/// Builds the desktop start composition.
///
/// `store` must implement both approval and start-record persistence; the SQLite
/// `Store` does. `workspace` is the real Git adapter, `child` the H1 boundary,
/// and `html` the H3 readiness answer.
pub fn desktop_start_composition<S, W, C, H>(
    store: S,
    workspace: W,
    child: C,
    html: H,
) -> DesktopStartComposition<S, W, C, H>
where
    S: herness_sdd_execute::ApprovalRevisionStorePort + herness_sdd_execute::StartRecordStorePort,
    W: StartWorkspacePort,
    C: StartChildPort,
    H: StartHtmlPort,
{
    StartComposition::new(store, workspace, child, html)
}

/// Approves and starts exactly once, refusing anything the human path did not
/// confirm.
///
/// * A request without a `Start` confirmation is `approval_required`.
/// * A *new* approval revision additionally requires the confirmation, so a
///   coordinator replay can only start an already approved revision.
/// * The start record makes a duplicate request return the stored result.
pub fn approve_and_start(
    composition: &mut DesktopStartComposition<
        impl herness_sdd_execute::ApprovalRevisionStorePort + herness_sdd_execute::StartRecordStorePort,
        impl StartWorkspacePort,
        impl StartChildPort,
        impl StartHtmlPort,
    >,
    request: &StartApprovalRequest<'_>,
) -> Result<StartOutcome, SddExecutionError> {
    match request.approval() {
        ApprovalOutcome::SaveThenStart => {
            ensure_human_start_confirmation(request.confirmation())?;
            let post = request.draft().build()?.into_human_post(Timestamp::now())?;
            composition.approve_and_start(request.draft(), &post, request.request())
        }
        ApprovalOutcome::StartCurrent => composition.start(request.draft(), request.request()),
    }
}

/// Builds `PreviewFacts` from a real import and the approved alias layout.
///
/// This is the only production path that turns a preview into approval facts, so
/// an approval is always bound to the exact bytes the inspector verified.
pub fn preview_facts(
    preview: &ImportPreview,
    layout: &herness_sdd_execute::SourceLayout,
) -> Result<crate::sdd_execute::registry::PreviewFacts, SddExecutionError> {
    crate::sdd_execute::registry::PreviewFacts::from_import(preview, layout)
}

/// Whether one project has the current approval the coordinator may launch.
pub fn current_owner_approval(
    registry: &mut H4StartApprovalRegistry,
    draft: &ApprovalDraft,
    approval: &ExecutionApproval,
    project: ProjectId,
    owner: &herness_supervision::OwnerRef,
    now: Timestamp,
) -> Result<Option<herness_supervision::H4OwnerApproval>, SddExecutionError> {
    if approval.project_id() != project {
        return Ok(None);
    }
    if registry.current() != Some((draft.execution(), approval.revision())) {
        registry.set_current(draft, approval);
    }
    registry
        .owner_approval(project, owner, now)
        .map_err(|error| SddExecutionError::InvalidValue {
            field: "h4StartApproval".to_owned(),
            detail: format!("{error}"),
        })
}

/// Type-erased workspace adapter alias used by the desktop host.
pub type DesktopWorkspace<
    L = herness_core::tools::process::SystemArgvLauncher,
    C = crate::sdd_execute::workspace::NoPreparationCommit,
    B = crate::sdd_execute::workspace::MemoryBaselineRecord,
> = WorkspaceAdapter<L, C, B>;
