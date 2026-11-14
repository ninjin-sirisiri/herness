//! Desktop H4 SDD execution adapters.
//!
//! This module is the desktop-side composition boundary for host-owned SDD
//! execution. It contains no Tauri window, IPC command, or UI type: the trusted
//! command layer (Task 21) and the approval registry (Task 13) call it, and it is
//! exercised directly by the `herness-sdd-execute-tests` workspace suite.
//!
//! Task 7 adds the real Git workspace adapter:
//!
//! * [`git::GitRunner`] is the only Git process caller in this module. Every call
//!   is one fixed argv in the selected checkout, launched through the shared
//!   [`herness_core::ProcessSupervisor`] as a host activity. Read-only calls pass
//!   `--no-optional-locks`, so observing never refreshes the index.
//! * [`workspace::WorkspaceAdapter`] implements H4's
//!   [`herness_sdd_execute::WorkspacePort`]: it resolves the one-time worktree
//!   decision, verifies the selected checkout before a start, creates an isolated
//!   worktree only when that was explicitly approved, runs the single permitted
//!   `.gitignore` preparation commit through `herness_core`'s host Git boundary,
//!   and fixes the branch baseline as one full SHA exactly once.
//!
//! Stage, gate, and commit stay in `herness_core::runtime::host_git`; this module
//! never stages, commits, amends, rebases, resets, cleans, or checks out a change,
//! and it never writes outside the selected checkout.
//!
//! Task 12 adds the real pack inspector bridge and the side-effect-free preview:
//!
//! * [`pack::PackInspector`] is the only process caller that starts the pack. It
//!   runs `python3 <pack>/scripts/plan-inspect` as one fixed argv through the
//!   shared supervisor, with the project root as cwd, the exact request bytes on
//!   stdin, a bounded capture, and a 30 second (or shorter remaining Task) budget.
//!   It verifies every claimed execution-contract input against the pack root and
//!   returns a [`pack::PackBinding`]; a stale or different fingerprint is
//!   `unavailable`, never a partial parse.
//! * [`pack::PlanImporter`] ties that bridge to a plan source and the approved
//!   alias roots. Its `import` reads the exact plan bytes, sends them to
//!   `inspect`, revalidates the response, and reads and verifies one snapshot per
//!   declared spec/source. It holds no H2, model, H3, store, or Git port, so the
//!   type system makes those side effects unreachable from a preview.
//! * [`source::ConfinedReader`] and [`source::PlanFileSource`] are the bounded,
//!   read-only readers. Every read is confined to a canonical root, refuses a
//!   symlink escape, a directory, or an oversize file, and never truncates.
//!
//! Task 14 adds [`packet`]: it turns one approved Task, the verified spec
//! snapshots, and the stored earlier-Task handoffs into the immutable packet the
//! child receives, plus the H2 [`H4PacketBinding`](herness_supervision::H4PacketBinding)
//! built from the packet's own digests. Task 15's coordinator calls
//! [`packet::task_packet`] before it creates the H2 target, passes
//! [`packet::H4TaskPacket::prompt`] as `H4TaskLaunch::instructions`, and passes
//! [`packet::H4TaskPacket::h2_binding`] as the launch's packet binding. H2 stores
//! the prompt in the target's immutable `WorkPacket`, so the first run, every
//! continuation, and a restore all render the same constraints and spec context;
//! the H4 path never needs `bind_owner_instruction`, which exists for H3
//! generation supersession and refuses an H4 owner kind. After the host commit,
//! [`packet::task_handoff`] turns the accepted report into the handoff the next
//! Task's packet carries.
//!
//! There is no fallback parser: an unusable exchange is an explicit
//! `unavailable`, never a `task-brief` scratch parse or a Rust guess.
//!
//! Task 17 adds the commit half of the Task completion:
//!
//! * [`finalize::HostGitCommitBoundary`] is the one [`herness_sdd_execute::HostGitPort`]
//!   over `herness_core`'s host Git boundary. It converts a recorded
//!   [`herness_sdd_execute::GitJournalEntry`] into the boundary's intent with the
//!   same explicit paths, bytes, digests, message, trailers, expected
//!   parent/tree, gate, and hook digest, and turns the report back into a
//!   [`herness_sdd_execute::GitCommitOutcome`]. The boundary's
//!   [`herness_core::HostGitAuthorization`] is minted only from the approved
//!   [`herness_sdd_execute::CommitAuthorization`].
//! * [`finalize::GitCheckoutObserver`] is the read-only
//!   [`herness_sdd_execute::CommitObservationPort`]: fixed argv for branch, HEAD,
//!   tree, parent, message, and index, plus one confined read per tracked path.
//! * [`host_commit::DesktopHostCommit`] implements
//!   [`barrier::HostCommitCompletion`]: it fixes the target set from the
//!   changes against BASE plus the barrier's verified companions and receipts,
//!   builds the intent, and runs [`herness_sdd_execute::finalize_task`].
//!   [`barrier::HtmlBarrierCompletion`] runs the final HTML barrier first, so a
//!   non-synced Task never reaches the commit.
//!
//! Nothing in this module pushes, pulls, merges, rebases, amends, resets, cleans,
//! or checks out a change, and no path discards a human's uncommitted work.

pub mod barrier;
pub mod composition;
pub mod coordinator;
pub mod finalize;
pub mod git;
pub mod host_commit;
pub mod pack;
pub mod packet;
pub mod readiness;
pub mod registry;
pub mod source;
pub mod workspace;

pub use barrier::{
    BoundTask, DesktopH4BarrierGate, DesktopTaskCompletion, H4RequiredDocuments,
    HostCommitCompletion, HtmlBarrierCompletion, NotConnectedCommit, SharedBarrierGate,
    TaskBarrierGate, VerifiedDocumentSource, VerifiedDocuments, as_readiness_port,
    barrier_allows_finalization, bind_shared_gate, origins_of, readiness_port, required_paths,
    shared_gate, shared_readiness_port,
};
pub use composition::{
    ApprovalOutcome, CurrentInputs, DesktopStartComposition, DesktopWorkspace, LiveStartFacts,
    StartApprovalRequest, UnavailableChildStart, approve_and_start, current_owner_approval,
    desktop_start_composition, ensure_human_start_confirmation, preview_facts,
};
pub use coordinator::{
    ApprovedTaskLaunch, DesktopCoordinator, H2ChildDispatch, H2ChildStatus, child_state,
    child_state_of, supervision_target_id,
};
pub use finalize::{
    ApprovedCommitIdentity, GitCheckoutObserver, HOST_COMMIT_FEATURE, HOST_COMMIT_OBSERVE_FEATURE,
    HostGitCommitBoundary, checkout_hooks_digest, outcome_from_report, recovery_of, rejection_of,
    unknown_of, verified_derived_targets,
};
pub use git::{
    GitProcessOutput, GitRunner, GitStatusEntry, GitWorktree, GitWorktreeStatus,
    WORKSPACE_GIT_TIMEOUT,
};
pub use host_commit::{DesktopHostCommit, TaskCommitExpectation};
pub use pack::{
    INSPECTOR_OUTPUT_LIMIT, INSPECTOR_SCRIPT, INSPECTOR_TIMEOUT, MINIMUM_PYTHON, PackBinding,
    PackInspector, PlanImporter, RootedPlanSource,
};
pub use packet::{
    H4TaskPacket, MAX_PACKET_BYTES, TaskDispatchSeam, TaskPacketOutcome, TaskPacketRefusal,
    packet_binding, packet_scope, prior_context, read_report, report_expectations, report_path,
    snapshot_sections, spec_section, task_handoff, task_packet,
};
pub use readiness::{DesktopH4Readiness, FixedReadinessDocuments, ReadinessDocumentSource};
pub use registry::{
    ApprovalBuild, ApprovalDraft, H4_BUDGET_POLICY_VERSION, H4_CONDITION_VERSION,
    H4StartApprovalRegistry, MemoryStartStore, PreviewFacts, PreviewTaskFacts, StartChildPort,
    StartComposition, StartHtmlPort, StartHtmlRequest, StartOutcome, StartRequest,
    StartWorkspacePort, UnsyncedStartHtml, derivation_uuid, h4_owner_ref,
};
pub use source::{
    ConfinedRead, ConfinedReader, PlanFileSource, read_and_verify_specs, read_spec_snapshot,
};
pub use workspace::{
    ApprovedDocument, ApprovedDocumentKind, BASE_BRANCH_FEATURE, BaselineRecord, GITIGNORE_PATH,
    HostGitPreparationCommit, ISOLATION_FEATURE, MemoryBaselineRecord, NoPreparationCommit,
    PREPARATION_COMMIT_FEATURE, PROGRESS_LEDGER_PATH, PreparationCommitPort, SDD_IGNORE_LINE,
    WorkspaceAdapter, WorkspaceDecision, WorkspaceExpectation, WorkspaceSelection,
    WorkspaceSelectionAnswer, WorkspaceSelectionInput, WorkspaceSelectionQuestion,
    WorkspaceSelectionSource, WorkspaceUndecided,
};
