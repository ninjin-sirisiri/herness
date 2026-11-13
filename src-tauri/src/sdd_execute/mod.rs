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

pub mod git;
pub mod workspace;

pub use git::{
    GitProcessOutput, GitRunner, GitStatusEntry, GitWorktree, GitWorktreeStatus,
    WORKSPACE_GIT_TIMEOUT,
};
pub use workspace::{
    ApprovedDocument, ApprovedDocumentKind, BASE_BRANCH_FEATURE, BaselineRecord, GITIGNORE_PATH,
    HostGitPreparationCommit, ISOLATION_FEATURE, MemoryBaselineRecord, NoPreparationCommit,
    PREPARATION_COMMIT_FEATURE, PROGRESS_LEDGER_PATH, PreparationCommitPort, SDD_IGNORE_LINE,
    WorkspaceAdapter, WorkspaceDecision, WorkspaceExpectation, WorkspaceSelection,
    WorkspaceSelectionAnswer, WorkspaceSelectionInput, WorkspaceSelectionQuestion,
    WorkspaceSelectionSource, WorkspaceUndecided,
};
