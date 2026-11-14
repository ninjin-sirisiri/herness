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
//! There is no fallback parser: an unusable exchange is an explicit
//! `unavailable`, never a `task-brief` scratch parse or a Rust guess.

pub mod git;
pub mod pack;
pub mod readiness;
pub mod source;
pub mod workspace;

pub use git::{
    GitProcessOutput, GitRunner, GitStatusEntry, GitWorktree, GitWorktreeStatus,
    WORKSPACE_GIT_TIMEOUT,
};
pub use pack::{
    INSPECTOR_OUTPUT_LIMIT, INSPECTOR_SCRIPT, INSPECTOR_TIMEOUT, MINIMUM_PYTHON, PackBinding,
    PackInspector, PlanImporter, RootedPlanSource,
};
pub use readiness::{DesktopH4Readiness, FixedReadinessDocuments, ReadinessDocumentSource};
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
