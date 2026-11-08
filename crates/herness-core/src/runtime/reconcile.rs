//! Restart reconciliation reports.
//!
//! Reconciling is read-only with respect to the project and side effects: the
//! runtime reads persisted operations and, for native file intents without a
//! result, compares the current file to the frozen intended content. It never
//! executes, retries, rolls back, or reuses a prior approval.

use std::path::Path;

use serde::Serialize;

use crate::contracts::connection::ConnectionInfo;
use crate::contracts::ids::{OperationId, ProjectId, RunId};
use crate::contracts::operation::{
    FrozenOperation, OperationOutcome, OperationRecord, OperationResult,
};
use crate::contracts::path::AbsolutePath;
use crate::contracts::run::RunState;
use crate::contracts::time::Timestamp;
use crate::permissions::{PermissionMode, PolicyVersion};
use crate::runtime::shutdown::ShutdownOutcome;
use crate::runtime::state::ShutdownRecord;
use crate::runtime::views::PendingApproval;
use crate::tools::path::ProjectRoot;
use crate::tools::{ToolArguments, ToolName, hash_bytes};

/// Restart report for every project owned by one runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationReport {
    projects: Vec<ProjectReconciliation>,
    previous_shutdown: Option<ShutdownSummary>,
    discarded_deferred_messages: u64,
}

impl ReconciliationReport {
    /// Creates a report.
    pub(crate) const fn new(
        projects: Vec<ProjectReconciliation>,
        previous_shutdown: Option<ShutdownSummary>,
        discarded_deferred_messages: u64,
    ) -> Self {
        Self {
            projects,
            previous_shutdown,
            discarded_deferred_messages,
        }
    }

    /// Per-project reports in stable project identifier order.
    pub fn projects(&self) -> &[ProjectReconciliation] {
        &self.projects
    }

    /// Summary of the previous process's explicit shutdown, when one exists.
    pub const fn previous_shutdown(&self) -> Option<&ShutdownSummary> {
        self.previous_shutdown.as_ref()
    }

    /// In-memory host-result messages the previous process discarded instead of
    /// replaying after restart.
    pub const fn discarded_deferred_messages(&self) -> u64 {
        self.discarded_deferred_messages
    }

    /// Replaces the connection status list after the host has restored the
    /// persisted non-secret settings into its registry.
    pub fn replace_connections(&mut self, connections: Vec<ConnectionInfo>) {
        for project in &mut self.projects {
            project.connections = connections.clone();
        }
    }
}

/// Non-secret summary of the previous process's explicit shutdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShutdownSummary {
    outcome: ShutdownOutcome,
    started_at: Timestamp,
    finished_at: Option<Timestamp>,
    stopped_runs: usize,
    unconfirmed_runs: Vec<RunId>,
    remaining_runs: Vec<RunId>,
    discarded_deferred_messages: u64,
    save_failures: u32,
}

impl ShutdownSummary {
    pub(crate) fn from_record(record: &ShutdownRecord) -> Self {
        Self {
            outcome: record.outcome,
            started_at: record.started_at,
            finished_at: record.finished_at,
            stopped_runs: record.stopped_runs.len(),
            unconfirmed_runs: record.unconfirmed_runs.clone(),
            remaining_runs: record.remaining_runs.clone(),
            discarded_deferred_messages: record.discarded_deferred_messages,
            save_failures: record.save_failures,
        }
    }

    /// Outcome recorded by the quitting process.
    pub const fn outcome(&self) -> ShutdownOutcome {
        self.outcome
    }

    /// When the quit flow started.
    pub const fn started_at(&self) -> Timestamp {
        self.started_at
    }

    /// When the quit flow recorded its final state.
    pub const fn finished_at(&self) -> Option<Timestamp> {
        self.finished_at
    }

    /// Number of runs included in the attempt.
    pub const fn stopped_runs(&self) -> usize {
        self.stopped_runs
    }

    /// Runs whose stop was unconfirmed or failed.
    pub fn unconfirmed_runs(&self) -> &[RunId] {
        &self.unconfirmed_runs
    }

    /// Runs that were still active when the attempt ended.
    pub fn remaining_runs(&self) -> &[RunId] {
        &self.remaining_runs
    }

    /// Host-result messages discarded instead of replayed.
    pub const fn discarded_deferred_messages(&self) -> u64 {
        self.discarded_deferred_messages
    }

    /// Number of stop or save failures recorded.
    pub const fn save_failures(&self) -> u32 {
        self.save_failures
    }
}

/// Restart report for one project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectReconciliation {
    project_id: ProjectId,
    path: AbsolutePath,
    runs: Vec<RunReconciliation>,
    operations: Vec<OperationReconciliation>,
    pending_approvals: Vec<PendingApproval>,
    connections: Vec<ConnectionInfo>,
    permission: PermissionReconciliation,
}

impl ProjectReconciliation {
    /// Creates a project report.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        project_id: ProjectId,
        path: AbsolutePath,
        runs: Vec<RunReconciliation>,
        operations: Vec<OperationReconciliation>,
        pending_approvals: Vec<PendingApproval>,
        connections: Vec<ConnectionInfo>,
        permission: PermissionReconciliation,
    ) -> Self {
        Self {
            project_id,
            path,
            runs,
            operations,
            pending_approvals,
            connections,
            permission,
        }
    }

    /// Project reported.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Canonical project path.
    pub const fn path(&self) -> &AbsolutePath {
        &self.path
    }

    /// Run states after restore. Previously active runs become `interrupted`.
    pub fn runs(&self) -> &[RunReconciliation] {
        &self.runs
    }

    /// Unresolved operations and their evidence classification.
    pub fn operations(&self) -> &[OperationReconciliation] {
        &self.operations
    }

    /// Pending approvals. Every restored approval is non-reusable.
    pub fn pending_approvals(&self) -> &[PendingApproval] {
        &self.pending_approvals
    }

    /// Current non-secret connection availability.
    pub fn connections(&self) -> &[ConnectionInfo] {
        &self.connections
    }

    /// Current permission context.
    pub const fn permission(&self) -> &PermissionReconciliation {
        &self.permission
    }
}

/// One restored run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunReconciliation {
    run_id: RunId,
    previous_state: RunState,
    state: RunState,
    awaiting_approval: bool,
}

impl RunReconciliation {
    /// Creates a run report.
    pub(crate) const fn new(
        run_id: RunId,
        previous_state: RunState,
        state: RunState,
        awaiting_approval: bool,
    ) -> Self {
        Self {
            run_id,
            previous_state,
            state,
            awaiting_approval,
        }
    }

    /// Run reported.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// State before restore.
    pub const fn previous_state(&self) -> RunState {
        self.previous_state
    }

    /// State after restore.
    pub const fn state(&self) -> RunState {
        self.state
    }

    /// Whether a restored approval refers to this run.
    pub const fn awaiting_approval(&self) -> bool {
        self.awaiting_approval
    }
}

/// How an unresolved operation was classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationSource {
    /// A durable result already exists.
    RecordedResult,
    /// Current native file content was compared with the frozen intent.
    NativeFileContent,
    /// The operation was a shell command whose completion cannot be proven.
    ShellUncertain,
    /// Read/search has no side effect.
    NoSideEffect,
    /// No usable evidence exists; human reconciliation is required.
    MissingEvidence,
}

/// One unresolved operation with its evidence classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationReconciliation {
    operation_id: OperationId,
    tool: ToolName,
    outcome: OperationOutcome,
    source: ReconciliationSource,
    detail: Option<String>,
}

impl OperationReconciliation {
    /// Creates an operation report.
    pub(crate) const fn new(
        operation_id: OperationId,
        tool: ToolName,
        outcome: OperationOutcome,
        source: ReconciliationSource,
        detail: Option<String>,
    ) -> Self {
        Self {
            operation_id,
            tool,
            outcome,
            source,
            detail,
        }
    }

    /// Operation reported.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Tool that was requested.
    pub const fn tool(&self) -> ToolName {
        self.tool
    }

    /// Evidence-supported classification.
    pub const fn outcome(&self) -> OperationOutcome {
        self.outcome
    }

    /// Kind of evidence used.
    pub const fn source(&self) -> ReconciliationSource {
        self.source
    }

    /// Sanitized explanation when a human needs to verify the result.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

/// Current permission context after restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionReconciliation {
    mode: PermissionMode,
    policy_version: PolicyVersion,
    evaluator_available: bool,
    automatic_mode_usable: bool,
}

impl PermissionReconciliation {
    /// Creates a permission report.
    pub(crate) fn new(
        mode: PermissionMode,
        policy_version: PolicyVersion,
        evaluator_available: bool,
    ) -> Self {
        Self {
            mode,
            policy_version,
            evaluator_available,
            automatic_mode_usable: evaluator_available,
        }
    }

    /// Current mode.
    pub const fn mode(&self) -> PermissionMode {
        self.mode
    }

    /// Current policy version.
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// Whether an evaluator is connected and available.
    pub const fn evaluator_available(&self) -> bool {
        self.evaluator_available
    }

    /// Whether automatic mode could be selected now.
    pub const fn automatic_mode_usable(&self) -> bool {
        self.automatic_mode_usable
    }
}

/// Classifies one unresolved operation without executing anything.
pub(crate) fn classify_operation(
    project_root: &Path,
    record: &OperationRecord,
) -> (OperationOutcome, ReconciliationSource, Option<String>) {
    if let Some(result) = record.result() {
        return classify_recorded(result);
    }
    let operation = record.intent().operation();
    match operation.tool() {
        ToolName::Read | ToolName::Search => (
            OperationOutcome::NotApplied,
            ReconciliationSource::NoSideEffect,
            Some("read/search has no side effect".to_owned()),
        ),
        ToolName::Bash => (
            OperationOutcome::Unverifiable,
            ReconciliationSource::ShellUncertain,
            Some("the shell completed or failed without durable evidence".to_owned()),
        ),
        ToolName::Write | ToolName::Edit => classify_file_intent(project_root, operation),
    }
}

fn classify_recorded(
    result: &OperationResult,
) -> (OperationOutcome, ReconciliationSource, Option<String>) {
    (
        result.outcome(),
        ReconciliationSource::RecordedResult,
        match result.outcome() {
            OperationOutcome::Applied => None,
            OperationOutcome::NotApplied => None,
            OperationOutcome::Unverifiable => Some(
                "the recorded result is unverifiable; human reconfirmation is required".to_owned(),
            ),
        },
    )
}

fn classify_file_intent(
    project_root: &Path,
    operation: &FrozenOperation,
) -> (OperationOutcome, ReconciliationSource, Option<String>) {
    let Ok(root) = ProjectRoot::new(project_root) else {
        return (
            OperationOutcome::Unverifiable,
            ReconciliationSource::MissingEvidence,
            Some("the project root is no longer readable".to_owned()),
        );
    };
    let raw = match operation.arguments() {
        ToolArguments::Write(arguments) => arguments.path.as_str(),
        ToolArguments::Edit(arguments) => arguments.path.as_str(),
        _ => {
            return (
                OperationOutcome::Unverifiable,
                ReconciliationSource::MissingEvidence,
                Some("the operation is not a native file intent".to_owned()),
            );
        }
    };
    let resolved = match root.existing_file(operation.cwd(), raw) {
        Ok(path) => path,
        Err(crate::contracts::errors::FileFailure::NotFound { .. }) => {
            return match operation.tool() {
                ToolName::Write => (
                    OperationOutcome::NotApplied,
                    ReconciliationSource::NativeFileContent,
                    Some("the target file is absent".to_owned()),
                ),
                ToolName::Edit => (
                    OperationOutcome::Unverifiable,
                    ReconciliationSource::NativeFileContent,
                    Some("the edit target is absent; absence does not prove the edit was not applied".to_owned()),
                ),
                _ => unreachable!("file intent is write or edit"),
            };
        }
        Err(error) => {
            return (
                OperationOutcome::Unverifiable,
                ReconciliationSource::NativeFileContent,
                Some(error.to_string()),
            );
        }
    };
    let bytes = match std::fs::read(resolved.absolute()) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                OperationOutcome::Unverifiable,
                ReconciliationSource::NativeFileContent,
                Some(format!("cannot read the target file: {:?}", error.kind())),
            );
        }
    };
    match operation.arguments() {
        ToolArguments::Write(arguments) => {
            if bytes == arguments.content.as_bytes() {
                (
                    OperationOutcome::Applied,
                    ReconciliationSource::NativeFileContent,
                    None,
                )
            } else {
                (
                    OperationOutcome::Unverifiable,
                    ReconciliationSource::NativeFileContent,
                    Some(format!(
                        "the target content differs from the intent (current version {})",
                        hash_bytes(&bytes)
                    )),
                )
            }
        }
        ToolArguments::Edit(arguments) => {
            let Ok(text) = String::from_utf8(bytes) else {
                return (
                    OperationOutcome::Unverifiable,
                    ReconciliationSource::NativeFileContent,
                    Some("the target file is not valid UTF-8".to_owned()),
                );
            };
            let old_present = text.contains(&arguments.old_text);
            let new_present = text.contains(&arguments.new_text);
            match (old_present, new_present) {
                (true, false) => (
                    OperationOutcome::NotApplied,
                    ReconciliationSource::NativeFileContent,
                    Some("the original text is still present".to_owned()),
                ),
                (false, true) => (
                    OperationOutcome::Applied,
                    ReconciliationSource::NativeFileContent,
                    None,
                ),
                _ => (
                    OperationOutcome::Unverifiable,
                    ReconciliationSource::NativeFileContent,
                    Some(
                        "the current text matches neither the before nor the after state"
                            .to_owned(),
                    ),
                ),
            }
        }
        _ => unreachable!("classify_file_intent only receives write/edit"),
    }
}
