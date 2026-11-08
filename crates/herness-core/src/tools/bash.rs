//! The `bash` native tool and its host-owned process-group lifecycle.
//!
//! Execution order is fixed:
//!
//! 1. validate the frozen arguments and reject a duplicate operation id;
//! 2. persist a checkpoint, the [`OperationIntent`], and a `shell.started`
//!    event in one store transaction;
//! 3. refuse to spawn when host stop has begun;
//! 4. spawn `/bin/sh -c <command>` in a new process group, record the pid/pgid
//!    in a `shell.spawned` audit event, and capture bounded output;
//! 5. wait, honoring timeout and stop, and terminate the managed group;
//! 6. persist the [`OperationResult`] with a structured
//!    [`ShellObservation`] and a `shell.finished` event in one transaction;
//! 7. only then return.
//!
//! A pre-intent persistence failure means no process is created. A post-run
//! persistence failure is reported as [`ShellFailure::Unverifiable`]; the host
//! does not retry the command, does not roll back its effects, and leaves the
//! intent visible for human reconciliation.
//!
//! A bash operation never emits `file.change` events, never attaches per-file
//! rationales, and never guesses which files changed. Purpose and output are
//! recorded separately from any file evidence.

use std::time::Duration;

use serde::Serialize;

use crate::contracts::errors::{ArgumentViolation, CoreError, ShellFailure};
use crate::contracts::events::{Event, EventDraft, EventKind, EventPayload};
use crate::contracts::ids::{AgentId, IdKind, OperationId, SessionId};
use crate::contracts::operation::{
    FrozenOperation, OperationEvidence, OperationIntent, OperationOutcome, OperationRecord,
    OperationResult,
};
use crate::contracts::path::AbsolutePath;
use crate::contracts::shell::{ShellObservation, ShellStopStatus};
use crate::contracts::time::Timestamp;
use crate::contracts::{Checkpoint, CheckpointFormatVersion, CheckpointPayload};
use crate::ports::{CheckpointCommit, StorePort};
use crate::tools::arguments::BashArgs;
use crate::tools::gateway::ToolExecutor;
use crate::tools::process::{
    CaptureHandle, DEFAULT_CAPTURE_TIMEOUT, DEFAULT_CONFIRM_TIMEOUT, DEFAULT_OUTPUT_LIMIT,
    DEFAULT_TIMEOUT_GRACE, ManagedChild, ManagedSignal, ProcessLauncher, ProcessSupervisor,
    SpawnRequest, SystemLauncher, signal_process_group, spawn_failure, supervise,
};
use crate::tools::{ToolArguments, ToolName};

/// Event kind persisted before the managed process is created.
pub const SHELL_STARTED_EVENT_KIND: &str = "shell.started";
/// Event kind persisted after the managed process group is created.
pub const SHELL_SPAWNED_EVENT_KIND: &str = "shell.spawned";
/// Event kind persisted with the operation result.
pub const SHELL_FINISHED_EVENT_KIND: &str = "shell.finished";

const AUDIT_CHECKPOINT_FORMAT: u32 = 1;
const AUDIT_CHECKPOINT_KIND: &str = "herness.shell-operation";

/// Result of a `bash` command that completed without a stop or timeout.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BashOutput {
    operation_id: OperationId,
    outcome: OperationOutcome,
    observation: ShellObservation,
    notification: Option<Event>,
}

impl BashOutput {
    /// Operation that produced the result.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Durable outcome. A completed command is `Applied` even when its exit
    /// code is non-zero; the observation carries the exit code.
    pub const fn outcome(&self) -> OperationOutcome {
        self.outcome
    }

    /// Structured observation persisted with the result.
    pub const fn observation(&self) -> &ShellObservation {
        &self.observation
    }

    /// Persisted `shell.finished` event, when this call appended one.
    pub const fn notification(&self) -> Option<&Event> {
        self.notification.as_ref()
    }
}

/// `bash` executor behind the permission gateway.
#[derive(Debug)]
pub struct BashExecutor<S, L = SystemLauncher> {
    agent_id: AgentId,
    session_id: SessionId,
    store: S,
    launcher: L,
    supervisor: ProcessSupervisor,
    output_limit: usize,
    timeout_grace: Duration,
    confirm_timeout: Duration,
    capture_timeout: Duration,
}

impl<S, L> BashExecutor<S, L> {
    /// Creates an executor for one agent session.
    pub fn new(
        agent_id: AgentId,
        session_id: SessionId,
        store: S,
        launcher: L,
        supervisor: ProcessSupervisor,
    ) -> Result<Self, CoreError> {
        if agent_id.project_id() != session_id.project_id() {
            return Err(CoreError::CrossProjectReference {
                id_kind: IdKind::Project,
                expected: agent_id.project_id(),
                found: session_id.project_id(),
            });
        }
        Ok(Self {
            agent_id,
            session_id,
            store,
            launcher,
            supervisor,
            output_limit: DEFAULT_OUTPUT_LIMIT,
            timeout_grace: DEFAULT_TIMEOUT_GRACE,
            confirm_timeout: DEFAULT_CONFIRM_TIMEOUT,
            capture_timeout: DEFAULT_CAPTURE_TIMEOUT,
        })
    }

    /// Sets the per-stream head and tail retention size.
    #[must_use]
    pub fn with_output_limit(mut self, limit: usize) -> Self {
        self.output_limit = limit;
        self
    }

    /// Sets the SIGTERM-to-SIGKILL grace for a command timeout.
    #[must_use]
    pub fn with_timeout_grace(mut self, grace: Duration) -> Self {
        self.timeout_grace = grace;
        self
    }

    /// Sets the time to wait for a group to disappear after SIGKILL.
    #[must_use]
    pub fn with_confirm_timeout(mut self, timeout: Duration) -> Self {
        self.confirm_timeout = timeout;
        self
    }

    /// Sets the time to wait for output readers after the group is gone.
    #[must_use]
    pub fn with_capture_timeout(mut self, timeout: Duration) -> Self {
        self.capture_timeout = timeout;
        self
    }

    /// Store connection used for intent, result, and audit persistence.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Mutable store connection, used by tests for fault injection.
    pub const fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Shared process-group supervisor.
    pub const fn supervisor(&self) -> &ProcessSupervisor {
        &self.supervisor
    }

    /// Launcher in use.
    pub const fn launcher(&self) -> &L {
        &self.launcher
    }

    /// Mutable launcher, used by tests.
    pub const fn launcher_mut(&mut self) -> &mut L {
        &mut self.launcher
    }
}

impl<S: StorePort, L: ProcessLauncher> BashExecutor<S, L> {
    fn persist_intent(
        &mut self,
        operation: &FrozenOperation,
        args: &BashArgs,
        started_at: Timestamp,
    ) -> Result<(), CoreError> {
        let event = started_event(operation, self.agent_id, self.session_id, args, started_at)?;
        let checkpoint = audit_checkpoint(operation, "intent", None, None)?;
        let intent = OperationIntent::new(operation.clone(), Timestamp::now());
        let commit = CheckpointCommit::new(checkpoint, Some(intent), vec![event])?;
        match self.store.commit_checkpoint(commit) {
            Ok(_) => Ok(()),
            Err(error @ CoreError::DuplicateOperation { .. }) => Err(error),
            Err(error) => Err(shell_error(ShellFailure::NotExecutable {
                detail: error.to_string(),
            })),
        }
    }

    fn persist_spawned(
        &mut self,
        operation: &FrozenOperation,
        pid: u32,
        pgid: u32,
    ) -> Result<(), CoreError> {
        let event = spawned_event(
            operation,
            self.agent_id,
            self.session_id,
            pid,
            pgid,
            Timestamp::now(),
        )?;
        let checkpoint = audit_checkpoint(operation, "spawned", Some(pid), Some(pgid))?;
        let commit = CheckpointCommit::new(checkpoint, None, vec![event])?;
        self.store
            .commit_checkpoint(commit)
            .map(|_| ())
            .map_err(|error| {
                shell_error(ShellFailure::Unverifiable {
                    detail: error.to_string(),
                })
            })
    }

    fn record_not_applied(&mut self, operation: &FrozenOperation) {
        let result = OperationResult::new(
            OperationOutcome::NotApplied,
            OperationEvidence::new(Vec::new(), false),
            Timestamp::now(),
        );
        // If this record fails, the pending intent remains visible to
        // reconciliation. The caller still receives the original failure.
        let _ = self
            .store
            .record_operation_result(&operation.operation_id(), result);
    }

    fn record_unverifiable_with_observation(
        &mut self,
        operation: &FrozenOperation,
        observation: &ShellObservation,
    ) {
        let result = OperationResult::new(
            OperationOutcome::Unverifiable,
            OperationEvidence::new(Vec::new(), true).with_shell(observation.clone()),
            Timestamp::now(),
        );
        // Best effort: a failing store leaves the pending intent visible.
        let _ = self
            .store
            .record_operation_result(&operation.operation_id(), result);
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_observation(
        &mut self,
        pid: u32,
        pgid: u32,
        started_at: Timestamp,
        completion: crate::tools::process::Completion,
        stdout: CaptureHandle,
        stderr: CaptureHandle,
    ) -> ShellObservation {
        let finished_at = Timestamp::now();
        ShellObservation::new(
            pid,
            pgid,
            completion.exit_code(),
            completion.terminating_signal(),
            completion.stop_status(),
            stdout.wait(self.capture_timeout),
            stderr.wait(self.capture_timeout),
            started_at,
            finished_at,
        )
    }

    fn persist_result(
        &mut self,
        operation: &FrozenOperation,
        observation: ShellObservation,
        outcome: OperationOutcome,
        shell_outcome_unknown: bool,
    ) -> Result<Option<Event>, CoreError> {
        let event = finished_event(operation, self.agent_id, self.session_id, &observation)?;
        let result = OperationResult::new(
            outcome,
            OperationEvidence::new(Vec::new(), shell_outcome_unknown).with_shell(observation),
            Timestamp::now(),
        );
        let receipt = self
            .store
            .record_operation_result_with_events(&operation.operation_id(), result, vec![event])
            .map_err(|error| {
                shell_error(ShellFailure::Unverifiable {
                    detail: error.to_string(),
                })
            })?;
        Ok(receipt.events().first().cloned())
    }
}

impl<S: StorePort, L: ProcessLauncher> ToolExecutor for BashExecutor<S, L> {
    type Output = BashOutput;

    fn execute(&mut self, operation: &FrozenOperation) -> Result<Self::Output, CoreError> {
        operation.arguments().validate()?;
        let ToolArguments::Bash(args) = operation.arguments() else {
            return Err(shell_error(ShellFailure::Unsupported {
                tool: operation.tool(),
            }));
        };
        if operation.tool() != ToolName::Bash {
            return Err(shell_error(ShellFailure::Unsupported {
                tool: operation.tool(),
            }));
        }

        // A replay or a recovered pending intent is never resent. The store's
        // unique constraint is authoritative; this check fails before any
        // spawn.
        if self.store.operation(&operation.operation_id())?.is_some() {
            return Err(CoreError::DuplicateOperation {
                operation: operation.operation_id(),
            });
        }

        let cwd = operation.cwd().clone();
        if !cwd.as_path().is_dir() {
            return Err(shell_error(ShellFailure::WorkingDirectoryUnavailable {
                path: cwd.as_str().to_owned(),
            }));
        }

        let started_at = Timestamp::now();
        self.persist_intent(operation, args, started_at)?;

        let Some(spawn_gate) = self.supervisor.begin_spawn() else {
            self.record_not_applied(operation);
            return Err(shell_error(ShellFailure::Stopped { confirmed: true }));
        };

        let request = SpawnRequest::new(args.command.as_str(), cwd);
        let mut child = match self.launcher.spawn(&request) {
            Ok(child) => child,
            Err(error) => {
                drop(spawn_gate);
                self.record_not_applied(operation);
                return Err(shell_error(spawn_failure(&error)));
            }
        };
        let pid = child.pid();
        let pgid = pid;
        let _lease = self
            .supervisor
            .register(operation.operation_id(), pid, pgid);
        drop(spawn_gate);
        if _lease.is_none() {
            // Defensive: stop began during the spawn window. Terminate
            // immediately; the wait path below observes the stop flag.
            signal_process_group(pgid, ManagedSignal::Terminate);
        }

        let stdout = CaptureHandle::start(child.take_stdout(), self.output_limit);
        let stderr = CaptureHandle::start(child.take_stderr(), self.output_limit);

        if let Err(error) = self.persist_spawned(operation, pid, pgid) {
            // The process exists but its audit record does not. Do not leave it
            // running: kill the group, observe the outcome, and report the
            // operation as unverifiable.
            signal_process_group(pgid, ManagedSignal::Kill);
            let completion = supervise(
                &mut child,
                pgid,
                &self.supervisor,
                Some(Duration::from_secs(0)),
                Duration::ZERO,
                self.confirm_timeout,
            );
            let observation =
                self.finish_observation(pid, pgid, started_at, completion, stdout, stderr);
            self.record_unverifiable_with_observation(operation, &observation);
            return Err(error);
        }

        let completion = supervise(
            &mut child,
            pgid,
            &self.supervisor,
            args.timeout_ms.map(Duration::from_millis),
            self.timeout_grace,
            self.confirm_timeout,
        );
        let stop_status = completion.stop_status();
        let confirmed = completion.confirmed();
        let observation =
            self.finish_observation(pid, pgid, started_at, completion, stdout, stderr);

        let (outcome, shell_outcome_unknown, failure) = match stop_status {
            ShellStopStatus::Completed
            | ShellStopStatus::ExitedNonZero
            | ShellStopStatus::Killed => (OperationOutcome::Applied, false, None),
            ShellStopStatus::StopRequested => (
                OperationOutcome::Unverifiable,
                false,
                Some(ShellFailure::Stopped { confirmed: true }),
            ),
            ShellStopStatus::Timeout => (
                OperationOutcome::Unverifiable,
                false,
                Some(ShellFailure::TimedOut { confirmed: true }),
            ),
            ShellStopStatus::Unconfirmed => (
                OperationOutcome::Unverifiable,
                true,
                Some(ShellFailure::Unconfirmed {
                    detail: if confirmed {
                        "the managed group ended without a confirmable exit status".to_owned()
                    } else {
                        "the managed process group could not be confirmed gone".to_owned()
                    },
                }),
            ),
        };

        let notification = self.persist_result(
            operation,
            observation.clone(),
            outcome,
            shell_outcome_unknown,
        )?;

        if let Some(failure) = failure {
            return Err(shell_error(failure));
        }

        Ok(BashOutput {
            operation_id: operation.operation_id(),
            outcome,
            observation,
            notification,
        })
    }
}

/// Read-only recovery data for a shell operation.
///
/// This never re-executes the command and never treats matching native file
/// hashes as proof that the shell succeeded. Pending and unverifiable
/// operations stay unresolved for human reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellReconciliation {
    operation_id: OperationId,
    command: String,
    purpose: String,
    cwd: AbsolutePath,
    timeout_ms: Option<u64>,
    pid: Option<u32>,
    pgid: Option<u32>,
    started_at: Timestamp,
    finished_at: Option<Timestamp>,
    outcome: Option<OperationOutcome>,
    stop_status: Option<ShellStopStatus>,
    shell_outcome_unknown: bool,
    observation: Option<ShellObservation>,
}

impl ShellReconciliation {
    /// Operation this data describes.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Frozen command string.
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Model-authored purpose, recorded separately from output.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Frozen working directory.
    pub const fn cwd(&self) -> &AbsolutePath {
        &self.cwd
    }

    /// Optional timeout supplied by the caller.
    pub const fn timeout_ms(&self) -> Option<u64> {
        self.timeout_ms
    }

    /// Pid, when durably recorded.
    pub const fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// Process-group id, when durably recorded.
    pub const fn pgid(&self) -> Option<u32> {
        self.pgid
    }

    /// Time the intent was recorded.
    pub const fn started_at(&self) -> Timestamp {
        self.started_at
    }

    /// Time the observation finished, when a result exists.
    pub const fn finished_at(&self) -> Option<Timestamp> {
        self.finished_at
    }

    /// Durable outcome, when recorded.
    pub const fn outcome(&self) -> Option<OperationOutcome> {
        self.outcome
    }

    /// Observed stop status, when recorded.
    pub const fn stop_status(&self) -> Option<ShellStopStatus> {
        self.stop_status
    }

    /// Whether the shell's completion or cleanup is uncertain.
    pub const fn shell_outcome_unknown(&self) -> bool {
        self.shell_outcome_unknown
    }

    /// Full persisted observation, when a result exists.
    pub const fn observation(&self) -> Option<&ShellObservation> {
        self.observation.as_ref()
    }
}

/// Builds read-only reconciliation data for a recorded bash operation.
///
/// `events` should be the operation's committed events in ascending sequence
/// order. A pending intent has no result and stays uncertain even if a file's
/// hash happens to match what the command would have written.
pub fn reconcile_shell_operation(
    record: &OperationRecord,
    events: &[Event],
) -> Option<ShellReconciliation> {
    let operation = record.intent().operation();
    let ToolArguments::Bash(args) = operation.arguments() else {
        return None;
    };
    let result = record.result();
    let observation = result.and_then(|result| result.evidence().shell()).cloned();
    let spawned = events.iter().rfind(|event| {
        event.kind().as_str() == SHELL_SPAWNED_EVENT_KIND
            && event.operation_id() == Some(operation.operation_id())
    });
    let pid = observation
        .as_ref()
        .map(ShellObservation::pid)
        .or_else(|| spawned.and_then(|event| payload_u32(event, "pid")));
    let pgid = observation
        .as_ref()
        .map(ShellObservation::pgid)
        .or_else(|| spawned.and_then(|event| payload_u32(event, "pgid")));
    let shell_outcome_unknown = match result {
        None => true,
        Some(result) => {
            result.outcome() == OperationOutcome::Unverifiable
                || result.evidence().shell_outcome_unknown()
                || observation.as_ref().is_some_and(|observation| {
                    observation.stop_status() == ShellStopStatus::Unconfirmed
                })
        }
    };
    Some(ShellReconciliation {
        operation_id: operation.operation_id(),
        command: args.command.as_str().to_owned(),
        purpose: args.purpose.as_str().to_owned(),
        cwd: operation.cwd().clone(),
        timeout_ms: args.timeout_ms,
        pid,
        pgid,
        started_at: record.intent().recorded_at(),
        finished_at: observation.as_ref().map(ShellObservation::finished_at),
        outcome: result.map(OperationResult::outcome),
        stop_status: observation.as_ref().map(ShellObservation::stop_status),
        shell_outcome_unknown,
        observation,
    })
}

fn payload_u32(event: &Event, field: &str) -> Option<u32> {
    event
        .payload()
        .as_value()
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
}

fn shell_error(failure: ShellFailure) -> CoreError {
    CoreError::ShellToolFailed {
        tool: ToolName::Bash,
        failure,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShellStartedPayload<'a> {
    operation_id: OperationId,
    command: &'a str,
    purpose: &'a str,
    cwd: &'a AbsolutePath,
    timeout_ms: Option<u64>,
    started_at: Timestamp,
}

fn started_event(
    operation: &FrozenOperation,
    agent_id: AgentId,
    session_id: SessionId,
    args: &BashArgs,
    started_at: Timestamp,
) -> Result<EventDraft, CoreError> {
    let payload = ShellStartedPayload {
        operation_id: operation.operation_id(),
        command: args.command.as_str(),
        purpose: args.purpose.as_str(),
        cwd: operation.cwd(),
        timeout_ms: args.timeout_ms,
        started_at,
    };
    event_draft(
        operation,
        agent_id,
        session_id,
        SHELL_STARTED_EVENT_KIND,
        &payload,
        started_at,
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShellSpawnedPayload {
    operation_id: OperationId,
    pid: u32,
    pgid: u32,
    spawned_at: Timestamp,
}

fn spawned_event(
    operation: &FrozenOperation,
    agent_id: AgentId,
    session_id: SessionId,
    pid: u32,
    pgid: u32,
    spawned_at: Timestamp,
) -> Result<EventDraft, CoreError> {
    let payload = ShellSpawnedPayload {
        operation_id: operation.operation_id(),
        pid,
        pgid,
        spawned_at,
    };
    event_draft(
        operation,
        agent_id,
        session_id,
        SHELL_SPAWNED_EVENT_KIND,
        &payload,
        spawned_at,
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShellFinishedPayload {
    operation_id: OperationId,
    pid: u32,
    pgid: u32,
    stop_status: ShellStopStatus,
    exit_code: Option<i32>,
    terminating_signal: Option<i32>,
    stdout_bytes: u64,
    stderr_bytes: u64,
    stdout_truncated: bool,
    stderr_truncated: bool,
    started_at: Timestamp,
    finished_at: Timestamp,
}

fn finished_event(
    operation: &FrozenOperation,
    agent_id: AgentId,
    session_id: SessionId,
    observation: &ShellObservation,
) -> Result<EventDraft, CoreError> {
    let payload = ShellFinishedPayload {
        operation_id: operation.operation_id(),
        pid: observation.pid(),
        pgid: observation.pgid(),
        stop_status: observation.stop_status(),
        exit_code: observation.exit_code(),
        terminating_signal: observation.terminating_signal(),
        stdout_bytes: observation.stdout().original_bytes(),
        stderr_bytes: observation.stderr().original_bytes(),
        stdout_truncated: observation.stdout().truncated(),
        stderr_truncated: observation.stderr().truncated(),
        started_at: observation.started_at(),
        finished_at: observation.finished_at(),
    };
    event_draft(
        operation,
        agent_id,
        session_id,
        SHELL_FINISHED_EVENT_KIND,
        &payload,
        observation.finished_at(),
    )
}

fn event_draft<T: Serialize>(
    operation: &FrozenOperation,
    agent_id: AgentId,
    session_id: SessionId,
    kind: &str,
    payload: &T,
    occurred_at: Timestamp,
) -> Result<EventDraft, CoreError> {
    let value = serde_json::to_value(payload).map_err(|error| CoreError::InvalidValue {
        field: "shellEventPayload".to_owned(),
        violation: ArgumentViolation::Invalid {
            detail: error.to_string(),
        },
    })?;
    EventDraft::new(
        operation.project_id(),
        agent_id,
        session_id,
        operation.run_id(),
        Some(operation.operation_id()),
        EventKind::new(kind)?,
        occurred_at,
        EventPayload::new(value),
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShellCheckpointPayload {
    kind: &'static str,
    stage: &'static str,
    operation_id: OperationId,
    pid: Option<u32>,
    pgid: Option<u32>,
}

fn audit_checkpoint(
    operation: &FrozenOperation,
    stage: &'static str,
    pid: Option<u32>,
    pgid: Option<u32>,
) -> Result<Checkpoint, CoreError> {
    let payload = ShellCheckpointPayload {
        kind: AUDIT_CHECKPOINT_KIND,
        stage,
        operation_id: operation.operation_id(),
        pid,
        pgid,
    };
    let bytes = serde_json::to_vec(&payload).map_err(|error| CoreError::InvalidValue {
        field: "shellCheckpoint".to_owned(),
        violation: ArgumentViolation::Invalid {
            detail: error.to_string(),
        },
    })?;
    Ok(Checkpoint::new(
        operation.run_id(),
        CheckpointFormatVersion::new(AUDIT_CHECKPOINT_FORMAT)
            .expect("audit checkpoint format 1 is non-zero"),
        CheckpointPayload::new(bytes),
    ))
}
