//! Required-check execution through the real H1 permission and tool gateway.
//!
//! A check is converted into a frozen `bash` operation and authorized by the
//! same H1 `ToolGateway`/`PermissionService` rules and grant ceiling used for
//! run tools. A denied, human-waiting, unsupported, or non-shell check becomes
//! an explicit `unavailable` result; it is never a pass.

use std::path::{Path, PathBuf};

use herness_core::permissions::{EvaluationContext, GrantScope, PermissionMode, SharedPolicy};
use herness_core::tools::{
    BashArgs, BashExecutor, BashOutput, NonEmptyText, ProcessSupervisor, Purpose, SystemLauncher,
    ToolArguments, ToolExecutor, ToolGateway,
};
use herness_core::{
    AbsolutePath, Checkpoint, CheckpointCommit, CommitReceipt, CoreError, EventDraft, HistoryPage,
    HistoryQuery, OperationId, OperationIntent, OperationOutcome, OperationRecord, OperationResult,
    ProjectId, RequestGateIntent, RunId, StorePort, Timestamp, ToolName,
};
use herness_supervision::freshness::{ManifestCoverage, TargetReadSet};
use herness_supervision::supervisor::{CheckExecution, CheckExecutionRequest, RequiredCheckPort};
use herness_supervision::verification::{
    GatewayVerification, VerificationDisposition, VerificationExecution, VerificationPlan,
    VerificationService,
};
use herness_supervision::{
    CheckStatus, EvidenceAcquirer, EvidenceScope, RequiredCheckResult, SupervisionError,
    SupervisionStorePort, ensure_inputs_in_scope, validate_check_cwd,
};

use crate::supervision::store::{HostClock, StoreHandle};
use crate::supervision::workspace::ProjectWorkspace;

/// Production required-check executor for one supervision target.
pub struct HostCheckPort {
    store: StoreHandle,
    agent: herness_core::AgentId,
    session: herness_core::SessionId,
    root: PathBuf,
    policy: SharedPolicy,
    requested_work: String,
}

impl HostCheckPort {
    /// Creates a check port for one child agent and project root.
    pub fn new(
        store: StoreHandle,
        agent: herness_core::AgentId,
        session: herness_core::SessionId,
        root: PathBuf,
        policy: SharedPolicy,
        requested_work: impl Into<String>,
    ) -> Self {
        Self {
            store,
            agent,
            session,
            root,
            policy,
            requested_work: requested_work.into(),
        }
    }

    fn unavailable(request: &CheckExecutionRequest) -> Result<CheckExecution, SupervisionError> {
        let result = RequiredCheckResult::new(
            request.check_id(),
            request.condition_id(),
            CheckStatus::Unavailable,
            None,
            request.condition_version(),
            request.target_version(),
            Timestamp::now(),
        )?;
        Ok(CheckExecution::new(result, None))
    }
}

impl RequiredCheckPort for HostCheckPort {
    fn execute(
        &mut self,
        request: &CheckExecutionRequest,
    ) -> Result<CheckExecution, SupervisionError> {
        let herness_supervision::VerificationOperation::Command { command } = request.operation()
        else {
            return Self::unavailable(request);
        };

        let invocation = request.invocation();
        let Ok(timeout_ms) = effective_check_timeout_ms(
            invocation.timeout_seconds(),
            request.remaining_active_seconds(),
        ) else {
            return Self::unavailable(request);
        };
        let Ok(cwd_path) = resolve_check_cwd(&self.root, invocation.cwd()) else {
            // An escaping cwd, a missing directory, or a symlink that leaves
            // the project is refused before anything is spawned.
            return Self::unavailable(request);
        };
        if ensure_inputs_in_scope(invocation.input_paths(), request.read_set()).is_err() {
            return Self::unavailable(request);
        }

        let record = self
            .store
            .load(request.project_id(), request.supervision_id())?
            .ok_or(SupervisionError::UnknownSupervision)?;
        let Some(run) = record
            .supervisor()
            .current_run()
            .or_else(|| record.run_group().runs().last().copied())
        else {
            return Self::unavailable(request);
        };

        let policy = self.policy.snapshot();
        if policy.mode() == PermissionMode::Automatic {
            // The required-check gateway is not given a permission evaluator in
            // this composition. Automatic mode therefore waits for a human
            // instead of allowing the check implicitly.
            return Self::unavailable(request);
        }

        let arguments = ToolArguments::Bash(BashArgs {
            command: NonEmptyText::new(command).map_err(|error| {
                SupervisionError::InvalidValue {
                    field: "check.command".to_owned(),
                    detail: error.to_string(),
                }
            })?,
            purpose: Purpose::new("supervision required check").map_err(|error| {
                SupervisionError::InvalidValue {
                    field: "check.purpose".to_owned(),
                    detail: error.to_string(),
                }
            })?,
            // Bound one check by the approved timeout and the remaining Task
            // time, whichever is shorter. An unstoppable or unknown exit stays
            // a non-pass.
            timeout_ms: Some(timeout_ms),
        });
        let cwd = AbsolutePath::new(cwd_path.to_string_lossy()).map_err(|error| {
            SupervisionError::InvalidValue {
                field: "check.cwd".to_owned(),
                detail: error.to_string(),
            }
        })?;
        let operation = herness_core::FrozenOperation::new(
            OperationId::new(request.project_id()),
            run,
            ToolName::Bash,
            arguments,
            cwd,
            policy.version(),
            policy.mode(),
        )
        .map_err(|error| SupervisionError::InvalidValue {
            field: "check.operation".to_owned(),
            detail: error.to_string(),
        })?;

        let workspace = ProjectWorkspace::new(self.root.clone());
        let service = VerificationService::new(workspace, HostClock);
        let mut read_set = request.read_set().to_vec();
        for path in invocation.input_paths() {
            if !read_set.contains(path) {
                read_set.push(path.clone());
            }
        }
        let plan = VerificationPlan::new(
            request.evidence_id(),
            request.supervision_id(),
            Some(request.condition_id()),
            Some(request.check_id()),
            // The host ran the approved operation itself. Claiming the child
            // did would be dishonest evidence.
            EvidenceAcquirer::Host,
            None,
            request.operation().clone(),
            EvidenceScope::new(
                vec![
                    format!("command: {command}"),
                    format!("cwd: {}", invocation.cwd()),
                    format!("timeoutSeconds: {}", invocation.timeout_seconds()),
                    format!("inputs: {}", invocation.input_paths().len()),
                ],
                vec![
                    "the host executed the approved check through the H1 permission boundary"
                        .to_owned(),
                    "the observation is bounded by the approved timeout and remaining Task time"
                        .to_owned(),
                ],
            )?,
            request.sequence(),
            request.target_version(),
            TargetReadSet::Declared(read_set),
        )?
        .with_invocation(invocation.clone());

        let bash = BashExecutor::new(
            self.agent,
            self.session,
            CheckAuditStore::new(self.store.clone(), operation.operation_id(), run),
            SystemLauncher,
            ProcessSupervisor::new(),
        )
        .map_err(|error| SupervisionError::InvalidValue {
            field: "check.executor".to_owned(),
            detail: error.to_string(),
        })?;
        let gateway = ToolGateway::new(CheckExecutor { bash });
        let grant = GrantScope::for_run(request.project_id(), &policy);
        let context = EvaluationContext::new(
            self.requested_work.clone(),
            vec![format!("check: {command}")],
        );
        let mut boundary = GatewayVerification::new(gateway, policy, grant, context);

        let mut evidence_store = self.store.clone();
        match service.verify(&mut evidence_store, plan, &operation, &mut boundary)? {
            VerificationDisposition::Recorded(evidence) => {
                let result =
                    RequiredCheckResult::from_evidence(&evidence, request.condition_version())?;
                Ok(CheckExecution::new(result, Some(*evidence)))
            }
            VerificationDisposition::Denied { .. }
            | VerificationDisposition::AwaitingHuman { .. }
            | VerificationDisposition::Failed { .. } => Self::unavailable(request),
        }
    }
}

struct CheckExecutor {
    bash: BashExecutor<CheckAuditStore, SystemLauncher>,
}

/// Audit-only [`StorePort`] adapter for a host-run required check.
///
/// The H1 `bash` executor persists an audit checkpoint, an operation intent
/// and events before spawning, and again when the process group is created and
/// resolved. For a check the host runs on behalf of a supervised child, that
/// audit data must not land in the child run's checkpoint slot: the slot holds
/// the engine conversation checkpoint that `start_continuation` validates.
///
/// This adapter keeps the durability contract and changes only the destination:
///
/// * the operation row, the audit checkpoint body, and the events commit in one
///   immediate transaction through [`Store::commit_operation_audit`], so a
///   crashed check still leaves a visible intent and its audit payload;
/// * the audit checkpoint body is stored under a host-state key namespaced by
///   the check operation, never in the `checkpoints` table;
/// * [`StorePort::load_checkpoint`] never reports a conversation checkpoint, so
///   the executor cannot mistake audit data for an engine snapshot.
pub(crate) struct CheckAuditStore {
    store: StoreHandle,
    operation: OperationId,
    run: RunId,
}

impl CheckAuditStore {
    /// Creates an audit sink bound to one check operation and its run.
    pub(crate) const fn new(store: StoreHandle, operation: OperationId, run: RunId) -> Self {
        Self {
            store,
            operation,
            run,
        }
    }

    fn state_key(&self) -> String {
        format!("h2.supervision.check.audit:{}", self.operation)
    }
}

impl StorePort for CheckAuditStore {
    fn commit_checkpoint(&mut self, commit: CheckpointCommit) -> Result<CommitReceipt, CoreError> {
        if commit.checkpoint().run_id() != self.run {
            return Err(CoreError::MismatchedRun {
                expected: self.run,
                found: commit.checkpoint().run_id(),
            });
        }
        if let Some(intent) = commit.operation()
            && intent.operation().operation_id() != self.operation
        {
            return Err(CoreError::InvalidValue {
                field: "checkAuditOperation".to_owned(),
                violation: herness_core::ArgumentViolation::Invalid {
                    detail: "the audit commit belongs to another operation".to_owned(),
                },
            });
        }
        let bytes =
            serde_json::to_vec(commit.checkpoint()).map_err(|error| CoreError::InvalidValue {
                field: "checkAuditCheckpoint".to_owned(),
                violation: herness_core::ArgumentViolation::Invalid {
                    detail: error.to_string(),
                },
            })?;
        self.store
            .lock()
            .commit_operation_audit(
                &self.state_key(),
                &bytes,
                commit.operation(),
                commit.events().to_vec(),
            )
            .map_err(Into::into)
    }

    fn load_checkpoint(&self, _run: &RunId) -> Result<Option<Checkpoint>, CoreError> {
        // A check has no conversation. Reporting the audit payload here would
        // let a caller treat it as an engine snapshot.
        Ok(None)
    }

    fn history(&self, query: HistoryQuery) -> Result<HistoryPage, CoreError> {
        self.store.history(query)
    }

    fn pending_operations(&self, project: &ProjectId) -> Result<Vec<OperationIntent>, CoreError> {
        self.store.pending_operations(project)
    }

    fn operation(&self, operation: &OperationId) -> Result<Option<OperationRecord>, CoreError> {
        self.store.operation(operation)
    }

    fn record_operation_result(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
    ) -> Result<(), CoreError> {
        self.store.record_operation_result(operation, result)
    }

    fn record_operation_result_with_events(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
        events: Vec<EventDraft>,
    ) -> Result<CommitReceipt, CoreError> {
        self.store
            .record_operation_result_with_events(operation, result, events)
    }

    fn record_model_request(
        &mut self,
        intent: RequestGateIntent,
        recorded_at: Timestamp,
    ) -> Result<(), CoreError> {
        self.store.record_model_request(intent, recorded_at)
    }

    fn record_model_request_observation(
        &mut self,
        observation: herness_core::ModelRequestObservation,
        observed_at: Timestamp,
    ) -> Result<(), CoreError> {
        self.store
            .record_model_request_observation(observation, observed_at)
    }
}

impl ToolExecutor for CheckExecutor {
    type Output = VerificationExecution;

    fn execute(
        &mut self,
        operation: &herness_core::FrozenOperation,
    ) -> Result<VerificationExecution, herness_core::CoreError> {
        match self.bash.execute(operation) {
            Ok(output) => execution_from_output(&output),
            // A timeout, a stop request, or an unconfirmed process group is an
            // observed non-pass, not a missing observation. Record it so the
            // evidence says what happened instead of claiming the check never
            // ran.
            Err(error @ herness_core::CoreError::ShellToolFailed { .. }) => {
                execution_from_shell_failure(&error)
            }
            Err(error) => Err(error),
        }
    }
}

fn execution_from_shell_failure(
    error: &herness_core::CoreError,
) -> Result<VerificationExecution, herness_core::CoreError> {
    let herness_core::CoreError::ShellToolFailed { failure, .. } = error else {
        return Err(error.clone());
    };
    let (status, exit_code, signal, timed_out) = match failure {
        herness_core::ShellFailure::TimedOut { confirmed } => (
            if *confirmed {
                CheckStatus::Fail
            } else {
                CheckStatus::Inconclusive
            },
            None,
            None,
            true,
        ),
        herness_core::ShellFailure::Stopped { .. }
        | herness_core::ShellFailure::Unconfirmed { .. }
        | herness_core::ShellFailure::Unverifiable { .. } => return Err(error.clone()),
        _ => return Err(error.clone()),
    };
    VerificationExecution::new(
        status,
        exit_code,
        signal,
        timed_out,
        false,
        format!("shell failure observed: {failure}"),
    )
    .map_err(|error| herness_core::CoreError::InvalidValue {
        field: "verificationExecution".to_owned(),
        violation: herness_core::ArgumentViolation::Invalid {
            detail: error.to_string(),
        },
    })
}

fn execution_from_output(
    output: &BashOutput,
) -> Result<VerificationExecution, herness_core::CoreError> {
    let observation = output.observation();
    let stop = observation.stop_status();
    let timed_out = matches!(stop, herness_core::ShellStopStatus::Timeout);
    let truncated = observation.stdout().truncated() || observation.stderr().truncated();
    let status = if matches!(stop, herness_core::ShellStopStatus::Completed)
        && observation.exit_code() == Some(0)
        && observation.terminating_signal().is_none()
        && !truncated
    {
        CheckStatus::Pass
    } else if matches!(
        stop,
        herness_core::ShellStopStatus::Completed
            | herness_core::ShellStopStatus::ExitedNonZero
            | herness_core::ShellStopStatus::Killed
            | herness_core::ShellStopStatus::Timeout
    ) {
        CheckStatus::Fail
    } else {
        // A stop the host sent, or an exit it could not confirm, never
        // establishes a pass. It stays inconclusive instead of being reported
        // as an observed failure.
        CheckStatus::Inconclusive
    };
    let stdout = bounded(observation.stdout().text());
    let stderr = bounded(observation.stderr().text());
    let detail = format!(
        "stop={:?} exit={:?} signal={:?} truncated={truncated} stdout={stdout:?} stderr={stderr:?}",
        stop,
        observation.exit_code(),
        observation.terminating_signal(),
    );
    let execution = VerificationExecution::new(
        status,
        observation.exit_code(),
        observation.terminating_signal(),
        timed_out,
        truncated,
        detail,
    )
    .map_err(|error| herness_core::CoreError::InvalidValue {
        field: "verificationExecution".to_owned(),
        violation: herness_core::ArgumentViolation::Invalid {
            detail: error.to_string(),
        },
    })?;
    let has_explicit = observation.exit_code().is_some()
        || observation.terminating_signal().is_some()
        || timed_out;
    if has_explicit && output.outcome() == OperationOutcome::Applied {
        return execution
            .with_operation_outcome(OperationOutcome::Applied)
            .map_err(|error| herness_core::CoreError::InvalidValue {
                field: "verificationExecution".to_owned(),
                violation: herness_core::ArgumentViolation::Invalid {
                    detail: error.to_string(),
                },
            });
    }
    Ok(execution)
}

fn bounded(value: &str) -> String {
    const LIMIT: usize = 4_096;
    if value.chars().count() <= LIMIT {
        return value.to_owned();
    }
    let mut truncated = value.chars().take(LIMIT).collect::<String>();
    truncated.push_str("… [truncated]");
    truncated
}

/// Milliseconds one check may run: the shorter of the approved timeout and the
/// remaining supervised Task time.
///
/// A zero remaining time is refused instead of spawning a process with no
/// budget. Both values are finite seconds; the conversion saturates.
pub fn effective_check_timeout_ms(
    explicit_seconds: u64,
    remaining_seconds: u64,
) -> Result<u64, SupervisionError> {
    if explicit_seconds == 0 {
        return Err(SupervisionError::InvalidValue {
            field: "check.timeoutSeconds".to_owned(),
            detail: "the approved timeout must be positive".to_owned(),
        });
    }
    if remaining_seconds == 0 {
        return Err(SupervisionError::InvalidValue {
            field: "check.remainingActiveSeconds".to_owned(),
            detail: "no supervised Task time remains for a check".to_owned(),
        });
    }
    Ok(explicit_seconds
        .min(remaining_seconds)
        .saturating_mul(1_000))
}

/// Resolves an approved check `cwd` against the canonical project root.
///
/// The value must be `.` or a directory inside the root. A missing directory,
/// an escaping path, or a symlink that resolves outside the root is refused
/// before a process is spawned.
pub fn resolve_check_cwd(root: &Path, cwd: &str) -> Result<PathBuf, SupervisionError> {
    validate_check_cwd(cwd)?;
    let canonical_root =
        std::fs::canonicalize(root).map_err(|error| SupervisionError::InvalidValue {
            field: "check.cwd".to_owned(),
            detail: format!("the project root cannot be resolved: {error}"),
        })?;
    let joined = if cwd == "." {
        canonical_root.clone()
    } else {
        canonical_root.join(cwd)
    };
    let canonical =
        std::fs::canonicalize(&joined).map_err(|error| SupervisionError::InvalidValue {
            field: "check.cwd".to_owned(),
            detail: format!("the approved working directory is unavailable: {error}"),
        })?;
    if !canonical.starts_with(&canonical_root) {
        return Err(SupervisionError::InvalidValue {
            field: "check.cwd".to_owned(),
            detail: "the approved working directory resolves outside the project root".to_owned(),
        });
    }
    if !canonical.is_dir() {
        return Err(SupervisionError::InvalidValue {
            field: "check.cwd".to_owned(),
            detail: "the approved working directory is not a directory".to_owned(),
        });
    }
    Ok(canonical)
}

/// Explicitly marks a manifest whose scope could not be established.
pub fn unavailable_manifest(
    project: herness_core::ProjectId,
    version: herness_supervision::TargetVersion,
    reason: impl AsRef<str>,
) -> Result<herness_supervision::freshness::TargetManifest, SupervisionError> {
    herness_supervision::freshness::TargetManifest::unknown(project, version, reason)
}

/// Whether a manifest can complete a target check.
pub fn manifest_is_complete(manifest: &herness_supervision::freshness::TargetManifest) -> bool {
    matches!(manifest.coverage(), ManifestCoverage::Complete)
}

/// Run identifier used by a check, if any.
pub fn check_run(record: &herness_supervision::SupervisionRecord) -> Option<RunId> {
    record
        .supervisor()
        .current_run()
        .or_else(|| record.run_group().runs().last().copied())
}
