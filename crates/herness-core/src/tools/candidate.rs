//! Candidate-only artifact tools: `candidate_read`, `candidate_write`, and
//! `candidate_edit`.
//!
//! These tools are exposed only when the host supplies both an
//! [`ArtifactHandle`] and an [`ArtifactPort`] for a candidate run. The model
//! addresses artifacts by slot, never by a project path. Formal Markdown, HTML,
//! CSS, settings, and shell operations are rejected by this executor.
//!
//! For `candidate_write` and `candidate_edit` the executor follows the same
//! pre-side-effect order as the native file tools:
//!
//! 1. validate the handle, artifact slot, and final arguments;
//! 2. read the current candidate and compute the exact planned content,
//!    version, and diff;
//! 3. persist the [`OperationIntent`], an audit checkpoint, and a
//!    `artifact.change.intended` event in one store transaction;
//! 4. call the host artifact port;
//! 5. verify the returned bytes and version, then persist `Applied` plus an
//!    `artifact.change` notification in one store transaction.
//!
//! An unavailable port is an explicit unsupported capability, never an empty
//! success.

use serde::Serialize;

use crate::contracts::artifact::{ArtifactHandle, ArtifactSlot, ArtifactSnapshot};
use crate::contracts::errors::{ArtifactFailure, CoreError, PortFeature};
use crate::contracts::events::{Event, EventDraft, EventKind, EventPayload};
use crate::contracts::ids::{AgentId, IdKind, OperationId, SessionId};
use crate::contracts::operation::{
    FrozenOperation, OperationEvidence, OperationIntent, OperationOutcome, OperationResult,
};
use crate::contracts::time::Timestamp;
use crate::contracts::{Checkpoint, CheckpointFormatVersion, CheckpointPayload};
use crate::ports::{ArtifactPort, CheckpointCommit, StorePort};
use crate::tools::arguments::{CandidateEditArgs, CandidateReadArgs, CandidateWriteArgs};
use crate::tools::diff::{FileDiff, line_diff};
use crate::tools::files::hash_bytes;
use crate::tools::gateway::ToolExecutor;
use crate::tools::{FileVersion, ToolArguments, ToolName};

/// Persisted notification kind for an applied candidate change.
pub const ARTIFACT_CHANGE_EVENT_KIND: &str = "artifact.change";
/// Persisted event kind for the intended candidate change written before the
/// side effect.
pub const ARTIFACT_CHANGE_INTENDED_EVENT_KIND: &str = "artifact.change.intended";

const AUDIT_CHECKPOINT_FORMAT: u32 = 1;
const AUDIT_CHECKPOINT_KIND: &str = "herness.artifact-operation";

/// Output of one candidate artifact operation.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "tool", content = "result", rename_all = "snake_case")]
pub enum CandidateToolOutput {
    /// A completed snapshot or candidate read.
    Read(CandidateReadOutput),
    /// An applied candidate write or edit.
    Change(Box<CandidateChange>),
}

/// Content observed from a candidate read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateReadOutput {
    artifact: ArtifactSlot,
    version: FileVersion,
    content: String,
}

impl CandidateReadOutput {
    /// Slot that was read.
    pub const fn artifact(&self) -> ArtifactSlot {
        self.artifact
    }

    /// Exact content version.
    pub const fn version(&self) -> &FileVersion {
        &self.version
    }

    /// Exact text content.
    pub fn content(&self) -> &str {
        &self.content
    }
}

/// A durably recorded candidate change returned to the caller.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateChange {
    operation_id: OperationId,
    tool: ToolName,
    artifact: ArtifactSlot,
    created: bool,
    before_version: Option<FileVersion>,
    after_version: FileVersion,
    diff: FileDiff,
    notification: Event,
}

impl CandidateChange {
    /// Operation that produced the change.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Tool that produced the change.
    pub const fn tool(&self) -> ToolName {
        self.tool
    }

    /// Candidate slot that changed.
    pub const fn artifact(&self) -> ArtifactSlot {
        self.artifact
    }

    /// Whether the candidate did not exist before this write.
    pub const fn created(&self) -> bool {
        self.created
    }

    /// Version observed before the change.
    pub const fn before_version(&self) -> Option<&FileVersion> {
        self.before_version.as_ref()
    }

    /// Version observed after the change.
    pub const fn after_version(&self) -> &FileVersion {
        &self.after_version
    }

    /// Persisted diff.
    pub const fn diff(&self) -> &FileDiff {
        &self.diff
    }

    /// Persisted `artifact.change` notification.
    pub const fn notification(&self) -> &Event {
        &self.notification
    }
}

/// Candidate artifact executor behind the permission gateway.
#[derive(Debug)]
pub struct CandidateArtifactTools<S, P> {
    store: S,
    agent_id: AgentId,
    session_id: SessionId,
    handle: ArtifactHandle,
    port: P,
}

impl<S, P> CandidateArtifactTools<S, P> {
    /// Creates an executor for exactly one host-issued candidate handle.
    ///
    /// The agent and session must belong to the same project as the handle.
    pub fn new(
        store: S,
        agent_id: AgentId,
        session_id: SessionId,
        handle: ArtifactHandle,
        port: P,
    ) -> Result<Self, CoreError> {
        if agent_id.project_id() != handle.project_id() {
            return Err(CoreError::CrossProjectReference {
                id_kind: IdKind::Project,
                expected: agent_id.project_id(),
                found: handle.project_id(),
            });
        }
        if session_id.project_id() != handle.project_id() {
            return Err(CoreError::CrossProjectReference {
                id_kind: IdKind::Project,
                expected: session_id.project_id(),
                found: handle.project_id(),
            });
        }
        Ok(Self {
            store,
            agent_id,
            session_id,
            handle,
            port,
        })
    }

    /// Agent that owns candidate operations.
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Session that owns candidate operations.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Current handle.
    pub const fn handle(&self) -> &ArtifactHandle {
        &self.handle
    }

    /// Store connection used for intent, result, and notification persistence.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Host artifact port.
    pub const fn port(&self) -> &P {
        &self.port
    }

    /// Mutable store connection, used by tests for fault injection.
    pub const fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Mutable host artifact port, used by tests for fault injection.
    pub const fn port_mut(&mut self) -> &mut P {
        &mut self.port
    }
}

impl<S: StorePort, P: ArtifactPort> CandidateArtifactTools<S, P> {
    fn verify_handle(
        &self,
        tool: ToolName,
        operation: &FrozenOperation,
        handle: &ArtifactHandle,
    ) -> Result<(), CoreError> {
        if handle.project_id() != operation.project_id() {
            return Err(CoreError::CrossProjectReference {
                id_kind: IdKind::Project,
                expected: operation.project_id(),
                found: handle.project_id(),
            });
        }
        if handle != &self.handle {
            return Err(artifact_error(
                tool,
                ArtifactFailure::StaleHandle {
                    expected_generation: self.handle.generation(),
                    found_generation: handle.generation(),
                },
            ));
        }
        Ok(())
    }

    fn read_current(
        &mut self,
        tool: ToolName,
        artifact: ArtifactSlot,
    ) -> Result<Option<ArtifactSnapshot>, CoreError> {
        let snapshot = self
            .port
            .read_artifact(&self.handle, artifact)
            .map_err(|failure| artifact_error(tool, failure))?;
        if let Some(snapshot) = &snapshot
            && snapshot.artifact() != artifact
        {
            return Err(artifact_error(
                tool,
                ArtifactFailure::ContentMismatch { artifact },
            ));
        }
        Ok(snapshot)
    }

    fn apply_read(
        &mut self,
        operation: &FrozenOperation,
        args: &CandidateReadArgs,
    ) -> Result<CandidateReadOutput, CoreError> {
        let tool = ToolName::CandidateRead;
        self.verify_handle(tool, operation, &args.handle)?;
        let snapshot = self.read_current(tool, args.artifact)?.ok_or_else(|| {
            artifact_error(
                tool,
                ArtifactFailure::NotFound {
                    artifact: args.artifact,
                },
            )
        })?;
        Ok(CandidateReadOutput {
            artifact: args.artifact,
            version: snapshot.version().clone(),
            content: snapshot.content().to_owned(),
        })
    }

    fn apply_write(
        &mut self,
        operation: &FrozenOperation,
        args: &CandidateWriteArgs,
    ) -> Result<CandidateChange, CoreError> {
        let tool = ToolName::CandidateWrite;
        self.verify_handle(tool, operation, &args.handle)?;
        if !args.artifact.is_candidate() {
            return Err(artifact_error(
                tool,
                ArtifactFailure::NotCandidateTarget {
                    artifact: args.artifact,
                },
            ));
        }
        let before = self.read_current(tool, args.artifact)?;
        let after_version = hash_bytes(args.content.as_bytes());
        let diff = line_diff(
            before.as_ref().map_or("", ArtifactSnapshot::content),
            &args.content,
            args.artifact.as_str(),
        );
        let created = before.is_none();
        self.persist_intent(
            operation,
            tool,
            args.artifact,
            created,
            before.as_ref().map(ArtifactSnapshot::version),
            &after_version,
            &diff,
            args.rationale.as_str(),
        )?;

        let observed = match self.port.write_artifact(
            &self.handle,
            args.artifact,
            &args.content,
            before.as_ref().map(ArtifactSnapshot::version),
        ) {
            Ok(observed) => observed,
            Err(failure) => {
                self.record_side_effect_failure(operation, &failure);
                return Err(artifact_error(tool, failure));
            }
        };
        self.finish_change(
            operation,
            tool,
            args.artifact,
            created,
            before.as_ref().map(ArtifactSnapshot::version).cloned(),
            &after_version,
            &args.content,
            &observed,
            &diff,
            args.rationale.as_str(),
        )
    }

    fn apply_edit(
        &mut self,
        operation: &FrozenOperation,
        args: &CandidateEditArgs,
    ) -> Result<CandidateChange, CoreError> {
        let tool = ToolName::CandidateEdit;
        self.verify_handle(tool, operation, &args.handle)?;
        if !args.artifact.is_candidate() {
            return Err(artifact_error(
                tool,
                ArtifactFailure::NotCandidateTarget {
                    artifact: args.artifact,
                },
            ));
        }
        let before = self.read_current(tool, args.artifact)?.ok_or_else(|| {
            artifact_error(
                tool,
                ArtifactFailure::NotFound {
                    artifact: args.artifact,
                },
            )
        })?;
        if let Some(expected) = &args.expected_version
            && expected != before.version()
        {
            return Err(artifact_error(
                tool,
                ArtifactFailure::VersionConflict {
                    artifact: args.artifact,
                    expected: expected.clone(),
                    actual: before.version().clone(),
                },
            ));
        }
        if args.old_text.is_empty() {
            return Err(artifact_error(tool, ArtifactFailure::EditTextEmpty));
        }
        let occurrences = before.content().match_indices(&args.old_text).count();
        if occurrences == 0 {
            return Err(artifact_error(
                tool,
                ArtifactFailure::EditTextNotFound {
                    artifact: args.artifact,
                },
            ));
        }
        if occurrences > 1 {
            return Err(artifact_error(
                tool,
                ArtifactFailure::EditTextNotUnique {
                    artifact: args.artifact,
                    occurrences: occurrences as u64,
                },
            ));
        }
        let after_content = before.content().replacen(&args.old_text, &args.new_text, 1);
        if after_content == before.content() {
            return Err(artifact_error(
                tool,
                ArtifactFailure::NoChange {
                    artifact: args.artifact,
                },
            ));
        }
        let after_version = hash_bytes(after_content.as_bytes());
        let diff = line_diff(before.content(), &after_content, args.artifact.as_str());
        self.persist_intent(
            operation,
            tool,
            args.artifact,
            false,
            Some(before.version()),
            &after_version,
            &diff,
            args.rationale.as_str(),
        )?;

        let observed = match self.port.write_artifact(
            &self.handle,
            args.artifact,
            &after_content,
            Some(before.version()),
        ) {
            Ok(observed) => observed,
            Err(failure) => {
                self.record_side_effect_failure(operation, &failure);
                return Err(artifact_error(tool, failure));
            }
        };
        self.finish_change(
            operation,
            tool,
            args.artifact,
            false,
            Some(before.version().clone()),
            &after_version,
            &after_content,
            &observed,
            &diff,
            args.rationale.as_str(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_change(
        &mut self,
        operation: &FrozenOperation,
        tool: ToolName,
        artifact: ArtifactSlot,
        created: bool,
        before: Option<FileVersion>,
        planned_version: &FileVersion,
        planned_content: &str,
        observed: &ArtifactSnapshot,
        diff: &FileDiff,
        rationale: &str,
    ) -> Result<CandidateChange, CoreError> {
        if observed.artifact() != artifact
            || observed.version() != planned_version
            || observed.content() != planned_content
        {
            self.record_unverifiable(operation);
            return Err(artifact_error(
                tool,
                ArtifactFailure::ContentMismatch { artifact },
            ));
        }
        self.persist_applied(
            operation,
            tool,
            artifact,
            created,
            before,
            observed.version(),
            diff,
            rationale,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_intent(
        &mut self,
        operation: &FrozenOperation,
        tool: ToolName,
        artifact: ArtifactSlot,
        created: bool,
        before: Option<&FileVersion>,
        planned_after: &FileVersion,
        diff: &FileDiff,
        rationale: &str,
    ) -> Result<(), CoreError> {
        let event = change_event(
            operation,
            self.agent_id,
            self.session_id,
            &self.handle,
            tool,
            ARTIFACT_CHANGE_INTENDED_EVENT_KIND,
            artifact,
            created,
            before,
            planned_after,
            diff,
            rationale,
        )?;
        let checkpoint = audit_checkpoint(
            operation,
            tool,
            "intent",
            artifact,
            before,
            Some(planned_after),
        )?;
        let intent = OperationIntent::new(operation.clone(), Timestamp::now());
        let commit = CheckpointCommit::new(checkpoint, Some(intent), vec![event])?;
        match self.store.commit_checkpoint(commit) {
            Ok(_) => Ok(()),
            Err(error @ CoreError::DuplicateOperation { .. }) => Err(error),
            Err(error) => Err(artifact_error(
                tool,
                ArtifactFailure::NotExecutable {
                    detail: error.to_string(),
                },
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_applied(
        &mut self,
        operation: &FrozenOperation,
        tool: ToolName,
        artifact: ArtifactSlot,
        created: bool,
        before: Option<FileVersion>,
        observed: &FileVersion,
        diff: &FileDiff,
        rationale: &str,
    ) -> Result<CandidateChange, CoreError> {
        let event = change_event(
            operation,
            self.agent_id,
            self.session_id,
            &self.handle,
            tool,
            ARTIFACT_CHANGE_EVENT_KIND,
            artifact,
            created,
            before.as_ref(),
            observed,
            diff,
            rationale,
        )?;
        let result = OperationResult::new(
            OperationOutcome::Applied,
            OperationEvidence::empty(),
            Timestamp::now(),
        );
        let receipt = self
            .store
            .record_operation_result_with_events(&operation.operation_id(), result, vec![event])
            .map_err(|error| {
                artifact_error(
                    tool,
                    ArtifactFailure::Unverifiable {
                        detail: error.to_string(),
                    },
                )
            })?;
        let notification = receipt.events().first().cloned().ok_or_else(|| {
            artifact_error(
                tool,
                ArtifactFailure::Unverifiable {
                    detail: "store committed no notification event".to_owned(),
                },
            )
        })?;
        Ok(CandidateChange {
            operation_id: operation.operation_id(),
            tool,
            artifact,
            created,
            before_version: before,
            after_version: observed.clone(),
            diff: diff.clone(),
            notification,
        })
    }

    fn record_side_effect_failure(
        &mut self,
        operation: &FrozenOperation,
        failure: &ArtifactFailure,
    ) {
        if matches!(
            failure,
            ArtifactFailure::Unverifiable { .. } | ArtifactFailure::ContentMismatch { .. }
        ) {
            self.record_unverifiable(operation);
        } else {
            self.record_not_applied(operation);
        }
    }

    fn record_not_applied(&mut self, operation: &FrozenOperation) {
        let result = OperationResult::new(
            OperationOutcome::NotApplied,
            OperationEvidence::empty(),
            Timestamp::now(),
        );
        let _ = self
            .store
            .record_operation_result(&operation.operation_id(), result);
    }

    fn record_unverifiable(&mut self, operation: &FrozenOperation) {
        let result = OperationResult::new(
            OperationOutcome::Unverifiable,
            OperationEvidence::empty(),
            Timestamp::now(),
        );
        let _ = self
            .store
            .record_operation_result(&operation.operation_id(), result);
    }
}

impl<S: StorePort, P: ArtifactPort> ToolExecutor for CandidateArtifactTools<S, P> {
    type Output = CandidateToolOutput;

    fn execute(&mut self, operation: &FrozenOperation) -> Result<Self::Output, CoreError> {
        operation.arguments().validate()?;
        let tool = operation.tool();
        if !tool.is_candidate() {
            return Err(artifact_error(
                tool,
                ArtifactFailure::ToolNotAllowed { tool },
            ));
        }
        if matches!(tool, ToolName::CandidateWrite | ToolName::CandidateEdit)
            && self.store.operation(&operation.operation_id())?.is_some()
        {
            return Err(CoreError::DuplicateOperation {
                operation: operation.operation_id(),
            });
        }
        match operation.arguments() {
            ToolArguments::CandidateRead(args) => self
                .apply_read(operation, args)
                .map(CandidateToolOutput::Read),
            ToolArguments::CandidateWrite(args) => self
                .apply_write(operation, args)
                .map(|change| CandidateToolOutput::Change(Box::new(change))),
            ToolArguments::CandidateEdit(args) => self
                .apply_edit(operation, args)
                .map(|change| CandidateToolOutput::Change(Box::new(change))),
            _ => Err(artifact_error(
                tool,
                ArtifactFailure::ToolNotAllowed { tool },
            )),
        }
    }
}

fn artifact_error(tool: ToolName, failure: ArtifactFailure) -> CoreError {
    match failure {
        ArtifactFailure::Unavailable => CoreError::UnsupportedPortFeature {
            feature: PortFeature::ArtifactStore,
        },
        other => CoreError::ArtifactToolFailed {
            tool,
            failure: other,
        },
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactChangePayload<'a> {
    artifact: ArtifactSlot,
    job_id: &'a str,
    generation: u64,
    operation_id: OperationId,
    tool: ToolName,
    created: bool,
    before_version: Option<&'a FileVersion>,
    after_version: &'a FileVersion,
    diff: &'a str,
    diff_truncated: bool,
    rationale: &'a str,
}

#[allow(clippy::too_many_arguments)]
fn change_event(
    operation: &FrozenOperation,
    agent_id: AgentId,
    session_id: SessionId,
    handle: &ArtifactHandle,
    tool: ToolName,
    kind: &str,
    artifact: ArtifactSlot,
    created: bool,
    before: Option<&FileVersion>,
    after: &FileVersion,
    diff: &FileDiff,
    rationale: &str,
) -> Result<EventDraft, CoreError> {
    let payload = ArtifactChangePayload {
        artifact,
        job_id: handle.job_id(),
        generation: handle.generation(),
        operation_id: operation.operation_id(),
        tool,
        created,
        before_version: before,
        after_version: after,
        diff: diff.text(),
        diff_truncated: diff.is_truncated(),
        rationale,
    };
    let value = serde_json::to_value(&payload).map_err(|error| CoreError::InvalidValue {
        field: "artifactChangePayload".to_owned(),
        violation: crate::contracts::errors::ArgumentViolation::Invalid {
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
        Timestamp::now(),
        EventPayload::new(value),
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditCheckpointPayload<'a> {
    kind: &'static str,
    stage: &'static str,
    operation_id: OperationId,
    tool: ToolName,
    artifact: ArtifactSlot,
    before_version: Option<&'a FileVersion>,
    after_version: Option<&'a FileVersion>,
}

fn audit_checkpoint(
    operation: &FrozenOperation,
    tool: ToolName,
    stage: &'static str,
    artifact: ArtifactSlot,
    before: Option<&FileVersion>,
    after: Option<&FileVersion>,
) -> Result<Checkpoint, CoreError> {
    let payload = AuditCheckpointPayload {
        kind: AUDIT_CHECKPOINT_KIND,
        stage,
        operation_id: operation.operation_id(),
        tool,
        artifact,
        before_version: before,
        after_version: after,
    };
    let bytes = serde_json::to_vec(&payload).map_err(|error| CoreError::InvalidValue {
        field: "artifactCheckpoint".to_owned(),
        violation: crate::contracts::errors::ArgumentViolation::Invalid {
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
