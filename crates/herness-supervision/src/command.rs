//! Idempotent host-owned supervision commands.
//!
//! Start, stop, reassess, resume, and change requests carry one host-owned
//! request ID. A repeated ID returns the previously recorded result and never
//! starts another run, sends another request, or cancels twice. The actual
//! transaction boundary lives behind [`SupervisionStorePort`]; this module
//! defines the deterministic orchestration the later store must make atomic.

use serde::{Deserialize, Serialize};

use herness_core::contracts::ProjectId;

use crate::error::SupervisionError;
use crate::ids::{SupervisionId, SupervisionRequestId, verify_scoped};
use crate::ports::SupervisionStorePort;
use crate::state::{SupervisionReason, SupervisionRecord, SupervisionState};

/// Host-owned supervision operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisionCommand {
    /// Start the first child run.
    Start,
    /// Stop the current run and supervision target.
    Stop,
    /// Reassess the current conditions from fresh or reused evidence.
    Reassess,
    /// Resume from a human wait or stopped state.
    Resume,
    /// Change approved conditions, profile, consent, or budget.
    Change,
}

impl SupervisionCommand {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Reassess => "reassess",
            Self::Resume => "resume",
            Self::Change => "change",
        }
    }

    /// Whether this command may be the first mutation of a new target.
    pub const fn is_start(self) -> bool {
        matches!(self, Self::Start)
    }
}

/// One idempotent host command request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupervisionRequest {
    request_id: SupervisionRequestId,
    supervision_id: SupervisionId,
    command: SupervisionCommand,
    expected_revision: u64,
}

impl SupervisionRequest {
    /// Creates a request whose request and supervision IDs share one project.
    pub fn new(
        request_id: SupervisionRequestId,
        supervision_id: SupervisionId,
        command: SupervisionCommand,
        expected_revision: u64,
    ) -> Result<Self, SupervisionError> {
        let project = request_id.project_id();
        verify_scoped(&request_id, project)?;
        verify_scoped(&supervision_id, project)?;
        if expected_revision == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "expectedRevision".to_owned(),
                detail: "revisions start at 1".to_owned(),
            });
        }
        Ok(Self {
            request_id,
            supervision_id,
            command,
            expected_revision,
        })
    }

    /// Host-owned idempotent request ID.
    pub const fn request_id(&self) -> SupervisionRequestId {
        self.request_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Command.
    pub const fn command(&self) -> SupervisionCommand {
        self.command
    }

    /// Revision the caller last observed.
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    /// Project that owns the request.
    pub const fn project_id(&self) -> ProjectId {
        self.request_id.project_id()
    }
}

/// Result of one committed supervision command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandResult {
    request_id: SupervisionRequestId,
    project_id: ProjectId,
    supervision_id: SupervisionId,
    command: SupervisionCommand,
    revision: u64,
    state: SupervisionState,
    reason: SupervisionReason,
}

impl CommandResult {
    /// Creates a result bound to one project and command.
    pub fn new(
        request_id: SupervisionRequestId,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        command: SupervisionCommand,
        revision: u64,
        state: SupervisionState,
        reason: SupervisionReason,
    ) -> Result<Self, SupervisionError> {
        verify_scoped(&request_id, project_id)?;
        verify_scoped(&supervision_id, project_id)?;
        if reason.state() != state {
            return Err(SupervisionError::InvalidStateReason {
                state,
                reason: reason.kind_label().to_owned(),
            });
        }
        Ok(Self {
            request_id,
            project_id,
            supervision_id,
            command,
            revision,
            state,
            reason,
        })
    }

    /// Request ID this result is bound to.
    pub const fn request_id(&self) -> SupervisionRequestId {
        self.request_id
    }

    /// Project.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Command that produced the result.
    pub const fn command(&self) -> SupervisionCommand {
        self.command
    }

    /// Stored revision after the command.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// State after the command.
    pub const fn state(&self) -> SupervisionState {
        self.state
    }

    /// Reason after the command.
    pub fn reason(&self) -> &SupervisionReason {
        &self.reason
    }
}

/// Executes one command through a store port.
///
/// The mutation closure runs at most once per request ID. A repeated request
/// returns the recorded result before loading or mutating state again. The
/// store implementation must make the compare-and-swap and result recording
/// atomic; this function prevents duplicate application at the contract level.
pub fn execute_command<S: SupervisionStorePort>(
    store: &mut S,
    request: SupervisionRequest,
    mutate: impl FnOnce(&SupervisionRecord) -> Result<SupervisionRecord, SupervisionError>,
) -> Result<CommandResult, SupervisionError> {
    if let Some(recorded) = store.command_result(request.request_id())? {
        if recorded.supervision_id() != request.supervision_id()
            || recorded.command() != request.command()
        {
            return Err(SupervisionError::DuplicateRequestConflict {
                request: request.request_id().to_string(),
                recorded: recorded.command().as_str().to_owned(),
                supplied: request.command().as_str().to_owned(),
            });
        }
        return Ok(recorded);
    }

    let project = request.project_id();
    let current = store
        .load(project, request.supervision_id())?
        .ok_or(SupervisionError::UnknownSupervision)?;
    if current.revision() != request.expected_revision() {
        return Err(SupervisionError::RevisionConflict {
            expected: request.expected_revision(),
            found: current.revision(),
        });
    }

    let mut next = mutate(&current)?;
    if next.project_id() != project || next.supervision_id() != request.supervision_id() {
        return Err(SupervisionError::CrossProjectReference {
            id_kind: "supervision record".to_owned(),
            expected: project,
            found: next.project_id(),
        });
    }
    next.set_command_revision(current.revision().saturating_add(1));
    let result = CommandResult {
        request_id: request.request_id(),
        project_id: project,
        supervision_id: request.supervision_id(),
        command: request.command(),
        revision: next.revision(),
        state: next.state(),
        reason: next.reason().clone(),
    };
    let revision = store.commit_command(
        project,
        request.supervision_id(),
        Some(current.revision()),
        &next,
        &result,
    )?;
    let mut result = result;
    result.revision = revision;
    Ok(result)
}
