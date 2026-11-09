//! Input correspondence, continuation boundaries, and idle evidence.
//!
//! A run reaching [`RunState::Idle`](crate::contracts::run::RunState::Idle)
//! only means the engine has no pending work. It does not prove that a
//! submitted input completed. The host must correlate acceptance, start, and
//! completion through [`InputId`] and must distinguish startup idle from a
//! completed submission with [`IdleEvidence`].

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::contracts::errors::CoreError;
use crate::contracts::ids::{AgentId, InputId, ProjectId, ProjectScope, RunId, SessionId};
use crate::permissions::{PermissionMode, PolicyVersion};

/// Progress of one submitted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputPhase {
    /// The host durably accepted the input.
    Accepted,
    /// The engine started work for the input.
    Started,
    /// The engine completed the submitted input.
    Completed,
    /// The input was cancelled before completion.
    Cancelled,
    /// The input failed before completion.
    Failed,
}

impl InputPhase {
    /// Whether this phase is the completed terminal state.
    pub const fn is_completed(self) -> bool {
        matches!(self, Self::Completed)
    }
}

/// One acceptance/start/completion correspondence record for an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputProgress {
    input_id: InputId,
    phase: InputPhase,
}

impl InputProgress {
    /// Creates a progress record for an input already scoped to its project.
    pub const fn new(input_id: InputId, phase: InputPhase) -> Self {
        Self { input_id, phase }
    }

    /// Input this record describes.
    pub const fn input_id(self) -> InputId {
        self.input_id
    }

    /// Current phase.
    pub const fn phase(self) -> InputPhase {
        self.phase
    }

    /// Whether the submitted input completed.
    pub const fn is_completed(self) -> bool {
        self.phase.is_completed()
    }
}

/// What the host may conclude from an engine idle observation.
///
/// Only [`IdleEvidence::InputCompleted`] associates idle with a completed
/// submitted input. Startup idle and a pending input never do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum IdleEvidence {
    /// The engine reported idle before any submitted input started.
    StartupIdle,
    /// A submitted input exists but has not completed.
    InputNotCompleted {
        /// Latest known acceptance/start/terminal state.
        progress: InputProgress,
    },
    /// The submitted input completed and the engine is idle.
    InputCompleted {
        /// Input that completed.
        input_id: InputId,
    },
}

impl IdleEvidence {
    /// Evidence for an engine that has not started a submitted input.
    pub const fn startup() -> Self {
        Self::StartupIdle
    }

    /// Builds evidence from the latest input progress.
    pub fn from_progress(progress: InputProgress) -> Self {
        if progress.is_completed() {
            Self::InputCompleted {
                input_id: progress.input_id(),
            }
        } else {
            Self::InputNotCompleted { progress }
        }
    }

    /// Input this evidence refers to, if any.
    pub const fn input_id(self) -> Option<InputId> {
        match self {
            Self::StartupIdle => None,
            Self::InputNotCompleted { progress } => Some(progress.input_id()),
            Self::InputCompleted { input_id } => Some(input_id),
        }
    }

    /// Whether idle may be associated with a completed submitted input.
    pub const fn is_input_completed(self) -> bool {
        matches!(self, Self::InputCompleted { .. })
    }
}

/// Boundary request for one additional run that continues a conversation.
///
/// The request names the previous run, the same agent/session, the current
/// permission state, and the submitted input. The new run identifier must be
/// distinct from the previous run. The caller is responsible for checking that
/// the previous run is stable and has no unresolved operations before sending
/// this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuationRequest {
    project_id: ProjectId,
    input_id: InputId,
    previous_run_id: RunId,
    run_id: RunId,
    agent_id: AgentId,
    session_id: SessionId,
    permission_mode: PermissionMode,
    policy_version: PolicyVersion,
}

impl ContinuationRequest {
    /// Creates a validated continuation request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        input_id: InputId,
        previous_run_id: RunId,
        run_id: RunId,
        agent_id: AgentId,
        session_id: SessionId,
        permission_mode: PermissionMode,
        policy_version: PolicyVersion,
    ) -> Result<Self, CoreError> {
        let scope = ProjectScope::new(project_id);
        scope.verify(&input_id)?;
        scope.verify(&previous_run_id)?;
        scope.verify(&run_id)?;
        scope.verify(&agent_id)?;
        scope.verify(&session_id)?;
        if previous_run_id == run_id {
            return Err(CoreError::InvalidValue {
                field: "runId".to_owned(),
                violation: crate::contracts::errors::ArgumentViolation::Invalid {
                    detail: "a continuation run must have a new run identifier".to_owned(),
                },
            });
        }
        Ok(Self {
            project_id,
            input_id,
            previous_run_id,
            run_id,
            agent_id,
            session_id,
            permission_mode,
            policy_version,
        })
    }

    /// Project that owns the continuation.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Submitted input this continuation carries.
    pub const fn input_id(&self) -> InputId {
        self.input_id
    }

    /// Stable previous run that supplies the conversation.
    pub const fn previous_run_id(&self) -> RunId {
        self.previous_run_id
    }

    /// New run identifier for the continuation.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Same agent as the previous run.
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Same session as the previous run.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Current permission mode.
    pub const fn permission_mode(&self) -> PermissionMode {
        self.permission_mode
    }

    /// Current permission policy version.
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }
}

impl<'de> Deserialize<'de> for ContinuationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            project_id: ProjectId,
            input_id: InputId,
            previous_run_id: RunId,
            run_id: RunId,
            agent_id: AgentId,
            session_id: SessionId,
            permission_mode: PermissionMode,
            policy_version: PolicyVersion,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.project_id,
            wire.input_id,
            wire.previous_run_id,
            wire.run_id,
            wire.agent_id,
            wire.session_id,
            wire.permission_mode,
            wire.policy_version,
        )
        .map_err(de::Error::custom)
    }
}
