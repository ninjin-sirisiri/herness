//! Synthetic project, identifier, event, and operation fixtures.

use herness_core::{
    AbsolutePath, AgentId, Event, EventDraft, EventKind, EventPayload, FrozenOperation,
    OperationId, PermissionMode, PolicyVersion, ProjectId, RunId, SessionId, Timestamp,
    ToolArguments, ToolName,
};

/// A synthetic project with a consistent set of scoped identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectFixture {
    /// Project identifier.
    pub project_id: ProjectId,
    /// Agent identifier.
    pub agent_id: AgentId,
    /// Session identifier.
    pub session_id: SessionId,
    /// Run identifier.
    pub run_id: RunId,
}

impl ProjectFixture {
    /// Creates a new synthetic project.
    pub fn new() -> Self {
        let project_id = ProjectId::new();
        Self {
            project_id,
            agent_id: AgentId::new(project_id),
            session_id: SessionId::new(project_id),
            run_id: RunId::new(project_id),
        }
    }

    /// Generates a new operation identifier in this project.
    pub fn operation_id(&self) -> OperationId {
        OperationId::new(self.project_id)
    }

    /// Synthetic absolute working directory.
    pub fn cwd(&self) -> AbsolutePath {
        AbsolutePath::new("/tmp/herness-runtime-fixture").expect("fixture cwd is absolute")
    }

    /// Creates a frozen operation in configured permission mode.
    pub fn frozen_operation(&self, tool: ToolName, arguments: ToolArguments) -> FrozenOperation {
        FrozenOperation::new(
            self.operation_id(),
            self.run_id,
            tool,
            arguments,
            self.cwd(),
            PolicyVersion::INITIAL,
            PermissionMode::Configured,
        )
        .expect("fixture operation is valid")
    }

    /// Creates a validated event draft in this project.
    pub fn event_draft(&self, kind: &str, payload: EventPayload) -> EventDraft {
        EventDraft::new(
            self.project_id,
            self.agent_id,
            self.session_id,
            self.run_id,
            None,
            EventKind::new(kind).expect("fixture event kind is non-empty"),
            Timestamp::from_unix_millis(1_700_000_000_000),
            payload,
        )
        .expect("fixture event scope is valid")
    }

    /// Creates a persisted event with sequence 1.
    pub fn event(&self, kind: &str, payload: EventPayload) -> Event {
        self.event_draft(kind, payload)
            .into_event(1)
            .expect("fixture sequence is positive")
    }
}

impl Default for ProjectFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// Creates a second, unrelated synthetic project.
pub fn second_project() -> ProjectFixture {
    ProjectFixture::new()
}
