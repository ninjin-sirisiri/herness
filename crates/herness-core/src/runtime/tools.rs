//! Host-injected tool execution for the runtime.
//!
//! The runtime owns the permission gateway and the approval continuation. The
//! actual side effect still belongs to a `ToolExecutor` implementation (the
//! native file/shell executors in a production composition). This module adds
//! only the run context and the structured result the runtime persists.

use serde::Serialize;
use serde_json::Value;

use crate::contracts::errors::CoreError;
use crate::contracts::ids::{AgentId, ProjectId, RunId, SessionId};
use crate::contracts::operation::{OperationEvidence, OperationOutcome};
use crate::contracts::path::AbsolutePath;
use crate::tools::ToolExecutor;

/// Run identity supplied immediately before one executor call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunToolContext {
    project_id: ProjectId,
    agent_id: AgentId,
    session_id: SessionId,
    run_id: RunId,
    cwd: AbsolutePath,
}

impl RunToolContext {
    /// Creates a run context for one executor call.
    pub const fn new(
        project_id: ProjectId,
        agent_id: AgentId,
        session_id: SessionId,
        run_id: RunId,
        cwd: AbsolutePath,
    ) -> Self {
        Self {
            project_id,
            agent_id,
            session_id,
            run_id,
            cwd,
        }
    }

    /// Project that owns the run.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Agent that owns the run's conversation.
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Session that owns the run's conversation.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Run being executed.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Frozen working directory.
    pub const fn cwd(&self) -> &AbsolutePath {
        &self.cwd
    }
}

/// Structured result of one executed tool operation.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolExecution {
    outcome: OperationOutcome,
    evidence: OperationEvidence,
    summary: Value,
}

impl ToolExecution {
    /// Creates a result. `summary` is non-secret tool output used for the model
    /// continuation; it is not automatically persisted in the audit event.
    pub const fn new(
        outcome: OperationOutcome,
        evidence: OperationEvidence,
        summary: Value,
    ) -> Self {
        Self {
            outcome,
            evidence,
            summary,
        }
    }

    /// A successful read or search with no side effect.
    pub fn observed(summary: Value) -> Self {
        Self::new(
            OperationOutcome::NotApplied,
            OperationEvidence::empty(),
            summary,
        )
    }

    /// A successful side effect.
    pub const fn applied(evidence: OperationEvidence, summary: Value) -> Self {
        Self::new(OperationOutcome::Applied, evidence, summary)
    }

    /// Durable outcome claimed by the executor.
    pub const fn outcome(&self) -> OperationOutcome {
        self.outcome
    }

    /// Evidence supporting the outcome.
    pub const fn evidence(&self) -> &OperationEvidence {
        &self.evidence
    }

    /// Tool output for the model continuation.
    pub const fn summary(&self) -> &Value {
        &self.summary
    }
}

/// Executor boundary for the runtime.
///
/// The runtime sets the run context before every call, so one executor value can
/// route to the correct per-agent store handle. No model-facing dispatch tool is
/// registered: only the host calls this trait.
///
/// Implementations remain responsible for the intent-before-side-effect rule:
/// the operation intent, checkpoint, and pre-side-effect audit event must be
/// durable before the executor changes anything. The runtime records a result
/// only when the executor did not record one itself.
pub trait RuntimeToolExecutor: ToolExecutor<Output = ToolExecution> {
    /// Sets the run identity used by the next `execute` call.
    fn enter_run(&mut self, context: RunToolContext) -> Result<(), CoreError>;
}
