//! Host-owned project, agent, and run composition.
//!
//! The runtime owns the project registry, host-created agent/session
//! identities, run lifecycle, approval continuation, restart reconciliation, and
//! committed-event subscription. Store, engine, credential, evaluator, and tool
//! implementations are injected by the desktop composition; this module never
//! depends on `herness-store` or `herness-engine-pi`.
//!
//! Safety rules implemented here:
//!
//! * a run starts only after the selected connection, permission mode, and
//!   required capabilities are usable;
//! * run state and its initial audit event are durable before `EnginePort::start`;
//! * a tool operation that needs human approval is persisted and the run enters
//!   `awaiting_approval` before any executor is reached;
//! * approvals are bound to the exact frozen operation, project, policy version,
//!   and mode; stale, restored, cross-project, repeated, and denied approvals
//!   never execute;
//! * `idle` is quiescence only, never task or goal completion, and a later run is
//!   a separate run;
//! * restore never starts engines, sends model requests, executes tools, or
//!   reuses prior approvals.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::json;

use crate::connections::ConnectionDirectory;
use crate::contracts::connection::{ConnectionId, ConnectionInfo, ConnectionStatus};
use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::events::{Event, EventDraft, EventKind, EventPayload};
use crate::contracts::history::HistoryLimit;
use crate::contracts::ids::{AgentId, IdKind, ProjectId, RunId, SessionId};
use crate::contracts::operation::FrozenOperation;
use crate::contracts::path::AbsolutePath;
use crate::contracts::run::RunState;
use crate::contracts::time::Timestamp;
use crate::permissions::{
    EvaluationContext, EvaluatorAvailability, GrantScope, PermissionMode, PermissionPolicy,
    PermissionRule, PolicyAdmin,
};
use crate::ports::engine::{EngineEvent, EngineInput, EnginePort, EngineStart, StopReport};
use crate::ports::{PermissionEvaluatorPort, RuntimeStore};
use crate::runtime::error::RuntimeError;
use crate::runtime::state::{
    AgentRecord, HOST_STATE_KEY, HostState, ProjectRecord, RunRecord, StoredGrant,
};
use crate::runtime::tools::{RunToolContext, RuntimeToolExecutor, ToolExecution};
use crate::runtime::views::{
    AgentView, DenialOutcome, PendingApproval, ProjectView, RunView, RuntimeSnapshot, StopOutcome,
};
use crate::skills::{
    CapabilityStatus, HostCapabilities, HostCapability, ToolchainConfig, ToolchainDetector,
};
use crate::tools::{GatewayError, ToolArguments, ToolGateway, ToolName};

/// Dependencies supplied by the trusted desktop composition.
pub struct RuntimeDependencies<S, E, T> {
    store: Arc<Mutex<S>>,
    engine: E,
    credentials: Arc<dyn crate::ports::CredentialPort + Send + Sync>,
    directory: ConnectionDirectory,
    policy: PolicyAdmin,
    evaluator: Option<Box<dyn PermissionEvaluatorPort + Send + Sync>>,
    capabilities: HostCapabilities,
    toolchain: ToolchainConfig,
    executor: T,
}

impl<S, E, T> RuntimeDependencies<S, E, T> {
    /// Creates the minimum dependency set. Capabilities default to the H1 set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<Mutex<S>>,
        engine: E,
        credentials: Arc<dyn crate::ports::CredentialPort + Send + Sync>,
        directory: ConnectionDirectory,
        policy: PolicyAdmin,
        executor: T,
    ) -> Self {
        Self {
            store,
            engine,
            credentials,
            directory,
            policy,
            evaluator: None,
            capabilities: HostCapabilities::h1(),
            toolchain: ToolchainConfig::empty(),
            executor,
        }
    }

    /// Supplies the H2 evaluator. Without an available evaluator, automatic
    /// mode is refused.
    #[must_use]
    pub fn with_evaluator(
        mut self,
        evaluator: Box<dyn PermissionEvaluatorPort + Send + Sync>,
    ) -> Self {
        self.evaluator = Some(evaluator);
        self
    }

    /// Replaces the host capability report.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: HostCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Replaces the toolchain configuration used by project-open summaries.
    #[must_use]
    pub fn with_toolchain(mut self, toolchain: ToolchainConfig) -> Self {
        self.toolchain = toolchain;
        self
    }
}

/// Host-created agent request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSpec {
    name: String,
    role: String,
    connection: ConnectionId,
    parent: Option<AgentId>,
    required_capabilities: Vec<HostCapability>,
    scope: Option<Vec<PermissionRule>>,
}

impl AgentSpec {
    /// Creates a root agent request.
    pub fn new(name: impl Into<String>, role: impl Into<String>, connection: ConnectionId) -> Self {
        Self {
            name: name.into().trim().to_owned(),
            role: role.into().trim().to_owned(),
            connection,
            parent: None,
            required_capabilities: Vec::new(),
            scope: None,
        }
    }

    /// Creates a host-owned child agent. Its grant scope is derived from the
    /// parent with [`GrantScope::derive_child`].
    #[must_use]
    pub fn child_of(mut self, parent: AgentId) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Declares a capability the run must have.
    #[must_use]
    pub fn requiring(mut self, capability: HostCapability) -> Self {
        self.required_capabilities.push(capability);
        self
    }

    /// Restricts the agent's grant scope. A child may only ask for a subset of
    /// its parent's scope.
    #[must_use]
    pub fn with_scope(mut self, rules: Vec<PermissionRule>) -> Self {
        self.scope = Some(rules);
        self
    }
}

/// Host runtime for one application process.
pub struct Runtime<S, E, T>
where
    S: RuntimeStore,
    E: EnginePort,
    T: RuntimeToolExecutor,
{
    store: Arc<Mutex<S>>,
    engine: E,
    credentials: Arc<dyn crate::ports::CredentialPort + Send + Sync>,
    directory: ConnectionDirectory,
    policy: PolicyAdmin,
    evaluator: Option<Box<dyn PermissionEvaluatorPort + Send + Sync>>,
    capabilities: HostCapabilities,
    toolchain: ToolchainDetector,
    gateway: ToolGateway<T>,
    state: HostState,
    /// Host-result messages waiting for an engine turn to become idle. This is
    /// in-process only; it never contains credentials or model output and is
    /// discarded by restart reconciliation.
    deferred_continuations: BTreeMap<RunId, Vec<String>>,
}

impl<S, E, T> Runtime<S, E, T>
where
    S: RuntimeStore,
    E: EnginePort,
    T: RuntimeToolExecutor,
{
    /// Restores persisted host state and produces a reconciliation report.
    ///
    /// Restore performs read-only store queries and filesystem evidence checks.
    /// It never calls the engine, sends model input, executes a tool, or reuses a
    /// prior approval.
    pub fn restore(
        dependencies: RuntimeDependencies<S, E, T>,
    ) -> Result<(Self, crate::runtime::reconcile::ReconciliationReport), RuntimeError> {
        let RuntimeDependencies {
            store,
            engine,
            credentials,
            directory,
            policy,
            evaluator,
            capabilities,
            toolchain,
            executor,
        } = dependencies;

        let state = {
            let store_guard = lock_store(&store)?;
            match store_guard
                .load_host_state(HOST_STATE_KEY)
                .map_err(RuntimeError::store)?
            {
                Some(bytes) => HostState::from_bytes(&bytes)?,
                None => HostState::default(),
            }
        };

        let mut runtime = Self {
            store,
            engine,
            credentials,
            directory,
            policy,
            evaluator,
            capabilities,
            toolchain: ToolchainDetector::new(toolchain),
            gateway: ToolGateway::new(executor),
            state,
            deferred_continuations: BTreeMap::new(),
        };
        let report = runtime.reconcile()?;
        Ok((runtime, report))
    }

    /// Current policy snapshot.
    pub fn policy(&self) -> &PermissionPolicy {
        self.policy.policy()
    }

    /// Human-only policy administration surface.
    ///
    /// This is intentionally not reachable from a tool or model request.
    pub fn policy_admin_mut(&mut self) -> &mut PolicyAdmin {
        &mut self.policy
    }

    /// Host capability report.
    pub const fn capabilities(&self) -> HostCapabilities {
        self.capabilities
    }

    /// Read-only connection directory.
    pub const fn directory(&self) -> &ConnectionDirectory {
        &self.directory
    }

    /// Engine adapter reference, for composition and lifecycle wiring.
    pub const fn engine(&self) -> &E {
        &self.engine
    }

    /// Mutable engine adapter reference.
    pub const fn engine_mut(&mut self) -> &mut E {
        &mut self.engine
    }

    /// Tool gateway reference, for composition wiring.
    pub const fn gateway(&self) -> &ToolGateway<T> {
        &self.gateway
    }

    /// Opens a real project directory.
    ///
    /// The path is canonicalized, must be a readable directory, and is mapped to
    /// one stable project identifier. A symlinked path is accepted only as its
    /// canonical real directory. Toolchain and capability deficiencies are
    /// returned as part of the view, never hidden.
    pub fn open_project(&mut self, path: impl AsRef<Path>) -> Result<ProjectView, RuntimeError> {
        let supplied = path.as_ref();
        let supplied_text = supplied.to_string_lossy().into_owned();
        let canonical =
            std::fs::canonicalize(supplied).map_err(|error| RuntimeError::ProjectUnreadable {
                path: supplied_text.clone(),
                detail: format!("{:?}", error.kind()),
            })?;
        let metadata =
            std::fs::metadata(&canonical).map_err(|error| RuntimeError::ProjectUnreadable {
                path: canonical.to_string_lossy().into_owned(),
                detail: format!("{:?}", error.kind()),
            })?;
        if !metadata.is_dir() {
            return Err(RuntimeError::ProjectNotDirectory {
                path: canonical.to_string_lossy().into_owned(),
            });
        }
        std::fs::read_dir(&canonical).map_err(|error| RuntimeError::ProjectUnreadable {
            path: canonical.to_string_lossy().into_owned(),
            detail: format!("{:?}", error.kind()),
        })?;

        let text = canonical
            .to_str()
            .ok_or_else(|| RuntimeError::ProjectUnreadable {
                path: canonical.to_string_lossy().into_owned(),
                detail: "path is not valid UTF-8".to_owned(),
            })?;
        let absolute = AbsolutePath::new(text).map_err(RuntimeError::invalid_value)?;

        let project_id = match self.state.project_id_for_path(&absolute) {
            Some(project_id) => project_id,
            None => {
                let mut next = self.state.clone();
                let project_id = ProjectId::new();
                next.projects_mut()
                    .insert(project_id, ProjectRecord::new(absolute.clone()));
                self.commit_state(next, Vec::new())?;
                project_id
            }
        };

        self.project_view(project_id)
    }

    /// Lists open projects in stable identifier order.
    pub fn projects(&self) -> Result<Vec<ProjectView>, RuntimeError> {
        self.state
            .projects()
            .keys()
            .copied()
            .map(|project| self.project_view(project))
            .collect()
    }

    /// Returns one project's view.
    pub fn project(&self, project: ProjectId) -> Result<ProjectView, RuntimeError> {
        self.project_view(project)
    }

    /// Creates a host-owned agent and independent session.
    pub fn create_agent(
        &mut self,
        project: ProjectId,
        spec: AgentSpec,
    ) -> Result<AgentView, RuntimeError> {
        let project_record = self.project_record(project)?.clone();
        if spec.name.is_empty() {
            return Err(RuntimeError::InvalidValue {
                field: "agentName".to_owned(),
                violation: ArgumentViolation::Empty,
            });
        }
        if spec.role.is_empty() {
            return Err(RuntimeError::InvalidValue {
                field: "agentRole".to_owned(),
                violation: ArgumentViolation::Empty,
            });
        }
        self.directory
            .get(spec.connection)
            .map_err(|_| RuntimeError::UnknownConnection {
                connection: spec.connection,
            })?;

        let policy = self.policy.policy().clone();
        let grant = match spec.parent {
            Some(parent_id) => {
                if parent_id.project_id() != project {
                    return Err(RuntimeError::CrossProject {
                        id_kind: IdKind::Agent,
                        expected: project,
                        found: parent_id.project_id(),
                    });
                }
                let parent = project_record
                    .agents
                    .get(&parent_id)
                    .ok_or(RuntimeError::UnknownAgent { agent: parent_id })?;
                let parent_scope = match &parent.grant {
                    Some(stored) => stored.to_scope(project)?,
                    None => GrantScope::for_run(project, &policy),
                };
                let requested = match spec.scope {
                    Some(rules) => GrantScope::new(project, rules, policy.mode(), policy.version())
                        .map_err(|error| RuntimeError::CorruptState {
                            detail: format!("agent grant: {error}"),
                        })?,
                    None => GrantScope::for_run(project, &policy),
                };
                Some(
                    parent_scope
                        .derive_child(&requested)
                        .map_err(|error| RuntimeError::GrantWidening { error })?,
                )
            }
            None => match spec.scope {
                Some(rules) => Some(
                    GrantScope::new(project, rules, policy.mode(), policy.version()).map_err(
                        |error| RuntimeError::CorruptState {
                            detail: format!("agent grant: {error}"),
                        },
                    )?,
                ),
                None => None,
            },
        };

        let agent_id = AgentId::new(project);
        let session_id = SessionId::new(project);
        let created_at = Timestamp::now();
        let record = AgentRecord {
            session_id,
            name: spec.name.clone(),
            role: spec.role.clone(),
            connection: spec.connection,
            parent: spec.parent,
            grant: grant.as_ref().map(StoredGrant::from_scope),
            required_capabilities: spec.required_capabilities.clone(),
            created_at,
        };

        let mut next = self.state.clone();
        next.projects_mut()
            .get_mut(&project)
            .ok_or(RuntimeError::UnknownProject { project })?
            .agents
            .insert(agent_id, record);
        self.commit_state(next, Vec::new())?;

        Ok(AgentView::new(
            project,
            agent_id,
            session_id,
            spec.name,
            spec.role,
            spec.connection,
            spec.parent,
            spec.required_capabilities,
            created_at,
        ))
    }

    /// Starts one run for an existing agent.
    pub fn start_run(
        &mut self,
        project: ProjectId,
        agent: AgentId,
        instructions: impl Into<String>,
    ) -> Result<RunView, RuntimeError> {
        let project_record = self.project_record(project)?.clone();
        if agent.project_id() != project {
            return Err(RuntimeError::CrossProject {
                id_kind: IdKind::Agent,
                expected: project,
                found: agent.project_id(),
            });
        }
        let agent_record = project_record
            .agents
            .get(&agent)
            .cloned()
            .ok_or(RuntimeError::UnknownAgent { agent })?;

        let status = self.connection_status(agent_record.connection)?;
        if status != ConnectionStatus::Available {
            return Err(RuntimeError::ConnectionUnavailable {
                connection: agent_record.connection,
                status,
            });
        }
        let policy = self.policy.policy().clone();
        self.ensure_mode_usable(&policy)?;
        self.ensure_capabilities(&agent_record)?;

        let grant = match &agent_record.grant {
            Some(stored) => {
                let grant = stored.to_scope(project)?;
                if grant.policy_version() != policy.version() {
                    return Err(RuntimeError::PermissionContextStale {
                        detail: format!(
                            "agent grant is at policy version {}, current version is {}",
                            grant.policy_version(),
                            policy.version()
                        ),
                    });
                }
                if grant.mode() != policy.mode() {
                    return Err(RuntimeError::PermissionContextStale {
                        detail: "agent grant mode differs from the current policy".to_owned(),
                    });
                }
                grant
            }
            None => GrantScope::for_run(project, &policy),
        };

        let run_id = RunId::new(project);
        let start = EngineStart::new(
            project,
            agent,
            agent_record.session_id,
            run_id,
            agent_record.connection,
            project_record.path.clone(),
            instructions.into(),
        )
        .map_err(RuntimeError::engine)?;

        let now = Timestamp::now();
        let record = RunRecord {
            agent_id: agent,
            session_id: agent_record.session_id,
            connection: agent_record.connection,
            state: RunState::Running,
            instructions: start.instructions().to_owned(),
            grant: StoredGrant::from_scope(&grant),
            mode: policy.mode(),
            policy_version: policy.version(),
            created_at: now,
            updated_at: now,
        };
        let event = event_draft(
            project,
            agent,
            agent_record.session_id,
            run_id,
            None,
            "run.started",
            json!({
                "state": record.state.as_str(),
                "connection": record.connection.to_string(),
                "mode": record.mode.to_string(),
                "policyVersion": record.policy_version.get(),
            }),
        )?;

        let mut next = self.state.clone();
        next.projects_mut()
            .get_mut(&project)
            .ok_or(RuntimeError::UnknownProject { project })?
            .runs
            .insert(run_id, record.clone());
        self.commit_state(next, vec![event])?;

        if let Err(error) = self.engine.start(start) {
            let mut next = self.state.clone();
            if let Some(stored) = next
                .projects_mut()
                .get_mut(&project)
                .and_then(|project| project.runs.get_mut(&run_id))
            {
                stored.state = RunState::Failed;
                stored.updated_at = Timestamp::now();
            }
            let failed = event_draft(
                project,
                agent,
                agent_record.session_id,
                run_id,
                None,
                "run.failed",
                json!({ "state": "failed", "stage": "engine_start" }),
            )
            .ok();
            let _ = self.commit_state(next, failed.into_iter().collect());
            return Err(RuntimeError::Engine { error });
        }

        Ok(run_view(project, run_id, &record))
    }

    /// Returns one run's current view.
    pub fn run(&self, project: ProjectId, run: RunId) -> Result<RunView, RuntimeError> {
        let record = self.run_record(project, run)?;
        Ok(run_view(project, run, record))
    }

    /// Sends one explicit host-approved text turn to a running engine.
    ///
    /// This is the human "start" input for a run. It validates the run state,
    /// records that an input was submitted without copying the text into the
    /// audit payload (the engine checkpoint holds the conversation), and then
    /// hands the text to the engine. A failed submission moves the run to
    /// `interrupted`; it is never retried automatically.
    pub fn submit_input(
        &mut self,
        project: ProjectId,
        run: RunId,
        text: impl Into<String>,
    ) -> Result<(), RuntimeError> {
        let text = text.into();
        if text.trim().is_empty() {
            return Err(RuntimeError::InvalidValue {
                field: "input".to_owned(),
                violation: ArgumentViolation::Empty,
            });
        }
        let record = self.run_record(project, run)?.clone();
        if record.state != RunState::Running {
            return Err(RuntimeError::InvalidRunTransition {
                from: record.state,
                to: RunState::Running,
            });
        }
        let event = event_draft(
            project,
            record.agent_id,
            record.session_id,
            run,
            None,
            "run.input_submitted",
            json!({ "source": "human", "unicodeScalars": text.chars().count() }),
        )?;
        self.commit_state(self.state.clone(), vec![event])?;
        if let Err(error) = self.engine.send_input(&run, EngineInput::Text(text)) {
            self.mark_interrupted(
                project,
                run,
                &record,
                "input_failed",
                json!({ "failure": error }),
            )?;
            return Err(RuntimeError::Engine { error });
        }
        Ok(())
    }

    /// Stops a run through the engine and records a checkpoint.
    ///
    /// A confirmed or already-inactive engine move to `paused`. An unconfirmed
    /// stop moves to `interrupted`. Neither is reported as `failed`, and an
    /// unconfirmed stop is never presented as fully stopped.
    pub fn stop_run(
        &mut self,
        project: ProjectId,
        run: RunId,
        reason: crate::ports::engine::StopReason,
    ) -> Result<StopOutcome, RuntimeError> {
        let record = self.run_record(project, run)?.clone();
        if record.state == RunState::Failed {
            return Err(RuntimeError::InvalidRunTransition {
                from: record.state,
                to: RunState::Paused,
            });
        }
        if !record.state.is_active() {
            let report = self
                .engine
                .request_stop(&run, reason)
                .map_err(RuntimeError::engine)?;
            return Ok(StopOutcome::new(
                run_view(project, run, &record),
                report,
                false,
            ));
        }

        let report = self
            .engine
            .request_stop(&run, reason)
            .map_err(RuntimeError::engine)?;
        let checkpoint = self.engine.checkpoint(&run).ok().flatten();
        let target = match report {
            StopReport::Stopped | StopReport::NotRunning => RunState::Paused,
            StopReport::Unconfirmed => RunState::Interrupted,
        };

        let invalidated = {
            let project_record = self.project_record(project)?;
            project_record
                .approvals
                .values()
                .filter(|approval| approval.run_id == run)
                .count()
        };
        self.gateway.service_mut().invalidate_run(run);
        self.deferred_continuations.remove(&run);

        let now = Timestamp::now();
        let mut next = self.state.clone();
        let project_record = next
            .projects_mut()
            .get_mut(&project)
            .ok_or(RuntimeError::UnknownProject { project })?;
        if let Some(stored) = project_record.runs.get_mut(&run) {
            stored.state = target;
            stored.updated_at = now;
        }
        project_record
            .approvals
            .retain(|_, approval| approval.run_id != run);
        let event = event_draft(
            project,
            record.agent_id,
            record.session_id,
            run,
            None,
            "run.stopped",
            json!({
                "from": record.state.as_str(),
                "to": target.as_str(),
                "report": serde_json::to_value(report).unwrap_or_default(),
                "invalidatedApprovals": invalidated,
            }),
        )?;
        let checkpoint_saved = checkpoint.is_some();
        self.commit_state_checkpoint(next, checkpoint, vec![event])?;

        let stored = self.run_record(project, run)?.clone();
        Ok(StopOutcome::new(
            run_view(project, run, &stored),
            report,
            checkpoint_saved,
        ))
    }

    /// Resumes a paused or interrupted run as the same run.
    ///
    /// This is an explicit human action. It re-checks the current credential and
    /// permission context, restores from the saved checkpoint, and does not send
    /// a model request or replay a tool. `idle` runs are not resumable; a later
    /// execution is a separate run.
    pub fn resume_run(&mut self, project: ProjectId, run: RunId) -> Result<RunView, RuntimeError> {
        let record = self.run_record(project, run)?.clone();
        if !matches!(record.state, RunState::Paused | RunState::Interrupted) {
            return Err(RuntimeError::InvalidRunTransition {
                from: record.state,
                to: RunState::Running,
            });
        }
        let project_record = self.project_record(project)?.clone();
        let agent_record = project_record.agents.get(&record.agent_id).cloned().ok_or(
            RuntimeError::UnknownAgent {
                agent: record.agent_id,
            },
        )?;
        let status = self.connection_status(record.connection)?;
        if status != ConnectionStatus::Available {
            return Err(RuntimeError::ConnectionUnavailable {
                connection: record.connection,
                status,
            });
        }
        let policy = self.policy.policy().clone();
        self.ensure_mode_usable(&policy)?;
        self.ensure_capabilities(&agent_record)?;
        let grant = record.grant.to_scope(project)?;
        if grant.policy_version() != policy.version() || grant.mode() != policy.mode() {
            return Err(RuntimeError::PermissionContextStale {
                detail: "the run grant no longer matches the current policy".to_owned(),
            });
        }

        let checkpoint = {
            let store = lock_store(&self.store)?;
            store
                .load_checkpoint(&run)
                .map_err(RuntimeError::store)?
                .ok_or(RuntimeError::NoCheckpoint { run })?
        };

        self.gateway.service_mut().invalidate_run(run);
        self.deferred_continuations.remove(&run);
        let now = Timestamp::now();
        let mut next = self.state.clone();
        let project_record = next
            .projects_mut()
            .get_mut(&project)
            .ok_or(RuntimeError::UnknownProject { project })?;
        project_record
            .approvals
            .retain(|_, approval| approval.run_id != run);
        if let Some(stored) = project_record.runs.get_mut(&run) {
            stored.state = RunState::Running;
            stored.updated_at = now;
        }
        let event = event_draft(
            project,
            record.agent_id,
            record.session_id,
            run,
            None,
            "run.resumed",
            json!({ "from": record.state.as_str(), "to": "running" }),
        )?;
        self.commit_state(next, vec![event])?;

        if let Err(error) = self.engine.resume(&run, checkpoint) {
            let mut next = self.state.clone();
            if let Some(stored) = next
                .projects_mut()
                .get_mut(&project)
                .and_then(|project| project.runs.get_mut(&run))
            {
                stored.state = RunState::Failed;
                stored.updated_at = Timestamp::now();
            }
            let failed = event_draft(
                project,
                record.agent_id,
                record.session_id,
                run,
                None,
                "run.failed",
                json!({ "state": "failed", "stage": "engine_resume" }),
            )
            .ok();
            let _ = self.commit_state(next, failed.into_iter().collect());
            return Err(RuntimeError::Engine { error });
        }

        let stored = self.run_record(project, run)?.clone();
        Ok(run_view(project, run, &stored))
    }

    /// Stable UI snapshot for reconnect.
    pub fn snapshot(&self, project: ProjectId) -> Result<RuntimeSnapshot, RuntimeError> {
        let project_record = self.project_record(project)?;
        let runs = project_record
            .runs
            .iter()
            .map(|(run, record)| run_view(project, *run, record))
            .collect();
        let pending = self.pending_approvals(project)?;
        let last_sequence = self.last_sequence(project)?;
        Ok(RuntimeSnapshot::new(project, runs, pending, last_sequence))
    }

    /// Reads committed events in ascending order after a project-bound cursor.
    pub fn subscribe(
        &self,
        project: ProjectId,
        cursor: Option<crate::runtime::views::SubscriptionCursor>,
        limit: HistoryLimit,
    ) -> Result<crate::runtime::views::EventBatch, RuntimeError> {
        self.project_record(project)?;
        if let Some(cursor) = &cursor {
            cursor.verify(project)?;
        }
        let after = cursor
            .as_ref()
            .map(crate::runtime::views::SubscriptionCursor::after_sequence)
            .filter(|sequence| *sequence > 0);
        let events = {
            let store = lock_store(&self.store)?;
            store
                .events_after(&project, after, limit)
                .map_err(RuntimeError::store)?
        };
        let last_sequence = events.last().map(Event::sequence).or(after).unwrap_or(0);
        Ok(crate::runtime::views::EventBatch::new(
            events,
            last_sequence,
        ))
    }

    /// Returns the last committed project sequence.
    pub fn last_sequence(&self, project: ProjectId) -> Result<u64, RuntimeError> {
        let page = {
            let store = lock_store(&self.store)?;
            store
                .history(crate::contracts::history::HistoryQuery::first(project))
                .map_err(RuntimeError::store)?
        };
        Ok(page.events().first().map_or(0, Event::sequence))
    }

    /// Drains engine events for one run and commits the resulting audit events.
    ///
    /// `idle` after this call means the engine is quiescent. It is not a
    /// completion claim and never starts another run.
    pub fn poll_run(&mut self, project: ProjectId, run: RunId) -> Result<Vec<Event>, RuntimeError> {
        self.run_record(project, run)?;
        let events = self
            .engine
            .poll_events(&run)
            .map_err(RuntimeError::engine)?;
        let mut committed = Vec::new();
        for event in events {
            committed.extend(self.handle_engine_event(project, run, event)?);
        }
        Ok(committed)
    }

    fn handle_engine_event(
        &mut self,
        project: ProjectId,
        run: RunId,
        event: EngineEvent,
    ) -> Result<Vec<Event>, RuntimeError> {
        match event {
            EngineEvent::TextDelta { .. } => Ok(Vec::new()),
            EngineEvent::TextCompleted { text } => {
                if text.is_empty() {
                    return Ok(Vec::new());
                }
                let record = self.run_record(project, run)?.clone();
                let event = event_draft(
                    project,
                    record.agent_id,
                    record.session_id,
                    run,
                    None,
                    "run.text_completed",
                    json!({ "text": text }),
                )?;
                let next = self.state.clone();
                let receipt = self.commit_state(next, vec![event])?;
                Ok(receipt.events().to_vec())
            }
            EngineEvent::ToolCall { tool, arguments } => {
                if self.engine.tool_execution_authority()
                    == crate::ports::ToolExecutionAuthority::Adapter
                {
                    // The adapter executes allowed tools itself and reports
                    // awaiting operations separately. Re-evaluating this frame
                    // would create a second executor for the same operation.
                    return Ok(Vec::new());
                }
                self.handle_tool_call(project, run, tool, arguments)
            }
            EngineEvent::ToolApprovalRequired { operation } => {
                self.record_engine_approval(project, run, operation)
            }
            EngineEvent::StateChanged(state) => self.handle_state_changed(project, run, state),
            EngineEvent::Failure { failure } => {
                let record = self.run_record(project, run)?.clone();
                let event = event_draft(
                    project,
                    record.agent_id,
                    record.session_id,
                    run,
                    None,
                    "run.failure",
                    json!({ "failure": failure }),
                )?;
                let next = self.state.clone();
                let receipt = self.commit_state(next, vec![event])?;
                Ok(receipt.events().to_vec())
            }
        }
    }

    fn handle_state_changed(
        &mut self,
        project: ProjectId,
        run: RunId,
        state: RunState,
    ) -> Result<Vec<Event>, RuntimeError> {
        let record = self.run_record(project, run)?.clone();
        let target = match (record.state, state) {
            (RunState::Failed | RunState::Paused | RunState::Interrupted, _) => record.state,
            (RunState::AwaitingApproval, RunState::Running | RunState::Idle) => {
                // The host is still waiting for a human decision. An engine
                // status echo cannot clear that state.
                record.state
            }
            (_, target) => target,
        };
        let now = Timestamp::now();
        let mut next = self.state.clone();
        if let Some(stored) = next
            .projects_mut()
            .get_mut(&project)
            .and_then(|project| project.runs.get_mut(&run))
        {
            stored.state = target;
            stored.updated_at = now;
        }
        let event = event_draft(
            project,
            record.agent_id,
            record.session_id,
            run,
            None,
            "run.state_changed",
            json!({ "from": record.state.as_str(), "to": target.as_str() }),
        )?;
        let receipt = self.commit_state(next, vec![event])?;
        if state == RunState::Idle && matches!(target, RunState::Idle | RunState::Running) {
            self.flush_deferred(project, run)?;
        }
        Ok(receipt.events().to_vec())
    }

    fn handle_tool_call(
        &mut self,
        project: ProjectId,
        run: RunId,
        tool: ToolName,
        arguments: ToolArguments,
    ) -> Result<Vec<Event>, RuntimeError> {
        let record = self.run_record(project, run)?.clone();
        if record.state != RunState::Running {
            // A late or redelivered tool frame must not start work while the run
            // is paused, interrupted, failed, or waiting for a human.
            let event = event_draft(
                project,
                record.agent_id,
                record.session_id,
                run,
                None,
                "run.tool_call_ignored",
                json!({ "tool": tool.as_str(), "state": record.state.as_str() }),
            )?;
            let receipt = self.commit_state(self.state.clone(), vec![event])?;
            return Ok(receipt.events().to_vec());
        }

        let policy = self.policy.policy().clone();
        self.ensure_mode_usable(&policy)?;
        let project_record = self.project_record(project)?.clone();
        let grant = record.grant.to_scope(project)?;
        if grant.policy_version() != policy.version() || grant.mode() != policy.mode() {
            self.mark_failed(
                project,
                run,
                &record,
                "permission_context_changed",
                json!({}),
            )?;
            return Err(RuntimeError::PermissionContextStale {
                detail: "grant does not match the current policy".to_owned(),
            });
        }

        let operation = match FrozenOperation::new(
            crate::contracts::ids::OperationId::new(project),
            run,
            tool,
            arguments,
            project_record.path.clone(),
            policy.version(),
            policy.mode(),
        ) {
            Ok(operation) => operation,
            Err(error) => {
                self.mark_failed(project, run, &record, "invalid_tool_arguments", json!({}))?;
                return Err(RuntimeError::InvalidArguments {
                    tool,
                    detail: error.to_string(),
                });
            }
        };

        let outcome = self
            .gateway
            .authorize(
                &policy,
                &grant,
                &operation,
                &EvaluationContext::new(record.instructions.clone(), Vec::new()),
                self.evaluator.as_deref_mut(),
            )
            .map_err(RuntimeError::store)?;

        match outcome {
            crate::permissions::PermissionOutcome::Deny { reason } => {
                let event = event_draft(
                    project,
                    record.agent_id,
                    record.session_id,
                    run,
                    Some(operation.operation_id()),
                    "run.operation_denied",
                    json!({
                        "operationId": operation.operation_id().to_string(),
                        "tool": tool.as_str(),
                        "reason": reason,
                    }),
                )?;
                let receipt = self.commit_state(self.state.clone(), vec![event])?;
                let message = format!(
                    "The host denied tool operation {} ({}) by permission policy. Do not retry it without a new human decision.",
                    operation.operation_id(),
                    tool.as_str()
                );
                self.send_continuation(project, run, &record, message)?;
                Ok(receipt.events().to_vec())
            }
            crate::permissions::PermissionOutcome::AwaitingApproval { request } => {
                self.persist_awaiting_approval(project, run, &record, operation, request.reason())
            }
            crate::permissions::PermissionOutcome::Allow { authorization } => {
                let mut committed = Vec::new();
                let result =
                    self.execute_authorized(project, run, &record, &operation, &authorization)?;
                committed.extend(result.events);
                if let Some(message) = result.continuation {
                    self.send_continuation(project, run, &record, message)?;
                }
                if result.uncertain {
                    self.mark_interrupted(
                        project,
                        run,
                        &record,
                        "tool_outcome_uncertain",
                        json!({ "operationId": operation.operation_id().to_string() }),
                    )?;
                } else if let Some(message) = result.failure_message {
                    self.send_continuation(project, run, &record, message)?;
                }
                Ok(committed)
            }
        }
    }

    /// Persists one human-wait decision exactly once for the run.
    fn persist_awaiting_approval(
        &mut self,
        project: ProjectId,
        run: RunId,
        record: &RunRecord,
        operation: FrozenOperation,
        reason: &crate::permissions::HumanWaitReason,
    ) -> Result<Vec<Event>, RuntimeError> {
        let operation_id = operation.operation_id();
        let approval = crate::runtime::state::ApprovalRecord {
            run_id: run,
            agent_id: record.agent_id,
            session_id: record.session_id,
            operation: operation.clone(),
            reason: approval_reason_label(reason),
            requested_at: Timestamp::now(),
            restored: false,
        };
        let now = Timestamp::now();
        let mut next = self.state.clone();
        let project_record = next
            .projects_mut()
            .get_mut(&project)
            .ok_or(RuntimeError::UnknownProject { project })?;
        if project_record.approvals.contains_key(&operation_id) {
            // A redelivered request is not a second decision.
            return Ok(Vec::new());
        }
        project_record.approvals.insert(operation_id, approval);
        if let Some(stored) = project_record.runs.get_mut(&run) {
            stored.state = RunState::AwaitingApproval;
            stored.updated_at = now;
        }
        let event = event_draft(
            project,
            record.agent_id,
            record.session_id,
            run,
            Some(operation_id),
            "run.awaiting_approval",
            json!({
                "operationId": operation_id.to_string(),
                "tool": operation.tool().as_str(),
                "state": RunState::AwaitingApproval.as_str(),
            }),
        )?;
        let receipt = self.commit_state(next, vec![event])?;
        Ok(receipt.events().to_vec())
    }

    /// Records a frozen operation that the trusted engine adapter refused to
    /// execute because its host policy required a human decision.
    ///
    /// The runtime re-applies its own policy to the exact operation and records
    /// the resulting human wait. It never executes here, and an operation that
    /// the adapter or runtime would not leave waiting is rejected without a
    /// side effect.
    fn record_engine_approval(
        &mut self,
        project: ProjectId,
        run: RunId,
        operation: FrozenOperation,
    ) -> Result<Vec<Event>, RuntimeError> {
        if operation.project_id() != project || operation.run_id() != run {
            return self.record_approval_rejection(project, run, None, "operation_scope_mismatch");
        }
        let operation_id = operation.operation_id();
        let record = self.run_record(project, run)?.clone();
        if record.state != RunState::Running {
            let event = event_draft(
                project,
                record.agent_id,
                record.session_id,
                run,
                Some(operation_id),
                "run.tool_approval_ignored",
                json!({
                    "operationId": operation_id.to_string(),
                    "state": record.state.as_str(),
                }),
            )?;
            let receipt = self.commit_state(self.state.clone(), vec![event])?;
            return Ok(receipt.events().to_vec());
        }
        if self
            .project_record(project)?
            .approvals
            .contains_key(&operation_id)
        {
            // The adapter may redeliver the same request; one decision remains.
            return Ok(Vec::new());
        }
        if self.operation_exists(operation_id)? {
            return self.record_approval_rejection(
                project,
                run,
                Some(operation_id),
                "operation_already_recorded",
            );
        }

        let policy = self.policy.policy().clone();
        if operation.policy_version() != policy.version()
            || operation.permission_mode() != policy.mode()
        {
            return self.record_approval_rejection(
                project,
                run,
                Some(operation_id),
                "stale_permission_context",
            );
        }
        let grant = record.grant.to_scope(project)?;
        if grant.policy_version() != policy.version() || grant.mode() != policy.mode() {
            return self.record_approval_rejection(
                project,
                run,
                Some(operation_id),
                "stale_permission_context",
            );
        }

        let outcome = self
            .gateway
            .authorize(
                &policy,
                &grant,
                &operation,
                &EvaluationContext::new(record.instructions.clone(), Vec::new()),
                self.evaluator.as_deref_mut(),
            )
            .map_err(RuntimeError::store)?;
        match outcome {
            crate::permissions::PermissionOutcome::AwaitingApproval { request } => {
                self.persist_awaiting_approval(project, run, &record, operation, request.reason())
            }
            crate::permissions::PermissionOutcome::Deny { .. } => {
                self.record_approval_rejection(project, run, Some(operation_id), "policy_denied")
            }
            crate::permissions::PermissionOutcome::Allow { .. } => self.record_approval_rejection(
                project,
                run,
                Some(operation_id),
                "policy_allow_without_human_decision",
            ),
        }
    }

    fn record_approval_rejection(
        &mut self,
        project: ProjectId,
        run: RunId,
        operation: Option<crate::contracts::ids::OperationId>,
        reason: &str,
    ) -> Result<Vec<Event>, RuntimeError> {
        let record = self.run_record(project, run)?.clone();
        let event = event_draft(
            project,
            record.agent_id,
            record.session_id,
            run,
            operation,
            "run.tool_approval_rejected",
            json!({ "reason": reason }),
        )?;
        let receipt = self.commit_state(self.state.clone(), vec![event])?;
        Ok(receipt.events().to_vec())
    }

    fn execute_authorized(
        &mut self,
        project: ProjectId,
        run: RunId,
        record: &RunRecord,
        operation: &FrozenOperation,
        authorization: &crate::permissions::Authorization,
    ) -> Result<ExecutedOperation, RuntimeError> {
        let policy = self.policy.policy().clone();
        let context = RunToolContext::new(
            project,
            record.agent_id,
            record.session_id,
            run,
            operation.cwd().clone(),
        );
        self.gateway
            .executor_mut()
            .enter_run(context)
            .map_err(RuntimeError::execution)?;

        match self.gateway.execute(&policy, operation, authorization) {
            Ok(execution) => {
                self.record_execution(project, run, record, operation, execution, false)
            }
            Err(GatewayError::Approval(error)) => {
                let mut next = self.state.clone();
                if let Some(project_record) = next.projects_mut().get_mut(&project) {
                    project_record.approvals.remove(&operation.operation_id());
                }
                self.commit_state(next, Vec::new())?;
                self.mark_interrupted(
                    project,
                    run,
                    record,
                    "approval_invalid_before_execution",
                    json!({ "operationId": operation.operation_id().to_string() }),
                )?;
                Err(RuntimeError::Approval { error })
            }
            Err(GatewayError::Executor(error)) => {
                let uncertain = is_uncertain(&error);
                let fallback = if uncertain {
                    crate::contracts::operation::OperationResult::new(
                        crate::contracts::operation::OperationOutcome::Unverifiable,
                        crate::contracts::operation::OperationEvidence::new(Vec::new(), true),
                        Timestamp::now(),
                    )
                } else {
                    crate::contracts::operation::OperationResult::new(
                        crate::contracts::operation::OperationOutcome::NotApplied,
                        crate::contracts::operation::OperationEvidence::empty(),
                        Timestamp::now(),
                    )
                };
                self.record_failed_execution(
                    project,
                    run,
                    record,
                    operation,
                    error.clone(),
                    fallback,
                    uncertain,
                )
            }
        }
    }

    fn record_execution(
        &mut self,
        project: ProjectId,
        run: RunId,
        record: &RunRecord,
        operation: &FrozenOperation,
        execution: ToolExecution,
        uncertain: bool,
    ) -> Result<ExecutedOperation, RuntimeError> {
        let now = Timestamp::now();
        let mut next = self.state.clone();
        if let Some(stored) = next
            .projects_mut()
            .get_mut(&project)
            .and_then(|project| project.runs.get_mut(&run))
        {
            stored.updated_at = now;
        }
        let event = event_draft(
            project,
            record.agent_id,
            record.session_id,
            run,
            Some(operation.operation_id()),
            if uncertain {
                "run.operation_failed"
            } else {
                "run.operation_completed"
            },
            json!({
                "operationId": operation.operation_id().to_string(),
                "tool": operation.tool().as_str(),
                "outcome": execution.outcome().as_str(),
            }),
        )?;

        let existing = self.operation_result(operation.operation_id())?;
        let has_intent = self.operation_exists(operation.operation_id())?;
        let receipt = if let Some(stored) = existing {
            let mut events = vec![event];
            if stored.outcome() != execution.outcome() {
                events = Vec::new();
            }
            self.commit_state(next, events)?
        } else if matches!(operation.tool(), ToolName::Read | ToolName::Search) || !has_intent {
            // Read/search have no side effect and no operation intent. A
            // non-compliant executor that produced no intent is also not turned
            // into an after-the-fact intent here.
            self.commit_state(next, vec![event])?
        } else {
            let result = crate::contracts::operation::OperationResult::new(
                execution.outcome(),
                execution.evidence().clone(),
                now,
            );
            self.commit_state_result(next, operation.operation_id(), result, vec![event])?
        };
        let outcome = execution.outcome();
        let summary = serde_json::to_string(execution.summary())
            .unwrap_or_else(|_| "\"tool output unavailable\"".to_owned());
        let continuation = (!uncertain).then(|| {
            format!(
                "Host result for tool operation {} ({}): outcome={}. Output: {summary}",
                operation.operation_id(),
                operation.tool().as_str(),
                execution.outcome().as_str()
            )
        });
        Ok(ExecutedOperation {
            events: receipt.events().to_vec(),
            outcome,
            continuation,
            failure_message: None,
            uncertain,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn record_failed_execution(
        &mut self,
        project: ProjectId,
        run: RunId,
        record: &RunRecord,
        operation: &FrozenOperation,
        error: CoreError,
        fallback: crate::contracts::operation::OperationResult,
        uncertain: bool,
    ) -> Result<ExecutedOperation, RuntimeError> {
        let now = Timestamp::now();
        let mut next = self.state.clone();
        if let Some(stored) = next
            .projects_mut()
            .get_mut(&project)
            .and_then(|project| project.runs.get_mut(&run))
        {
            stored.updated_at = now;
        }
        let event = event_draft(
            project,
            record.agent_id,
            record.session_id,
            run,
            Some(operation.operation_id()),
            "run.operation_failed",
            json!({
                "operationId": operation.operation_id().to_string(),
                "tool": operation.tool().as_str(),
                "outcome": fallback.outcome().as_str(),
                "failure": error,
            }),
        )?;
        let existing = self.operation_result(operation.operation_id())?;
        let has_intent = self.operation_exists(operation.operation_id())?;
        let receipt = match existing {
            Some(stored) if stored.outcome() == fallback.outcome() => {
                self.commit_state(next, vec![event])?
            }
            Some(_) => self.commit_state(next, Vec::new())?,
            None if !has_intent => self.commit_state(next, vec![event])?,
            None => self.commit_state_result(
                next,
                operation.operation_id(),
                fallback.clone(),
                vec![event],
            )?,
        };
        let outcome = fallback.outcome();
        let continuation = if uncertain {
            None
        } else {
            Some(format!(
                "Host result for tool operation {} ({}): outcome={} ({error}). Do not assume the side effect happened.",
                operation.operation_id(),
                operation.tool().as_str(),
                fallback.outcome().as_str()
            ))
        };
        Ok(ExecutedOperation {
            events: receipt.events().to_vec(),
            outcome,
            continuation: None,
            failure_message: continuation,
            uncertain,
        })
    }

    fn send_continuation(
        &mut self,
        project: ProjectId,
        run: RunId,
        record: &RunRecord,
        message: String,
    ) -> Result<(), RuntimeError> {
        let current = self.run_record(project, run)?.clone();
        if current.state != RunState::Running {
            return Ok(());
        }
        let event = event_draft(
            project,
            record.agent_id,
            record.session_id,
            run,
            None,
            "run.host_message",
            json!({ "reason": "operation_continuation" }),
        )?;
        self.commit_state(self.state.clone(), vec![event])?;
        match self
            .engine
            .send_input(&run, EngineInput::Text(message.clone()))
        {
            Ok(()) => Ok(()),
            Err(CoreError::InvalidRunTransition { .. }) => {
                // The model is still finishing the turn that produced the
                // approval request. Do not fail the human decision; deliver
                // the host result when the engine reports idle.
                self.deferred_continuations
                    .entry(run)
                    .or_default()
                    .push(message);
                let event = event_draft(
                    project,
                    record.agent_id,
                    record.session_id,
                    run,
                    None,
                    "run.host_message_deferred",
                    json!({ "reason": "engine_active" }),
                )?;
                self.commit_state(self.state.clone(), vec![event])?;
                Ok(())
            }
            Err(error) => {
                self.mark_interrupted(
                    project,
                    run,
                    record,
                    "continuation_failed",
                    json!({ "failure": error }),
                )?;
                Err(RuntimeError::Engine { error })
            }
        }
    }

    /// Delivers queued host results after the engine becomes idle.
    fn flush_deferred(&mut self, project: ProjectId, run: RunId) -> Result<(), RuntimeError> {
        let Some(messages) = self.deferred_continuations.remove(&run) else {
            return Ok(());
        };
        let record = self.run_record(project, run)?.clone();
        let mut remaining = messages.into_iter();
        while let Some(message) = remaining.next() {
            match self
                .engine
                .send_input(&run, EngineInput::Text(message.clone()))
            {
                Ok(()) => {}
                Err(CoreError::InvalidRunTransition { .. }) => {
                    let mut queued = vec![message];
                    queued.extend(remaining);
                    self.deferred_continuations.insert(run, queued);
                    return Ok(());
                }
                Err(error) => {
                    self.mark_interrupted(
                        project,
                        run,
                        &record,
                        "continuation_failed",
                        json!({ "failure": error }),
                    )?;
                    return Err(RuntimeError::Engine { error });
                }
            }
        }
        Ok(())
    }

    fn mark_failed(
        &mut self,
        project: ProjectId,
        run: RunId,
        record: &RunRecord,
        stage: &str,
        detail: serde_json::Value,
    ) -> Result<(), RuntimeError> {
        self.mark_state(project, run, record, RunState::Failed, stage, detail)
    }

    fn mark_interrupted(
        &mut self,
        project: ProjectId,
        run: RunId,
        record: &RunRecord,
        stage: &str,
        detail: serde_json::Value,
    ) -> Result<(), RuntimeError> {
        self.mark_state(project, run, record, RunState::Interrupted, stage, detail)
    }

    fn mark_state(
        &mut self,
        project: ProjectId,
        run: RunId,
        record: &RunRecord,
        state: RunState,
        stage: &str,
        detail: serde_json::Value,
    ) -> Result<(), RuntimeError> {
        if matches!(
            state,
            RunState::Failed | RunState::Interrupted | RunState::Paused
        ) {
            self.deferred_continuations.remove(&run);
        }
        let now = Timestamp::now();
        let mut next = self.state.clone();
        if let Some(stored) = next
            .projects_mut()
            .get_mut(&project)
            .and_then(|project| project.runs.get_mut(&run))
        {
            stored.state = state;
            stored.updated_at = now;
        }
        let event = event_draft(
            project,
            record.agent_id,
            record.session_id,
            run,
            None,
            "run.state_changed",
            json!({
                "from": record.state.as_str(),
                "to": state.as_str(),
                "stage": stage,
                "detail": detail,
            }),
        )?;
        self.commit_state(next, vec![event])?;
        Ok(())
    }

    /// Persisted pending approvals for one project.
    pub fn pending_approvals(
        &self,
        project: ProjectId,
    ) -> Result<Vec<PendingApproval>, RuntimeError> {
        let project_record = self.project_record(project)?;
        Ok(pending_views(project, project_record, self.policy.policy()))
    }

    /// Approves a pending operation by identifier and executes it once.
    pub fn approve(
        &mut self,
        project: ProjectId,
        operation: crate::contracts::ids::OperationId,
    ) -> Result<crate::runtime::views::ApprovalOutcome, RuntimeError> {
        self.approve_with_expected_operation(project, operation, None)
    }

    /// Approves an operation after checking the exact operation the human saw.
    ///
    /// Passing a changed operation (different arguments, cwd, policy version, or
    /// mode) is rejected without executing.
    pub fn approve_with_expected_operation(
        &mut self,
        project: ProjectId,
        operation_id: crate::contracts::ids::OperationId,
        expected: Option<&FrozenOperation>,
    ) -> Result<crate::runtime::views::ApprovalOutcome, RuntimeError> {
        if operation_id.project_id() != project {
            return Err(RuntimeError::CrossProject {
                id_kind: IdKind::Operation,
                expected: project,
                found: operation_id.project_id(),
            });
        }
        let project_record = self.project_record(project)?.clone();
        let approval = project_record.approvals.get(&operation_id).cloned().ok_or(
            RuntimeError::ApprovalUnknown {
                operation: operation_id,
            },
        )?;
        if approval.restored {
            return Err(RuntimeError::ApprovalRestored {
                operation: operation_id,
            });
        }
        if let Some(expected) = expected
            && expected != &approval.operation
        {
            return Err(RuntimeError::ApprovalInvalid {
                operation: operation_id,
                reason: crate::permissions::InvalidationReason::ArgumentsChanged,
            });
        }
        let run_record =
            project_record
                .runs
                .get(&approval.run_id)
                .cloned()
                .ok_or(RuntimeError::UnknownRun {
                    run: approval.run_id,
                })?;
        if run_record.state != RunState::AwaitingApproval {
            return Err(RuntimeError::InvalidRunTransition {
                from: run_record.state,
                to: RunState::Running,
            });
        }
        let policy = self.policy.policy().clone();
        self.ensure_mode_usable(&policy)?;
        let status = self.connection_status(run_record.connection)?;
        if status != ConnectionStatus::Available {
            return Err(RuntimeError::ConnectionUnavailable {
                connection: run_record.connection,
                status,
            });
        }
        let binding = crate::permissions::DecisionBinding::from_operation(&approval.operation);
        if let Err(reason) = binding.check(&approval.operation, &policy) {
            self.invalidate_approval(project, &run_record, &approval, reason.clone())?;
            return Err(RuntimeError::ApprovalInvalid {
                operation: operation_id,
                reason,
            });
        }

        let authorization = match self.gateway.approve(&policy, &approval.operation, project) {
            Ok(authorization) => authorization,
            Err(error) => {
                return Err(RuntimeError::Approval { error });
            }
        };

        let mut committed = Vec::new();
        let result = self.execute_authorized(
            project,
            approval.run_id,
            &run_record,
            &approval.operation,
            &authorization,
        )?;
        committed.extend(result.events);
        // The approval is no longer pending once the authorization was consumed.
        let mut next = self.state.clone();
        if let Some(record) = next.projects_mut().get_mut(&project) {
            record.approvals.remove(&operation_id);
            if let Some(run) = record.runs.get_mut(&approval.run_id) {
                if run.state == RunState::AwaitingApproval {
                    run.state = RunState::Running;
                }
                run.updated_at = Timestamp::now();
            }
        }
        let resolved_event = event_draft(
            project,
            run_record.agent_id,
            run_record.session_id,
            approval.run_id,
            Some(operation_id),
            "run.approval_resolved",
            json!({
                "operationId": operation_id.to_string(),
                "tool": approval.operation.tool().as_str(),
                "decision": "approved",
            }),
        )?;
        let receipt = self.commit_state(next, vec![resolved_event])?;
        committed.extend(receipt.events().to_vec());

        if let Some(message) = result.continuation {
            self.send_continuation(project, approval.run_id, &run_record, message)?;
        }
        if let Some(message) = result.failure_message {
            self.send_continuation(project, approval.run_id, &run_record, message)?;
        }
        if result.uncertain {
            self.mark_interrupted(
                project,
                approval.run_id,
                &run_record,
                "approved_tool_outcome_uncertain",
                json!({ "operationId": operation_id.to_string() }),
            )?;
        }

        let run = self.run(project, approval.run_id)?;
        let outcome = result.outcome;
        Ok(crate::runtime::views::ApprovalOutcome::new(
            operation_id,
            true,
            outcome,
            run,
        ))
    }

    /// Denies a pending operation. The executor is never reached.
    pub fn deny(
        &mut self,
        project: ProjectId,
        operation_id: crate::contracts::ids::OperationId,
    ) -> Result<DenialOutcome, RuntimeError> {
        if operation_id.project_id() != project {
            return Err(RuntimeError::CrossProject {
                id_kind: IdKind::Operation,
                expected: project,
                found: operation_id.project_id(),
            });
        }
        let project_record = self.project_record(project)?.clone();
        let approval = project_record.approvals.get(&operation_id).cloned().ok_or(
            RuntimeError::ApprovalUnknown {
                operation: operation_id,
            },
        )?;
        let run_record =
            project_record
                .runs
                .get(&approval.run_id)
                .cloned()
                .ok_or(RuntimeError::UnknownRun {
                    run: approval.run_id,
                })?;
        let policy = self.policy.policy().clone();
        // Mark the in-process ledger when it still knows the decision. A restored
        // approval has no ledger entry, which is harmless for a denial.
        let _ = self.gateway.deny(&policy, &approval.operation, project);

        let now = Timestamp::now();
        let mut next = self.state.clone();
        if let Some(record) = next.projects_mut().get_mut(&project) {
            record.approvals.remove(&operation_id);
            if let Some(run) = record.runs.get_mut(&approval.run_id) {
                if matches!(run.state, RunState::AwaitingApproval) {
                    run.state = RunState::Running;
                }
                run.updated_at = now;
            }
        }
        let event = event_draft(
            project,
            approval.agent_id,
            approval.session_id,
            approval.run_id,
            Some(operation_id),
            "run.approval_resolved",
            json!({
                "operationId": operation_id.to_string(),
                "tool": approval.operation.tool().as_str(),
                "decision": "denied",
            }),
        )?;
        self.commit_state(next, vec![event])?;

        let message = format!(
            "The human denied tool operation {} ({}). Do not retry it without a new human decision.",
            operation_id,
            approval.operation.tool().as_str()
        );
        if run_record.state == RunState::Running || run_record.state == RunState::AwaitingApproval {
            self.send_continuation(project, approval.run_id, &run_record, message)?;
        }
        let run = self.run(project, approval.run_id)?;
        Ok(DenialOutcome::new(operation_id, run))
    }

    fn invalidate_approval(
        &mut self,
        project: ProjectId,
        run_record: &RunRecord,
        approval: &crate::runtime::state::ApprovalRecord,
        reason: crate::permissions::InvalidationReason,
    ) -> Result<(), RuntimeError> {
        let now = Timestamp::now();
        let mut next = self.state.clone();
        if let Some(record) = next.projects_mut().get_mut(&project) {
            record.approvals.remove(&approval.operation.operation_id());
            if let Some(run) = record.runs.get_mut(&approval.run_id) {
                run.state = RunState::Interrupted;
                run.updated_at = now;
            }
        }
        let event = event_draft(
            project,
            run_record.agent_id,
            run_record.session_id,
            approval.run_id,
            Some(approval.operation.operation_id()),
            "run.approval_invalidated",
            json!({
                "operationId": approval.operation.operation_id().to_string(),
                "reason": reason,
            }),
        )?;
        self.commit_state(next, vec![event])?;
        Ok(())
    }

    fn project_view(&self, project: ProjectId) -> Result<ProjectView, RuntimeError> {
        let record = self.project_record(project)?;
        let connections = self.connection_summaries()?;
        Ok(ProjectView::new(
            project,
            record.path.clone(),
            connections,
            self.capabilities,
            self.toolchain.detect(),
        ))
    }

    fn connection_summaries(&self) -> Result<Vec<ConnectionInfo>, RuntimeError> {
        let settings = self
            .directory
            .list()
            .map_err(|error| RuntimeError::ConnectionRegistry {
                detail: error.to_string(),
            })?;
        settings
            .into_iter()
            .map(|settings| {
                let status = self.connection_status(settings.connection_id())?;
                settings.public_info(status).map_err(RuntimeError::store)
            })
            .collect()
    }

    fn connection_status(
        &self,
        connection: ConnectionId,
    ) -> Result<ConnectionStatus, RuntimeError> {
        self.directory
            .get(connection)
            .map_err(|_| RuntimeError::UnknownConnection { connection })?;
        match self.credentials.availability(&connection) {
            Ok(crate::ports::CredentialAvailability::Available) => Ok(ConnectionStatus::Available),
            Ok(crate::ports::CredentialAvailability::LoginRequired) => {
                Ok(ConnectionStatus::LoginRequired)
            }
            Ok(crate::ports::CredentialAvailability::Unavailable) => {
                Ok(ConnectionStatus::AuthRequired)
            }
            Err(_) => Ok(ConnectionStatus::Unavailable),
        }
    }

    fn ensure_mode_usable(&self, policy: &PermissionPolicy) -> Result<(), RuntimeError> {
        if policy.mode() == PermissionMode::Automatic {
            let availability = self
                .evaluator
                .as_ref()
                .map_or(EvaluatorAvailability::Unavailable, |evaluator| {
                    evaluator.availability()
                });
            if !availability.is_available() {
                return Err(RuntimeError::PermissionModeUnavailable {
                    mode: PermissionMode::Automatic,
                });
            }
        }
        Ok(())
    }

    fn ensure_capabilities(&self, agent: &AgentRecord) -> Result<(), RuntimeError> {
        for capability in &agent.required_capabilities {
            if let CapabilityStatus::Unavailable { reason } = self.capabilities.status(*capability)
            {
                return Err(RuntimeError::CapabilityUnavailable {
                    capability: *capability,
                    reason,
                });
            }
        }
        Ok(())
    }

    fn project_record(&self, project: ProjectId) -> Result<&ProjectRecord, RuntimeError> {
        self.state
            .projects()
            .get(&project)
            .ok_or(RuntimeError::UnknownProject { project })
    }

    fn run_record(&self, project: ProjectId, run: RunId) -> Result<&RunRecord, RuntimeError> {
        if run.project_id() != project {
            return Err(RuntimeError::CrossProject {
                id_kind: IdKind::Run,
                expected: project,
                found: run.project_id(),
            });
        }
        self.project_record(project)?
            .runs
            .get(&run)
            .ok_or(RuntimeError::UnknownRun { run })
    }

    fn operation_result(
        &self,
        operation: crate::contracts::ids::OperationId,
    ) -> Result<Option<crate::contracts::operation::OperationResult>, RuntimeError> {
        let store = lock_store(&self.store)?;
        let record = store.operation(&operation).map_err(RuntimeError::store)?;
        Ok(record.and_then(|record| record.result().cloned()))
    }

    fn operation_exists(
        &self,
        operation: crate::contracts::ids::OperationId,
    ) -> Result<bool, RuntimeError> {
        let store = lock_store(&self.store)?;
        store
            .operation(&operation)
            .map(|record| record.is_some())
            .map_err(RuntimeError::store)
    }

    fn commit_state(
        &mut self,
        next: HostState,
        events: Vec<EventDraft>,
    ) -> Result<crate::ports::CommitReceipt, RuntimeError> {
        let bytes = next.to_bytes()?;
        let receipt = {
            let mut store = lock_store(&self.store)?;
            store
                .save_host_state_and_events(HOST_STATE_KEY, &bytes, events)
                .map_err(RuntimeError::store)?
        };
        self.state = next;
        Ok(receipt)
    }

    fn commit_state_checkpoint(
        &mut self,
        next: HostState,
        checkpoint: Option<crate::contracts::checkpoint::Checkpoint>,
        events: Vec<EventDraft>,
    ) -> Result<crate::ports::CommitReceipt, RuntimeError> {
        let bytes = next.to_bytes()?;
        let receipt = {
            let mut store = lock_store(&self.store)?;
            match checkpoint {
                Some(checkpoint) => {
                    let commit = crate::ports::CheckpointCommit::new(checkpoint, None, events)
                        .map_err(RuntimeError::store)?;
                    store
                        .save_host_state_and_checkpoint(HOST_STATE_KEY, &bytes, commit)
                        .map_err(RuntimeError::store)?
                }
                None => store
                    .save_host_state_and_events(HOST_STATE_KEY, &bytes, events)
                    .map_err(RuntimeError::store)?,
            }
        };
        self.state = next;
        Ok(receipt)
    }

    fn commit_state_result(
        &mut self,
        next: HostState,
        operation: crate::contracts::ids::OperationId,
        result: crate::contracts::operation::OperationResult,
        events: Vec<EventDraft>,
    ) -> Result<crate::ports::CommitReceipt, RuntimeError> {
        let bytes = next.to_bytes()?;
        let receipt = {
            let mut store = lock_store(&self.store)?;
            store
                .record_operation_result_with_state(
                    HOST_STATE_KEY,
                    &bytes,
                    &operation,
                    result,
                    events,
                )
                .map_err(RuntimeError::store)?
        };
        self.state = next;
        Ok(receipt)
    }

    fn reconcile(
        &mut self,
    ) -> Result<crate::runtime::reconcile::ReconciliationReport, RuntimeError> {
        use crate::runtime::reconcile::{
            OperationReconciliation, PermissionReconciliation, ProjectReconciliation,
            ReconciliationReport, RunReconciliation,
        };

        let policy = self.policy.policy().clone();
        let evaluator_available = self
            .evaluator
            .as_ref()
            .map_or(EvaluatorAvailability::Unavailable, |evaluator| {
                evaluator.availability()
            })
            .is_available();
        let permission =
            PermissionReconciliation::new(policy.mode(), policy.version(), evaluator_available);

        let projects = self
            .state
            .projects()
            .iter()
            .map(|(project, record)| (*project, record.clone()))
            .collect::<Vec<_>>();
        let mut next = self.state.clone();
        let mut reports = Vec::with_capacity(projects.len());

        for (project_id, project) in projects {
            let mut updated = project.clone();
            for approval in updated.approvals.values_mut() {
                approval.restored = true;
            }
            let mut runs = Vec::with_capacity(updated.runs.len());
            for (run_id, run) in &mut updated.runs {
                let previous_state = run.state;
                if matches!(
                    previous_state,
                    RunState::Running | RunState::AwaitingApproval
                ) {
                    run.state = RunState::Interrupted;
                    run.updated_at = Timestamp::now();
                }
                let awaiting_approval = updated
                    .approvals
                    .values()
                    .any(|approval| approval.run_id == *run_id);
                runs.push(RunReconciliation::new(
                    *run_id,
                    previous_state,
                    run.state,
                    awaiting_approval,
                ));
            }

            let unresolved = {
                let store = lock_store(&self.store)?;
                store
                    .unresolved_operations(&project_id)
                    .map_err(RuntimeError::store)?
            };
            let operations = unresolved
                .iter()
                .map(|record| {
                    let (outcome, source, detail) = crate::runtime::reconcile::classify_operation(
                        updated.path.as_path(),
                        record,
                    );
                    OperationReconciliation::new(
                        record.intent().operation().operation_id(),
                        record.intent().operation().tool(),
                        outcome,
                        source,
                        detail,
                    )
                })
                .collect();

            let pending = pending_views(project_id, &updated, &policy);
            next.projects_mut().insert(project_id, updated.clone());
            reports.push(ProjectReconciliation::new(
                project_id,
                updated.path.clone(),
                runs,
                operations,
                pending,
                self.connection_summaries()?,
                permission,
            ));
        }

        if next != self.state {
            self.commit_state(next, Vec::new())?;
        }
        Ok(ReconciliationReport::new(reports))
    }
}

struct ExecutedOperation {
    events: Vec<Event>,
    outcome: crate::contracts::operation::OperationOutcome,
    continuation: Option<String>,
    failure_message: Option<String>,
    uncertain: bool,
}

fn lock_store<S>(store: &Arc<Mutex<S>>) -> Result<MutexGuard<'_, S>, RuntimeError> {
    store.lock().map_err(|_| RuntimeError::CorruptState {
        detail: "store lock was poisoned".to_owned(),
    })
}

fn run_view(project: ProjectId, run: RunId, record: &RunRecord) -> RunView {
    RunView::new(
        project,
        run,
        record.agent_id,
        record.session_id,
        record.connection,
        record.state,
        record.instructions.clone(),
        record.mode,
        record.policy_version,
        record.created_at,
        record.updated_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn event_draft(
    project: ProjectId,
    agent: AgentId,
    session: SessionId,
    run: RunId,
    operation: Option<crate::contracts::ids::OperationId>,
    kind: &str,
    payload: serde_json::Value,
) -> Result<EventDraft, RuntimeError> {
    EventDraft::new(
        project,
        agent,
        session,
        run,
        operation,
        EventKind::new(kind).map_err(RuntimeError::store)?,
        Timestamp::now(),
        EventPayload::new(payload),
    )
    .map_err(RuntimeError::store)
}

fn approval_reason_label(reason: &crate::permissions::HumanWaitReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| {
            value
                .get("kind")
                .and_then(|kind| kind.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "approval_required".to_owned())
}

fn pending_views(
    project: ProjectId,
    record: &ProjectRecord,
    policy: &PermissionPolicy,
) -> Vec<PendingApproval> {
    record
        .approvals
        .values()
        .map(|approval| {
            let binding = crate::permissions::DecisionBinding::from_operation(&approval.operation);
            let reusable = !approval.restored
                && binding.check(&approval.operation, policy).is_ok()
                && record
                    .runs
                    .get(&approval.run_id)
                    .is_some_and(|run| run.state == RunState::AwaitingApproval);
            PendingApproval::new(
                project,
                approval.run_id,
                approval.agent_id,
                approval.session_id,
                approval.operation.clone(),
                binding,
                approval.reason.clone(),
                approval.requested_at,
                approval.restored,
                reusable,
            )
        })
        .collect()
}

fn is_uncertain(error: &CoreError) -> bool {
    match error {
        CoreError::FileToolFailed {
            failure: crate::contracts::errors::FileFailure::Unverifiable { .. },
            ..
        } => true,
        CoreError::ShellToolFailed { failure, .. } => matches!(
            failure,
            crate::contracts::errors::ShellFailure::Unverifiable { .. }
                | crate::contracts::errors::ShellFailure::Unconfirmed { .. }
                | crate::contracts::errors::ShellFailure::Stopped { .. }
                | crate::contracts::errors::ShellFailure::TimedOut { .. }
        ),
        _ => false,
    }
}

impl RuntimeError {
    fn store(error: CoreError) -> Self {
        Self::Store { error }
    }

    fn engine(error: CoreError) -> Self {
        Self::Engine { error }
    }

    fn execution(error: CoreError) -> Self {
        Self::Execution { error }
    }

    fn invalid_value(error: CoreError) -> Self {
        Self::InvalidValue {
            field: "path".to_owned(),
            violation: ArgumentViolation::Invalid {
                detail: error.to_string(),
            },
        }
    }
}
