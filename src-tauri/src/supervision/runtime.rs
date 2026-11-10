//! Real H1 runtime and recovery composition for one supervision target.
//!
//! The adapter borrows the single desktop `Runtime`; it does not create a
//! second engine, executor, store, or run state. Supervisor-allocated run and
//! input identifiers are used directly so a retry after a crash is idempotent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use herness_core::permissions::{MatchMethod, PermissionRule, RuleTarget};
use herness_core::runtime::{AgentSpec, RecoveryMode};
use herness_core::{
    AbsolutePath, ArtifactHandle, ContinuationPort, ContinuationRequest, InputId, InputPhase,
    InputProgress, ProjectId, RunId, RunState, StopReason, ToolName,
};
use herness_supervision::freshness::TargetManifest;
use herness_supervision::operations::OperationRuntimePort;
use herness_supervision::recovery::{
    ManagedProcessState, RecoveryCheckpoint, RecoveryRuntimePort, RecoveryStopState,
};
use herness_supervision::supervisor::{
    ChildRunContinuation, ChildRunStart, StopDisposition, SupervisionRuntimePort,
    TargetSnapshotRequest, capture_target_snapshot,
};
use herness_supervision::{
    ExecutionScope, SupervisionError, SupervisionId, WorkPacket, WorkPacketRejection,
};

use crate::host::DesktopRuntime;
use crate::supervision::plan::StoredPlan;
use crate::supervision::store::StoreHandle;
use crate::supervision::workspace::ProjectWorkspace;

/// One child identity allocated by the real H1 runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildIdentity {
    /// Child agent.
    pub agent_id: herness_core::AgentId,
    /// Child conversation.
    pub session_id: herness_core::SessionId,
}

/// Shared plans keyed by project and supervision target.
pub type PlanMap = Arc<Mutex<BTreeMap<(ProjectId, SupervisionId), StoredPlan>>>;

/// Real H1 composition consumed by the supervisor and explicit operations.
pub struct DesktopH1<'a> {
    runtime: &'a mut DesktopRuntime,
    store: StoreHandle,
    plans: PlanMap,
    candidate_artifact: Option<ArtifactHandle>,
}

impl<'a> DesktopH1<'a> {
    /// Creates one adapter over the existing desktop runtime.
    pub const fn new(runtime: &'a mut DesktopRuntime, store: StoreHandle, plans: PlanMap) -> Self {
        Self {
            runtime,
            store,
            plans,
            candidate_artifact: None,
        }
    }

    /// Installs the host-issued candidate handle for the H3 generation this
    /// adapter is about to start or continue.
    ///
    /// With a handle installed, the H1 run receives only the candidate tools
    /// and the run grant is the candidate allowlist even though H2 created the
    /// child agent from the approved execution scope. Without one, the normal
    /// native supervision path is unchanged.
    pub fn set_candidate_artifact(&mut self, handle: Option<ArtifactHandle>) {
        self.candidate_artifact = handle;
    }

    fn plan(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<StoredPlan, SupervisionError> {
        let plan = self
            .plans
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&(project, supervision))
            .cloned()
            .ok_or(SupervisionError::Unsupported {
                feature: "supervision plan is not available".to_owned(),
            })?;
        plan.verify()?;
        if plan.packet.project_id() != project {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "supervision plan".to_owned(),
                expected: project,
                found: plan.packet.project_id(),
            });
        }
        Ok(plan)
    }

    /// Rechecks that the request packet is byte-for-byte the stored immutable
    /// packet after verifying both fingerprints.
    fn verified_packet<'p>(
        &self,
        plan: &'p StoredPlan,
        request: &WorkPacket,
    ) -> Result<&'p WorkPacket, SupervisionError> {
        request.verify()?;
        if request != &plan.packet {
            return Err(SupervisionError::WorkPacketRejected {
                reason: WorkPacketRejection::Mismatch {
                    field: "packet".to_owned(),
                },
            });
        }
        Ok(&plan.packet)
    }

    fn runtime_error(error: impl std::fmt::Display) -> SupervisionError {
        SupervisionError::InvalidValue {
            field: "h1.runtime".to_owned(),
            detail: error.to_string(),
        }
    }
}

impl SupervisionRuntimePort for DesktopH1<'_> {
    fn start_child(&mut self, request: &ChildRunStart) -> Result<(), SupervisionError> {
        let plan = self.plan(request.project_id(), request.supervision_id())?;
        let text = self.verified_packet(&plan, request.packet())?.prompt();
        match &self.candidate_artifact {
            Some(handle) => self
                .runtime
                .start_candidate_run_with_id(
                    request.project_id(),
                    plan.child.agent_id,
                    request.run_id(),
                    &text,
                    handle.clone(),
                )
                .map_err(Self::runtime_error)?,
            None => self
                .runtime
                .start_run_with_id(
                    request.project_id(),
                    plan.child.agent_id,
                    request.run_id(),
                    &text,
                )
                .map_err(Self::runtime_error)?,
        };
        self.runtime
            .submit_input_as(
                request.project_id(),
                request.run_id(),
                request.input_id(),
                text,
            )
            .map_err(Self::runtime_error)?;
        Ok(())
    }

    fn continue_child(&mut self, request: &ChildRunContinuation) -> Result<(), SupervisionError> {
        let plan = self.plan(request.project_id(), request.supervision_id())?;
        let text = self.continuation_input(&plan, request)?;
        let policy = self.runtime.policy();
        let continuation = ContinuationRequest::new(
            request.project_id(),
            request.input_id(),
            request.previous_run_id(),
            request.run_id(),
            plan.child.agent_id,
            plan.child.session_id,
            policy.mode(),
            policy.version(),
        )
        .map_err(Self::runtime_error)?;
        match &self.candidate_artifact {
            Some(handle) => {
                self.runtime
                    .continue_run_with_artifact(
                        request.project_id(),
                        request.previous_run_id(),
                        text.clone(),
                        handle.clone(),
                    )
                    .map_err(Self::runtime_error)?;
            }
            None => {
                ContinuationPort::continue_run(self.runtime, &continuation)
                    .map_err(Self::runtime_error)?;
            }
        }
        self.runtime
            .submit_input_as(
                request.project_id(),
                request.run_id(),
                request.input_id(),
                text,
            )
            .map_err(Self::runtime_error)?;
        Ok(())
    }

    fn input_progress(&mut self, input_id: InputId) -> Result<InputProgress, SupervisionError> {
        Ok(self
            .runtime
            .input_progress(input_id)
            .map_err(Self::runtime_error)?
            .unwrap_or(InputProgress::new(input_id, InputPhase::Failed)))
    }

    fn run_state(&mut self, run_id: RunId) -> Result<RunState, SupervisionError> {
        Ok(self
            .runtime
            .run(run_id.project_id(), run_id)
            .map_err(Self::runtime_error)?
            .state())
    }

    fn request_stop(&mut self, run_id: RunId) -> Result<StopDisposition, SupervisionError> {
        let outcome = self
            .runtime
            .stop_run(run_id.project_id(), run_id, StopReason::UserRequest)
            .map_err(Self::runtime_error)?;
        Ok(match outcome.report() {
            herness_core::StopReport::Stopped | herness_core::StopReport::NotRunning => {
                StopDisposition::Confirmed
            }
            herness_core::StopReport::Unconfirmed => StopDisposition::Unconfirmed,
        })
    }

    fn target_snapshot(
        &mut self,
        request: &TargetSnapshotRequest,
    ) -> Result<TargetManifest, SupervisionError> {
        let root = self.project_root(request.project_id())?;
        let workspace = ProjectWorkspace::new(root);
        match capture_target_snapshot(&workspace, request) {
            Ok(manifest) => Ok(manifest),
            Err(error) => TargetManifest::unknown(
                request.project_id(),
                request.target_version(),
                format!("the target manifest could not be established: {error}"),
            ),
        }
    }
}

impl DesktopH1<'_> {
    fn project_root(&mut self, project: ProjectId) -> Result<PathBuf, SupervisionError> {
        Ok(self
            .runtime
            .project(project)
            .map_err(Self::runtime_error)?
            .path()
            .as_path()
            .to_path_buf())
    }

    fn continuation_input(
        &self,
        plan: &StoredPlan,
        request: &ChildRunContinuation,
    ) -> Result<String, SupervisionError> {
        let packet = self.verified_packet(plan, request.packet())?;
        Ok(format!(
            "{}\n\nCurrent deficiency:\n{}",
            packet.prompt(),
            continuation_text(request)
        ))
    }
}

/// Maps one approved execution scope to the H1 grant rules the child runs
/// with. Read/search become path-prefix rules on read paths, write/edit on
/// write paths, and bash is absent unless the scope allows it.
fn scope_permission_rules(
    scope: &ExecutionScope,
    root: &Path,
) -> Result<Vec<PermissionRule>, SupervisionError> {
    let mut rules = Vec::new();
    for path in scope.read_paths() {
        for tool in [ToolName::Read, ToolName::Search] {
            rules.push(file_scope_rule(tool, path, root)?);
        }
    }
    for path in scope.write_paths() {
        for tool in [ToolName::Write, ToolName::Edit] {
            rules.push(file_scope_rule(tool, path, root)?);
        }
    }
    if scope.allow_shell() {
        rules.push(
            PermissionRule::allow(
                RuleTarget::Tool {
                    tool: ToolName::Bash,
                },
                MatchMethod::AnyInvocation,
            )
            .map_err(|error| SupervisionError::InvalidValue {
                field: "executionScope.allowShell".to_owned(),
                detail: error.to_string(),
            })?,
        );
    }
    Ok(rules)
}

fn file_scope_rule(
    tool: ToolName,
    path: &str,
    root: &Path,
) -> Result<PermissionRule, SupervisionError> {
    let relative = Path::new(path);
    if relative.is_absolute() {
        return Err(SupervisionError::InvalidValue {
            field: "executionScope.path".to_owned(),
            detail: "scope paths must be project-relative".to_owned(),
        });
    }
    let joined = root.join(relative);
    let text = joined
        .to_str()
        .ok_or_else(|| SupervisionError::InvalidValue {
            field: "executionScope.path".to_owned(),
            detail: "the project root or scope path is not valid UTF-8".to_owned(),
        })?;
    let absolute = AbsolutePath::new(text).map_err(|error| SupervisionError::InvalidValue {
        field: "executionScope.path".to_owned(),
        detail: error.to_string(),
    })?;
    PermissionRule::allow(
        RuleTarget::FilePath {
            tool,
            root: absolute,
        },
        MatchMethod::PathPrefix,
    )
    .map_err(|error| SupervisionError::InvalidValue {
        field: "executionScope.path".to_owned(),
        detail: error.to_string(),
    })
}

impl RecoveryRuntimePort for DesktopH1<'_> {
    fn run_state(&mut self, run: RunId) -> Result<RunState, SupervisionError> {
        <Self as SupervisionRuntimePort>::run_state(self, run)
    }

    fn recovery_mode(&mut self, run: RunId) -> Result<RecoveryMode, SupervisionError> {
        self.runtime.recovery_mode(run).map_err(Self::runtime_error)
    }

    fn managed_processes(
        &mut self,
        run: RunId,
    ) -> Result<Vec<ManagedProcessState>, SupervisionError> {
        let project = run.project_id();
        let operations = self
            .store
            .lock()
            .unresolved_operations(&project)
            .map_err(|error| SupervisionError::StorageFailure {
                detail: error.to_string(),
            })?;
        Ok(operations
            .into_iter()
            .filter(|record| {
                record.intent().operation().run_id() == run
                    && record.intent().operation().tool() == herness_core::ToolName::Bash
            })
            .map(|record| {
                ManagedProcessState::new(
                    record.intent().operation().operation_id().to_string(),
                    true,
                    false,
                )
            })
            .collect())
    }

    fn checkpoint(&mut self, run: RunId) -> Result<RecoveryCheckpoint, SupervisionError> {
        match self.store.lock().load_checkpoint_record(&run) {
            Ok(Some(_)) => Ok(RecoveryCheckpoint::Present),
            Ok(None) => Ok(RecoveryCheckpoint::Missing),
            Err(error) => Ok(RecoveryCheckpoint::Ambiguous(error.to_string())),
        }
    }

    fn stop_state(&mut self, run: RunId) -> Result<RecoveryStopState, SupervisionError> {
        Ok(
            match <Self as SupervisionRuntimePort>::run_state(self, run)? {
                RunState::Paused => RecoveryStopState::Confirmed,
                RunState::Interrupted => RecoveryStopState::Unconfirmed,
                _ => RecoveryStopState::NotRequested,
            },
        )
    }

    fn permissions_current(
        &mut self,
        record: &herness_supervision::SupervisionRecord,
    ) -> Result<bool, SupervisionError> {
        let policy = self.runtime.policy();
        if let Some(run) = record.run_group().runs().last().copied() {
            let view = self
                .runtime
                .run(run.project_id(), run)
                .map_err(Self::runtime_error)?;
            if view.policy_version() != policy.version() || view.mode() != policy.mode() {
                return Ok(false);
            }
            let project = self
                .runtime
                .project(record.project_id())
                .map_err(Self::runtime_error)?;
            let Some(connection) = project
                .connections()
                .iter()
                .find(|connection| connection.connection_id() == view.connection())
            else {
                return Ok(false);
            };
            if connection.status() != herness_core::ConnectionStatus::Available {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl OperationRuntimePort for DesktopH1<'_> {
    fn request_stop(&mut self, run: RunId) -> Result<StopDisposition, SupervisionError> {
        <Self as SupervisionRuntimePort>::request_stop(self, run)
    }
}

/// Ports the host composition needs beyond the four supervisor/operation
/// traits: create a child identity and read the project root.
pub trait DesktopSupervisionRuntime:
    SupervisionRuntimePort + RecoveryRuntimePort + OperationRuntimePort
{
    /// Creates the isolated child agent/session for one supervision target.
    ///
    /// The approved execution scope becomes the child grant: read/search on
    /// read paths, write/edit on write paths, and bash only when allowed.
    fn create_child(
        &mut self,
        project: ProjectId,
        connection: herness_core::ConnectionId,
        scope: &ExecutionScope,
    ) -> Result<ChildIdentity, SupervisionError>;

    /// Canonical project root used by manifests and check execution.
    fn project_path(&mut self, project: ProjectId) -> Result<PathBuf, SupervisionError>;

    /// Latest permission policy used by the check boundary.
    fn policy(&self) -> herness_core::PermissionPolicy;

    /// Shared policy handle used by the check boundary.
    fn shared_policy(&self) -> herness_core::SharedPolicy;

    /// Reads one stored record through the real store.
    fn record(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<Option<herness_supervision::SupervisionRecord>, SupervisionError>;
}

impl DesktopSupervisionRuntime for DesktopH1<'_> {
    fn create_child(
        &mut self,
        project: ProjectId,
        connection: herness_core::ConnectionId,
        scope: &ExecutionScope,
    ) -> Result<ChildIdentity, SupervisionError> {
        if scope.project_id() != project {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "execution scope".to_owned(),
                expected: project,
                found: scope.project_id(),
            });
        }
        let root = self.project_root(project)?;
        let rules = scope_permission_rules(scope, &root)?;
        let agent = self
            .runtime
            .create_agent(
                project,
                AgentSpec::new("supervision-child", "implementer", connection).with_scope(rules),
            )
            .map_err(Self::runtime_error)?;
        Ok(ChildIdentity {
            agent_id: agent.agent_id(),
            session_id: agent.session_id(),
        })
    }

    fn project_path(&mut self, project: ProjectId) -> Result<PathBuf, SupervisionError> {
        self.project_root(project)
    }

    fn policy(&self) -> herness_core::PermissionPolicy {
        self.runtime.policy().clone()
    }

    fn shared_policy(&self) -> herness_core::SharedPolicy {
        self.runtime.policy_handle()
    }

    fn record(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<Option<herness_supervision::SupervisionRecord>, SupervisionError> {
        Ok(self
            .store
            .lock()
            .load_supervision_record(project, supervision)?)
    }
}

fn continuation_text(request: &ChildRunContinuation) -> String {
    let deficiency = request.deficiency();
    let mut text = deficiency.instruction().to_owned();
    if !deficiency.failed_checks().is_empty() {
        text.push_str("\nFailed checks: ");
        text.push_str(
            &deficiency
                .failed_checks()
                .iter()
                .map(|check| format!("{} ({})", check.check_id(), check.status().as_str()))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    if !deficiency.unmet_conditions().is_empty() {
        text.push_str("\nUnmet conditions: ");
        text.push_str(
            &deficiency
                .unmet_conditions()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    if !deficiency.evidence().is_empty() {
        text.push_str("\nEvidence: ");
        text.push_str(
            &deficiency
                .evidence()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    text
}
