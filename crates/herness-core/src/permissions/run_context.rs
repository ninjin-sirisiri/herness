//! Host-resolved permission context for one engine run.
//!
//! The host decides the run's grant ceiling, the current policy handle, the
//! shared evaluator, and the stop/deadline control. The engine adapter receives
//! this value on start, continuation, or resume and uses it as-is. It must not
//! reconstruct a wider grant, substitute `None` for the evaluator, or invent
//! stop state.

use std::fmt;

use crate::contracts::errors::CoreError;
use crate::contracts::ids::{IdKind, ProjectId, RunId};
use crate::permissions::control::RunControl;
use crate::permissions::grant::GrantScope;
use crate::permissions::policy::SharedPolicy;
use crate::ports::evaluator::SharedPermissionEvaluator;

/// Everything the real tool path needs to authorize one run's operations.
#[derive(Clone)]
pub struct RunPermissionContext {
    project_id: ProjectId,
    run_id: RunId,
    grant: GrantScope,
    policy: SharedPolicy,
    evaluator: Option<SharedPermissionEvaluator>,
    control: RunControl,
}

impl RunPermissionContext {
    /// Creates a context after checking the project scope of both identifiers.
    pub fn new(
        project_id: ProjectId,
        run_id: RunId,
        grant: GrantScope,
        policy: SharedPolicy,
        evaluator: Option<SharedPermissionEvaluator>,
        control: RunControl,
    ) -> Result<Self, CoreError> {
        if run_id.project_id() != project_id {
            return Err(CoreError::CrossProjectReference {
                id_kind: IdKind::Run,
                expected: project_id,
                found: run_id.project_id(),
            });
        }
        if grant.project_id() != project_id {
            return Err(CoreError::CrossProjectReference {
                id_kind: IdKind::Project,
                expected: project_id,
                found: grant.project_id(),
            });
        }
        Ok(Self {
            project_id,
            run_id,
            grant,
            policy,
            evaluator,
            control,
        })
    }

    /// Project owning the run.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Run this context authorizes.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Exact host-resolved grant ceiling for this run.
    pub const fn grant(&self) -> &GrantScope {
        &self.grant
    }

    /// Shared current policy handle.
    pub const fn policy(&self) -> &SharedPolicy {
        &self.policy
    }

    /// Shared host-selected evaluator, when automatic mode is configured.
    pub const fn evaluator(&self) -> Option<&SharedPermissionEvaluator> {
        self.evaluator.as_ref()
    }

    /// Stop/deadline control shared with the host.
    pub const fn control(&self) -> &RunControl {
        &self.control
    }

    /// Re-targets the same grant, policy, evaluator, and control to a new run.
    ///
    /// Used by a continuation test helper and by the adapter when it rebuilds a
    /// run's tool runtime. The new run must belong to the same project.
    pub fn for_run(&self, run_id: RunId) -> Result<Self, CoreError> {
        Self::new(
            self.project_id,
            run_id,
            self.grant.clone(),
            self.policy.clone(),
            self.evaluator.clone(),
            self.control.clone(),
        )
    }
}

impl fmt::Debug for RunPermissionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunPermissionContext")
            .field("project_id", &self.project_id)
            .field("run_id", &self.run_id)
            .field("grant", &self.grant)
            .field("mode", &self.policy.mode())
            .field("policy_version", &self.policy.version())
            .field("evaluator", &self.evaluator.is_some())
            .field("control", &self.control.snapshot())
            .finish()
    }
}
