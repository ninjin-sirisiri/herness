//! Typed H4 identifiers.
//!
//! Every execution, Task, approval, dispatch, commit, progress, and control
//! identity is a distinct Rust type. The wire form is
//! `"<kind>:<project-uuid>:<local-uuid>"`, mirroring H1 and H2 identifiers.
//!
//! H1 run states, H2 supervision states, and H2 supervision identifiers are
//! never reused as H4 Task identity or Task state. An H2 identifier may appear
//! only inside [`H2SupervisionRef`], an H1 run only inside [`RunInputRef`], and
//! neither value can be turned into a Task progression without an explicit H4
//! decision recorded by the coordinator.

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use herness_core::contracts::{
    AgentId, InputId, ProjectId, RunId, ScopedId, ScopedIdKind, SessionId,
};
use herness_supervision::SupervisionId;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SddExecutionError;

/// Marker trait implemented by each H4 identifier kind.
pub trait ExecutionKeyKind:
    Copy + PartialEq + Eq + PartialOrd + Ord + std::hash::Hash + 'static
{
    /// Stable prefix used in the wire representation.
    const PREFIX: &'static str;
    /// Stable label used in structured errors.
    const LABEL: &'static str;
}

macro_rules! key_kind {
    ($name:ident, $prefix:literal, $label:literal) => {
        /// Marker type for one H4 identifier kind.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {}

        impl ExecutionKeyKind for $name {
            const PREFIX: &'static str = $prefix;
            const LABEL: &'static str = $label;
        }
    };
}

key_kind!(ExecutionKind, "execution", "execution");
key_kind!(TaskKind, "task", "Task");
key_kind!(ApprovalKind, "execution_approval", "execution approval");
key_kind!(DispatchKind, "dispatch", "dispatch request");
key_kind!(CommitKind, "commit", "commit request");
key_kind!(ProgressKind, "progress", "progress journal entry");
key_kind!(ControlKind, "control", "control request");

/// A typed H4 identifier bound to exactly one project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionScopedId<K: ExecutionKeyKind> {
    project: ProjectId,
    local: Uuid,
    _kind: PhantomData<fn() -> K>,
}

impl<K: ExecutionKeyKind> ExecutionScopedId<K> {
    /// Generates a new random identifier within `project`.
    pub fn new(project: ProjectId) -> Self {
        Self {
            project,
            local: Uuid::new_v4(),
            _kind: PhantomData,
        }
    }

    /// Reconstructs an identifier from its project and local UUID parts.
    pub const fn from_parts(project: ProjectId, local: Uuid) -> Self {
        Self {
            project,
            local,
            _kind: PhantomData,
        }
    }

    /// Project this identifier belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project
    }

    /// Project-local UUID part.
    pub const fn local_id(&self) -> Uuid {
        self.local
    }

    /// Rejects the identifier when it belongs to another project.
    pub fn validate_in(&self, project: ProjectId) -> Result<(), SddExecutionError> {
        if self.project == project {
            Ok(())
        } else {
            Err(SddExecutionError::CrossProjectReference {
                id_kind: K::LABEL.to_owned(),
                expected: project,
                found: self.project,
            })
        }
    }
}

impl<K: ExecutionKeyKind> fmt::Display for ExecutionScopedId<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", K::PREFIX, self.project, self.local)
    }
}

impl<K: ExecutionKeyKind> FromStr for ExecutionScopedId<K> {
    type Err = SddExecutionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || SddExecutionError::InvalidId {
            id_kind: K::LABEL.to_owned(),
            value: value.to_owned(),
        };

        let mut parts = value.split(':');
        let prefix = parts.next().ok_or_else(invalid)?;
        let project = parts.next().ok_or_else(invalid)?;
        let local = parts.next().ok_or_else(invalid)?;
        if parts.next().is_some() || prefix != K::PREFIX {
            return Err(invalid());
        }
        let project = ProjectId::from_str(project).map_err(|_| invalid())?;
        let local = Uuid::parse_str(local).map_err(|_| invalid())?;
        Ok(Self::from_parts(project, local))
    }
}

impl<K: ExecutionKeyKind> Serialize for ExecutionScopedId<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de, K: ExecutionKeyKind> Deserialize<'de> for ExecutionScopedId<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// One host-owned execution of one approved plan.
pub type ExecutionId = ExecutionScopedId<ExecutionKind>;
/// Stable Task identity inside one execution.
pub type TaskStableId = ExecutionScopedId<TaskKind>;
/// One immutable H4 execution approval revision.
pub type ApprovalId = ExecutionScopedId<ApprovalKind>;
/// Idempotent Task dispatch request.
pub type DispatchRequestId = ExecutionScopedId<DispatchKind>;
/// Idempotent host commit request.
pub type CommitRequestId = ExecutionScopedId<CommitKind>;
/// Idempotent progress-ledger write request.
pub type ProgressJournalId = ExecutionScopedId<ProgressKind>;
/// Idempotent pause, cancel, resume, re-approval, or start request.
pub type ControlRequestId = ExecutionScopedId<ControlKind>;

/// Monotonic revision of one execution's durable state.
///
/// This is not a plan revision. A snapshot compare-and-set uses this value; an
/// approval names a plan revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionRevision(u64);

impl ExecutionRevision {
    /// First revision of a new execution.
    pub const INITIAL: Self = Self(1);

    /// Creates a positive revision.
    pub fn new(value: u64) -> Result<Self, SddExecutionError> {
        if value == 0 {
            return Err(SddExecutionError::InvalidValue {
                field: "executionRevision".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        Ok(Self(value))
    }

    /// Numeric revision.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Next revision.
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Revision of one approved plan and its approval record.
///
/// This is not an execution revision and not a Task number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanRevision(u64);

impl PlanRevision {
    /// First approved revision of one imported plan.
    pub const INITIAL: Self = Self(1);

    /// Creates a positive revision.
    pub fn new(value: u64) -> Result<Self, SddExecutionError> {
        if value == 0 {
            return Err(SddExecutionError::InvalidValue {
                field: "planRevision".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        Ok(Self(value))
    }

    /// Numeric revision.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One-based Task number assigned by the plan.
///
/// A Task's stable identity is [`TaskStableId`]; the number is only the plan's
/// ordering label and is never re-derived from a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskNumber(u32);

impl TaskNumber {
    /// Creates a one-based Task number.
    pub fn new(value: u32) -> Result<Self, SddExecutionError> {
        if value == 0 {
            return Err(SddExecutionError::InvalidValue {
                field: "taskNumber".to_owned(),
                detail: "Task numbers start at one".to_owned(),
            });
        }
        Ok(Self(value))
    }

    /// Numeric Task number.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// H1 project sequence observed at snapshot time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProjectSequence(u64);

impl ProjectSequence {
    /// Wraps an observed sequence.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Numeric sequence.
    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! hex_sha_id {
    ($name:ident, $label:literal, $field:literal) => {
        #[doc = concat!("A 40-character hexadecimal Git ", $label, ".")]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Parses a 40-character hexadecimal object name.
            pub fn parse(value: impl AsRef<str>) -> Result<Self, SddExecutionError> {
                let value = value.as_ref().trim();
                if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(SddExecutionError::InvalidValue {
                        field: $field.to_owned(),
                        detail: concat!("expected a 40-character hexadecimal Git ", $label)
                            .to_owned(),
                    });
                }
                Ok(Self(value.to_ascii_lowercase()))
            }

            /// Full 40-character object name.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// First seven characters used by the progress ledger output.
            pub fn short(&self) -> &str {
                &self.0[..7]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = SddExecutionError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(de::Error::custom)
            }
        }
    };
}

hex_sha_id!(Baseline, "commit baseline", "baseline");
hex_sha_id!(CommitSha, "commit", "commit");
hex_sha_id!(TreeSha, "tree", "tree");

/// Stable Task identity plus the plan's number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskRef {
    stable_id: TaskStableId,
    number: TaskNumber,
}

impl TaskRef {
    /// Creates a Task reference.
    pub const fn new(stable_id: TaskStableId, number: TaskNumber) -> Self {
        Self { stable_id, number }
    }

    /// Stable Task identity.
    pub const fn stable_id(self) -> TaskStableId {
        self.stable_id
    }

    /// Plan-assigned Task number.
    pub const fn number(self) -> TaskNumber {
        self.number
    }

    /// Project that owns the stable identity.
    pub const fn project_id(self) -> ProjectId {
        self.stable_id.project_id()
    }

    /// Rejects a Task reference from another project.
    pub fn ensure_project(self, project: ProjectId) -> Result<(), SddExecutionError> {
        self.stable_id.validate_in(project)
    }
}

impl fmt::Display for TaskRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Task {} ({})", self.number.get(), self.stable_id)
    }
}

/// H4 reference to the H2 supervision target created for one Task.
///
/// The value only records that an H2 target exists. It is not an H2 state and
/// cannot be interpreted as Task completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H2SupervisionRef {
    supervision_id: SupervisionId,
}

impl H2SupervisionRef {
    /// Records an H2 target reference.
    pub const fn new(supervision_id: SupervisionId) -> Self {
        Self { supervision_id }
    }

    /// H2 supervision identifier owned by H2.
    pub const fn supervision_id(self) -> SupervisionId {
        self.supervision_id
    }

    /// Rejects a reference that belongs to another project.
    pub fn ensure_project(self, project: ProjectId) -> Result<(), SddExecutionError> {
        if self.supervision_id.project_id() == project {
            Ok(())
        } else {
            Err(SddExecutionError::CrossProjectReference {
                id_kind: "H2 supervision".to_owned(),
                expected: project,
                found: self.supervision_id.project_id(),
            })
        }
    }
}

/// H1 run and optional input that produced one child turn.
///
/// H4 records the reference so evidence can name the exact H1 turn. The value
/// does not carry an H1 run state and is not convertible into a Task
/// progression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunInputRef {
    run_id: RunId,
    #[serde(default)]
    input_id: Option<InputId>,
}

impl RunInputRef {
    /// Records one H1 run and input.
    pub fn new(run_id: RunId, input_id: Option<InputId>) -> Result<Self, SddExecutionError> {
        let project = run_id.project_id();
        if let Some(input) = &input_id {
            verify_core_id(input, project)?;
        }
        Ok(Self { run_id, input_id })
    }

    /// H1 run identifier.
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// H1 input identifier, when one input was submitted.
    pub const fn input_id(self) -> Option<InputId> {
        self.input_id
    }

    /// Rejects a reference that belongs to another project.
    pub fn ensure_project(self, project: ProjectId) -> Result<(), SddExecutionError> {
        verify_core_id(&self.run_id, project)?;
        if let Some(input) = &self.input_id {
            verify_core_id(input, project)?;
        }
        Ok(())
    }
}

/// H1 child agent and conversation session used for one Task.
///
/// H4 keeps this reference separate from the H2 target and from the Task. The
/// same child is continued inside H2's limits; a new child identity is not
/// created by re-delivering a start request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChildIdentity {
    agent_id: AgentId,
    session_id: SessionId,
}

impl ChildIdentity {
    /// Records one H1 child.
    pub fn new(agent_id: AgentId, session_id: SessionId) -> Result<Self, SddExecutionError> {
        let project = agent_id.project_id();
        verify_core_id(&session_id, project)?;
        Ok(Self {
            agent_id,
            session_id,
        })
    }

    /// Child agent identifier.
    pub const fn agent_id(self) -> AgentId {
        self.agent_id
    }

    /// Child conversation session identifier.
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    /// Rejects a child that belongs to another project.
    pub fn ensure_project(self, project: ProjectId) -> Result<(), SddExecutionError> {
        verify_core_id(&self.agent_id, project)?;
        verify_core_id(&self.session_id, project)
    }
}

/// Verifies that a core project-scoped identifier belongs to `project`.
pub(crate) fn verify_core_id<K: ScopedIdKind>(
    id: &ScopedId<K>,
    project: ProjectId,
) -> Result<(), SddExecutionError> {
    id.validate_in(&project)
        .map_err(|_| SddExecutionError::CrossProjectReference {
            id_kind: K::KIND.as_str().to_owned(),
            expected: project,
            found: id.project_id(),
        })
}

/// Verifies that an H4 scoped identifier belongs to `project`.
pub(crate) fn verify_scoped<K: ExecutionKeyKind>(
    id: &ExecutionScopedId<K>,
    project: ProjectId,
) -> Result<(), SddExecutionError> {
    id.validate_in(project)
}
