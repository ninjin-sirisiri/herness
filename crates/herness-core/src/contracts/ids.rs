//! Typed, project-scoped identifiers.
//!
//! Every agent, session, run, and operation identifier carries the project it
//! belongs to. A reference from another project is therefore detectable and is
//! rejected by [`ScopedId::validate_in`] and [`ProjectScope::verify`].

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::contracts::errors::CoreError;

/// Kind label used by structured identifier errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdKind {
    /// A project identifier.
    Project,
    /// An agent identifier.
    Agent,
    /// A conversation session identifier.
    Session,
    /// A run identifier.
    Run,
    /// A tool operation identifier.
    Operation,
    /// A connection identifier.
    Connection,
}

impl IdKind {
    /// Stable wire/display label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Agent => "agent",
            Self::Session => "session",
            Self::Run => "run",
            Self::Operation => "operation",
            Self::Connection => "connection",
        }
    }
}

/// Identifier of a local project directory opened by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectId(Uuid);

impl ProjectId {
    /// Generates a new random project identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wraps an existing UUID.
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the underlying UUID.
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for ProjectId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ProjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ProjectId {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| CoreError::InvalidId {
                id_kind: IdKind::Project,
                value: value.to_owned(),
            })
    }
}

impl Serialize for ProjectId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ProjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// Marker trait implemented by each project-scoped identifier kind.
pub trait ScopedIdKind: Copy + 'static {
    /// Stable prefix used in the wire representation.
    const PREFIX: &'static str;
    /// Kind label used in structured errors.
    const KIND: IdKind;
}

/// Marker for agent identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentKind {}

/// Marker for session identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionKind {}

/// Marker for run identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RunKind {}

/// Marker for operation identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperationKind {}

impl ScopedIdKind for AgentKind {
    const PREFIX: &'static str = "agent";
    const KIND: IdKind = IdKind::Agent;
}

impl ScopedIdKind for SessionKind {
    const PREFIX: &'static str = "session";
    const KIND: IdKind = IdKind::Session;
}

impl ScopedIdKind for RunKind {
    const PREFIX: &'static str = "run";
    const KIND: IdKind = IdKind::Run;
}

impl ScopedIdKind for OperationKind {
    const PREFIX: &'static str = "operation";
    const KIND: IdKind = IdKind::Operation;
}

/// A typed identifier that belongs to exactly one project.
///
/// The wire form is `"<kind>:<project-uuid>:<local-uuid>"`, for example
/// `"run:6f1c...:d2b4..."`. Parsing rejects the wrong kind prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopedId<K: ScopedIdKind> {
    project: ProjectId,
    local: Uuid,
    _kind: PhantomData<fn() -> K>,
}

impl<K: ScopedIdKind> ScopedId<K> {
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
    pub fn validate_in(&self, project: &ProjectId) -> Result<(), CoreError> {
        if self.project == *project {
            Ok(())
        } else {
            Err(CoreError::CrossProjectReference {
                id_kind: K::KIND,
                expected: *project,
                found: self.project,
            })
        }
    }
}

impl<K: ScopedIdKind> fmt::Display for ScopedId<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", K::PREFIX, self.project, self.local)
    }
}

impl<K: ScopedIdKind> FromStr for ScopedId<K> {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || CoreError::InvalidId {
            id_kind: K::KIND,
            value: value.to_owned(),
        };

        let mut parts = value.split(':');
        let prefix = parts.next().ok_or_else(invalid)?;
        let project = parts.next().ok_or_else(invalid)?;
        let local = parts.next().ok_or_else(invalid)?;
        if parts.next().is_some() || prefix != K::PREFIX {
            return Err(invalid());
        }

        let project = project.parse::<ProjectId>().map_err(|_| invalid())?;
        let local = Uuid::parse_str(local).map_err(|_| invalid())?;
        Ok(Self::from_parts(project, local))
    }
}

impl<K: ScopedIdKind> Serialize for ScopedId<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de, K: ScopedIdKind> Deserialize<'de> for ScopedId<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// Agent identifier.
pub type AgentId = ScopedId<AgentKind>;
/// Conversation session identifier.
pub type SessionId = ScopedId<SessionKind>;
/// Run identifier.
pub type RunId = ScopedId<RunKind>;
/// Tool operation identifier.
pub type OperationId = ScopedId<OperationKind>;

/// A verified project ownership scope used to reject cross-project references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProjectScope(ProjectId);

impl ProjectScope {
    /// Creates a scope for `project`.
    pub const fn new(project: ProjectId) -> Self {
        Self(project)
    }

    /// Project owned by this scope.
    pub const fn project_id(&self) -> ProjectId {
        self.0
    }

    /// Verifies that a scoped identifier belongs to this project.
    pub fn verify<K: ScopedIdKind>(&self, id: &ScopedId<K>) -> Result<(), CoreError> {
        id.validate_in(&self.0)
    }
}
