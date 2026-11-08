//! Versioned public events.
//!
//! Every persisted event carries [`ContractVersion`], project/agent/session/run
//! identifiers, an optional operation identifier, a project-monotonic sequence,
//! a timestamp, a kind, and a structured payload. Deserialization rejects
//! unknown contract versions and cross-project identifier mixes.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::ids::{AgentId, OperationId, ProjectId, ProjectScope, RunId, SessionId};
use crate::contracts::time::Timestamp;
use crate::contracts::version::ContractVersion;

/// Stable event type label.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventKind(String);

impl EventKind {
    /// Validates a non-empty event kind.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CoreError> {
        let trimmed = value.as_ref().trim();
        if trimmed.is_empty() {
            return Err(CoreError::InvalidValue {
                field: "eventKind".to_owned(),
                violation: ArgumentViolation::Empty,
            });
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Borrows the kind label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EventKind {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for EventKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EventKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Structured event payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventPayload(Value);

impl EventPayload {
    /// Wraps a JSON payload.
    pub fn new(value: Value) -> Self {
        Self(value)
    }

    /// Borrows the JSON payload.
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    /// Consumes the payload and returns the JSON value.
    pub fn into_value(self) -> Value {
        self.0
    }
}

/// An event before the store assigns its sequence.
#[derive(Debug, Clone, PartialEq)]
pub struct EventDraft {
    project_id: ProjectId,
    agent_id: AgentId,
    session_id: SessionId,
    run_id: RunId,
    operation_id: Option<OperationId>,
    kind: EventKind,
    occurred_at: Timestamp,
    payload: EventPayload,
}

impl EventDraft {
    /// Creates a validated event draft.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        agent_id: AgentId,
        session_id: SessionId,
        run_id: RunId,
        operation_id: Option<OperationId>,
        kind: EventKind,
        occurred_at: Timestamp,
        payload: EventPayload,
    ) -> Result<Self, CoreError> {
        validate_scope(
            project_id,
            &agent_id,
            &session_id,
            &run_id,
            operation_id.as_ref(),
        )?;
        Ok(Self {
            project_id,
            agent_id,
            session_id,
            run_id,
            operation_id,
            kind,
            occurred_at,
            payload,
        })
    }

    /// Project this event belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Agent this event belongs to.
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Session this event belongs to.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Run this event belongs to.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Optional operation this event belongs to.
    pub const fn operation_id(&self) -> Option<OperationId> {
        self.operation_id
    }

    /// Event type label.
    pub fn kind(&self) -> &EventKind {
        &self.kind
    }

    /// Event creation time.
    pub const fn occurred_at(&self) -> Timestamp {
        self.occurred_at
    }

    /// Structured event payload.
    pub fn payload(&self) -> &EventPayload {
        &self.payload
    }

    /// Assigns the store-managed sequence and produces a persisted event.
    pub fn into_event(self, sequence: u64) -> Result<Event, CoreError> {
        Event::new(
            ContractVersion::CURRENT,
            self.project_id,
            self.agent_id,
            self.session_id,
            self.run_id,
            self.operation_id,
            sequence,
            self.kind,
            self.occurred_at,
            self.payload,
        )
    }
}

/// A persisted, versioned public event.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    contract_version: ContractVersion,
    project_id: ProjectId,
    agent_id: AgentId,
    session_id: SessionId,
    run_id: RunId,
    operation_id: Option<OperationId>,
    sequence: u64,
    kind: EventKind,
    occurred_at: Timestamp,
    payload: EventPayload,
}

impl Event {
    /// Creates a validated persisted event.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_version: ContractVersion,
        project_id: ProjectId,
        agent_id: AgentId,
        session_id: SessionId,
        run_id: RunId,
        operation_id: Option<OperationId>,
        sequence: u64,
        kind: EventKind,
        occurred_at: Timestamp,
        payload: EventPayload,
    ) -> Result<Self, CoreError> {
        if sequence == 0 {
            return Err(CoreError::InvalidEvent {
                field: "sequence".to_owned(),
                violation: ArgumentViolation::MustBePositive,
            });
        }
        validate_scope(
            project_id,
            &agent_id,
            &session_id,
            &run_id,
            operation_id.as_ref(),
        )?;

        Ok(Self {
            contract_version,
            project_id,
            agent_id,
            session_id,
            run_id,
            operation_id,
            sequence,
            kind,
            occurred_at,
            payload,
        })
    }

    /// Public contract version.
    pub const fn contract_version(&self) -> ContractVersion {
        self.contract_version
    }

    /// Project this event belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Agent this event belongs to.
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Session this event belongs to.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Run this event belongs to.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Optional operation this event belongs to.
    pub const fn operation_id(&self) -> Option<OperationId> {
        self.operation_id
    }

    /// Project-monotonic sequence assigned by the store.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Event type label.
    pub fn kind(&self) -> &EventKind {
        &self.kind
    }

    /// Event creation time.
    pub const fn occurred_at(&self) -> Timestamp {
        self.occurred_at
    }

    /// Structured event payload.
    pub fn payload(&self) -> &EventPayload {
        &self.payload
    }
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            contract_version: ContractVersion,
            project_id: ProjectId,
            agent_id: AgentId,
            session_id: SessionId,
            run_id: RunId,
            operation_id: Option<OperationId>,
            sequence: u64,
            kind: EventKind,
            occurred_at: Timestamp,
            payload: EventPayload,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.contract_version,
            wire.project_id,
            wire.agent_id,
            wire.session_id,
            wire.run_id,
            wire.operation_id,
            wire.sequence,
            wire.kind,
            wire.occurred_at,
            wire.payload,
        )
        .map_err(de::Error::custom)
    }
}

fn validate_scope(
    project_id: ProjectId,
    agent_id: &AgentId,
    session_id: &SessionId,
    run_id: &RunId,
    operation_id: Option<&OperationId>,
) -> Result<(), CoreError> {
    let scope = ProjectScope::new(project_id);
    scope.verify(agent_id)?;
    scope.verify(session_id)?;
    scope.verify(run_id)?;
    if let Some(operation_id) = operation_id {
        scope.verify(operation_id)?;
    }
    Ok(())
}
