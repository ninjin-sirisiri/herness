//! Versioned public events.
//!
//! New public events are written as contract version 2. A version-2 event
//! carries the project, a subject, an optional operation identifier, a
//! project-monotonic sequence, a timestamp, a kind, and a structured payload.
//!
//! The subject is either a [`RunSubject`] (real project-matched agent/session/
//! run identifiers) or a [`HostActivitySubject`] (a project-bound stable
//! activity kind and activity identifier). Host activity events never invent a
//! run identifier. Operation identifiers are allowed only on run subjects.
//!
//! Version-1 events are read through the explicit [`Event::from_v1`]
//! compatibility decoder as run-subject events. The stored identifiers,
//! sequence, kind, timestamp, and payload are preserved. Unknown versions are
//! rejected instead of being silently downgraded.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::ids::{
    AgentId, HostActivityId, IdKind, OperationId, ProjectId, ProjectScope, RunId, SessionId,
};
use crate::contracts::time::Timestamp;
use crate::contracts::version::{CONTRACT_VERSION, ContractVersion};

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

/// Reference to one real run and its owning agent/session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunSubject {
    project_id: ProjectId,
    agent_id: AgentId,
    session_id: SessionId,
    run_id: RunId,
}

impl RunSubject {
    /// Creates a run reference whose identifiers all belong to `project_id`.
    pub fn new(
        project_id: ProjectId,
        agent_id: AgentId,
        session_id: SessionId,
        run_id: RunId,
    ) -> Result<Self, CoreError> {
        let scope = ProjectScope::new(project_id);
        scope.verify(&agent_id)?;
        scope.verify(&session_id)?;
        scope.verify(&run_id)?;
        Ok(Self {
            project_id,
            agent_id,
            session_id,
            run_id,
        })
    }

    /// Project that owns the run.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Agent that owns the session.
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Conversation session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Run identifier.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }
}

impl<'de> Deserialize<'de> for RunSubject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            project_id: ProjectId,
            agent_id: AgentId,
            session_id: SessionId,
            run_id: RunId,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.project_id, wire.agent_id, wire.session_id, wire.run_id)
            .map_err(de::Error::custom)
    }
}

/// Reference to one host activity that has no run.
///
/// The activity kind and identifier are stable within the project. This
/// subject exists so supervision activity before run creation does not have to
/// fake a run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostActivitySubject {
    project_id: ProjectId,
    activity_kind: EventKind,
    activity_id: HostActivityId,
}

impl HostActivitySubject {
    /// Creates a host activity reference bound to `project_id`.
    pub fn new(
        project_id: ProjectId,
        activity_kind: EventKind,
        activity_id: HostActivityId,
    ) -> Result<Self, CoreError> {
        ProjectScope::new(project_id).verify(&activity_id)?;
        Ok(Self {
            project_id,
            activity_kind,
            activity_id,
        })
    }

    /// Project that owns the activity.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Stable host activity kind label.
    pub fn activity_kind(&self) -> &EventKind {
        &self.activity_kind
    }

    /// Stable host activity identifier.
    pub const fn activity_id(&self) -> HostActivityId {
        self.activity_id
    }
}

impl<'de> Deserialize<'de> for HostActivitySubject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            project_id: ProjectId,
            activity_kind: EventKind,
            activity_id: HostActivityId,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.project_id, wire.activity_kind, wire.activity_id).map_err(de::Error::custom)
    }
}

/// What a version-2 event or model request is attached to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum EventSubject {
    /// A real run.
    Run(RunSubject),
    /// A host activity that has no run.
    HostActivity(HostActivitySubject),
}

impl EventSubject {
    /// Project that owns the subject.
    pub const fn project_id(&self) -> ProjectId {
        match self {
            Self::Run(run) => run.project_id,
            Self::HostActivity(activity) => activity.project_id,
        }
    }

    /// Run reference, if this is a run subject.
    pub const fn run(&self) -> Option<RunSubject> {
        match self {
            Self::Run(run) => Some(*run),
            Self::HostActivity(_) => None,
        }
    }

    /// Host activity reference, if this is an activity subject.
    pub const fn host_activity(&self) -> Option<&HostActivitySubject> {
        match self {
            Self::Run(_) => None,
            Self::HostActivity(activity) => Some(activity),
        }
    }
}

/// An event before the store assigns its sequence.
///
/// [`EventDraft::new`] creates a run-subject draft. Use
/// [`EventDraft::for_host_activity`] for events that precede or do not have a
/// run. The resulting event is always written as contract version 2.
#[derive(Debug, Clone, PartialEq)]
pub struct EventDraft {
    subject: EventSubject,
    operation_id: Option<OperationId>,
    kind: EventKind,
    occurred_at: Timestamp,
    payload: EventPayload,
}

impl EventDraft {
    /// Creates a validated run-subject event draft.
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
        let subject = EventSubject::Run(RunSubject::new(project_id, agent_id, session_id, run_id)?);
        validate_operation(&subject, operation_id.as_ref())?;
        Ok(Self {
            subject,
            operation_id,
            kind,
            occurred_at,
            payload,
        })
    }

    /// Creates a draft for a host activity that has no run.
    ///
    /// Operation identifiers are rejected because they belong to run subjects.
    pub fn for_host_activity(
        project_id: ProjectId,
        activity_kind: EventKind,
        activity_id: HostActivityId,
        kind: EventKind,
        occurred_at: Timestamp,
        payload: EventPayload,
    ) -> Result<Self, CoreError> {
        let subject = EventSubject::HostActivity(HostActivitySubject::new(
            project_id,
            activity_kind,
            activity_id,
        )?);
        Ok(Self {
            subject,
            operation_id: None,
            kind,
            occurred_at,
            payload,
        })
    }

    /// Subject this event is attached to.
    pub const fn subject(&self) -> &EventSubject {
        &self.subject
    }

    /// Project this event belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.subject.project_id()
    }

    /// Run reference, if this is a run-subject event.
    pub const fn run_subject(&self) -> Option<RunSubject> {
        self.subject.run()
    }

    /// Agent this event belongs to, if it has a run subject.
    pub fn agent_id(&self) -> Option<AgentId> {
        self.run_subject().map(|run| run.agent_id())
    }

    /// Session this event belongs to, if it has a run subject.
    pub fn session_id(&self) -> Option<SessionId> {
        self.run_subject().map(|run| run.session_id())
    }

    /// Run this event belongs to, if it has a run subject.
    pub fn run_id(&self) -> Option<RunId> {
        self.run_subject().map(|run| run.run_id())
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

    /// Assigns the store-managed sequence and produces a version-2 event.
    pub fn into_event(self, sequence: u64) -> Result<Event, CoreError> {
        Event::new(
            self.subject,
            self.operation_id,
            sequence,
            self.kind,
            self.occurred_at,
            self.payload,
        )
    }
}

/// A persisted, versioned public event.
///
/// Version-2 events serialize with a `subject`. A version-1 event read through
/// [`Event::from_v1`] keeps its original version and serializes with the legacy
/// run fields so existing history data round-trips unchanged.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    contract_version: ContractVersion,
    subject: EventSubject,
    operation_id: Option<OperationId>,
    sequence: u64,
    kind: EventKind,
    occurred_at: Timestamp,
    payload: EventPayload,
}

impl Event {
    /// Creates a validated current-version (version 2) event.
    pub fn new(
        subject: EventSubject,
        operation_id: Option<OperationId>,
        sequence: u64,
        kind: EventKind,
        occurred_at: Timestamp,
        payload: EventPayload,
    ) -> Result<Self, CoreError> {
        validate_sequence(sequence)?;
        validate_operation(&subject, operation_id.as_ref())?;
        Ok(Self {
            contract_version: ContractVersion::CURRENT,
            subject,
            operation_id,
            sequence,
            kind,
            occurred_at,
            payload,
        })
    }

    /// Explicit version-1 compatibility decoder.
    ///
    /// A stored version-1 event has an implicit run subject. Its project,
    /// agent, session, run, optional operation, sequence, kind, timestamp, and
    /// payload are preserved exactly. This is the only path that produces a
    /// version-1 [`Event`].
    #[allow(clippy::too_many_arguments)]
    pub fn from_v1(
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
        validate_sequence(sequence)?;
        let subject = EventSubject::Run(RunSubject::new(project_id, agent_id, session_id, run_id)?);
        validate_operation(&subject, operation_id.as_ref())?;
        Ok(Self {
            contract_version: ContractVersion::V1,
            subject,
            operation_id,
            sequence,
            kind,
            occurred_at,
            payload,
        })
    }

    /// Public contract version carried by this event.
    pub const fn contract_version(&self) -> ContractVersion {
        self.contract_version
    }

    /// Subject this event is attached to.
    pub const fn subject(&self) -> &EventSubject {
        &self.subject
    }

    /// Project this event belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.subject.project_id()
    }

    /// Run reference, if this is a run-subject event.
    pub const fn run_subject(&self) -> Option<RunSubject> {
        self.subject.run()
    }

    /// Agent this event belongs to, if it has a run subject.
    pub fn agent_id(&self) -> Option<AgentId> {
        self.run_subject().map(|run| run.agent_id())
    }

    /// Session this event belongs to, if it has a run subject.
    pub fn session_id(&self) -> Option<SessionId> {
        self.run_subject().map(|run| run.session_id())
    }

    /// Run this event belongs to, if it has a run subject.
    pub fn run_id(&self) -> Option<RunId> {
        self.run_subject().map(|run| run.run_id())
    }

    /// Optional operation this event belongs to. Only run subjects may carry
    /// an operation identifier.
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

impl Serialize for Event {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct WireV2<'a> {
            contract_version: ContractVersion,
            project_id: ProjectId,
            subject: &'a EventSubject,
            operation_id: Option<OperationId>,
            sequence: u64,
            kind: &'a EventKind,
            occurred_at: Timestamp,
            payload: &'a EventPayload,
        }

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct WireV1<'a> {
            contract_version: ContractVersion,
            project_id: ProjectId,
            agent_id: AgentId,
            session_id: SessionId,
            run_id: RunId,
            operation_id: Option<OperationId>,
            sequence: u64,
            kind: &'a EventKind,
            occurred_at: Timestamp,
            payload: &'a EventPayload,
        }

        if self.contract_version == ContractVersion::V1 {
            let Some(run) = self.subject.run() else {
                return Err(serde::ser::Error::custom(
                    "version 1 event must carry a run subject",
                ));
            };
            WireV1 {
                contract_version: self.contract_version,
                project_id: run.project_id(),
                agent_id: run.agent_id(),
                session_id: run.session_id(),
                run_id: run.run_id(),
                operation_id: self.operation_id,
                sequence: self.sequence,
                kind: &self.kind,
                occurred_at: self.occurred_at,
                payload: &self.payload,
            }
            .serialize(serializer)
        } else {
            WireV2 {
                contract_version: self.contract_version,
                project_id: self.project_id(),
                subject: &self.subject,
                operation_id: self.operation_id,
                sequence: self.sequence,
                kind: &self.kind,
                occurred_at: self.occurred_at,
                payload: &self.payload,
            }
            .serialize(serializer)
        }
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
            contract_version: u32,
            project_id: ProjectId,
            #[serde(default)]
            subject: Option<EventSubject>,
            #[serde(default)]
            agent_id: Option<AgentId>,
            #[serde(default)]
            session_id: Option<SessionId>,
            #[serde(default)]
            run_id: Option<RunId>,
            #[serde(default)]
            operation_id: Option<OperationId>,
            sequence: u64,
            kind: EventKind,
            occurred_at: Timestamp,
            payload: EventPayload,
        }

        let wire = Wire::deserialize(deserializer)?;
        match wire.contract_version {
            1 => {
                if wire.subject.is_some() {
                    return Err(de::Error::custom(invalid_event(
                        "subject",
                        "version 1 events do not carry a subject; their run reference is implicit",
                    )));
                }
                let (Some(agent_id), Some(session_id), Some(run_id)) =
                    (wire.agent_id, wire.session_id, wire.run_id)
                else {
                    return Err(de::Error::custom(invalid_event(
                        "runId",
                        "version 1 events require agentId, sessionId, and runId",
                    )));
                };
                Self::from_v1(
                    wire.project_id,
                    agent_id,
                    session_id,
                    run_id,
                    wire.operation_id,
                    wire.sequence,
                    wire.kind,
                    wire.occurred_at,
                    wire.payload,
                )
                .map_err(de::Error::custom)
            }
            2 => {
                if wire.agent_id.is_some() || wire.session_id.is_some() || wire.run_id.is_some() {
                    return Err(de::Error::custom(invalid_event(
                        "subject",
                        "version 2 events must use subject, not legacy agent/session/run fields",
                    )));
                }
                let Some(subject) = wire.subject else {
                    return Err(de::Error::custom(invalid_event(
                        "subject",
                        "version 2 events require a run or host activity subject",
                    )));
                };
                if subject.project_id() != wire.project_id {
                    return Err(de::Error::custom(CoreError::CrossProjectReference {
                        id_kind: IdKind::Project,
                        expected: wire.project_id,
                        found: subject.project_id(),
                    }));
                }
                Self::new(
                    subject,
                    wire.operation_id,
                    wire.sequence,
                    wire.kind,
                    wire.occurred_at,
                    wire.payload,
                )
                .map_err(de::Error::custom)
            }
            found => Err(de::Error::custom(CoreError::UnknownContractVersion {
                found,
                expected: CONTRACT_VERSION,
            })),
        }
    }
}

fn validate_sequence(sequence: u64) -> Result<(), CoreError> {
    if sequence == 0 {
        return Err(CoreError::InvalidEvent {
            field: "sequence".to_owned(),
            violation: ArgumentViolation::MustBePositive,
        });
    }
    Ok(())
}

fn validate_operation(
    subject: &EventSubject,
    operation_id: Option<&OperationId>,
) -> Result<(), CoreError> {
    let Some(operation_id) = operation_id else {
        return Ok(());
    };
    let Some(run) = subject.run() else {
        return Err(invalid_event(
            "operationId",
            "operation identifiers are allowed only on run subjects",
        ));
    };
    ProjectScope::new(run.project_id()).verify(operation_id)?;
    Ok(())
}

fn invalid_event(field: &str, detail: impl Into<String>) -> CoreError {
    CoreError::InvalidEvent {
        field: field.to_owned(),
        violation: ArgumentViolation::Invalid {
            detail: detail.into(),
        },
    }
}
