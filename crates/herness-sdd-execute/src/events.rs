//! H4 state events on the existing H1 host-activity envelope.
//!
//! H4 does not define a second project sequence or a private event table. A
//! durable revision advance, its operation result, and its event commit in one
//! immediate transaction; the store assigns the next project sequence and
//! exposes the events only after the commit. A notification queue is never a
//! progress condition.
//!
//! Payloads carry identifiers, states, revisions, and sequences only. They never
//! carry prompts, plan bodies, HTML bodies, model text, or credentials.

use herness_core::{EventDraft, EventKind, EventPayload, HostActivityId, ProjectId, Timestamp};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::contract::ControlRecord;
use crate::error::SddExecutionError;
use crate::ids::{ExecutionId, ExecutionRevision, TaskNumber};
use crate::journal::{
    DispatchJournalEntry, GitCommitOutcome, GitJournalEntry, GitJournalState, JournalEntryState,
    ProgressJournalEntry, ProgressJournalState, ProgressWriteOutcome,
};
use crate::snapshot::ExecutionSnapshot;

/// Host-activity kind for one H4 execution.
pub const SDD_EXECUTION_ACTIVITY_KIND: &str = "sdd_execution.execution";
/// Event kind for a committed execution snapshot revision.
pub const SDD_SNAPSHOT_EVENT_KIND: &str = "sdd_execution.snapshot";
/// Event kind for a recorded control-operation intent or result.
pub const SDD_OPERATION_EVENT_KIND: &str = "sdd_execution.operation";
/// Event kind for a committed dispatch journal record.
pub const SDD_DISPATCH_EVENT_KIND: &str = "sdd_execution.dispatch";
/// Event kind for a committed Git journal record.
pub const SDD_GIT_EVENT_KIND: &str = "sdd_execution.commit";
/// Event kind for a committed progress journal record.
pub const SDD_PROGRESS_EVENT_KIND: &str = "sdd_execution.progress";

fn kind(value: &'static str) -> Result<EventKind, SddExecutionError> {
    EventKind::new(value).map_err(|error| SddExecutionError::InvalidValue {
        field: "eventKind".to_owned(),
        detail: error.to_string(),
    })
}

/// Deterministic host-activity ID for one execution's events.
pub fn execution_activity_id(execution_id: ExecutionId) -> HostActivityId {
    let mut value = [0_u8; 16];
    value.copy_from_slice(
        &Sha256::digest(format!("h4-execution-activity\0{execution_id}").as_bytes())[..16],
    );
    HostActivityId::from_parts(execution_id.project_id(), Uuid::from_bytes(value))
}

fn draft(
    project_id: ProjectId,
    execution_id: ExecutionId,
    event_kind: &'static str,
    occurred_at: Timestamp,
    payload: serde_json::Value,
) -> Result<EventDraft, SddExecutionError> {
    if execution_id.project_id() != project_id {
        return Err(SddExecutionError::CrossProjectReference {
            id_kind: "event execution".to_owned(),
            expected: project_id,
            found: execution_id.project_id(),
        });
    }
    EventDraft::for_host_activity(
        project_id,
        kind(SDD_EXECUTION_ACTIVITY_KIND)?,
        execution_activity_id(execution_id),
        kind(event_kind)?,
        occurred_at,
        EventPayload::new(payload),
    )
    .map_err(|error| SddExecutionError::InvalidValue {
        field: "eventDraft".to_owned(),
        detail: error.to_string(),
    })
}

fn task_payload(number: TaskNumber, stable_id: impl ToString) -> serde_json::Value {
    json!({
        "number": number.get(),
        "stableId": stable_id.to_string(),
    })
}
/// Shared snapshot summary for a state event payload.
fn snapshot_fields(snapshot: &ExecutionSnapshot) -> serde_json::Value {
    let current_task = snapshot
        .current_task()
        .map(|task| task_payload(task.number(), task.stable_id()));
    let stop = snapshot.stop().map(|stop| {
        json!({
            "reason": stop.reason().as_str(),
            "requiredAction": stop.required_action().map(|action| action.as_str()),
        })
    });
    let applied = snapshot.applied_revision();
    json!({
        "state": snapshot.state().as_str(),
        "currentTask": current_task,
        "stop": stop,
        "appliedRevision": {
            "state": applied.state().as_str(),
            "revision": applied.revision().map(|revision| revision.get()),
        },
        "finalProjectSequence": snapshot.final_project_sequence().map(|value| value.get()),
    })
}

/// Builds the event for one committed snapshot revision.
pub fn snapshot_event(
    snapshot: &ExecutionSnapshot,
    occurred_at: Timestamp,
) -> Result<EventDraft, SddExecutionError> {
    let mut payload = snapshot_fields(snapshot);
    payload["formatVersion"] = json!(1);
    payload["actor"] = json!("host");
    payload["executionId"] = json!(snapshot.execution_id().to_string());
    payload["revision"] = json!(snapshot.revision().get());
    draft(
        snapshot.project_id(),
        snapshot.execution_id(),
        SDD_SNAPSHOT_EVENT_KIND,
        occurred_at,
        payload,
    )
}

/// Builds the event for one recorded control-operation intent.
///
/// The payload records the request, its expected revision, and its state. It
/// never claims a resulting revision the record does not hold.
pub fn operation_event(
    record: &ControlRecord,
    occurred_at: Timestamp,
) -> Result<EventDraft, SddExecutionError> {
    let identity = record.identity();
    let execution_id = identity.execution_id();
    let mut payload = json!({
        "formatVersion": 1,
        "actor": "host",
        "executionId": execution_id.to_string(),
        "requestId": identity.request_id().to_string(),
        "expectedRevision": identity.expected_revision().get(),
        "state": journal_entry_state(record.state()),
        "operation": record.outcome().map(|result| result.operation().as_str()),
        "resultingRevision": record
            .outcome()
            .map(|result| result.resulting_revision().get()),
    });
    if let Some(result) = record.outcome() {
        payload["snapshot"] = snapshot_fields(result.snapshot());
    }
    draft(
        identity.project_id(),
        execution_id,
        SDD_OPERATION_EVENT_KIND,
        occurred_at,
        payload,
    )
}

const fn journal_entry_state(state: JournalEntryState) -> &'static str {
    match state {
        JournalEntryState::Intent => "intent",
        JournalEntryState::Recorded => "recorded",
    }
}

const fn git_state(state: GitJournalState) -> &'static str {
    match state {
        GitJournalState::Intent => "intent",
        GitJournalState::Committed => "committed",
        GitJournalState::Rejected => "rejected",
        GitJournalState::ResultUnknown => "result_unknown",
    }
}

const fn progress_state(state: ProgressJournalState) -> &'static str {
    match state {
        ProgressJournalState::Intent => "intent",
        ProgressJournalState::Recorded => "recorded",
        ProgressJournalState::ResultUnknown => "result_unknown",
    }
}

/// Builds the event for one committed dispatch journal record.
///
/// The journal entry carries the request guard and the created H2 target/child.
/// It does not re-expose the dispatch content, so the event names only the
/// request, its state, the expected revision, and the created references.
pub fn dispatch_event(
    entry: &DispatchJournalEntry,
    occurred_at: Timestamp,
) -> Result<EventDraft, SddExecutionError> {
    let identity = entry.identity();
    let execution_id = identity.execution_id();
    let mut payload = json!({
        "formatVersion": 1,
        "actor": "host",
        "executionId": execution_id.to_string(),
        "requestId": identity.request_id().to_string(),
        "expectedRevision": identity.expected_revision().get(),
        "state": journal_entry_state(entry.state()),
    });
    if let Some(result) = entry.outcome() {
        payload["supervisionId"] = json!(result.supervision_id().to_string());
        payload["childAgentId"] = json!(result.child().agent_id().to_string());
        payload["childSessionId"] = json!(result.child().session_id().to_string());
    }
    draft(
        identity.project_id(),
        execution_id,
        SDD_DISPATCH_EVENT_KIND,
        occurred_at,
        payload,
    )
}

/// Builds the event for one committed Git journal record.
pub fn git_event(
    entry: &GitJournalEntry,
    occurred_at: Timestamp,
) -> Result<EventDraft, SddExecutionError> {
    let identity = entry.identity();
    let execution_id = identity.execution_id();
    let commit = match entry.outcome() {
        Some(GitCommitOutcome::Committed { commit, .. }) => Some(commit.to_string()),
        _ => None,
    };
    let payload = json!({
        "formatVersion": 1,
        "actor": "host",
        "executionId": execution_id.to_string(),
        "requestId": identity.request_id().to_string(),
        "expectedRevision": identity.expected_revision().get(),
        "state": git_state(entry.state()),
        "taskNumber": entry.intent().task().number().get(),
        "commit": commit,
    });
    draft(
        identity.project_id(),
        execution_id,
        SDD_GIT_EVENT_KIND,
        occurred_at,
        payload,
    )
}

/// Builds the event for one committed progress journal record.
pub fn progress_event(
    entry: &ProgressJournalEntry,
    occurred_at: Timestamp,
) -> Result<EventDraft, SddExecutionError> {
    let identity = entry.identity();
    let execution_id = identity.execution_id();
    let digest = match entry.outcome() {
        Some(ProgressWriteOutcome::Written { digest }) => Some(digest.to_string()),
        _ => None,
    };
    let payload = json!({
        "formatVersion": 1,
        "actor": "host",
        "executionId": execution_id.to_string(),
        "requestId": identity.request_id().to_string(),
        "expectedRevision": identity.expected_revision().get(),
        "state": progress_state(entry.state()),
        "documentDigest": digest,
    });
    draft(
        identity.project_id(),
        execution_id,
        SDD_PROGRESS_EVENT_KIND,
        occurred_at,
        payload,
    )
}

/// The newest revision written by this build, exposed for adapters that need to
/// name the revision an event describes.
pub const fn revision_of(snapshot: &ExecutionSnapshot) -> ExecutionRevision {
    snapshot.revision()
}
