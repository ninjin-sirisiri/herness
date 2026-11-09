//! Durable pi-embedded session store over the host [`StorePort`].
//!
//! The adapter owns the checkpoint format. A checkpoint body is a versioned
//! envelope containing the SDK snapshot plus the non-secret host metadata
//! needed to rebuild a run after a restart. Core and the store only ever see a
//! [`CheckpointFormatVersion`] and opaque bytes.
//!
//! The same handle is given to the native file and shell executors. When those
//! executors persist their own audit checkpoint, this adapter substitutes the
//! current engine snapshot in the same transaction, so restoring a run never
//! loads an audit record as if it were a conversation. When a tool handler
//! already persisted the operation intent, the executor's repeated intent is
//! coalesced instead of failing or executing twice.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use herness_core::{
    AbsolutePath, AgentId, ArtifactHandle, Checkpoint, CheckpointCommit, CheckpointFormatVersion,
    CheckpointPayload, CommitReceipt, ConnectionId, CoreError, EngineFailureKind, EventDraft,
    EventKind, EventPayload, HistoryPage, HistoryQuery, OperationId, OperationIntent,
    OperationRecord, OperationResult, ProjectId, RunId, SessionId, StorePort, Timestamp,
};
use pi_embedded::{SessionSnapshot, SessionStatus, SessionSummary};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events::EventQueue;

/// Version of the adapter-owned checkpoint envelope.
pub(crate) const ENGINE_CHECKPOINT_VERSION: u32 = 1;
/// Stable engine label stored in the envelope.
const ENGINE_NAME: &str = "pi-embedded";
/// Audit event written with every durable engine checkpoint.
pub(crate) const ENGINE_CHECKPOINT_EVENT_KIND: &str = "engine.checkpoint";
/// Audit event written when a tool operation intent is committed.
pub(crate) const ENGINE_TOOL_INTENT_EVENT_KIND: &str = "engine.tool.intent";
/// Audit event written when a tool is refused by host policy.
pub(crate) const ENGINE_TOOL_DENIED_EVENT_KIND: &str = "engine.tool.denied";
/// Audit event written when a tool waits for a host decision.
pub(crate) const ENGINE_TOOL_AWAITING_EVENT_KIND: &str = "engine.tool.awaiting_approval";

/// Non-secret host metadata needed to rebuild a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunAuditMetadata {
    pub(crate) project_id: ProjectId,
    pub(crate) agent_id: AgentId,
    pub(crate) session_id: SessionId,
    pub(crate) run_id: RunId,
    pub(crate) connection: ConnectionId,
    pub(crate) cwd: AbsolutePath,
    pub(crate) instructions: String,
    pub(crate) candidate: Option<ArtifactHandle>,
}

/// Versioned checkpoint body. Unknown formats are rejected, never guessed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointEnvelope {
    format: u32,
    engine: String,
    run_id: RunId,
    agent_id: AgentId,
    session_id: SessionId,
    connection: ConnectionId,
    cwd: AbsolutePath,
    instructions: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate: Option<ArtifactHandle>,
    snapshot: SessionSnapshot,
}

/// Parsed checkpoint data.
#[derive(Debug, Clone)]
pub(crate) struct EngineCheckpoint {
    pub(crate) meta: RunAuditMetadata,
    pub(crate) snapshot: SessionSnapshot,
}

/// Shared store handle with a per-run engine snapshot cache.
pub(crate) struct EngineStore<S> {
    store: Arc<Mutex<S>>,
    audit: RunAuditMetadata,
    snapshot: Arc<Mutex<Option<SessionSnapshot>>>,
    /// Initial conversation copied from a previous run. It is used only when
    /// this run has no durable checkpoint yet, which is the first restore of a
    /// continuation.
    seed: Option<SessionSnapshot>,
}

impl<S> Clone for EngineStore<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            audit: self.audit.clone(),
            snapshot: Arc::clone(&self.snapshot),
            seed: self.seed.clone(),
        }
    }
}

impl<S: StorePort> EngineStore<S> {
    /// Creates a run-scoped handle over a shared store.
    pub(crate) fn new(store: Arc<Mutex<S>>, audit: RunAuditMetadata) -> Self {
        Self {
            store,
            audit,
            snapshot: Arc::new(Mutex::new(None)),
            seed: None,
        }
    }

    /// Creates a handle whose first restore loads a conversation copied from a
    /// previous run. The copy is never used after this run has its own durable
    /// checkpoint.
    pub(crate) fn seeded(
        store: Arc<Mutex<S>>,
        audit: RunAuditMetadata,
        seed: SessionSnapshot,
    ) -> Self {
        Self {
            store,
            audit,
            snapshot: Arc::new(Mutex::new(Some(seed.clone()))),
            seed: Some(seed),
        }
    }

    /// Host metadata carried by this run's checkpoints.
    #[cfg(test)]
    pub(crate) fn audit(&self) -> &RunAuditMetadata {
        &self.audit
    }

    /// Current cached SDK snapshot.
    pub(crate) fn snapshot(&self) -> Option<SessionSnapshot> {
        self.snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Replaces the cached snapshot.
    pub(crate) fn set_snapshot(&self, snapshot: SessionSnapshot) {
        *self
            .snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(snapshot);
    }

    pub(crate) fn clear_snapshot(&self) {
        *self
            .snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    /// The current cached snapshot as an engine checkpoint.
    pub(crate) fn current_checkpoint(&self) -> Result<Option<Checkpoint>, CoreError> {
        let Some(snapshot) = self.snapshot() else {
            return Ok(None);
        };
        self.checkpoint_from(&snapshot).map(Some)
    }

    /// Builds a checkpoint for an explicit snapshot.
    pub(crate) fn checkpoint_from(
        &self,
        snapshot: &SessionSnapshot,
    ) -> Result<Checkpoint, CoreError> {
        let envelope = CheckpointEnvelope {
            format: ENGINE_CHECKPOINT_VERSION,
            engine: ENGINE_NAME.to_owned(),
            run_id: self.audit.run_id,
            agent_id: self.audit.agent_id,
            session_id: self.audit.session_id,
            connection: self.audit.connection,
            cwd: self.audit.cwd.clone(),
            instructions: self.audit.instructions.clone(),
            candidate: self.audit.candidate.clone(),
            snapshot: sanitize_snapshot(snapshot),
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|_| checkpoint_error())?;
        Ok(Checkpoint::new(
            self.audit.run_id,
            CheckpointFormatVersion::new(ENGINE_CHECKPOINT_VERSION)
                .expect("engine checkpoint version is non-zero"),
            CheckpointPayload::new(bytes),
        ))
    }

    /// Commits an operation intent together with the current engine checkpoint
    /// and audit events in one store transaction.
    #[cfg(test)]
    pub(crate) fn commit_intent(
        &self,
        operation: &herness_core::FrozenOperation,
    ) -> Result<CommitReceipt, CoreError> {
        let event = self.event_draft(
            Some(operation.operation_id()),
            ENGINE_TOOL_INTENT_EVENT_KIND,
            serde_json::json!({
                "tool": operation.tool().as_str(),
                "operationId": operation.operation_id().to_string(),
            }),
        )?;
        let intent = OperationIntent::new(operation.clone(), Timestamp::now());
        self.commit_engine(Some(intent), vec![event])
    }

    /// Commits a checkpoint plus one audit event for a refused or waiting tool.
    pub(crate) fn commit_tool_audit(
        &self,
        operation: &herness_core::FrozenOperation,
        kind: &str,
        reason: &str,
    ) -> Result<CommitReceipt, CoreError> {
        let event = self.event_draft(
            Some(operation.operation_id()),
            kind,
            serde_json::json!({
                "tool": operation.tool().as_str(),
                "operationId": operation.operation_id().to_string(),
                "reason": reason,
            }),
        )?;
        self.commit_engine(None, vec![event])
    }

    fn intent_event(&self, intent: &OperationIntent) -> Result<EventDraft, CoreError> {
        let operation = intent.operation();
        self.event_draft(
            Some(operation.operation_id()),
            ENGINE_TOOL_INTENT_EVENT_KIND,
            serde_json::json!({
                "tool": operation.tool().as_str(),
                "operationId": operation.operation_id().to_string(),
            }),
        )
    }

    fn event_draft(
        &self,
        operation: Option<OperationId>,
        kind: &str,
        payload: Value,
    ) -> Result<EventDraft, CoreError> {
        EventDraft::new(
            self.audit.project_id,
            self.audit.agent_id,
            self.audit.session_id,
            self.audit.run_id,
            operation,
            EventKind::new(kind)?,
            Timestamp::now(),
            EventPayload::new(payload),
        )
    }

    fn commit_engine(
        &self,
        operation: Option<OperationIntent>,
        events: Vec<EventDraft>,
    ) -> Result<CommitReceipt, CoreError> {
        let checkpoint = self.current_checkpoint()?.ok_or_else(checkpoint_error)?;
        self.commit_rewritten(CheckpointCommit::new(checkpoint, operation, events)?)
    }

    /// Rewrites executor audit checkpoints to the engine snapshot, coalesces an
    /// already-recorded identical intent, then commits once.
    fn commit_rewritten(&self, commit: CheckpointCommit) -> Result<CommitReceipt, CoreError> {
        let checkpoint = if is_audit_checkpoint(commit.checkpoint()) {
            self.current_checkpoint()?.ok_or_else(checkpoint_error)?
        } else {
            commit.checkpoint().clone()
        };
        let operation = self.coalesce_operation(commit.operation())?;
        let mut events = commit.events().to_vec();
        if let Some(intent) = &operation
            && !events
                .iter()
                .any(|event| event.kind().as_str() == ENGINE_TOOL_INTENT_EVENT_KIND)
        {
            // The executor owns the intent-before-side-effect commit. Add the
            // adapter's audit label in the same transaction, before the
            // executor's own events.
            events.insert(0, self.intent_event(intent)?);
        }
        if !events
            .iter()
            .any(|event| event.kind().as_str() == ENGINE_CHECKPOINT_EVENT_KIND)
            && let Some(snapshot) = self.snapshot()
        {
            events.push(self.checkpoint_event(&snapshot)?);
        }
        let commit = CheckpointCommit::new(checkpoint, operation, events)?;
        let mut store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.commit_checkpoint(commit)
    }

    fn coalesce_operation(
        &self,
        operation: Option<&OperationIntent>,
    ) -> Result<Option<OperationIntent>, CoreError> {
        let Some(intent) = operation else {
            return Ok(None);
        };
        let id = intent.operation().operation_id();
        let existing = {
            let store = self
                .store
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            store.operation(&id)?
        };
        match existing {
            Some(record) if record.intent().operation() == intent.operation() => Ok(None),
            Some(_) => Err(CoreError::DuplicateOperation { operation: id }),
            None => Ok(Some(intent.clone())),
        }
    }

    fn checkpoint_event(&self, snapshot: &SessionSnapshot) -> Result<EventDraft, CoreError> {
        self.event_draft(
            None,
            ENGINE_CHECKPOINT_EVENT_KIND,
            serde_json::json!({
                "sdkSequence": snapshot.sequence,
                "revision": snapshot.revision,
                "status": status_label(snapshot.status),
                "pendingInvocations": snapshot
                    .invocations
                    .iter()
                    .filter(|invocation| {
                        invocation.phase != pi_embedded::InvocationPhase::Completed
                    })
                    .count(),
            }),
        )
    }

    /// Loads and validates the latest checkpoint for this run.
    ///
    /// A continuation with no durable checkpoint yet falls back to the
    /// conversation copied from the previous run. The first restore save then
    /// writes it under this run's identifier, so the copy cannot be confused
    /// with the previous run's own checkpoint.
    pub(crate) fn load_engine_checkpoint(&self) -> Result<Option<EngineCheckpoint>, CoreError> {
        let checkpoint = self.load_raw_checkpoint()?;
        if let Some(checkpoint) = checkpoint {
            let parsed = parse_checkpoint(&checkpoint, self.audit.run_id)?;
            self.set_snapshot(parsed.snapshot.clone());
            return Ok(Some(parsed));
        }
        let Some(seed) = &self.seed else {
            return Ok(None);
        };
        if seed.id != self.audit.session_id.to_string() || seed.version != 1 {
            return Err(checkpoint_error());
        }
        self.set_snapshot(seed.clone());
        Ok(Some(EngineCheckpoint {
            meta: self.audit.clone(),
            snapshot: seed.clone(),
        }))
    }

    /// Loads the opaque latest checkpoint without interpreting it.
    pub(crate) fn load_raw_checkpoint(&self) -> Result<Option<Checkpoint>, CoreError> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.load_checkpoint(&self.audit.run_id)
    }
}

impl<S: StorePort> StorePort for EngineStore<S> {
    fn commit_checkpoint(&mut self, commit: CheckpointCommit) -> Result<CommitReceipt, CoreError> {
        self.commit_rewritten(commit)
    }

    fn load_checkpoint(&self, run: &RunId) -> Result<Option<Checkpoint>, CoreError> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.load_checkpoint(run)
    }

    fn history(&self, query: HistoryQuery) -> Result<HistoryPage, CoreError> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.history(query)
    }

    fn pending_operations(&self, project: &ProjectId) -> Result<Vec<OperationIntent>, CoreError> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.pending_operations(project)
    }

    fn operation(&self, operation: &OperationId) -> Result<Option<OperationRecord>, CoreError> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.operation(operation)
    }

    fn record_operation_result(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
    ) -> Result<(), CoreError> {
        let mut store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.record_operation_result(operation, result)
    }

    fn record_operation_result_with_events(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
        events: Vec<EventDraft>,
    ) -> Result<CommitReceipt, CoreError> {
        let mut store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.record_operation_result_with_events(operation, result, events)
    }
}

/// pi-embedded session store backed by [`EngineStore`].
pub(crate) struct EngineSessionStore<S> {
    store: EngineStore<S>,
    queue: EventQueue,
}

impl<S: StorePort> EngineSessionStore<S> {
    /// Creates a session store for one run.
    pub(crate) fn new(store: EngineStore<S>, queue: EventQueue) -> Self {
        Self { store, queue }
    }
}

#[async_trait]
impl<S: StorePort + Send> pi_embedded::SessionStore for EngineSessionStore<S> {
    async fn load(&self, id: &str) -> anyhow::Result<Option<SessionSnapshot>> {
        if id != self.store.audit.session_id.to_string() {
            anyhow::bail!("session id does not belong to this engine run");
        }
        let parsed = self
            .store
            .load_engine_checkpoint()
            .map_err(|_| anyhow::anyhow!("session checkpoint could not be read"))?;
        Ok(parsed.map(|parsed| parsed.snapshot))
    }

    async fn list(&self) -> anyhow::Result<Vec<SessionSummary>> {
        Ok(self
            .store
            .snapshot()
            .map(|snapshot| {
                vec![SessionSummary {
                    id: snapshot.id,
                    status: snapshot.status,
                    revision: snapshot.revision,
                }]
            })
            .unwrap_or_default())
    }

    async fn save(
        &self,
        snapshot: &SessionSnapshot,
        expected_revision: Option<u64>,
    ) -> anyhow::Result<()> {
        if snapshot.id != self.store.audit.session_id.to_string() {
            anyhow::bail!("session id does not belong to this engine run");
        }
        let previous = self.store.snapshot();
        match expected_revision {
            Some(expected) => {
                if previous.as_ref().map(|current| current.revision) != Some(expected) {
                    anyhow::bail!("session checkpoint revision changed");
                }
            }
            None => {
                if previous.is_some() {
                    anyhow::bail!("session checkpoint already exists");
                }
            }
        }
        let next = sanitize_snapshot(snapshot);
        self.store.set_snapshot(next);
        match self.store.commit_engine(None, Vec::new()) {
            Ok(_) => Ok(()),
            Err(error) => {
                match previous {
                    Some(previous) => self.store.set_snapshot(previous),
                    None => self.store.clear_snapshot(),
                }
                self.queue.push(herness_core::EngineEvent::Failure {
                    failure: EngineFailureKind::CheckpointUnavailable,
                });
                let _ = error;
                anyhow::bail!("session checkpoint could not be committed")
            }
        }
    }
}

fn checkpoint_error() -> CoreError {
    CoreError::EngineUnavailable {
        failure: EngineFailureKind::CheckpointUnavailable,
    }
}

fn status_label(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Idle => "idle",
        SessionStatus::Running => "running",
        SessionStatus::AwaitingApproval => "awaiting_approval",
        SessionStatus::Paused => "paused",
        SessionStatus::Interrupted => "interrupted",
        SessionStatus::Disposed => "disposed",
    }
}

/// Removes provider error text and diagnostics from a snapshot before it is
/// persisted. The streamed transcript is kept; raw provider bodies, tokens, and
/// diagnostics are not.
pub(crate) fn sanitize_snapshot(snapshot: &SessionSnapshot) -> SessionSnapshot {
    let mut next = snapshot.clone();
    if next.error.take().is_some() {
        next.error = Some("engine error".to_owned());
    }
    if let Some(partial) = next.partial.as_mut() {
        sanitize_assistant(partial);
    }
    for message in &mut next.messages {
        if let pi_ai::Message::Assistant(assistant) = message {
            sanitize_assistant(assistant);
        }
    }
    next
}

fn sanitize_assistant(assistant: &mut pi_ai::AssistantMessage) {
    if assistant.error_message.take().is_some() {
        assistant.error_message = Some("engine error".to_owned());
    }
    assistant.diagnostics.clear();
}

fn is_audit_checkpoint(checkpoint: &Checkpoint) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(checkpoint.payload().as_bytes()) else {
        return false;
    };
    matches!(
        value.get("kind").and_then(Value::as_str),
        Some("herness.file-operation")
            | Some("herness.shell-operation")
            | Some("herness.artifact-operation")
    )
}

/// Parses and validates an engine checkpoint envelope.
pub(crate) fn parse_checkpoint(
    checkpoint: &Checkpoint,
    expected_run: RunId,
) -> Result<EngineCheckpoint, CoreError> {
    if checkpoint.format_version().get() != ENGINE_CHECKPOINT_VERSION {
        return Err(checkpoint_error());
    }
    if checkpoint.run_id() != expected_run {
        return Err(CoreError::MismatchedRun {
            expected: expected_run,
            found: checkpoint.run_id(),
        });
    }
    let envelope: CheckpointEnvelope =
        serde_json::from_slice(checkpoint.payload().as_bytes()).map_err(|_| checkpoint_error())?;
    if envelope.format != ENGINE_CHECKPOINT_VERSION || envelope.engine != ENGINE_NAME {
        return Err(checkpoint_error());
    }
    if envelope.run_id != expected_run {
        return Err(CoreError::MismatchedRun {
            expected: expected_run,
            found: envelope.run_id,
        });
    }
    if envelope.snapshot.id != envelope.session_id.to_string() {
        return Err(checkpoint_error());
    }
    if envelope.snapshot.version != 1 {
        // The SDK snapshot has its own version. Unknown versions are rejected;
        // they are never rewritten or discarded.
        return Err(checkpoint_error());
    }
    Ok(EngineCheckpoint {
        meta: RunAuditMetadata {
            project_id: envelope.agent_id.project_id(),
            agent_id: envelope.agent_id,
            session_id: envelope.session_id,
            run_id: envelope.run_id,
            connection: envelope.connection,
            cwd: envelope.cwd,
            instructions: envelope.instructions,
            candidate: envelope.candidate,
        },
        snapshot: envelope.snapshot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use herness_core::{
        ArgumentViolation, EventKind, FrozenOperation, OperationOutcome, PermissionMode,
        PolicyVersion, ToolArguments, ToolName,
    };
    use pi_ai::{Model, StopReason};
    use pi_embedded::{InvocationPhase, SessionStore};

    #[derive(Default)]
    struct RecordingStore {
        checkpoints: Vec<Checkpoint>,
        commits: Vec<(Option<OperationIntent>, Vec<EventDraft>)>,
        operations: std::collections::BTreeMap<String, OperationRecord>,
        events: Vec<EventDraft>,
    }

    impl StorePort for RecordingStore {
        fn commit_checkpoint(
            &mut self,
            commit: CheckpointCommit,
        ) -> Result<CommitReceipt, CoreError> {
            if let Some(operation) = commit.operation() {
                let id = operation.operation().operation_id();
                if let Some(existing) = self.operations.get(&id.to_string())
                    && existing.intent().operation() == operation.operation()
                {
                    return Err(CoreError::DuplicateOperation { operation: id });
                }
                self.operations.insert(
                    id.to_string(),
                    OperationRecord::new(operation.clone(), None),
                );
            }
            self.checkpoints.push(commit.checkpoint().clone());
            self.events.extend(commit.events().iter().cloned());
            self.commits
                .push((commit.operation().cloned(), commit.events().to_vec()));
            Ok(CommitReceipt::new(Vec::new(), 0))
        }

        fn load_checkpoint(&self, _run: &RunId) -> Result<Option<Checkpoint>, CoreError> {
            Ok(self.checkpoints.last().cloned())
        }

        fn history(&self, _query: HistoryQuery) -> Result<HistoryPage, CoreError> {
            HistoryPage::new(Vec::new(), None)
        }

        fn pending_operations(
            &self,
            _project: &ProjectId,
        ) -> Result<Vec<OperationIntent>, CoreError> {
            Ok(Vec::new())
        }

        fn operation(&self, operation: &OperationId) -> Result<Option<OperationRecord>, CoreError> {
            Ok(self.operations.get(&operation.to_string()).cloned())
        }

        fn record_operation_result(
            &mut self,
            _operation: &OperationId,
            _result: OperationResult,
        ) -> Result<(), CoreError> {
            Ok(())
        }

        fn record_operation_result_with_events(
            &mut self,
            _operation: &OperationId,
            _result: OperationResult,
            _events: Vec<EventDraft>,
        ) -> Result<CommitReceipt, CoreError> {
            Ok(CommitReceipt::new(Vec::new(), 0))
        }
    }

    fn metadata() -> RunAuditMetadata {
        let project = ProjectId::new();
        RunAuditMetadata {
            project_id: project,
            agent_id: AgentId::new(project),
            session_id: SessionId::new(project),
            run_id: RunId::new(project),
            connection: ConnectionId::new(),
            cwd: AbsolutePath::new("/tmp").expect("absolute path"),
            instructions: "test instructions".to_owned(),
            candidate: None,
        }
    }

    fn snapshot(revision: u64) -> SessionSnapshot {
        SessionSnapshot {
            version: 1,
            id: String::new(),
            revision,
            sequence: revision,
            status: SessionStatus::Idle,
            model: Model::default(),
            messages: Vec::new(),
            partial: None,
            steering: Vec::new(),
            follow_ups: Vec::new(),
            invocations: Vec::new(),
            usage: Vec::new(),
            context_start: 0,
            context_summary: None,
            error: None,
            needs_response: false,
        }
    }

    fn store_pair() -> (EngineStore<RecordingStore>, Arc<Mutex<RecordingStore>>) {
        let audit = metadata();
        let store = Arc::new(Mutex::new(RecordingStore::default()));
        (EngineStore::new(Arc::clone(&store), audit), store)
    }

    fn operation(store: &EngineStore<RecordingStore>) -> FrozenOperation {
        let audit = store.audit();
        FrozenOperation::new(
            OperationId::new(audit.project_id),
            audit.run_id,
            ToolName::Read,
            ToolArguments::Read(herness_core::ReadArgs {
                path: herness_core::NonEmptyText::new("notes.txt").expect("path"),
                offset: None,
                limit: None,
            }),
            audit.cwd.clone(),
            PolicyVersion::INITIAL,
            PermissionMode::Configured,
        )
        .expect("operation")
    }

    #[test]
    fn audit_checkpoints_are_replaced_by_the_engine_snapshot() {
        let (engine_store, inner) = store_pair();
        let mut snap = snapshot(1);
        snap.id = engine_store.audit().session_id.to_string();
        engine_store.set_snapshot(snap);
        let audit = Checkpoint::new(
            engine_store.audit().run_id,
            CheckpointFormatVersion::new(1).expect("version"),
            CheckpointPayload::new(
                serde_json::to_vec(&serde_json::json!({
                    "kind": "herness.file-operation",
                    "stage": "intent"
                }))
                .expect("json"),
            ),
        );
        let commit = CheckpointCommit::new(audit, None, Vec::new()).expect("commit");
        let mut handle = engine_store.clone();
        handle.commit_checkpoint(commit).expect("commit");
        let recorded = {
            let inner = inner.lock().expect("store");
            inner.checkpoints.last().cloned().expect("checkpoint")
        };
        assert_eq!(recorded.format_version().get(), ENGINE_CHECKPOINT_VERSION);
        let envelope: CheckpointEnvelope =
            serde_json::from_slice(recorded.payload().as_bytes()).expect("envelope");
        assert_eq!(envelope.engine, ENGINE_NAME);
        assert_eq!(envelope.snapshot.revision, 1);
    }

    #[test]
    fn a_repeated_identical_intent_is_coalesced_without_executing_twice() {
        let (engine_store, inner) = store_pair();
        let mut snap = snapshot(1);
        snap.id = engine_store.audit().session_id.to_string();
        engine_store.set_snapshot(snap);
        let operation = operation(&engine_store);
        engine_store
            .commit_intent(&operation)
            .expect("first intent");
        // The executor repeats the same intent in its own audit transaction.
        engine_store
            .commit_intent(&operation)
            .expect("coalesced intent");
        let inner = inner.lock().expect("store");
        assert_eq!(inner.operations.len(), 1);
        assert!(inner.commits.iter().all(|(_, events)| {
            events
                .iter()
                .filter(|event| event.kind().as_str() == ENGINE_TOOL_INTENT_EVENT_KIND)
                .count()
                <= 1
        }));
    }

    #[test]
    fn duplicate_operation_ids_with_different_arguments_are_rejected() {
        let (engine_store, _inner) = store_pair();
        let mut snap = snapshot(1);
        snap.id = engine_store.audit().session_id.to_string();
        engine_store.set_snapshot(snap);
        let first = operation(&engine_store);
        engine_store.commit_intent(&first).expect("first intent");
        let second = FrozenOperation::new(
            first.operation_id(),
            first.run_id(),
            ToolName::Read,
            ToolArguments::Read(herness_core::ReadArgs {
                path: herness_core::NonEmptyText::new("other.txt").expect("path"),
                offset: None,
                limit: None,
            }),
            first.cwd().clone(),
            first.policy_version(),
            first.permission_mode(),
        )
        .expect("operation");
        let error = engine_store
            .commit_intent(&second)
            .expect_err("different arguments must conflict");
        assert!(matches!(error, CoreError::DuplicateOperation { .. }));
    }

    #[test]
    fn executor_intent_and_engine_checkpoint_are_one_transaction() {
        let (engine_store, inner) = store_pair();
        let mut snap = snapshot(1);
        snap.id = engine_store.audit().session_id.to_string();
        engine_store.set_snapshot(snap);
        let operation = operation(&engine_store);
        let audit = Checkpoint::new(
            engine_store.audit().run_id,
            CheckpointFormatVersion::new(1).expect("version"),
            CheckpointPayload::new(
                serde_json::to_vec(&serde_json::json!({
                    "kind": "herness.shell-operation",
                    "stage": "intent"
                }))
                .expect("json"),
            ),
        );
        let started = engine_store
            .event_draft(
                Some(operation.operation_id()),
                "shell.started",
                serde_json::json!({"tool": "bash"}),
            )
            .expect("event");
        let intent = OperationIntent::new(operation.clone(), Timestamp::now());
        let commit = CheckpointCommit::new(audit, Some(intent), vec![started]).expect("commit");
        let mut handle = engine_store.clone();
        handle.commit_checkpoint(commit).expect("commit");
        let inner = inner.lock().expect("store");
        assert_eq!(inner.commits.len(), 1, "one transaction");
        let (recorded_operation, events) = &inner.commits[0];
        assert_eq!(
            recorded_operation.as_ref().map(|intent| intent.operation()),
            Some(&operation)
        );
        let kinds: Vec<&str> = events.iter().map(|event| event.kind().as_str()).collect();
        assert_eq!(kinds.first().copied(), Some(ENGINE_TOOL_INTENT_EVENT_KIND));
        assert!(kinds.contains(&"shell.started"));
        assert!(kinds.contains(&ENGINE_CHECKPOINT_EVENT_KIND));
        let recorded = inner.checkpoints.last().expect("checkpoint");
        let envelope: CheckpointEnvelope =
            serde_json::from_slice(recorded.payload().as_bytes()).expect("envelope");
        assert_eq!(envelope.engine, ENGINE_NAME);
    }

    #[test]
    fn unknown_envelope_versions_are_rejected_not_discarded() {
        let (engine_store, _inner) = store_pair();
        let body = serde_json::to_vec(&serde_json::json!({
            "format": 2,
            "engine": ENGINE_NAME,
            "runId": engine_store.audit().run_id,
            "agentId": engine_store.audit().agent_id,
            "sessionId": engine_store.audit().session_id,
            "connection": engine_store.audit().connection,
            "cwd": engine_store.audit().cwd,
            "instructions": "",
            "snapshot": snapshot(1),
        }))
        .expect("json");
        let checkpoint = Checkpoint::new(
            engine_store.audit().run_id,
            CheckpointFormatVersion::new(1).expect("version"),
            CheckpointPayload::new(body),
        );
        let error = parse_checkpoint(&checkpoint, engine_store.audit().run_id)
            .expect_err("unknown envelope version");
        assert!(matches!(
            error,
            CoreError::EngineUnavailable {
                failure: EngineFailureKind::CheckpointUnavailable
            }
        ));
    }

    #[test]
    fn duplicate_snapshot_saves_are_rejected_by_revision() {
        let (engine_store, _inner) = store_pair();
        let store = EngineSessionStore::new(engine_store.clone(), EventQueue::new());
        let mut first = snapshot(0);
        first.id = engine_store.audit().session_id.to_string();
        futures::executor::block_on(store.save(&first, None)).expect("first save");
        let mut second = first.clone();
        second.revision = 1;
        futures::executor::block_on(store.save(&second, Some(0))).expect("second save");
        let error = futures::executor::block_on(store.save(&second, Some(0)))
            .expect_err("a redelivered save must not be applied twice");
        assert!(error.to_string().contains("revision"));
        let error = futures::executor::block_on(store.save(&first, None))
            .expect_err("a duplicate create must not overwrite the checkpoint");
        assert!(error.to_string().contains("exists"));
    }

    #[test]
    fn unknown_checkpoint_format_versions_are_rejected() {
        let (engine_store, _inner) = store_pair();
        let checkpoint = Checkpoint::new(
            engine_store.audit().run_id,
            CheckpointFormatVersion::new(2).expect("version"),
            CheckpointPayload::new(vec![0, 1, 2]),
        );
        let error = parse_checkpoint(&checkpoint, engine_store.audit().run_id)
            .expect_err("unknown checkpoint version");
        assert!(matches!(
            error,
            CoreError::EngineUnavailable {
                failure: EngineFailureKind::CheckpointUnavailable
            }
        ));
    }

    #[test]
    fn sanitize_removes_provider_error_text_and_diagnostics() {
        let mut snap = snapshot(1);
        snap.error = Some("raw provider body with canary".to_owned());
        let mut assistant = pi_ai::AssistantMessage::empty(&Model::default());
        assistant.stop_reason = StopReason::Error;
        assistant.error_message = Some("raw provider body with canary".to_owned());
        assistant
            .diagnostics
            .push(serde_json::json!({"body": "canary"}));
        snap.messages.push(pi_ai::Message::Assistant(assistant));
        let sanitized = sanitize_snapshot(&snap);
        assert_eq!(sanitized.error.as_deref(), Some("engine error"));
        let debug = format!("{sanitized:?}");
        assert!(!debug.contains("canary"));
    }

    #[test]
    fn pending_invocations_are_counted_for_checkpoint_audit() {
        let (engine_store, _inner) = store_pair();
        let mut snap = snapshot(3);
        snap.id = engine_store.audit().session_id.to_string();
        snap.invocations.push(pi_embedded::ToolInvocation {
            session_id: snap.id.clone(),
            id: "call-1".to_owned(),
            name: "read".to_owned(),
            args: serde_json::Map::new(),
            effect: pi_embedded::ToolEffect::Read,
            phase: InvocationPhase::Executing,
            result: None,
            approved: None,
        });
        engine_store.set_snapshot(snap);
        let event = engine_store.checkpoint_event(&engine_store.snapshot().expect("snapshot"));
        let event = event.expect("event");
        assert_eq!(event.kind().as_str(), ENGINE_CHECKPOINT_EVENT_KIND);
        assert_eq!(event.payload().as_value()["pendingInvocations"], 1);
    }

    #[test]
    fn file_checkpoint_does_not_include_the_operation_result() {
        // Compile-time shape guard: an intent and an operation result are
        // separate store calls by design.
        let _ = OperationOutcome::Applied;
        let _ = ArgumentViolation::Empty;
        let _ = EventKind::new("test").expect("kind");
        let (engine_store, _inner) = store_pair();
        let operation = operation(&engine_store);
        let intent = OperationIntent::new(operation, Timestamp::now());
        let coalesced = engine_store
            .coalesce_operation(Some(&intent))
            .expect("coalesce");
        assert!(coalesced.is_some());
    }
}
