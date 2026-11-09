//! Native file tools: `read`, `search`, `write`, and `edit`.
//!
//! The executor is the [`ToolExecutor`] behind the permission gateway. For
//! `write` and `edit` it follows this fixed order:
//!
//! 1. resolve the target and capture the before version;
//! 2. serialize writers to the same canonical file path;
//! 3. persist a checkpoint, the [`OperationIntent`], and a
//!    `file.change.intended` event in one store transaction;
//! 4. re-check the path and version immediately before writing;
//! 5. write atomically with a temporary file and `rename` in the same
//!    directory, preserving permissions when overwriting;
//! 6. hash the observed result and persist `Applied` plus a `file.change`
//!    notification event in one store transaction;
//! 7. only then return success.
//!
//! A pre-write persistence failure means no file is touched. A post-write
//! persistence failure is reported as [`FileFailure::Unverifiable`]; the host
//! does not roll back or retry, and reconciliation can see the intent without a
//! result.
//!
//! The checkpoint payload written by this module is a host audit record for a
//! file operation, not an engine conversation snapshot. Task 9 replaces it with
//! engine-owned checkpoints while keeping the intent commit in the same
//! transaction.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};

use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::contracts::errors::{ArgumentViolation, CoreError, FileFailure};
use crate::contracts::events::{Event, EventDraft, EventKind, EventPayload};
use crate::contracts::ids::{AgentId, IdKind, OperationId, SessionId};
use crate::contracts::operation::{
    FileObservation, FrozenOperation, OperationEvidence, OperationIntent, OperationOutcome,
    OperationResult,
};
use crate::contracts::path::AbsolutePath;
use crate::contracts::time::Timestamp;
use crate::contracts::{Checkpoint, CheckpointFormatVersion, CheckpointPayload};
use crate::ports::{CheckpointCommit, StorePort};
use crate::tools::arguments::{EditArgs, WriteArgs};
use crate::tools::diff::FileDiff;
use crate::tools::gateway::ToolExecutor;
use crate::tools::path::{ProjectRoot, ResolvedPath};
use crate::tools::{FileVersion, ToolArguments, ToolName};

use crate::tools::{edit, read, search, write};

/// Persisted notification kind for an applied file change.
pub const FILE_CHANGE_EVENT_KIND: &str = "file.change";
/// Persisted event kind for the intended change written before the side effect.
pub const FILE_CHANGE_INTENDED_EVENT_KIND: &str = "file.change.intended";

const AUDIT_CHECKPOINT_FORMAT: u32 = 1;
const AUDIT_CHECKPOINT_KIND: &str = "herness.file-operation";

/// Output of one native file operation.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "tool", content = "result", rename_all = "snake_case")]
pub enum FileToolOutput {
    /// A completed read.
    Read(read::ReadOutput),
    /// A completed search.
    Search(search::SearchOutput),
    /// An applied write or edit, with its persisted notification.
    Change(Box<FileChange>),
}

/// A durably recorded file change returned to the caller.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileChange {
    operation_id: OperationId,
    tool: ToolName,
    path: AbsolutePath,
    created: bool,
    before_version: Option<FileVersion>,
    after_version: FileVersion,
    diff: FileDiff,
    notification: Event,
}

impl FileChange {
    /// Operation that produced the change.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Tool that produced the change.
    pub const fn tool(&self) -> ToolName {
        self.tool
    }

    /// Absolute path that changed.
    pub const fn path(&self) -> &AbsolutePath {
        &self.path
    }

    /// Whether the change created a new file.
    pub const fn created(&self) -> bool {
        self.created
    }

    /// Version observed before the change (`None` for creation).
    pub const fn before_version(&self) -> Option<&FileVersion> {
        self.before_version.as_ref()
    }

    /// Version observed after the change.
    pub const fn after_version(&self) -> &FileVersion {
        &self.after_version
    }

    /// Persisted diff.
    pub const fn diff(&self) -> &FileDiff {
        &self.diff
    }

    /// The persisted `file.change` event, already committed with its sequence.
    /// Redelivering this event is never an instruction to re-apply the change.
    pub const fn notification(&self) -> &Event {
        &self.notification
    }
}

/// In-process writer serialization keyed by canonical file path.
#[derive(Debug, Default)]
pub struct FileLockRegistry {
    locked: Mutex<BTreeSet<PathBuf>>,
    available: Condvar,
}

impl FileLockRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn acquire(&self, path: PathBuf) -> FileLockGuard<'_> {
        let mut locked = self
            .locked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while locked.contains(&path) {
            locked = self
                .available
                .wait(locked)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        locked.insert(path.clone());
        FileLockGuard {
            registry: self,
            path,
        }
    }
}

/// RAII guard for one serialized file path.
#[derive(Debug)]
pub struct FileLockGuard<'a> {
    registry: &'a FileLockRegistry,
    path: PathBuf,
}

impl Drop for FileLockGuard<'_> {
    fn drop(&mut self) {
        let mut locked = self
            .registry
            .locked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locked.remove(&self.path);
        self.registry.available.notify_all();
    }
}

/// Native file tools for one agent session and store connection.
#[derive(Debug)]
pub struct NativeFileTools<S> {
    root: ProjectRoot,
    agent_id: AgentId,
    session_id: SessionId,
    store: S,
    locks: Arc<FileLockRegistry>,
}

impl<S> NativeFileTools<S> {
    /// Creates an executor with its own in-process lock registry.
    pub fn new(
        root: ProjectRoot,
        agent_id: AgentId,
        session_id: SessionId,
        store: S,
    ) -> Result<Self, CoreError> {
        Self::with_lock_registry(
            root,
            agent_id,
            session_id,
            store,
            Arc::new(FileLockRegistry::new()),
        )
    }

    /// Creates an executor sharing a lock registry with other executors.
    ///
    /// Sharing the registry is what makes concurrent editors in one host
    /// process agree on the same per-file lock.
    pub fn with_lock_registry(
        root: ProjectRoot,
        agent_id: AgentId,
        session_id: SessionId,
        store: S,
        locks: Arc<FileLockRegistry>,
    ) -> Result<Self, CoreError> {
        if agent_id.project_id() != session_id.project_id() {
            return Err(CoreError::CrossProjectReference {
                id_kind: IdKind::Project,
                expected: agent_id.project_id(),
                found: session_id.project_id(),
            });
        }
        Ok(Self {
            root,
            agent_id,
            session_id,
            store,
            locks,
        })
    }

    /// Project root used for path validation.
    pub const fn project_root(&self) -> &ProjectRoot {
        &self.root
    }

    /// Store connection used for intent, result, and notification persistence.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Mutable store connection, used by tests for fault injection.
    pub const fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }
}

impl<S: StorePort> NativeFileTools<S> {
    fn apply_write(
        &mut self,
        operation: &FrozenOperation,
        args: &WriteArgs,
    ) -> Result<FileChange, CoreError> {
        let tool = ToolName::Write;
        let initial = write::plan(&self.root, operation.cwd(), args)
            .map_err(|failure| tool_error(tool, failure))?;
        let registry = Arc::clone(&self.locks);
        let _guard = registry.acquire(initial.path().lock_key());

        // Re-plan under the lock so the before version and diff are captured
        // after any earlier in-process writer finished.
        let plan = write::plan(&self.root, operation.cwd(), args)
            .map_err(|failure| tool_error(tool, failure))?;
        let absolute = plan
            .path()
            .absolute_value()
            .map_err(|failure| tool_error(tool, failure))?;

        self.persist_intent(
            operation,
            tool,
            &absolute,
            true,
            None,
            plan.version(),
            plan.diff(),
            args.rationale.as_str(),
        )?;

        if let Err(failure) = self
            .root
            .creatable_file(operation.cwd(), args.path.as_str())
        {
            self.record_not_applied(operation, plan.path(), None);
            return Err(tool_error(tool, failure));
        }

        if let Err(error) = atomic_write(plan.path().absolute(), plan.content().as_bytes(), false) {
            self.record_not_applied(operation, plan.path(), None);
            return Err(tool_error(
                tool,
                FileFailure::Io {
                    path: plan.path().relative_display(),
                    error_kind: format!("{:?}", error.kind()),
                },
            ));
        }

        let observed = match hash_file(plan.path().absolute()) {
            Ok(observed) => observed,
            Err(failure) => {
                self.record_unverifiable(operation, &absolute, None, None);
                return Err(tool_error(tool, failure));
            }
        };
        if observed != *plan.version() {
            self.record_unverifiable(operation, &absolute, None, Some(&observed));
            return Err(tool_error(
                tool,
                FileFailure::Unverifiable {
                    detail: "observed content hash differs from the planned hash".to_owned(),
                },
            ));
        }

        self.persist_applied(
            operation,
            tool,
            &absolute,
            true,
            None,
            &observed,
            plan.diff(),
            args.rationale.as_str(),
        )
    }

    fn apply_edit(
        &mut self,
        operation: &FrozenOperation,
        args: &EditArgs,
    ) -> Result<FileChange, CoreError> {
        let tool = ToolName::Edit;
        let initial = edit::plan(&self.root, operation.cwd(), args)
            .map_err(|failure| tool_error(tool, failure))?;
        let registry = Arc::clone(&self.locks);
        let _guard = registry.acquire(initial.path().lock_key());

        let plan = edit::plan(&self.root, operation.cwd(), args)
            .map_err(|failure| tool_error(tool, failure))?;
        let absolute = plan
            .path()
            .absolute_value()
            .map_err(|failure| tool_error(tool, failure))?;

        self.persist_intent(
            operation,
            tool,
            &absolute,
            false,
            Some(plan.before_version()),
            plan.after_version(),
            plan.diff(),
            args.rationale.as_str(),
        )?;

        // Re-read the current version immediately before writing. The
        // in-process lock makes this deterministic for host writers; an
        // external process can still race between this check and `rename`, and
        // this module does not claim OS-level isolation.
        let recheck = self.recheck_edit(operation.cwd(), args.path.as_str());
        let current = match recheck {
            Ok(current) => current,
            Err(failure) => {
                self.record_not_applied(operation, plan.path(), None);
                return Err(tool_error(tool, failure));
            }
        };
        if current != *plan.before_version() {
            self.record_not_applied(operation, plan.path(), Some(current.clone()));
            return Err(tool_error(
                tool,
                FileFailure::VersionConflict {
                    path: plan.path().relative_display(),
                    expected: plan.before_version().clone(),
                    actual: current,
                },
            ));
        }

        if let Err(error) = atomic_write(
            plan.path().absolute(),
            plan.after_content().as_bytes(),
            true,
        ) {
            self.record_not_applied(operation, plan.path(), Some(plan.before_version().clone()));
            return Err(tool_error(
                tool,
                FileFailure::Io {
                    path: plan.path().relative_display(),
                    error_kind: format!("{:?}", error.kind()),
                },
            ));
        }

        let observed = match hash_file(plan.path().absolute()) {
            Ok(observed) => observed,
            Err(failure) => {
                self.record_unverifiable(
                    operation,
                    &absolute,
                    Some(plan.before_version().clone()),
                    None,
                );
                return Err(tool_error(tool, failure));
            }
        };
        if observed != *plan.after_version() {
            self.record_unverifiable(
                operation,
                &absolute,
                Some(plan.before_version().clone()),
                Some(&observed),
            );
            return Err(tool_error(
                tool,
                FileFailure::Unverifiable {
                    detail: "observed content hash differs from the planned hash".to_owned(),
                },
            ));
        }

        self.persist_applied(
            operation,
            tool,
            &absolute,
            false,
            Some(plan.before_version().clone()),
            &observed,
            plan.diff(),
            args.rationale.as_str(),
        )
    }

    fn recheck_edit(&self, cwd: &AbsolutePath, raw: &str) -> Result<FileVersion, FileFailure> {
        let resolved = self.root.existing_file(cwd, raw)?;
        let bytes = fs::read(resolved.absolute()).map_err(|error| FileFailure::Io {
            path: resolved.relative_display(),
            error_kind: format!("{:?}", error.kind()),
        })?;
        Ok(hash_bytes(&bytes))
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_intent(
        &mut self,
        operation: &FrozenOperation,
        tool: ToolName,
        absolute: &AbsolutePath,
        created: bool,
        before: Option<&FileVersion>,
        planned_after: &FileVersion,
        diff: &FileDiff,
        rationale: &str,
    ) -> Result<(), CoreError> {
        let event = change_event(
            operation,
            self.agent_id,
            self.session_id,
            tool,
            FILE_CHANGE_INTENDED_EVENT_KIND,
            absolute,
            created,
            before,
            planned_after,
            diff,
            rationale,
        )?;
        let checkpoint = audit_checkpoint(
            operation,
            tool,
            "intent",
            absolute,
            before,
            Some(planned_after),
            None,
        )?;
        let intent = OperationIntent::new(operation.clone(), Timestamp::now());
        let commit = CheckpointCommit::new(checkpoint, Some(intent), vec![event])?;
        match self.store.commit_checkpoint(commit) {
            Ok(_) => Ok(()),
            Err(error @ CoreError::DuplicateOperation { .. }) => Err(error),
            Err(error) => Err(tool_error(
                tool,
                FileFailure::NotExecutable {
                    detail: error.to_string(),
                },
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_applied(
        &mut self,
        operation: &FrozenOperation,
        tool: ToolName,
        absolute: &AbsolutePath,
        created: bool,
        before: Option<FileVersion>,
        observed: &FileVersion,
        diff: &FileDiff,
        rationale: &str,
    ) -> Result<FileChange, CoreError> {
        let event = change_event(
            operation,
            self.agent_id,
            self.session_id,
            tool,
            FILE_CHANGE_EVENT_KIND,
            absolute,
            created,
            before.as_ref(),
            observed,
            diff,
            rationale,
        )?;
        let result = OperationResult::new(
            OperationOutcome::Applied,
            OperationEvidence::new(
                vec![FileObservation::new(
                    absolute.clone(),
                    before.clone(),
                    Some(observed.clone()),
                )],
                false,
            ),
            Timestamp::now(),
        );
        let receipt = self
            .store
            .record_operation_result_with_events(&operation.operation_id(), result, vec![event])
            .map_err(|error| {
                tool_error(
                    tool,
                    FileFailure::Unverifiable {
                        detail: error.to_string(),
                    },
                )
            })?;
        let notification = receipt.events().first().cloned().ok_or_else(|| {
            tool_error(
                tool,
                FileFailure::Unverifiable {
                    detail: "store committed no notification event".to_owned(),
                },
            )
        })?;
        Ok(FileChange {
            operation_id: operation.operation_id(),
            tool,
            path: absolute.clone(),
            created,
            before_version: before,
            after_version: observed.clone(),
            diff: diff.clone(),
            notification,
        })
    }

    fn record_not_applied(
        &mut self,
        operation: &FrozenOperation,
        path: &ResolvedPath,
        observed: Option<FileVersion>,
    ) {
        let Ok(absolute) = path.absolute_value() else {
            return;
        };
        let result = OperationResult::new(
            OperationOutcome::NotApplied,
            OperationEvidence::new(
                vec![FileObservation::new(absolute, observed.clone(), observed)],
                false,
            ),
            Timestamp::now(),
        );
        // If even this record fails, the pending intent remains visible to
        // reconciliation. The caller still receives the original conflict.
        let _ = self
            .store
            .record_operation_result(&operation.operation_id(), result);
    }

    fn record_unverifiable(
        &mut self,
        operation: &FrozenOperation,
        absolute: &AbsolutePath,
        before: Option<FileVersion>,
        observed: Option<&FileVersion>,
    ) {
        let result = OperationResult::new(
            OperationOutcome::Unverifiable,
            OperationEvidence::new(
                vec![FileObservation::new(
                    absolute.clone(),
                    before,
                    observed.cloned(),
                )],
                false,
            ),
            Timestamp::now(),
        );
        let _ = self
            .store
            .record_operation_result(&operation.operation_id(), result);
    }
}

impl<S: StorePort> ToolExecutor for NativeFileTools<S> {
    type Output = FileToolOutput;

    fn execute(&mut self, operation: &FrozenOperation) -> Result<Self::Output, CoreError> {
        operation.arguments().validate()?;
        let tool = operation.tool();
        if matches!(tool, ToolName::Write | ToolName::Edit)
            && self.store.operation(&operation.operation_id())?.is_some()
        {
            // The store's unique constraint is still authoritative; this guard
            // makes a replay fail with `DuplicateOperation` even when the file
            // state would otherwise fail a different pre-check first.
            return Err(CoreError::DuplicateOperation {
                operation: operation.operation_id(),
            });
        }
        match operation.arguments() {
            ToolArguments::Read(args) => read::read(&self.root, operation.cwd(), args)
                .map(FileToolOutput::Read)
                .map_err(|failure| tool_error(tool, failure)),
            ToolArguments::Search(args) => search::search(&self.root, operation.cwd(), args)
                .map(FileToolOutput::Search)
                .map_err(|failure| tool_error(tool, failure)),
            ToolArguments::Write(args) => self
                .apply_write(operation, args)
                .map(|change| FileToolOutput::Change(Box::new(change))),
            ToolArguments::Edit(args) => self
                .apply_edit(operation, args)
                .map(|change| FileToolOutput::Change(Box::new(change))),
            ToolArguments::Bash(_) => Err(tool_error(tool, FileFailure::Unsupported { tool })),
            ToolArguments::CandidateRead(_)
            | ToolArguments::CandidateWrite(_)
            | ToolArguments::CandidateEdit(_) => {
                Err(tool_error(tool, FileFailure::Unsupported { tool }))
            }
        }
    }
}

/// Computes the content version used by native file tools.
pub fn hash_bytes(bytes: &[u8]) -> FileVersion {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    FileVersion::new(hex).expect("SHA-256 hex is non-empty")
}

fn hash_file(path: &Path) -> Result<FileVersion, FileFailure> {
    let bytes = fs::read(path).map_err(|error| FileFailure::Io {
        path: path.to_string_lossy().into_owned(),
        error_kind: format!("{:?}", error.kind()),
    })?;
    Ok(hash_bytes(&bytes))
}

/// Writes bytes to a temporary file in the target directory and renames it.
pub(crate) fn atomic_write(
    path: &Path,
    content: &[u8],
    preserve_permissions: bool,
) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "target path has no parent directory",
        )
    })?;
    let temp = parent.join(format!(".herness-tmp-{}", Uuid::new_v4().simple()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options.open(&temp)?;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        if preserve_permissions && let Ok(metadata) = fs::metadata(path) {
            fs::set_permissions(&temp, metadata.permissions())?;
        }
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileChangePayload<'a> {
    path: &'a AbsolutePath,
    operation_id: OperationId,
    tool: ToolName,
    created: bool,
    before_version: Option<&'a FileVersion>,
    after_version: &'a FileVersion,
    diff: &'a str,
    diff_truncated: bool,
    rationale: &'a str,
}

#[allow(clippy::too_many_arguments)]
fn change_event(
    operation: &FrozenOperation,
    agent_id: AgentId,
    session_id: SessionId,
    tool: ToolName,
    kind: &str,
    path: &AbsolutePath,
    created: bool,
    before: Option<&FileVersion>,
    after: &FileVersion,
    diff: &FileDiff,
    rationale: &str,
) -> Result<EventDraft, CoreError> {
    let payload = FileChangePayload {
        path,
        operation_id: operation.operation_id(),
        tool,
        created,
        before_version: before,
        after_version: after,
        diff: diff.text(),
        diff_truncated: diff.is_truncated(),
        rationale,
    };
    let value = serde_json::to_value(&payload).map_err(|error| CoreError::InvalidValue {
        field: "fileChangePayload".to_owned(),
        violation: ArgumentViolation::Invalid {
            detail: error.to_string(),
        },
    })?;
    EventDraft::new(
        operation.project_id(),
        agent_id,
        session_id,
        operation.run_id(),
        Some(operation.operation_id()),
        EventKind::new(kind)?,
        Timestamp::now(),
        EventPayload::new(value),
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditCheckpointPayload<'a> {
    kind: &'static str,
    stage: &'static str,
    operation_id: OperationId,
    tool: ToolName,
    path: &'a AbsolutePath,
    before_version: Option<&'a FileVersion>,
    after_version: Option<&'a FileVersion>,
    outcome: Option<&'static str>,
}

fn audit_checkpoint(
    operation: &FrozenOperation,
    tool: ToolName,
    stage: &'static str,
    path: &AbsolutePath,
    before: Option<&FileVersion>,
    after: Option<&FileVersion>,
    outcome: Option<&'static str>,
) -> Result<Checkpoint, CoreError> {
    let payload = AuditCheckpointPayload {
        kind: AUDIT_CHECKPOINT_KIND,
        stage,
        operation_id: operation.operation_id(),
        tool,
        path,
        before_version: before,
        after_version: after,
        outcome,
    };
    let bytes = serde_json::to_vec(&payload).map_err(|error| CoreError::InvalidValue {
        field: "fileCheckpoint".to_owned(),
        violation: ArgumentViolation::Invalid {
            detail: error.to_string(),
        },
    })?;
    Ok(Checkpoint::new(
        operation.run_id(),
        CheckpointFormatVersion::new(AUDIT_CHECKPOINT_FORMAT)
            .expect("audit checkpoint format 1 is non-zero"),
        CheckpointPayload::new(bytes),
    ))
}

fn tool_error(tool: ToolName, failure: FileFailure) -> CoreError {
    CoreError::FileToolFailed { tool, failure }
}
