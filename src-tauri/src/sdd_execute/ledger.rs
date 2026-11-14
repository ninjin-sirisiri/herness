//! The desktop progress-ledger writer: atomic, digit-verified, and gated.
//!
//! This module is the only desktop implementation of H4's
//! [`herness_sdd_execute::ProgressLedgerPort`]. It writes the compatibility
//! `.sdd/progress.md` under the approved checkout and nothing else.
//!
//! # Atomic write
//!
//! Every write is: create a uniquely named temporary file **in the same
//! directory**, write the exact bytes, `sync_all`, then `rename` it over the
//! destination. A rename inside one directory is atomic on the host filesystems,
//! so a reader never sees a half-written ledger. The temporary file is removed
//! on every failure path.
//!
//! # What a failure means
//!
//! The port maps each failure onto H4's
//! [`ProgressWriteOutcome`](herness_sdd_execute::ProgressWriteOutcome):
//!
//! * the temporary file could not be created or written →
//!   `Failed { TemporaryFileFailed }`;
//! * the destination changed after the host read it, or the rename failed →
//!   `Failed { ReplaceFailed }` (or `ExternalModification` for the former);
//! * an observed result that cannot be confirmed → `Unknown`, which waits for a
//!   human instead of being retried.
//!
//! In every one of those cases
//! [`herness_sdd_execute::write_progress`] returns a human wait, and
//! [`hold_after_progress`] persists it, so the next Task never starts.
//!
//! # Confinement
//!
//! The output path is project-relative. It is resolved under the canonical
//! checkout and must not escape it: a `..` component, an absolute path, a
//! symlink leaving the root, or a directory destination is refused before any
//! file is created.
//!
//! # The Task brief and report
//!
//! [`write_task_brief`] writes the same atomic way, from the approved plan body,
//! to the pack's `.sdd/briefs/task-N-brief.md`. The report file is the child's
//! own output; the host only reads it, so there is no report writer here.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use herness_sdd_execute::{
    ExecutionRevision, ExecutionSnapshot, ExecutionStorePort, FailureDetails, ProgressJournalEntry,
    ProgressLedgerOutcome, ProgressLedgerPort, ProgressWriteOutcome, SddExecutionError, StopRecord,
    write_progress,
};

/// `unavailable` feature prefix used for a failed progress write.
pub const PROGRESS_LEDGER_FEATURE: &str = "sdd_execute.progressLedger";

/// Writes the compatibility `.sdd/progress.md` inside one approved checkout.
#[derive(Debug, Clone)]
pub struct DesktopProgressLedger {
    root: PathBuf,
}

impl DesktopProgressLedger {
    /// Binds the writer to one canonical checkout root.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, SddExecutionError> {
        let root = root.into();
        let canonical = fs::canonicalize(&root).map_err(|error| {
            unavailable(&format!(
                "the approved checkout {} cannot be resolved: {}",
                root.display(),
                error.kind()
            ))
        })?;
        if !canonical.is_dir() {
            return Err(unavailable(&format!(
                "the approved checkout {} is not a directory",
                root.display()
            )));
        }
        Ok(Self { root: canonical })
    }

    /// The canonical checkout root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Reads the document, returning `None` when it does not exist.
    ///
    /// A destination that is not a regular file (a directory, a symlink) reads
    /// as absent: it is not a project ledger the host can reproduce. The write
    /// path re-probes it and reports `ReplaceFailed`, so nothing is ever
    /// truncated, followed, or replaced.
    pub fn read_document(&self, output_path: &str) -> Result<Option<Vec<u8>>, SddExecutionError> {
        let destination = self.destination(output_path)?;
        match fs::symlink_metadata(&destination) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Ok(None);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(unavailable(&format!(
                    "{output_path} cannot be inspected: {}",
                    error.kind()
                )));
            }
        }
        match fs::read(&destination) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(unavailable(&format!(
                "{output_path} cannot be read: {}",
                error.kind()
            ))),
        }
    }

    /// Writes `bytes` through a temporary file and one atomic rename.
    ///
    /// `expected` is the digest of the document the host read before planning
    /// the write. When the destination no longer carries it, the write is
    /// `ExternalModification` and nothing is replaced. A destination that is not
    /// a regular file is a `ReplaceFailed`: the host never replaces something it
    /// cannot identify as the ledger.
    pub fn write_document(
        &self,
        output_path: &str,
        bytes: &[u8],
        expected: Option<&herness_sdd_execute::Sha256Digest>,
    ) -> Result<ProgressWriteOutcome, SddExecutionError> {
        let destination = self.destination(output_path)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                unavailable(&format!(
                    "the {} directory cannot be created: {}",
                    parent.display(),
                    error.kind()
                ))
            })?;
        }
        // Re-read right before the write: an external edit between planning and
        // writing is a human wait, not a silent overwrite.
        let current = match probe_destination(&destination) {
            Ok(Probe::Absent) => None,
            Ok(Probe::Regular(bytes)) => Some(bytes),
            Ok(Probe::NotRegular) => {
                return Ok(ProgressWriteOutcome::Failed {
                    reason: herness_sdd_execute::ProgressFailure::ReplaceFailed,
                });
            }
            Err(error) => {
                return Err(unavailable(&format!(
                    "{output_path} cannot be inspected: {}",
                    error.kind()
                )));
            }
        };
        match (expected, &current) {
            (Some(expected), Some(bytes)) => {
                if &herness_sdd_execute::Sha256Digest::sha256(bytes) != expected {
                    return Ok(ProgressWriteOutcome::Failed {
                        reason: herness_sdd_execute::ProgressFailure::ExternalModification,
                    });
                }
            }
            (Some(_), None) => {
                return Ok(ProgressWriteOutcome::Failed {
                    reason: herness_sdd_execute::ProgressFailure::ExternalModification,
                });
            }
            (None, Some(_)) => {
                // The document appeared after the host read "absent". It is not
                // this write's to replace.
                return Ok(ProgressWriteOutcome::Failed {
                    reason: herness_sdd_execute::ProgressFailure::ExternalModification,
                });
            }
            (None, None) => {}
        }

        let temporary = self.temporary_path(&destination)?;
        let written = (|| -> std::io::Result<()> {
            let mut file = open_new(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
            // A directory or permission problem is a failed write, never a
            // success with a missing document.
            return Ok(ProgressWriteOutcome::Failed {
                reason: herness_sdd_execute::ProgressFailure::TemporaryFileFailed,
            });
        }
        if fs::rename(&temporary, &destination).is_err() {
            let _ = fs::remove_file(&temporary);
            return Ok(ProgressWriteOutcome::Failed {
                reason: herness_sdd_execute::ProgressFailure::ReplaceFailed,
            });
        }
        // Read back: the recorded digest must be the digest actually on disk.
        match fs::read(&destination) {
            Ok(observed) if observed == bytes => Ok(ProgressWriteOutcome::Written {
                digest: herness_sdd_execute::Sha256Digest::sha256(&observed),
            }),
            _ => Ok(ProgressWriteOutcome::Unknown),
        }
    }

    /// Resolves and confines one project-relative destination.
    pub fn destination(&self, output_path: &str) -> Result<PathBuf, SddExecutionError> {
        herness_sdd_execute::validate_project_path("progress.outputPath", output_path)?;
        let joined = self.root.join(output_path);
        // The path must not escape the root. `validate_project_path` already
        // refuses `..`, but a pre-existing symlinked directory could still move
        // it, so the existing prefix is canonicalized and re-checked.
        if let Some(parent) = joined.parent() {
            let mut probe = parent.to_path_buf();
            while !probe.exists() {
                match probe.parent() {
                    Some(next) => probe = next.to_path_buf(),
                    None => break,
                }
            }
            if let Ok(resolved) = fs::canonicalize(&probe)
                && !resolved.starts_with(&self.root)
            {
                return Err(unavailable(&format!(
                    "{output_path} resolves outside the approved checkout"
                )));
            }
        }
        Ok(joined)
    }

    fn temporary_path(&self, destination: &Path) -> Result<PathBuf, SddExecutionError> {
        let parent = destination.parent().ok_or_else(|| {
            unavailable("the progress ledger destination has no parent directory")
        })?;
        let name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| unavailable("the progress ledger destination has no file name"))?;
        let local = uuid::Uuid::new_v4();
        Ok(parent.join(format!(".{name}.{local}.tmp")))
    }
}

impl ProgressLedgerPort for DesktopProgressLedger {
    fn read(&mut self, output_path: &str) -> Result<Option<Vec<u8>>, SddExecutionError> {
        self.read_document(output_path)
    }

    fn write(
        &mut self,
        entry: &ProgressJournalEntry,
        expected: Option<&herness_sdd_execute::Sha256Digest>,
    ) -> Result<ProgressWriteOutcome, SddExecutionError> {
        // Re-render from durable state, so the bytes written are exactly the
        // bytes whose digest the journal recorded with the intent.
        let content = entry.content();
        let rendered = herness_sdd_execute::render_content(content)?;
        self.write_document(content.output_path(), rendered.text().as_bytes(), expected)
    }
}

/// Writes the compatibility ledger and holds the next Task on any failure.
///
/// The returned revision is the one the caller persists. A write failure, a
/// conflict with an externally modified document, or an unconfirmed result
/// records `waiting_human` with the reason and leaves every Task, range, and
/// baseline untouched; on success the revision is unchanged and the caller may
/// start the next Task.
pub fn write_and_hold(
    store: &mut dyn ExecutionStorePort,
    ledger: &mut DesktopProgressLedger,
    request: &herness_sdd_execute::ProgressWriteRequest,
    snapshot: &ExecutionSnapshot,
) -> Result<ProgressWriteResult, SddExecutionError> {
    let outcome = write_progress(store, ledger, request)?;
    match outcome {
        ProgressLedgerOutcome::Written { digest } => Ok(ProgressWriteResult {
            outcome: ProgressLedgerOutcome::Written { digest },
            revision: snapshot.revision(),
            held: false,
            stop: None,
            detail: None,
        }),
        ProgressLedgerOutcome::Unchanged { digest } => Ok(ProgressWriteResult {
            outcome: ProgressLedgerOutcome::Unchanged { digest },
            revision: snapshot.revision(),
            held: false,
            stop: None,
            detail: None,
        }),
        ProgressLedgerOutcome::HumanWait { reason, stop } => {
            let detail = reason.detail();
            let revision = hold_after_progress(store, snapshot, stop)?;
            Ok(ProgressWriteResult {
                outcome: ProgressLedgerOutcome::HumanWait { reason, stop },
                revision,
                held: true,
                stop: Some(stop),
                detail: Some(detail),
            })
        }
    }
}

/// Persists one `waiting_human` hold for a failed progress write.
///
/// The snapshot keeps every Task, range, and baseline; only the execution state
/// and the stop record change. The revision advances by exactly one with a
/// compare-and-swap.
pub fn hold_after_progress(
    store: &mut dyn ExecutionStorePort,
    snapshot: &ExecutionSnapshot,
    stop: StopRecord,
) -> Result<ExecutionRevision, SddExecutionError> {
    herness_sdd_execute::hold_next_task(store, snapshot, stop)
}

/// Writes one Task's compatibility brief file from the approved plan body.
///
/// The brief is the exact Task text `sdd-execute` would have produced with
/// `scripts/task-brief`, written atomically and only inside the approved
/// checkout. It never overwrites a brief the durable state does not expect: a
/// differing existing brief is an `unavailable` hold, not a silent replacement.
pub fn write_task_brief(
    ledger: &DesktopProgressLedger,
    brief_path: &str,
    body: &str,
) -> Result<(), SddExecutionError> {
    let destination = ledger.destination(brief_path)?;
    // A brief that already carries these bytes is left alone, so a retry is not
    // a "document changed" failure.
    match ledger.read_document(brief_path)? {
        Some(existing) if existing == body.as_bytes() => return Ok(()),
        Some(_) => {
            return Err(unavailable(&format!(
                "{brief_path} already carries a different brief; the host does not overwrite it"
            )));
        }
        None => {}
    }
    match ledger.write_document(brief_path, body.as_bytes(), None) {
        Ok(ProgressWriteOutcome::Written { .. }) => Ok(()),
        Ok(ProgressWriteOutcome::Failed { reason }) => Err(unavailable(&format!(
            "{brief_path} could not be written: {}",
            reason_label(reason)
        ))),
        Ok(ProgressWriteOutcome::Unknown) => Err(unavailable(&format!(
            "{brief_path} write result is unknown; reconcile the file before the next Task"
        ))),
        Err(error) => Err(error),
    }
    .and_then(|()| {
        if destination.is_file() {
            Ok(())
        } else {
            Err(unavailable(&format!(
                "{brief_path} is absent after its write"
            )))
        }
    })
}

const fn reason_label(reason: herness_sdd_execute::ProgressFailure) -> &'static str {
    match reason {
        herness_sdd_execute::ProgressFailure::TemporaryFileFailed => "temporary file failed",
        herness_sdd_execute::ProgressFailure::ReplaceFailed => "replacement failed",
        herness_sdd_execute::ProgressFailure::ExternalModification => {
            "the document changed while it was written"
        }
        herness_sdd_execute::ProgressFailure::StaleState => "durable state no longer matches",
    }
}

/// The result of one gated progress write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressWriteResult {
    outcome: ProgressLedgerOutcome,
    revision: ExecutionRevision,
    held: bool,
    stop: Option<StopRecord>,
    detail: Option<String>,
}

impl ProgressWriteResult {
    /// The ledger outcome.
    pub fn outcome(&self) -> &ProgressLedgerOutcome {
        &self.outcome
    }

    /// The revision the caller persists.
    pub const fn revision(&self) -> ExecutionRevision {
        self.revision
    }

    /// Whether the next Task is held.
    pub const fn held(&self) -> bool {
        self.held
    }

    /// The recorded stop, when held.
    pub fn stop(&self) -> Option<&StopRecord> {
        self.stop.as_ref()
    }

    /// Non-secret explanation, when held.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// Whether the next Task may start.
    pub const fn may_continue(&self) -> bool {
        !self.held
    }
}

/// Ensures a temporary file cannot be left behind by a failed open.
///
/// Kept public so a test can prove the writer uses `create_new` on a unique
/// name and never truncates an existing file.
pub fn open_new(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

enum Probe {
    Absent,
    Regular(Vec<u8>),
    NotRegular,
}

fn probe_destination(destination: &Path) -> std::io::Result<Probe> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Ok(Probe::NotRegular);
            }
            fs::read(destination).map(Probe::Regular)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Probe::Absent),
        Err(error) => Err(error),
    }
}

fn unavailable(detail: &str) -> SddExecutionError {
    SddExecutionError::Unavailable {
        feature: format!("{PROGRESS_LEDGER_FEATURE}: {detail}"),
        details: FailureDetails::none().boxed(),
    }
}
