//! Bounded, read-only reads of the project plan and of approved spec/source
//! snapshots.
//!
//! Every read is confined to a canonical root, refuses a symlink escape, a
//! directory, or a non-regular file, and never reads more than its limit. A
//! read produces the exact bytes plus the canonical path it opened, so the pure
//! verification in [`herness_sdd_execute::import`] can prove the confinement
//! after the fact instead of trusting the reader.
//!
//! Nothing here writes. There is no create, rename, delete, chmod, or temporary
//! file, and Python is never asked to write bytecode for the pack.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use herness_core::contracts::ProjectId;
use herness_sdd_execute::import::{OVERSIZE_PLAN_FEATURE, OVERSIZE_SNAPSHOT_FEATURE};
use herness_sdd_execute::{
    FailureDetails, MAX_PLAN_BYTES, MAX_SPEC_SNAPSHOT_BYTES, PlanDigest, PlanObservation, PlanPath,
    PlanSourcePort, PlanSourceRead, SddExecutionError, SourceLayout, SourceSnapshot,
    SpecSnapshotSet, verify_spec_snapshots,
};

/// One file read confined to a canonical root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinedRead {
    canonical_path: String,
    bytes: Vec<u8>,
}

impl ConfinedRead {
    /// Canonical absolute path that was opened.
    pub fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    /// Exact bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Exact byte length.
    pub fn byte_length(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Digest of the exact bytes.
    pub fn digest(&self) -> PlanDigest {
        PlanDigest::sha256(&self.bytes)
    }
}

fn unavailable(feature: &str, detail: impl std::fmt::Display) -> SddExecutionError {
    SddExecutionError::Unavailable {
        feature: format!("{feature}: {detail}"),
        details: FailureDetails::none().boxed(),
    }
}

fn invalid(field: &str, detail: impl Into<String>) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.into(),
    }
}

/// Reads one file under a canonical root, never above `max_bytes`.
#[derive(Debug, Clone)]
pub struct ConfinedReader {
    root: PathBuf,
    root_text: String,
    max_bytes: u64,
}

impl ConfinedReader {
    /// Canonicalizes `root` once and refuses a missing or non-directory root.
    pub fn new(root: impl AsRef<Path>, max_bytes: u64) -> Result<Self, SddExecutionError> {
        if max_bytes == 0 {
            return Err(invalid("reader.maxBytes", "must be greater than zero"));
        }
        let canonical = fs::canonicalize(root.as_ref()).map_err(|error| {
            invalid(
                "reader.root",
                format!("cannot canonicalize the root: {}", error.kind()),
            )
        })?;
        let metadata = fs::metadata(&canonical).map_err(|error| {
            invalid(
                "reader.root",
                format!("cannot read the root: {}", error.kind()),
            )
        })?;
        if !metadata.is_dir() {
            return Err(invalid("reader.root", "must be a directory"));
        }
        let root_text = canonical
            .to_str()
            .ok_or_else(|| invalid("reader.root", "must be valid UTF-8"))?
            .to_owned();
        Ok(Self {
            root: canonical,
            root_text: trim_trailing_slash(root_text),
            max_bytes,
        })
    }

    /// Canonical root.
    pub fn root(&self) -> &str {
        &self.root_text
    }

    /// Per-read byte limit.
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Reads `relative` (a validated normalized path) inside the root.
    ///
    /// The canonical path must stay strictly below the root, so `..`, an
    /// absolute path, or a symlink that leaves the root is refused before any
    /// byte is read. A file whose size exceeds the limit is refused without
    /// being truncated.
    pub fn read(&self, relative: &str) -> Result<ConfinedRead, SddExecutionError> {
        self.read_reporting(relative, OVERSIZE_SNAPSHOT_FEATURE)
    }

    /// Reads `relative`, labelling an oversize file with `oversize_feature`.
    fn read_reporting(
        &self,
        relative: &str,
        oversize_feature: &str,
    ) -> Result<ConfinedRead, SddExecutionError> {
        let candidate = self.root.join(relative);
        let canonical = fs::canonicalize(&candidate).map_err(|error| {
            invalid(
                "reader.path",
                format!("{relative} is not readable: {}", error.kind()),
            )
        })?;
        let canonical_text = canonical
            .to_str()
            .ok_or_else(|| invalid("reader.path", format!("{relative} is not valid UTF-8")))?
            .to_owned();
        if !self.contains(&canonical_text) {
            return Err(invalid(
                "reader.path",
                format!("{relative} resolves outside its approved root"),
            ));
        }
        // `canonicalize` follows symlinks; the resulting path is a real file.
        let metadata = fs::metadata(&canonical).map_err(|error| {
            invalid(
                "reader.path",
                format!("{relative} is not readable: {}", error.kind()),
            )
        })?;
        if !metadata.is_file() {
            return Err(invalid(
                "reader.path",
                format!("{relative} is not a regular file"),
            ));
        }
        if metadata.len() > self.max_bytes {
            return Err(unavailable(
                oversize_feature,
                format!(
                    "{relative} is {} bytes; the maximum is {} and it is never truncated",
                    metadata.len(),
                    self.max_bytes
                ),
            ));
        }
        let file = File::open(&canonical).map_err(|error| {
            invalid(
                "reader.path",
                format!("{relative} is not readable: {}", error.kind()),
            )
        })?;
        let mut bytes = Vec::with_capacity(metadata.len().min(self.max_bytes) as usize + 1);
        // Read one byte past the limit so a file that grew between stat and read
        // is refused instead of silently truncated.
        file.take(self.max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                invalid(
                    "reader.path",
                    format!("{relative} could not be read: {}", error.kind()),
                )
            })?;
        if bytes.len() as u64 > self.max_bytes {
            return Err(unavailable(
                oversize_feature,
                format!(
                    "{relative} grew past the {} byte maximum and is never truncated",
                    self.max_bytes
                ),
            ));
        }
        Ok(ConfinedRead {
            canonical_path: canonical_text,
            bytes,
        })
    }

    /// Whether `canonical_text` is strictly below the root.
    pub fn contains(&self, canonical_text: &str) -> bool {
        canonical_text
            .strip_prefix(&self.root_text)
            .is_some_and(|rest| {
                !rest.is_empty() && rest.starts_with('/') && rest.trim_end_matches('/').len() > 1
            })
    }
}

fn trim_trailing_slash(mut value: String) -> String {
    while value.len() > 1 && value.ends_with('/') {
        value.pop();
    }
    value
}

/// The project plan file as a read-only [`PlanSourcePort`].
///
/// `read_plan` returns the exact bytes at the approved path with a verified
/// digest. `observe` reads twice and only reports a stable observation when the
/// two reads agree, so an edit in progress is never reported as stable.
#[derive(Debug, Clone)]
pub struct PlanFileSource {
    project_id: ProjectId,
    project_root: PathBuf,
    reader: ConfinedReader,
}

impl PlanFileSource {
    /// Creates a source over one canonical project root.
    pub fn new(
        project_id: ProjectId,
        project_root: impl AsRef<Path>,
    ) -> Result<Self, SddExecutionError> {
        let reader = ConfinedReader::new(project_root.as_ref(), MAX_PLAN_BYTES)?;
        Ok(Self {
            project_id,
            project_root: reader.root.clone(),
            reader,
        })
    }

    /// Canonical project root.
    pub fn project_root(&self) -> &str {
        self.reader.root()
    }

    /// Project this source belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Reads the exact plan bytes, never above the 2 MiB limit.
    pub fn read_exact(&self, plan_path: &PlanPath) -> Result<ConfinedRead, SddExecutionError> {
        let read = self
            .reader
            .read_reporting(plan_path.as_str(), OVERSIZE_PLAN_FEATURE)?;
        if read.bytes.is_empty() {
            return Err(invalid(
                "plan.source",
                "the plan file is empty; the exact bytes are required",
            ));
        }
        if read.byte_length() > MAX_PLAN_BYTES {
            return Err(unavailable(
                OVERSIZE_PLAN_FEATURE,
                format!(
                    "the plan is {} bytes; the maximum is {MAX_PLAN_BYTES}",
                    read.byte_length()
                ),
            ));
        }
        Ok(read)
    }

    /// The confined reader used for the plan.
    pub const fn reader(&self) -> &ConfinedReader {
        &self.reader
    }

    /// Project root as a path.
    pub fn root_path(&self) -> &Path {
        &self.project_root
    }
}

impl PlanSourcePort for PlanFileSource {
    fn read_plan(
        &self,
        project_id: ProjectId,
        plan_path: &PlanPath,
    ) -> Result<PlanSourceRead, SddExecutionError> {
        if project_id != self.project_id {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "planSource".to_owned(),
                expected: self.project_id,
                found: project_id,
            });
        }
        let read = self.read_exact(plan_path)?;
        let digest = read.digest();
        PlanSourceRead::new(read.bytes, digest)
    }

    fn observe(
        &self,
        project_id: ProjectId,
        plan_path: &PlanPath,
    ) -> Result<PlanObservation, SddExecutionError> {
        if project_id != self.project_id {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "planSource".to_owned(),
                expected: self.project_id,
                found: project_id,
            });
        }
        let first = match self.reader.read(plan_path.as_str()) {
            Ok(read) => read,
            Err(SddExecutionError::InvalidValue { .. }) => return Ok(PlanObservation::missing()),
            Err(error) => return Err(error),
        };
        let second = match self.reader.read(plan_path.as_str()) {
            Ok(read) => read,
            Err(SddExecutionError::InvalidValue { .. }) => return Ok(PlanObservation::missing()),
            Err(error) => return Err(error),
        };
        let stable = first.bytes == second.bytes;
        Ok(PlanObservation::observed(
            second.digest(),
            second.byte_length(),
            stable,
        ))
    }
}

/// Reads one approved spec/source snapshot through the confined reader that
/// matches its declared source.
///
/// The alias root comes from the human-approved [`SourceLayout`]; a declared
/// alias that the layout does not carry, or a path outside the alias's approved
/// read paths, is refused before any read.
pub fn read_spec_snapshot(
    layout: &SourceLayout,
    spec_ref: &herness_sdd_execute::PreviewSpecRef,
) -> Result<SourceSnapshot, SddExecutionError> {
    let resolved = layout.resolve(spec_ref)?;
    let reader = ConfinedReader::new(resolved.root(), MAX_SPEC_SNAPSHOT_BYTES)?;
    if reader.root() != resolved.root() {
        // The approved root must be canonical. A layout built from a symlinked
        // alias root would compare the canonical file path with the unresolved
        // root and refuse every read; say so instead of reporting an escape.
        return Err(invalid(
            "source.absoluteRoot",
            format!(
                "the approved root {:?} is not canonical (it resolves to {:?})",
                resolved.root(),
                reader.root()
            ),
        ));
    }
    let read = reader.read(resolved.relative())?;
    // The pure verifier repeats this check; failing here keeps a symlink escape
    // from ever becoming a supplied snapshot.
    layout.confine(&resolved, read.canonical_path())?;
    let canonical_path = read.canonical_path().to_owned();
    SourceSnapshot::new(
        spec_ref.source(),
        spec_ref.path(),
        canonical_path,
        read.bytes,
    )
}

/// Reads and verifies every root spec reference of a preview.
///
/// Snapshots are read in first-declaration order, each through its own
/// confined root, and then verified by the pure rules (existence, unique
/// heading per applied section, root confinement, exact bytes and digest).
pub fn read_and_verify_specs(
    layout: &SourceLayout,
    refs: &[herness_sdd_execute::PreviewSpecRef],
) -> Result<SpecSnapshotSet, SddExecutionError> {
    let mut snapshots = Vec::with_capacity(refs.len());
    for spec_ref in refs {
        snapshots.push(read_spec_snapshot(layout, spec_ref)?);
    }
    verify_spec_snapshots(layout, refs, &snapshots)
}
