//! Target manifests and evidence freshness by applicability.
//!
//! Freshness is not elapsed time. A manifest records HEAD when known, every
//! owner-defined read-set input, uncommitted/untracked/external content, and
//! relevant dependency/settings inputs by SHA-256 content digest. Evidence is
//! reused only when the inputs it was acquired against still match. Changes
//! outside an evidence item's read-set preserve it; related changes invalidate
//! only the evidence that depends on them.
//!
//! The module performs no file I/O. A host supplies
//! [`WorkspaceSnapshotPort`]; tests use synthetic in-memory workspace values.

use std::collections::{BTreeMap, BTreeSet};

use herness_core::contracts::{ProjectId, Timestamp};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::SupervisionError;
use crate::evidence::{
    ContentDigest, ContentFingerprint, EvidenceRecord, TargetScope, TargetVersion,
};
use crate::ids::EvidenceId;
use crate::ports::ClockPort;
use crate::state::{StaleCompletion, SupervisionRecord, SupervisionState};

/// How the owner bounded the target read-set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetReadSet {
    /// Paths the owner declared as relevant, plus dependency/settings inputs.
    Declared(Vec<String>),
    /// The owner could not bound the scope, so the whole project input
    /// manifest is used.
    WholeProject,
}

/// Category of one workspace input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputOrigin {
    /// A tracked, committed project file.
    Tracked,
    /// A tracked file with uncommitted content.
    Uncommitted,
    /// An untracked file.
    Untracked,
    /// A file changed outside the host, for example by a shell or editor.
    External,
    /// A dependency manifest or lock input.
    Dependency,
    /// A project setting or configuration input.
    Settings,
}

impl InputOrigin {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tracked => "tracked",
            Self::Uncommitted => "uncommitted",
            Self::Untracked => "untracked",
            Self::External => "external",
            Self::Dependency => "dependency",
            Self::Settings => "settings",
        }
    }

    const fn relevant_when_declared(self) -> bool {
        matches!(self, Self::Dependency | Self::Settings)
    }
}

/// One workspace input path and its origin category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceInput {
    path: String,
    origin: InputOrigin,
}

impl WorkspaceInput {
    /// Creates a bounded project-relative input path.
    pub fn new(path: impl AsRef<str>, origin: InputOrigin) -> Result<Self, SupervisionError> {
        let path = validate_relative_path("workspace.path", path.as_ref())?;
        Ok(Self { path, origin })
    }

    /// Project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Where the input came from.
    pub const fn origin(&self) -> InputOrigin {
        self.origin
    }
}

/// Host reader for project inputs.
///
/// Implementations must return exact current bytes, not mtimes or a HEAD-only
/// view. A missing path is `Ok(None)`, which is fingerprinted as absence.
pub trait WorkspaceSnapshotPort {
    /// Current HEAD or equivalent revision, when known.
    fn head(&self) -> Result<Option<String>, SupervisionError>;

    /// Currently observable project inputs with their origin category.
    fn inputs(&self) -> Result<Vec<WorkspaceInput>, SupervisionError>;

    /// Exact bytes for one project-relative path.
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, SupervisionError>;
}

/// How much of the project input set a manifest covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestCoverage {
    /// The manifest covers every path it claims to cover.
    Complete,
    /// The host could enumerate only part of the project inputs.
    Partial(String),
    /// The host could not establish the input set at all.
    Unknown(String),
}

impl ManifestCoverage {
    /// Stable wire label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial(_) => "partial",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Whether the coverage is complete.
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// One content input observed for a target manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestEntry {
    path: String,
    origin: InputOrigin,
    present: bool,
    digest: ContentDigest,
}

impl ManifestEntry {
    /// Project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Origin category.
    pub const fn origin(&self) -> InputOrigin {
        self.origin
    }

    /// Whether the path existed at capture time.
    pub const fn present(&self) -> bool {
        self.present
    }

    /// Content digest, or the absence digest when `present` is false.
    pub fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

/// Content-addressed target manifest for one exact project snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetManifest {
    project_id: ProjectId,
    version: TargetVersion,
    head: Option<String>,
    read_set: Vec<String>,
    coverage: ManifestCoverage,
    entries: Vec<ManifestEntry>,
}

impl TargetManifest {
    /// Creates a validated manifest.
    pub fn new(
        project_id: ProjectId,
        version: TargetVersion,
        head: Option<String>,
        read_set: Vec<String>,
        coverage: ManifestCoverage,
        entries: Vec<ManifestEntry>,
    ) -> Result<Self, SupervisionError> {
        if read_set.is_empty() && coverage.is_complete() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "target.readSet".to_owned(),
                detail: "a complete manifest requires at least one bounded path".to_owned(),
            });
        }
        let mut bounded = BTreeSet::new();
        for path in &read_set {
            let checked = validate_relative_path("target.readSet", path)?;
            if !bounded.insert(checked) {
                return Err(SupervisionError::EvidenceContractViolation {
                    field: "target.readSet".to_owned(),
                    detail: "read-set paths must be unique".to_owned(),
                });
            }
        }
        let head = validate_head(head)?;
        let mut by_path = BTreeMap::new();
        for entry in entries {
            let path = validate_relative_path("target.entry.path", &entry.path)?;
            if by_path.contains_key(&path) {
                return Err(SupervisionError::EvidenceContractViolation {
                    field: "target.entries".to_owned(),
                    detail: "manifest entries must be unique per path".to_owned(),
                });
            }
            by_path.insert(path, entry);
        }
        if coverage.is_complete() {
            for path in &bounded {
                if !by_path.contains_key(path) {
                    return Err(SupervisionError::EvidenceContractViolation {
                        field: "target.entries".to_owned(),
                        detail: format!("read-set path {path:?} has no fingerprint"),
                    });
                }
            }
        }
        Ok(Self {
            project_id,
            version,
            head,
            read_set: bounded.into_iter().collect(),
            coverage,
            entries: by_path.into_values().collect(),
        })
    }

    /// Explicit unknown-scope manifest. Applicability cannot be established
    /// from this value; evaluations become inconclusive rather than passing.
    pub fn unknown(
        project_id: ProjectId,
        version: TargetVersion,
        detail: impl AsRef<str>,
    ) -> Result<Self, SupervisionError> {
        let detail = non_empty_detail("target.coverage", detail)?;
        Ok(Self {
            project_id,
            version,
            head: None,
            read_set: Vec::new(),
            coverage: ManifestCoverage::Unknown(detail),
            entries: Vec::new(),
        })
    }

    /// Project that owns the target.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Target version.
    pub const fn version(&self) -> TargetVersion {
        self.version
    }

    /// Observed HEAD, when known.
    pub fn head(&self) -> Option<&str> {
        self.head.as_deref()
    }

    /// Paths the manifest covers.
    pub fn read_set(&self) -> &[String] {
        &self.read_set
    }

    /// Coverage state.
    pub const fn coverage(&self) -> &ManifestCoverage {
        &self.coverage
    }

    /// Observed entries in path order.
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// Looks up one input.
    pub fn entry(&self, path: &str) -> Option<&ManifestEntry> {
        self.entries.iter().find(|entry| entry.path == path)
    }

    /// Stable digest over HEAD, coverage, read-set, and content entries.
    pub fn manifest_digest(&self) -> Result<ContentDigest, SupervisionError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Material<'a> {
            project_id: String,
            version: u64,
            head: Option<&'a str>,
            read_set: &'a [String],
            coverage: &'a ManifestCoverage,
            entries: Vec<MaterialEntry<'a>>,
        }

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct MaterialEntry<'a> {
            path: &'a str,
            origin: &'static str,
            present: bool,
            digest: &'a str,
        }

        let material = Material {
            project_id: self.project_id.to_string(),
            version: self.version.get(),
            head: self.head.as_deref(),
            read_set: &self.read_set,
            coverage: &self.coverage,
            entries: self
                .entries
                .iter()
                .map(|entry| MaterialEntry {
                    path: &entry.path,
                    origin: entry.origin.as_str(),
                    present: entry.present,
                    digest: entry.digest.as_str(),
                })
                .collect(),
        };
        let bytes =
            serde_json::to_vec(&material).map_err(|error| SupervisionError::InvalidValue {
                field: "target.manifest".to_owned(),
                detail: format!("could not serialize the manifest digest: {error}"),
            })?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Builds the evidence-facing target scope. Unknown or partial coverage
    /// cannot be recorded as an exact evidence target.
    pub fn target_scope(&self) -> Result<TargetScope, SupervisionError> {
        if !self.coverage.is_complete() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "target.coverage".to_owned(),
                detail: format!(
                    "{} coverage cannot back an exact evidence target",
                    self.coverage.as_str()
                ),
            });
        }
        if self.read_set.is_empty() || self.entries.is_empty() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "target.entries".to_owned(),
                detail: "the project input manifest is empty".to_owned(),
            });
        }
        let fingerprints = self
            .entries
            .iter()
            .map(|entry| ContentFingerprint::new(&entry.path, entry.digest.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        TargetScope::new_with_head(
            self.project_id,
            self.version,
            self.read_set.clone(),
            fingerprints,
            self.head.clone(),
        )
    }

    /// Content differences against another manifest, sorted by path.
    pub fn diff(&self, previous: &TargetManifest) -> ManifestDiff {
        let mut paths = BTreeSet::new();
        paths.extend(self.entries.iter().map(|entry| entry.path.clone()));
        paths.extend(previous.entries.iter().map(|entry| entry.path.clone()));
        let mut diff = ManifestDiff::default();
        for path in paths {
            match (self.entry(&path), previous.entry(&path)) {
                (Some(current), Some(previous)) => {
                    if current.present != previous.present || current.digest != previous.digest {
                        diff.changed.push(path);
                    }
                }
                (Some(_), None) => diff.added.push(path),
                (None, Some(_)) => diff.removed.push(path),
                (None, None) => {}
            }
        }
        diff
    }

    /// Differences between this manifest and the inputs an evidence target
    /// was acquired against.
    pub fn diff_scope(&self, scope: &TargetScope) -> ManifestDiff {
        let mut paths = BTreeSet::new();
        paths.extend(self.entries.iter().map(|entry| entry.path.clone()));
        paths.extend(
            scope
                .fingerprints()
                .iter()
                .map(|item| item.path().to_owned()),
        );
        let mut diff = ManifestDiff::default();
        for path in paths {
            match (self.entry(&path), scope_fingerprint(scope, &path)) {
                (Some(current), Some(previous)) => {
                    if !current.present || current.digest != *previous.digest() {
                        diff.changed.push(path);
                    }
                }
                (Some(_), None) => diff.added.push(path),
                (None, Some(_)) => diff.removed.push(path),
                (None, None) => {}
            }
        }
        diff
    }
}

/// Sorted content differences between two manifests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestDiff {
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
}

impl ManifestDiff {
    /// Paths present now but not before.
    pub fn added(&self) -> &[String] {
        &self.added
    }

    /// Paths present before but missing now.
    pub fn removed(&self) -> &[String] {
        &self.removed
    }

    /// Paths whose presence or content changed.
    pub fn changed(&self) -> &[String] {
        &self.changed
    }

    /// Every differing path in sorted order.
    pub fn paths(&self) -> Vec<String> {
        let mut paths = BTreeSet::new();
        paths.extend(self.added.iter().cloned());
        paths.extend(self.removed.iter().cloned());
        paths.extend(self.changed.iter().cloned());
        paths.into_iter().collect()
    }

    /// Whether no content difference was observed.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// Applicability of one evidence item to the current manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EvidenceApplicability {
    /// The exact inputs the evidence covers still match.
    Applies,
    /// Related inputs changed; this evidence no longer supports completion.
    Invalidated {
        /// Related paths that changed.
        changed_paths: Vec<String>,
    },
    /// The host cannot establish scope, so the evidence is inconclusive.
    UnknownScope {
        /// Non-secret explanation.
        detail: String,
    },
}

impl EvidenceApplicability {
    /// Whether the evidence may be reused.
    pub const fn applies(&self) -> bool {
        matches!(self, Self::Applies)
    }

    /// Whether the evidence is known to be stale.
    pub const fn is_invalidated(&self) -> bool {
        matches!(self, Self::Invalidated { .. })
    }

    /// Whether the host could not establish scope.
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::UnknownScope { .. })
    }
}

/// Freshness result for one evidence item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceFreshness {
    evidence_id: EvidenceId,
    check_id: Option<crate::ids::CheckId>,
    applicability: EvidenceApplicability,
}

impl EvidenceFreshness {
    /// Evidence item checked.
    pub const fn evidence_id(&self) -> EvidenceId {
        self.evidence_id
    }

    /// Required check the evidence answers, if any.
    pub const fn check_id(&self) -> Option<crate::ids::CheckId> {
        self.check_id
    }

    /// Applicability result.
    pub const fn applicability(&self) -> &EvidenceApplicability {
        &self.applicability
    }
}

/// Freshness of a set of evidence against one manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreshnessReport {
    project_id: ProjectId,
    target_version: TargetVersion,
    manifest_digest: ContentDigest,
    evidence: Vec<EvidenceFreshness>,
}

impl FreshnessReport {
    /// Project.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Target version checked against.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Digest of the current manifest.
    pub fn manifest_digest(&self) -> &ContentDigest {
        &self.manifest_digest
    }

    /// Per-evidence results.
    pub fn evidence(&self) -> &[EvidenceFreshness] {
        &self.evidence
    }

    /// Whether every evidence item still applies.
    pub fn all_apply(&self) -> bool {
        self.evidence
            .iter()
            .all(|item| item.applicability.applies())
    }

    /// Evidence IDs that no longer apply.
    pub fn invalidated(&self) -> Vec<EvidenceId> {
        self.evidence
            .iter()
            .filter(|item| !item.applicability.applies())
            .map(|item| item.evidence_id)
            .collect()
    }
}

/// Post-completion stale report. Applying it never starts a run or resumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleCompletionReport {
    stale: StaleCompletion,
    auto_resume: bool,
}

impl StaleCompletionReport {
    /// Stale-snapshot marker.
    pub const fn stale(&self) -> &StaleCompletion {
        &self.stale
    }

    /// Always false: H2 does not resume automatically after completion.
    pub const fn auto_resume(&self) -> bool {
        self.auto_resume
    }

    /// Evidence that no longer applies.
    pub fn affected_evidence(&self) -> &[EvidenceId] {
        self.stale.affected_evidence()
    }

    /// Marks the record's completion snapshot stale while keeping the completed
    /// state and history unchanged.
    pub fn apply(&self, record: &mut SupervisionRecord) -> Result<(), SupervisionError> {
        record.mark_completion_stale(self.stale.clone())
    }
}

/// Result of checking a completed record against current inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CompletionFreshness {
    /// The recorded snapshot still matches the current inputs.
    Applies {
        /// Current target version.
        target_version: TargetVersion,
        /// Current manifest digest.
        manifest_digest: ContentDigest,
    },
    /// Related inputs changed after completion.
    Stale(StaleCompletionReport),
    /// The host cannot establish scope, so the completion must not be claimed
    /// as current.
    Inconclusive {
        /// Non-secret explanation.
        detail: String,
    },
}

impl CompletionFreshness {
    /// Whether the completion still applies.
    pub const fn applies(&self) -> bool {
        matches!(self, Self::Applies { .. })
    }

    /// Stale report, when the snapshot lost applicability.
    pub const fn stale(&self) -> Option<&StaleCompletionReport> {
        match self {
            Self::Stale(report) => Some(report),
            _ => None,
        }
    }
}

/// Manifest capture and freshness evaluation.
#[derive(Debug, Clone)]
pub struct FreshnessService<W, C> {
    workspace: W,
    clock: C,
}

impl<W: WorkspaceSnapshotPort, C: ClockPort> FreshnessService<W, C> {
    /// Creates a service over an injected workspace reader and clock.
    pub const fn new(workspace: W, clock: C) -> Self {
        Self { workspace, clock }
    }

    /// Captures a content-addressed manifest for the current workspace.
    pub fn capture(
        &self,
        project_id: ProjectId,
        version: TargetVersion,
        read_set: TargetReadSet,
    ) -> Result<TargetManifest, SupervisionError> {
        capture_manifest(&self.workspace, project_id, version, read_set)
    }

    /// Captures a whole-project manifest when the owner scope is unknown.
    pub fn widen(
        &self,
        project_id: ProjectId,
        version: TargetVersion,
    ) -> Result<TargetManifest, SupervisionError> {
        self.capture(project_id, version, TargetReadSet::WholeProject)
    }

    /// Compares one evidence item against the current manifest.
    pub fn evaluate_evidence(
        &self,
        manifest: &TargetManifest,
        evidence: &EvidenceRecord,
    ) -> Result<EvidenceApplicability, SupervisionError> {
        evaluate_evidence(manifest, evidence)
    }

    /// Compares evidence to the current manifest. Only affected evidence is
    /// invalidated.
    pub fn evaluate(
        &self,
        manifest: &TargetManifest,
        evidence: &[EvidenceRecord],
    ) -> Result<FreshnessReport, SupervisionError> {
        let mut results = Vec::with_capacity(evidence.len());
        for item in evidence {
            results.push(EvidenceFreshness {
                evidence_id: item.id(),
                check_id: item.check_id(),
                applicability: evaluate_evidence(manifest, item)?,
            });
        }
        Ok(FreshnessReport {
            project_id: manifest.project_id(),
            target_version: manifest.version(),
            manifest_digest: manifest.manifest_digest()?,
            evidence: results,
        })
    }

    /// Re-checks a completed record's snapshot immediately before claiming it
    /// is still current. Related changes produce a stale report; unknown scope
    /// is inconclusive.
    pub fn evaluate_completion(
        &self,
        record: &SupervisionRecord,
        manifest: &TargetManifest,
        evidence: &[EvidenceRecord],
    ) -> Result<CompletionFreshness, SupervisionError> {
        if manifest.project_id() != record.project_id() {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "target manifest".to_owned(),
                expected: record.project_id(),
                found: manifest.project_id(),
            });
        }
        if record.state() != SupervisionState::Completed {
            return Err(SupervisionError::InvalidStateReason {
                state: record.state(),
                reason: "completion_freshness".to_owned(),
            });
        }
        let Some(snapshot) = record.completion() else {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "completion".to_owned(),
                detail: "a completed record requires a completion snapshot".to_owned(),
            });
        };
        if !manifest.coverage().is_complete() {
            return Ok(CompletionFreshness::Inconclusive {
                detail: format!(
                    "{} coverage cannot establish completion applicability",
                    manifest.coverage().as_str()
                ),
            });
        }

        let mut changed = BTreeSet::new();
        let mut affected = Vec::new();
        for evidence_id in snapshot.evidence() {
            let Some(item) = evidence.iter().find(|item| item.id() == *evidence_id) else {
                return Ok(CompletionFreshness::Inconclusive {
                    detail: format!("completion evidence {evidence_id} is not available"),
                });
            };
            match evaluate_evidence(manifest, item)? {
                EvidenceApplicability::Applies => {}
                EvidenceApplicability::Invalidated { changed_paths } => {
                    affected.push(*evidence_id);
                    changed.extend(changed_paths);
                }
                EvidenceApplicability::UnknownScope { detail } => {
                    return Ok(CompletionFreshness::Inconclusive { detail });
                }
            }
        }

        if snapshot.observation_digest() != &manifest.manifest_digest()? {
            for evidence_id in snapshot.evidence() {
                if let Some(item) = evidence.iter().find(|item| item.id() == *evidence_id) {
                    changed.extend(manifest.diff_scope(item.target()).paths());
                }
            }
        }

        if changed.is_empty() {
            return Ok(CompletionFreshness::Applies {
                target_version: manifest.version(),
                manifest_digest: manifest.manifest_digest()?,
            });
        }
        affected.sort();
        affected.dedup();
        let stale = StaleCompletion::new(
            snapshot.target_version(),
            manifest.version(),
            changed.into_iter().collect(),
            affected,
            self.clock.now(),
        )?;
        Ok(CompletionFreshness::Stale(StaleCompletionReport {
            stale,
            auto_resume: false,
        }))
    }
}

/// Captures a manifest from any workspace reader.
pub fn capture_manifest<W: WorkspaceSnapshotPort + ?Sized>(
    workspace: &W,
    project_id: ProjectId,
    version: TargetVersion,
    read_set: TargetReadSet,
) -> Result<TargetManifest, SupervisionError> {
    let head = validate_head(workspace.head()?)?;
    let inputs = workspace.inputs()?;
    let mut origins = BTreeMap::new();
    for input in inputs {
        if origins.insert(input.path.clone(), input.origin).is_some() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "workspace.inputs".to_owned(),
                detail: "workspace input paths must be unique".to_owned(),
            });
        }
    }

    let selected: BTreeSet<String> = match read_set {
        TargetReadSet::Declared(paths) => {
            if paths.is_empty() {
                return Err(SupervisionError::EvidenceContractViolation {
                    field: "target.readSet".to_owned(),
                    detail: "a declared read-set must contain at least one path".to_owned(),
                });
            }
            let mut selected = BTreeSet::new();
            for path in paths {
                selected.insert(validate_relative_path("target.readSet", &path)?);
            }
            for (path, origin) in &origins {
                if origin.relevant_when_declared() {
                    selected.insert(path.clone());
                }
            }
            selected
        }
        TargetReadSet::WholeProject => origins.keys().cloned().collect(),
    };

    if selected.is_empty() {
        return Err(SupervisionError::EvidenceContractViolation {
            field: "target.readSet".to_owned(),
            detail: "the project input manifest is empty".to_owned(),
        });
    }

    let mut entries = Vec::with_capacity(selected.len());
    for path in selected {
        let origin = origins.get(&path).copied().unwrap_or(InputOrigin::Tracked);
        let bytes = workspace.read(&path)?;
        let (present, digest) = match bytes {
            Some(bytes) => (true, ContentDigest::sha256(&bytes)),
            None => (false, absence_digest(&path)),
        };
        entries.push(ManifestEntry {
            path,
            origin,
            present,
            digest,
        });
    }

    TargetManifest::new(
        project_id,
        version,
        head,
        entries.iter().map(|entry| entry.path.clone()).collect(),
        ManifestCoverage::Complete,
        entries,
    )
}

fn evaluate_evidence(
    manifest: &TargetManifest,
    evidence: &EvidenceRecord,
) -> Result<EvidenceApplicability, SupervisionError> {
    evidence.target().ensure_project(manifest.project_id())?;
    if evidence.project_id() != manifest.project_id() {
        return Err(SupervisionError::CrossProjectReference {
            id_kind: "evidence".to_owned(),
            expected: manifest.project_id(),
            found: evidence.project_id(),
        });
    }
    match manifest.coverage() {
        ManifestCoverage::Unknown(detail) => {
            return Ok(EvidenceApplicability::UnknownScope {
                detail: detail.clone(),
            });
        }
        ManifestCoverage::Partial(detail) => {
            if evidence
                .target()
                .read_set()
                .iter()
                .any(|path| manifest.entry(path).is_none())
                || evidence
                    .target()
                    .fingerprints()
                    .iter()
                    .any(|item| manifest.entry(item.path()).is_none())
            {
                return Ok(EvidenceApplicability::UnknownScope {
                    detail: detail.clone(),
                });
            }
        }
        ManifestCoverage::Complete => {}
    }

    let mut changed = BTreeSet::new();
    for item in evidence.target().fingerprints() {
        match manifest.entry(item.path()) {
            Some(entry) if entry.present && entry.digest == *item.digest() => {}
            _ => {
                changed.insert(item.path().to_owned());
            }
        }
    }
    for path in evidence.target().read_set() {
        if !evidence
            .target()
            .fingerprints()
            .iter()
            .any(|item| item.path() == path)
        {
            changed.insert(path.clone());
        }
    }

    if changed.is_empty() {
        Ok(EvidenceApplicability::Applies)
    } else {
        Ok(EvidenceApplicability::Invalidated {
            changed_paths: changed.into_iter().collect(),
        })
    }
}

fn scope_fingerprint<'a>(scope: &'a TargetScope, path: &str) -> Option<&'a ContentFingerprint> {
    scope.fingerprints().iter().find(|item| item.path() == path)
}

fn absence_digest(path: &str) -> ContentDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"herness.target-manifest.absent.v1\0");
    hasher.update(path.as_bytes());
    ContentDigest::parse(format!("{:x}", hasher.finalize())).expect("sha-256 digest is valid")
}

fn validate_head(head: Option<String>) -> Result<Option<String>, SupervisionError> {
    head.map(|head| {
        let trimmed = head.trim();
        if trimmed.is_empty() || trimmed.chars().count() > 256 {
            Err(SupervisionError::EvidenceContractViolation {
                field: "target.head".to_owned(),
                detail: "a recorded HEAD must be non-empty and at most 256 characters".to_owned(),
            })
        } else {
            Ok(trimmed.to_owned())
        }
    })
    .transpose()
}

fn validate_relative_path(field: &str, path: &str) -> Result<String, SupervisionError> {
    let trimmed = path.trim();
    if trimmed.is_empty()
        || trimmed == "*"
        || trimmed == "."
        || trimmed == "/"
        || trimmed.starts_with('/')
        || trimmed
            .split('/')
            .any(|part| part == ".." || part.is_empty())
        || trimmed.split('\\').count() > 1
    {
        return Err(SupervisionError::EvidenceContractViolation {
            field: field.to_owned(),
            detail: "paths must be bounded project-relative paths".to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}

fn non_empty_detail(field: &str, detail: impl AsRef<str>) -> Result<String, SupervisionError> {
    let trimmed = detail.as_ref().trim();
    if trimmed.is_empty() || trimmed.chars().count() > 512 {
        return Err(SupervisionError::EvidenceContractViolation {
            field: field.to_owned(),
            detail: "coverage detail must be non-empty and at most 512 characters".to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}

impl<W, C> FreshnessService<W, C> {
    /// Timestamp observed for the next evaluation.
    pub fn now(&self) -> Timestamp
    where
        C: ClockPort,
    {
        self.clock.now()
    }
}
