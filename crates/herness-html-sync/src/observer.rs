//! H3 change detection, quiet-period scheduling, and periodic reconciliation.
//!
//! The observer merges three notification paths — H1's persisted native
//! file-change notifications, shell/external-editor observations, and
//! filesystem watcher events — into one content comparison. A document is
//! identified by the canonical [`DocumentKey`] supplied by the common SDD
//! Target resolver; this module never discovers or expands a Target set of its
//! own. Notifications for dotfiles, undeclared Markdown, or unrelated paths are
//! ignored.
//!
//! Every stable read is compared by exact SHA-256 of the current bytes, never by
//! mtime alone. Repeated edits keep one document pending until the approved
//! quiet period (750 ms by default) has elapsed; only the stable revision is
//! emitted. The periodic scan (5 s by default) catches missed notifications and
//! runs on open projects, while an explicit watcher recovery performs one full
//! scan and resynchronises revisions without creating authoring work.
//!
//! The crate has no Tauri, database, engine, or filesystem-watcher dependency.
//! [`FilesystemSourceReader`] is a plain `std::fs` implementation of
//! [`SourceReadPort`]; the desktop watcher adapter feeds [`ChangeSignal`]s into
//! this logic. Reads and time come from injected ports so tests never sleep.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use herness_core::{ProjectId, PublicationRequestId, Timestamp};
use herness_supervision::{ClockReading, ContentDigest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::H3ApprovalLimits;
use crate::document::{DocumentKey, FingerprintKind, MAX_DOCUMENT_PATH_BYTES, SourceSnapshot};
use crate::error::H3Error;
use crate::ids::PublicationId;
use crate::state::{ApplicabilityReason, H3Settings};

/// Directory holding H3 evaluation receipts, relative to the project root.
pub const HTML_EVIDENCE_DIR: &str = "docs/sdd/html-evidence";

/// Where one change notification came from.
///
/// The source explains how the host learned about a path, not why the file
/// changed. The observer never attributes an actor or a reason to a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeSource {
    /// H1 persisted a native file-tool write or edit.
    NativeSaved,
    /// A shell command observed by the host may have changed the path.
    Shell,
    /// An external editor save observed by the host.
    ExternalEditor,
    /// A filesystem watcher event.
    FilesystemWatcher,
}

impl ChangeSource {
    /// Stable label used in reports and serde.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeSaved => "native_saved",
            Self::Shell => "shell",
            Self::ExternalEditor => "external_editor",
            Self::FilesystemWatcher => "filesystem_watcher",
        }
    }
}

/// One path notification from any merged source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSignal {
    path: String,
    source: ChangeSource,
}

impl ChangeSignal {
    /// Validates one project-relative notification path.
    pub fn new(path: impl Into<String>, source: ChangeSource) -> Result<Self, H3Error> {
        let path = path.into();
        validate_relative_path(&path)?;
        Ok(Self { path, source })
    }

    /// Project-relative path with `/` separators.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// How the host learned about this path.
    pub const fn source(&self) -> ChangeSource {
        self.source
    }
}

/// A shared CSS or referenced-resource dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// Shared stylesheet.
    Css,
    /// A referenced local resource such as an image.
    Resource,
}

impl DependencyKind {
    /// Stable label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Css => "css",
            Self::Resource => "resource",
        }
    }

    /// Fingerprint kind a change invalidates.
    pub const fn fingerprint_kind(self) -> FingerprintKind {
        match self {
            Self::Css => FingerprintKind::Css,
            Self::Resource => FingerprintKind::Resources,
        }
    }
}

/// One caller-supplied dependency path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DependencyPath {
    path: String,
    kind: DependencyKind,
}

impl DependencyPath {
    /// Validates a project-relative dependency path.
    pub fn new(path: impl Into<String>, kind: DependencyKind) -> Result<Self, H3Error> {
        let path = path.into();
        validate_relative_path(&path)?;
        Ok(Self { path, kind })
    }

    /// Project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Dependency kind.
    pub const fn kind(&self) -> DependencyKind {
        self.kind
    }
}

/// Caller-supplied Target and dependency set for one open project.
///
/// Construction validates only the list it was given. It does not walk the
/// project or add dotfiles, nested Markdown, or anything else: the common SDD
/// resolver remains the only Target declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationTargets {
    project: ProjectId,
    documents: Vec<DocumentKey>,
    dependencies: Vec<DependencyPath>,
    settle_ms: u64,
    reconcile_interval_ms: u64,
    max_source_bytes: u64,
}

impl ObservationTargets {
    /// Builds a Target set using the approved default limits.
    pub fn new(
        project: ProjectId,
        documents: Vec<DocumentKey>,
        dependencies: Vec<DependencyPath>,
    ) -> Result<Self, H3Error> {
        Self::with_limits(
            project,
            documents,
            dependencies,
            &H3ApprovalLimits::default(),
        )
    }

    /// Builds the observed Target set from the canonical H3 settings.
    ///
    /// The caller supplies only dependencies; the Markdown Target list comes
    /// from the settings that the common SDD resolver approved, never from an
    /// independent filesystem walk. An absent approval uses the approved
    /// default limits; a present approval uses its exact approved limits.
    pub fn from_settings(
        settings: &H3Settings,
        dependencies: Vec<DependencyPath>,
    ) -> Result<Self, H3Error> {
        let documents = settings
            .target_paths()
            .iter()
            .map(|path| DocumentKey::new(settings.project_id(), path.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let limits = settings
            .approval()
            .map(|approval| approval.limits().clone())
            .unwrap_or_default();
        Self::with_limits(settings.project_id(), documents, dependencies, &limits)
    }

    /// Builds a Target set with the quiet period, periodic interval, and source
    /// limit taken from one approved limits value.
    pub fn with_limits(
        project: ProjectId,
        mut documents: Vec<DocumentKey>,
        mut dependencies: Vec<DependencyPath>,
        limits: &H3ApprovalLimits,
    ) -> Result<Self, H3Error> {
        if documents.is_empty() {
            return Err(H3Error::empty("documents"));
        }
        for document in &documents {
            document.validate_in(project)?;
        }
        let supplied = documents.len();
        documents.sort_by(|left, right| left.target_path().cmp(right.target_path()));
        documents.dedup();
        if documents.len() != supplied {
            return Err(H3Error::invalid(
                "documents",
                "the observed Target set contains duplicates",
            ));
        }
        let supplied = dependencies.len();
        dependencies.sort();
        dependencies.dedup();
        if dependencies.len() != supplied {
            return Err(H3Error::invalid(
                "dependencies",
                "the observed dependency set contains duplicates",
            ));
        }
        for (index, dependency) in dependencies.iter().enumerate() {
            if dependencies[..index]
                .iter()
                .any(|earlier| earlier.path == dependency.path)
            {
                return Err(H3Error::invalid(
                    "dependencies",
                    "one path cannot be both CSS and a referenced resource",
                ));
            }
        }
        for document in &documents {
            let companion = document.companion_path();
            if dependencies.iter().any(|dependency| {
                dependency.path == document.target_path() || dependency.path == companion
            }) {
                return Err(H3Error::invalid(
                    "dependencies",
                    "a dependency path collides with a Target or its companion",
                ));
            }
        }
        if limits.settle_ms() == 0 || limits.reconcile_interval_ms() == 0 {
            return Err(H3Error::must_be_positive("observationInterval"));
        }
        Ok(Self {
            project,
            documents,
            dependencies,
            settle_ms: limits.settle_ms(),
            reconcile_interval_ms: limits.reconcile_interval_ms(),
            max_source_bytes: limits.source_bytes(),
        })
    }

    /// Project this set belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project
    }

    /// Canonical Target documents.
    pub fn documents(&self) -> &[DocumentKey] {
        &self.documents
    }

    /// Dependency paths in sorted order.
    pub fn dependencies(&self) -> &[DependencyPath] {
        &self.dependencies
    }

    /// Quiet period in milliseconds.
    pub const fn settle_ms(&self) -> u64 {
        self.settle_ms
    }

    /// Periodic reconciliation interval in milliseconds.
    pub const fn reconcile_interval_ms(&self) -> u64 {
        self.reconcile_interval_ms
    }

    /// Maximum Markdown source bytes from the approved limits.
    pub const fn max_source_bytes(&self) -> u64 {
        self.max_source_bytes
    }
}

/// Why a document may not start authoring work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IneligibleReason {
    /// No H3 settings are stored for the project.
    NoSettings,
    /// Settings exist but carry no human configuration approval.
    Unapproved,
    /// H3 is disabled for the project.
    Disabled,
    /// The approval is revoked, superseded, or expired.
    ApprovalNotCurrent,
    /// The stored settings no longer match their scope fingerprint.
    InvalidSettings,
}

/// Whether observations may start authoring work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationEligibility {
    approved_settings_version: Option<u64>,
    reason: Option<IneligibleReason>,
    settings_version: Option<u64>,
}

impl ObservationEligibility {
    /// Approved settings that may start automatic work.
    pub fn approved(settings_version: u64) -> Result<Self, H3Error> {
        if settings_version == 0 {
            return Err(H3Error::must_be_positive("settingsVersion"));
        }
        Ok(Self {
            approved_settings_version: Some(settings_version),
            reason: None,
            settings_version: Some(settings_version),
        })
    }

    /// Scan-only observation.
    pub const fn ineligible(reason: IneligibleReason, settings_version: Option<u64>) -> Self {
        Self {
            approved_settings_version: None,
            reason: Some(reason),
            settings_version,
        }
    }

    /// Derives eligibility from the current settings and approval.
    ///
    /// Settings without a human approval, disabled settings, revoked or
    /// expired approvals, and tampered settings are all scan-only. This
    /// function performs no I/O and never treats a receipt or repository file
    /// as approval.
    pub fn from_settings(settings: Option<&H3Settings>, now: Timestamp) -> Self {
        let Some(settings) = settings else {
            return Self::ineligible(IneligibleReason::NoSettings, None);
        };
        let version = Some(settings.version());
        if !settings.verify_fingerprint() {
            return Self::ineligible(IneligibleReason::InvalidSettings, version);
        }
        if !settings.enabled() {
            return Self::ineligible(IneligibleReason::Disabled, version);
        }
        let Some(approval) = settings.approval() else {
            return Self::ineligible(IneligibleReason::Unapproved, version);
        };
        if !approval.is_current_at(now) {
            return Self::ineligible(IneligibleReason::ApprovalNotCurrent, version);
        }
        if approval.settings_version() != settings.version()
            || approval.project_id() != settings.project_id()
        {
            return Self::ineligible(IneligibleReason::InvalidSettings, version);
        }
        Self {
            approved_settings_version: Some(settings.version()),
            reason: None,
            settings_version: version,
        }
    }

    /// Whether stable revisions may start authoring work.
    pub const fn is_approved(&self) -> bool {
        self.approved_settings_version.is_some()
    }

    /// Approved settings version, when eligible.
    pub const fn approved_settings_version(&self) -> Option<u64> {
        self.approved_settings_version
    }

    /// Stored settings version this value was derived from.
    pub const fn settings_version(&self) -> Option<u64> {
        self.settings_version
    }

    /// Why the document is ineligible, when it is.
    pub const fn ineligible_reason(&self) -> Option<IneligibleReason> {
        self.reason
    }
}

/// Injected wall and monotonic clock.
pub trait ObservationClock {
    /// Reads both clocks at one instant.
    fn read(&self) -> ClockReading;
}

/// Process clock backed by `Instant` and the system wall clock.
#[derive(Debug)]
pub struct SystemObservationClock {
    started: Instant,
}

impl SystemObservationClock {
    /// Starts a clock at the current instant.
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl Default for SystemObservationClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ObservationClock for SystemObservationClock {
    fn read(&self) -> ClockReading {
        let monotonic = self.started.elapsed().as_millis();
        let monotonic_millis = u64::try_from(monotonic).unwrap_or(u64::MAX);
        ClockReading::new(Timestamp::now(), monotonic_millis)
    }
}

/// Why one exact read failed or was not usable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceReadError {
    /// The path was not a canonical project-relative path.
    InvalidPath,
    /// The file does not exist.
    NotFound,
    /// The path is not a regular file.
    NotRegularFile,
    /// Canonicalization escaped the project root (for example a symlink).
    OutsideProject,
    /// The host filesystem returned an error.
    Io {
        /// Sanitized operating-system detail.
        detail: String,
    },
}

impl SourceReadError {
    /// Stable label for reports.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidPath => "invalid_path",
            Self::NotFound => "not_found",
            Self::NotRegularFile => "not_regular_file",
            Self::OutsideProject => "outside_project",
            Self::Io { .. } => "io",
        }
    }
}

/// One exact byte read plus whether the file remained stable during it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRead {
    bytes: Vec<u8>,
    stable: bool,
}

impl FileRead {
    /// Creates a read result.
    pub fn new(bytes: Vec<u8>, stable: bool) -> Self {
        Self { bytes, stable }
    }

    /// Exact bytes observed.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether length and modification time did not change during the read.
    pub const fn is_stable(&self) -> bool {
        self.stable
    }
}

/// Injected exact-content reader.
pub trait SourceReadPort {
    /// Reads one validated project-relative path.
    fn read(&self, path: &str) -> Result<FileRead, SourceReadError>;
}

/// `std::fs` reader rooted at one canonical project directory.
///
/// The reader rejects `..`, absolute paths, and canonical targets outside the
/// project root (including symlink escapes). It reads through one open handle
/// and compares metadata before and after so an unstable read is reported
/// rather than treated as a stable revision.
#[derive(Debug, Clone)]
pub struct FilesystemSourceReader {
    root: PathBuf,
}

impl FilesystemSourceReader {
    /// Creates a reader for an existing project root.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, H3Error> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(H3Error::invalid(
                "projectRoot",
                "the project root must be an absolute path",
            ));
        }
        let canonical = fs::canonicalize(root).map_err(|error| H3Error::Storage {
            detail: format!("cannot canonicalize the project root: {error}"),
        })?;
        if !canonical.is_dir() {
            return Err(H3Error::invalid(
                "projectRoot",
                "the project root must be a directory",
            ));
        }
        Ok(Self { root: canonical })
    }

    /// Canonical project root.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl SourceReadPort for FilesystemSourceReader {
    fn read(&self, path: &str) -> Result<FileRead, SourceReadError> {
        validate_relative_path(path).map_err(|_| SourceReadError::InvalidPath)?;
        let joined = self.root.join(path);
        let canonical = fs::canonicalize(&joined).map_err(map_read_error)?;
        if !canonical.starts_with(&self.root) {
            return Err(SourceReadError::OutsideProject);
        }
        let mut file = fs::File::open(&canonical).map_err(map_read_error)?;
        let before = file.metadata().map_err(map_read_error)?;
        if !before.is_file() {
            return Err(SourceReadError::NotRegularFile);
        }
        let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
        file.read_to_end(&mut bytes).map_err(map_read_error)?;
        let after = file.metadata().map_err(map_read_error)?;
        let modified_same = match (before.modified(), after.modified()) {
            (Ok(left), Ok(right)) => left == right,
            _ => true,
        };
        let stable =
            before.len() == after.len() && modified_same && bytes.len() as u64 == after.len();
        Ok(FileRead::new(bytes, stable))
    }
}

fn map_read_error(error: std::io::Error) -> SourceReadError {
    if error.kind() == std::io::ErrorKind::NotFound {
        SourceReadError::NotFound
    } else {
        SourceReadError::Io {
            detail: error.to_string(),
        }
    }
}

/// Which companion file was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionFileKind {
    /// The formal `.html` companion.
    Html,
    /// The evaluation receipt in `docs/sdd/html-evidence`.
    Receipt,
}

impl CompanionFileKind {
    /// Stable label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Receipt => "receipt",
        }
    }
}

/// One host publication write that the observer may absorb as self.
///
/// Task 19 owns the execution. The expected-write interface lets the observer
/// compare an observed companion or receipt digest with the request ID and
/// bytes the host intended to write; a match is a self-notification, not an
/// external conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedPublicationWrite {
    publication: PublicationId,
    request: PublicationRequestId,
    document: DocumentKey,
    html_digest: ContentDigest,
    receipt_digest: Option<ContentDigest>,
}

impl ExpectedPublicationWrite {
    /// Creates an expected write for one document.
    pub fn new(
        publication: PublicationId,
        request: PublicationRequestId,
        document: DocumentKey,
        html_digest: ContentDigest,
    ) -> Result<Self, H3Error> {
        let project = document.project_id();
        publication.validate_in(project)?;
        Ok(Self {
            publication,
            request,
            document,
            html_digest,
            receipt_digest: None,
        })
    }

    /// Binds the exact receipt bytes that publication will write.
    pub fn with_receipt(mut self, receipt_digest: ContentDigest) -> Self {
        self.receipt_digest = Some(receipt_digest);
        self
    }

    /// Publication journal identifier.
    pub const fn publication(&self) -> PublicationId {
        self.publication
    }

    /// H1 publication request identifier.
    pub const fn request(&self) -> &PublicationRequestId {
        &self.request
    }

    /// Document being published.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Expected exact HTML bytes.
    pub const fn html_digest(&self) -> &ContentDigest {
        &self.html_digest
    }

    /// Expected exact receipt bytes, when one will be written.
    pub const fn receipt_digest(&self) -> Option<&ContentDigest> {
        self.receipt_digest.as_ref()
    }
}

/// Path of the deterministic evaluation receipt for one document.
pub fn html_evidence_path(document: &DocumentKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(document.target_path().as_bytes());
    format!("{HTML_EVIDENCE_DIR}/{}.json", hex(&hasher.finalize()))
}

/// Aggregate fingerprint recipe for one dependency kind.
///
/// The digest covers the kind label and every sorted `(path, exact-file-digest)`
/// pair. The observer and later publication/evidence code use this one recipe
/// so a CSS or resource read-set can be compared without redefining it.
pub fn dependency_fingerprint<'a>(
    kind: DependencyKind,
    entries: impl IntoIterator<Item = (&'a str, ContentDigest)>,
) -> ContentDigest {
    let mut entries: Vec<(&str, ContentDigest)> = entries.into_iter().collect();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    let mut hasher = Sha256::new();
    hasher.update(b"h3-dependency-set\0");
    hasher.update(kind.as_str().as_bytes());
    for (path, digest) in entries {
        hasher.update(b"\0");
        hasher.update(path.as_bytes());
        hasher.update(b"\0");
        hasher.update(digest.as_str().as_bytes());
    }
    ContentDigest::sha256(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// How the observer learned that a stable revision was available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationTrigger {
    /// First full scan when the project was opened.
    InitialScan,
    /// A merged file notification settled.
    FileNotification,
    /// The periodic reconciliation found a change.
    PeriodicScan,
    /// A watcher-recovery scan resynchronised the revision.
    WatcherRecovery,
}

/// How the stable bytes relate to the last emitted revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceChange {
    /// First observation of this document in the process.
    Initial,
    /// Bytes differ from the last emitted revision.
    Modified,
    /// Bytes are exactly the last emitted revision.
    Unchanged,
}

/// One stable source observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceObservation {
    /// Document observed.
    pub document: DocumentKey,
    /// Monotonic revision and exact digest.
    pub snapshot: SourceSnapshot,
    /// Relationship to the last emitted revision.
    pub change: SourceChange,
    /// Trigger for this read.
    pub trigger: ObservationTrigger,
    /// Notification sources merged into the final read.
    pub observed_via: Vec<ChangeSource>,
    /// Current settings eligibility.
    pub eligibility: ObservationEligibility,
}

impl SourceObservation {
    /// Whether Task 16 may turn this observation into authoring work.
    pub fn is_authoring_candidate(&self) -> bool {
        self.eligibility.is_approved()
            && matches!(self.change, SourceChange::Initial | SourceChange::Modified)
            && self.trigger != ObservationTrigger::WatcherRecovery
    }
}

/// One dependency fingerprint change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyInvalidation {
    /// Fingerprint kind that changed.
    pub kind: FingerprintKind,
    /// Digest observed before this change.
    pub before: ContentDigest,
    /// Exact digest now observed.
    pub after: ContentDigest,
    /// Open documents whose evidence and applicability became stale.
    pub documents: Vec<DocumentKey>,
    /// Structured applicability reason to persist with each document.
    pub reason: ApplicabilityReason,
}

/// Classification of one companion or receipt observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompanionChange {
    /// The exact bytes match a registered publication write.
    SelfNotification {
        /// Publication journal identifier.
        publication: PublicationId,
        /// H1 publication request identifier.
        request: PublicationRequestId,
    },
    /// The file changed without a matching expected write.
    External,
    /// A previously observed file is now missing.
    Missing,
}

/// One companion or receipt observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionObservation {
    /// Document whose companion changed.
    pub document: DocumentKey,
    /// Companion file kind.
    pub file: CompanionFileKind,
    /// Project-relative path.
    pub path: String,
    /// Exact bytes observed, or `None` when the file disappeared.
    pub digest: Option<ContentDigest>,
    /// Self, external, or missing.
    pub change: CompanionChange,
}

/// One recovery scan result for a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReconciliation {
    /// Document reconciled.
    pub document: DocumentKey,
    /// Revision emitted before recovery, when one existed.
    pub previous: Option<SourceSnapshot>,
    /// Revision now stored after resynchronisation.
    pub current: Option<SourceSnapshot>,
    /// Whether the exact bytes differed from the previous revision.
    pub changed: bool,
}

/// Explicit uncertainty result. None of these values names an external actor
/// or guesses why a file changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationUncertainty {
    /// The source changed while it was being read.
    UnstableRead {
        /// Document observed.
        document: DocumentKey,
        /// Time of the read.
        at: Timestamp,
    },
    /// The source could not be read exactly.
    UnreadableSource {
        /// Document observed.
        document: DocumentKey,
        /// Structured read failure.
        reason: SourceReadError,
        /// Time of the read.
        at: Timestamp,
    },
    /// The Markdown exceeded the approved source limit; it was not truncated.
    SourceTooLarge {
        /// Document observed.
        document: DocumentKey,
        /// Bytes observed.
        bytes: u64,
        /// Approved maximum.
        max: u64,
        /// Time of the read.
        at: Timestamp,
    },
    /// A content change was found without a matching notification.
    MissedNotification {
        /// Document affected.
        document: DocumentKey,
        /// Time the periodic scan found it.
        at: Timestamp,
    },
    /// A dependency could not be read exactly.
    UnreadableDependency {
        /// Dependency kind.
        kind: DependencyKind,
        /// Project-relative path.
        path: String,
        /// Structured read failure.
        reason: SourceReadError,
        /// Time of the read.
        at: Timestamp,
    },
    /// A dependency changed during its read.
    UnstableDependency {
        /// Dependency kind.
        kind: DependencyKind,
        /// Project-relative path.
        path: String,
        /// Time of the read.
        at: Timestamp,
    },
    /// A companion or receipt could not be read exactly.
    UnreadableCompanion {
        /// Document whose companion was read.
        document: DocumentKey,
        /// Companion file kind.
        file: CompanionFileKind,
        /// Structured read failure.
        reason: SourceReadError,
        /// Time of the read.
        at: Timestamp,
    },
    /// The watcher is unavailable. Periodic reconciliation continues.
    WatcherUnavailable {
        /// Time the failure was reported.
        at: Timestamp,
    },
    /// An internal revision contract rejected the observation.
    Contract {
        /// Sanitized detail.
        detail: String,
        /// Time of the observation.
        at: Timestamp,
    },
}

/// Watcher state visible to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherStatus {
    /// Events are expected to arrive.
    Healthy,
    /// The watcher is unavailable; periodic reconciliation continues.
    Unavailable {
        /// Wall-clock time the failure was reported.
        since: Timestamp,
    },
}

/// Current observer health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserverHealth {
    /// Watcher state.
    pub watcher: WatcherStatus,
    /// Wall-clock time of the last full scan.
    pub last_scan: Option<Timestamp>,
    /// Wall-clock time of the last full scan without uncertainty.
    pub last_successful_scan: Option<Timestamp>,
    /// Documents currently waiting for the quiet period.
    pub pending_documents: usize,
    /// Documents with an unreadable or unstable source.
    pub uncertain_documents: Vec<DocumentKey>,
}

impl ObserverHealth {
    /// Whether the watcher is currently available.
    pub const fn watcher_is_healthy(&self) -> bool {
        matches!(self.watcher, WatcherStatus::Healthy)
    }

    /// Whether any document read was not usable.
    pub fn has_uncertainty(&self) -> bool {
        !self.uncertain_documents.is_empty()
    }
}

/// One reconciliation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserverTick {
    /// Stable source observations in processing order.
    pub sources: Vec<SourceObservation>,
    /// Dependency fingerprint invalidations.
    pub dependencies: Vec<DependencyInvalidation>,
    /// Companion and receipt observations.
    pub companions: Vec<CompanionObservation>,
    /// Watcher-recovery resynchronisations.
    pub recoveries: Vec<RecoveryReconciliation>,
    /// Explicit uncertainty results.
    pub uncertainties: Vec<ObservationUncertainty>,
    /// Health after the pass.
    pub health: ObserverHealth,
}

impl ObserverTick {
    fn new() -> Self {
        Self {
            sources: Vec::new(),
            dependencies: Vec::new(),
            companions: Vec::new(),
            recoveries: Vec::new(),
            uncertainties: Vec::new(),
            health: ObserverHealth {
                watcher: WatcherStatus::Healthy,
                last_scan: None,
                last_successful_scan: None,
                pending_documents: 0,
                uncertain_documents: Vec::new(),
            },
        }
    }

    fn extend(&mut self, other: Self) {
        self.sources.extend(other.sources);
        self.dependencies.extend(other.dependencies);
        self.companions.extend(other.companions);
        self.recoveries.extend(other.recoveries);
        self.uncertainties.extend(other.uncertainties);
    }

    /// Stable observations that may start authoring work.
    pub fn authoring_candidates(&self) -> Vec<&SourceObservation> {
        self.sources
            .iter()
            .filter(|observation| observation.is_authoring_candidate())
            .collect()
    }
}

#[derive(Debug, Clone)]
struct PendingEdit {
    last_activity: ClockReading,
    digest: Option<ContentDigest>,
    sources: BTreeSet<ChangeSource>,
}

#[derive(Debug, Clone, Default)]
struct CompanionState {
    scanned: bool,
    digest: Option<ContentDigest>,
}

#[derive(Debug, Clone)]
struct WatchedDocument {
    key: DocumentKey,
    last_emitted: Option<SourceSnapshot>,
    counter: u64,
    pending: Option<PendingEdit>,
    uncertain: bool,
    stale: Option<FingerprintKind>,
    html: CompanionState,
    receipt: CompanionState,
}

#[derive(Debug, Clone)]
struct ExpectedFile {
    write: ExpectedPublicationWrite,
    file: CompanionFileKind,
    digest: ContentDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    Initial,
    Periodic,
    Recovery,
}

/// Change observer for one open project.
///
/// A caller that closes a project drops its observer; a new open scans with the
/// caller-supplied baselines. No method sends, authors, or writes a project
/// file.
pub struct ProjectObserver<R: SourceReadPort, C: ObservationClock> {
    targets: ObservationTargets,
    eligibility: ObservationEligibility,
    reader: R,
    clock: C,
    documents: BTreeMap<DocumentKey, WatchedDocument>,
    dirty: VecDeque<DocumentKey>,
    dependencies: BTreeMap<DependencyKind, Vec<DependencyPath>>,
    dependency_digests: BTreeMap<DependencyKind, ContentDigest>,
    dependency_dirty: bool,
    companion_dirty: BTreeSet<DocumentKey>,
    expected_files: BTreeMap<String, ExpectedFile>,
    watcher: WatcherStatus,
    last_scan: Option<ClockReading>,
    last_successful_scan: Option<Timestamp>,
}

impl<R: SourceReadPort, C: ObservationClock> ProjectObserver<R, C> {
    /// Creates an observer for one open project.
    pub fn new(
        targets: ObservationTargets,
        eligibility: ObservationEligibility,
        reader: R,
        clock: C,
    ) -> Result<Self, H3Error> {
        if let Some(version) = eligibility.approved_settings_version()
            && version == 0
        {
            return Err(H3Error::must_be_positive("settingsVersion"));
        }
        let mut documents = BTreeMap::new();
        for key in targets.documents() {
            documents.insert(
                key.clone(),
                WatchedDocument {
                    key: key.clone(),
                    last_emitted: None,
                    counter: 0,
                    pending: None,
                    uncertain: false,
                    stale: None,
                    html: CompanionState::default(),
                    receipt: CompanionState::default(),
                },
            );
        }
        let mut dependencies: BTreeMap<DependencyKind, Vec<DependencyPath>> = BTreeMap::new();
        for dependency in targets.dependencies() {
            dependencies
                .entry(dependency.kind())
                .or_default()
                .push(dependency.clone());
        }
        Ok(Self {
            targets,
            eligibility,
            reader,
            clock,
            documents,
            dirty: VecDeque::new(),
            dependencies,
            dependency_digests: BTreeMap::new(),
            dependency_dirty: false,
            companion_dirty: BTreeSet::new(),
            expected_files: BTreeMap::new(),
            watcher: WatcherStatus::Healthy,
            last_scan: None,
            last_successful_scan: None,
        })
    }

    /// Caller-supplied Target and dependency set.
    pub const fn targets(&self) -> &ObservationTargets {
        &self.targets
    }

    /// Current settings eligibility.
    pub const fn eligibility(&self) -> ObservationEligibility {
        self.eligibility
    }

    /// Replaces settings eligibility before the next observation is emitted.
    pub fn set_eligibility(&mut self, eligibility: ObservationEligibility) {
        self.eligibility = eligibility;
    }

    /// Restores a stored source revision so a restart continues monotonically.
    pub fn seed_source(
        &mut self,
        document: &DocumentKey,
        snapshot: SourceSnapshot,
    ) -> Result<(), H3Error> {
        document.validate_in(self.targets.project_id())?;
        let Some(state) = self.documents.get_mut(document) else {
            return Err(H3Error::invalid(
                "document",
                "the document is not part of the observed Target set",
            ));
        };
        state.counter = state.counter.max(snapshot.revision().get());
        state.last_emitted = Some(snapshot);
        state.pending = None;
        self.dirty.retain(|key| key != document);
        Ok(())
    }

    /// Restores a stored dependency fingerprint.
    pub fn seed_dependency(&mut self, kind: DependencyKind, digest: ContentDigest) {
        self.dependency_digests.insert(kind, digest);
    }

    /// Current dependency fingerprint, when one has been seeded or scanned.
    pub fn dependency_digest(&self, kind: DependencyKind) -> Option<&ContentDigest> {
        self.dependency_digests.get(&kind)
    }

    /// Registers one expected publication write.
    ///
    /// Both the HTML and (when supplied) receipt paths are registered. A
    /// duplicate registration with identical values is idempotent; different
    /// bytes or another publication for the same paths conflict.
    pub fn expect_publication_write(
        &mut self,
        write: ExpectedPublicationWrite,
    ) -> Result<(), H3Error> {
        if !self.documents.contains_key(&write.document) {
            return Err(H3Error::invalid(
                "document",
                "the document is not part of the observed Target set",
            ));
        }
        for existing in self.expected_files.values() {
            if existing.write.publication == write.publication && existing.write == write {
                return Ok(());
            }
            if existing.write.publication == write.publication {
                return Err(H3Error::RecordConflict {
                    record: "expected publication write",
                    id: write.publication.to_string(),
                });
            }
        }
        let html_path = write.document.companion_path();
        let receipt_path = html_evidence_path(&write.document);
        let mut entries = vec![(
            html_path,
            ExpectedFile {
                write: write.clone(),
                file: CompanionFileKind::Html,
                digest: write.html_digest.clone(),
            },
        )];
        if let Some(receipt) = &write.receipt_digest {
            entries.push((
                receipt_path,
                ExpectedFile {
                    write: write.clone(),
                    file: CompanionFileKind::Receipt,
                    digest: receipt.clone(),
                },
            ));
        }
        for (path, entry) in entries {
            if self.expected_files.contains_key(&path) {
                return Err(H3Error::RecordConflict {
                    record: "expected publication path",
                    id: path,
                });
            }
            self.expected_files.insert(path, entry);
        }
        Ok(())
    }

    /// Retires one publication expectation after the journal is committed.
    pub fn retire_publication_write(&mut self, publication: PublicationId) -> bool {
        let before = self.expected_files.len();
        self.expected_files
            .retain(|_, entry| entry.write.publication != publication);
        self.expected_files.len() != before
    }

    /// Delivers one notification. Returns whether it named a watched file.
    ///
    /// Repeated notifications update the same pending activity; they never
    /// create a second pending entry or a second job.
    pub fn notify(&mut self, signal: ChangeSignal) -> bool {
        let now = self.clock.read();
        if let Some(key) = self
            .documents
            .values()
            .find(|state| state.key.target_path() == signal.path)
            .map(|state| state.key.clone())
        {
            self.queue_pending(&key, now, Some(signal.source), None);
            return true;
        }
        if self
            .targets
            .dependencies()
            .iter()
            .any(|dependency| dependency.path == signal.path)
        {
            self.dependency_dirty = true;
            return true;
        }
        if let Some(key) = self
            .documents
            .values()
            .find(|state| state.key.companion_path() == signal.path)
            .map(|state| state.key.clone())
        {
            self.companion_dirty.insert(key);
            return true;
        }
        if let Some(key) = self
            .documents
            .values()
            .find(|state| html_evidence_path(&state.key) == signal.path)
            .map(|state| state.key.clone())
        {
            self.companion_dirty.insert(key);
            return true;
        }
        false
    }

    /// Reports that the filesystem watcher failed. Periodic scans continue.
    pub fn report_watcher_failure(&mut self) -> ObserverTick {
        let now = self.clock.read();
        self.watcher = WatcherStatus::Unavailable { since: now.wall() };
        let mut tick = ObserverTick::new();
        tick.uncertainties
            .push(ObservationUncertainty::WatcherUnavailable { at: now.wall() });
        self.finish_tick(tick)
    }

    /// Performs one full recovery scan and resynchronises revisions.
    ///
    /// Recovery emits no authoring candidates and never sends or writes. If the
    /// observer has never scanned, the first scan is an initial scan.
    pub fn recover_watcher(&mut self) -> ObserverTick {
        let now = self.clock.read();
        self.watcher = WatcherStatus::Healthy;
        if self.last_scan.is_none() {
            self.full_scan(ScanMode::Initial, now)
        } else {
            self.full_scan(ScanMode::Recovery, now)
        }
    }

    /// Runs the initial full scan when the project is first opened.
    pub fn initial_scan(&mut self) -> ObserverTick {
        let now = self.clock.read();
        if self.last_scan.is_some() {
            return self.poll();
        }
        self.full_scan(ScanMode::Initial, now)
    }

    /// Advances the observer: settles pending edits and runs periodic scans.
    ///
    /// Tests drive this with a fake clock; production calls it from the host
    /// timer. This method never sleeps and never performs a model or network
    /// call.
    pub fn poll(&mut self) -> ObserverTick {
        let now = self.clock.read();
        if self.last_scan.is_none() {
            return self.full_scan(ScanMode::Initial, now);
        }
        let mut tick = ObserverTick::new();
        self.drain_due_pending(now, &mut tick);
        if self.periodic_due(now) {
            let scan = self.full_scan(ScanMode::Periodic, now);
            tick.extend(scan);
        } else {
            if self.dependency_dirty {
                self.scan_dependencies(now, &mut tick);
                self.dependency_dirty = false;
            }
            if !self.companion_dirty.is_empty() {
                let dirty = std::mem::take(&mut self.companion_dirty);
                for key in dirty {
                    self.scan_companion_documents(&key, now, &mut tick);
                }
            }
        }
        self.finish_tick(tick)
    }

    /// Current health snapshot.
    pub fn health(&self) -> ObserverHealth {
        let mut uncertain = Vec::new();
        let mut pending = 0;
        for state in self.documents.values() {
            if state.pending.is_some() {
                pending += 1;
            }
            if state.uncertain {
                uncertain.push(state.key.clone());
            }
        }
        ObserverHealth {
            watcher: self.watcher,
            last_scan: self.last_scan.map(|reading| reading.wall()),
            last_successful_scan: self.last_successful_scan,
            pending_documents: pending,
            uncertain_documents: uncertain,
        }
    }

    /// Documents waiting for the quiet period, in dirty order.
    pub fn pending_documents(&self) -> Vec<DocumentKey> {
        self.dirty
            .iter()
            .filter(|key| {
                self.documents
                    .get(*key)
                    .is_some_and(|state| state.pending.is_some())
            })
            .cloned()
            .collect()
    }

    /// Whether one document is waiting for the quiet period.
    pub fn is_pending(&self, document: &DocumentKey) -> bool {
        self.documents
            .get(document)
            .is_some_and(|state| state.pending.is_some())
    }

    /// Last stable source revision, when one was emitted or seeded.
    pub fn source_snapshot(&self, document: &DocumentKey) -> Option<&SourceSnapshot> {
        self.documents
            .get(document)
            .and_then(|state| state.last_emitted.as_ref())
    }

    /// Dependency kind that invalidated this document's evidence, if any.
    pub fn stale_dependency(&self, document: &DocumentKey) -> Option<FingerprintKind> {
        self.documents.get(document).and_then(|state| state.stale)
    }

    fn full_scan(&mut self, mode: ScanMode, now: ClockReading) -> ObserverTick {
        let mut tick = ObserverTick::new();
        let uncertainties_before = tick.uncertainties.len();
        self.last_scan = Some(now);
        let keys: Vec<DocumentKey> = self.documents.keys().cloned().collect();
        for key in keys {
            match mode {
                ScanMode::Initial => self.scan_initial_source(&key, now, &mut tick),
                ScanMode::Periodic => self.detect_missed_source(&key, now, &mut tick),
                ScanMode::Recovery => self.resync_source(&key, now, &mut tick),
            }
        }
        self.scan_dependencies(now, &mut tick);
        for key in self.documents.keys().cloned().collect::<Vec<_>>() {
            self.scan_companion_documents(&key, now, &mut tick);
        }
        self.dependency_dirty = false;
        self.companion_dirty.clear();
        if tick.uncertainties.len() == uncertainties_before {
            self.last_successful_scan = Some(now.wall());
        }
        self.finish_tick(tick)
    }

    fn finish_tick(&self, mut tick: ObserverTick) -> ObserverTick {
        tick.health = self.health();
        tick
    }

    fn periodic_due(&self, now: ClockReading) -> bool {
        let Some(last) = self.last_scan else {
            return true;
        };
        elapsed_millis(last, now) >= self.targets.reconcile_interval_ms
    }

    fn queue_pending(
        &mut self,
        key: &DocumentKey,
        now: ClockReading,
        source: Option<ChangeSource>,
        digest: Option<ContentDigest>,
    ) {
        let Some(state) = self.documents.get_mut(key) else {
            return;
        };
        match &mut state.pending {
            Some(pending) => {
                pending.last_activity = now;
                if let Some(source) = source {
                    pending.sources.insert(source);
                }
                if digest.is_some() {
                    pending.digest = digest;
                }
            }
            None => {
                let mut sources = BTreeSet::new();
                if let Some(source) = source {
                    sources.insert(source);
                }
                state.pending = Some(PendingEdit {
                    last_activity: now,
                    digest,
                    sources,
                });
                self.dirty.push_back(key.clone());
            }
        }
    }

    fn clear_pending(&mut self, key: &DocumentKey) {
        if let Some(state) = self.documents.get_mut(key) {
            state.pending = None;
        }
        self.dirty.retain(|queued| queued != key);
    }

    fn requeue_pending(&mut self, key: &DocumentKey) {
        if self
            .documents
            .get(key)
            .is_some_and(|state| state.pending.is_some())
            && !self.dirty.contains(key)
        {
            self.dirty.push_back(key.clone());
        }
    }

    fn drain_due_pending(&mut self, now: ClockReading, tick: &mut ObserverTick) {
        let mut due = Vec::new();
        let mut remaining = VecDeque::new();
        while let Some(key) = self.dirty.pop_front() {
            let Some(state) = self.documents.get(&key) else {
                continue;
            };
            let Some(pending) = &state.pending else {
                continue;
            };
            if elapsed_millis(pending.last_activity, now) >= self.targets.settle_ms {
                due.push(key);
            } else {
                remaining.push_back(key);
            }
        }
        self.dirty = remaining;
        for key in due {
            self.record_stable_source(&key, now, ObservationTrigger::PeriodicScan, tick);
        }
    }

    fn scan_initial_source(
        &mut self,
        key: &DocumentKey,
        now: ClockReading,
        tick: &mut ObserverTick,
    ) {
        self.record_stable_source(key, now, ObservationTrigger::InitialScan, tick);
    }

    fn detect_missed_source(
        &mut self,
        key: &DocumentKey,
        now: ClockReading,
        tick: &mut ObserverTick,
    ) {
        if self
            .documents
            .get(key)
            .is_some_and(|state| state.pending.is_some())
        {
            return;
        }
        let read = match self.reader.read(key.target_path()) {
            Ok(read) => read,
            Err(reason) => {
                self.mark_unreadable_source(key, reason, now, tick);
                return;
            }
        };
        if !read.is_stable() {
            self.mark_unstable_source(key, now, tick);
            return;
        }
        let digest = ContentDigest::sha256(read.bytes());
        let state = self.documents.get(key).expect("watched document exists");
        let changed = state
            .last_emitted
            .as_ref()
            .is_none_or(|snapshot| snapshot.digest() != &digest);
        if !changed {
            return;
        }
        self.queue_pending(key, now, None, Some(digest));
        tick.uncertainties
            .push(ObservationUncertainty::MissedNotification {
                document: key.clone(),
                at: now.wall(),
            });
    }

    fn record_stable_source(
        &mut self,
        key: &DocumentKey,
        now: ClockReading,
        base_trigger: ObservationTrigger,
        tick: &mut ObserverTick,
    ) {
        let Some(state) = self.documents.get(key) else {
            return;
        };
        let pending_sources = state
            .pending
            .as_ref()
            .map(|pending| pending.sources.clone())
            .unwrap_or_default();
        let pending_digest = state
            .pending
            .as_ref()
            .and_then(|pending| pending.digest.clone());
        let trigger = if pending_sources.is_empty() {
            base_trigger
        } else {
            ObservationTrigger::FileNotification
        };
        let previous = state.last_emitted.clone();
        let counter = state.counter;
        let read = match self.reader.read(key.target_path()) {
            Ok(read) => read,
            Err(reason) => {
                self.clear_pending(key);
                self.mark_unreadable_source(key, reason, now, tick);
                return;
            }
        };
        if !read.is_stable() {
            if let Some(state) = self.documents.get_mut(key)
                && let Some(pending) = &mut state.pending
            {
                pending.last_activity = now;
            }
            self.requeue_pending(key);
            self.mark_unstable_source(key, now, tick);
            return;
        }
        let bytes = read.bytes();
        if bytes.len() as u64 > self.targets.max_source_bytes {
            self.clear_pending(key);
            if let Some(state) = self.documents.get_mut(key) {
                state.uncertain = true;
            }
            tick.uncertainties
                .push(ObservationUncertainty::SourceTooLarge {
                    document: key.clone(),
                    bytes: bytes.len() as u64,
                    max: self.targets.max_source_bytes,
                    at: now.wall(),
                });
            return;
        }
        let digest = ContentDigest::sha256(bytes);
        if let Some(pending_digest) = pending_digest
            && pending_digest != digest
        {
            if let Some(state) = self.documents.get_mut(key)
                && let Some(pending) = &mut state.pending
            {
                pending.digest = Some(digest);
                pending.last_activity = now;
            }
            self.requeue_pending(key);
            return;
        }
        let change = match &previous {
            None => SourceChange::Initial,
            Some(snapshot) if snapshot.digest() == &digest => SourceChange::Unchanged,
            Some(_) => SourceChange::Modified,
        };
        let snapshot = match change {
            SourceChange::Unchanged => previous
                .clone()
                .expect("an unchanged source has a previous snapshot"),
            SourceChange::Initial | SourceChange::Modified => {
                let next = counter.saturating_add(1);
                match SourceSnapshot::observe(previous.as_ref(), next, digest) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        self.clear_pending(key);
                        tick.uncertainties.push(ObservationUncertainty::Contract {
                            detail: error.to_string(),
                            at: now.wall(),
                        });
                        return;
                    }
                }
            }
        };
        let state = self
            .documents
            .get_mut(key)
            .expect("watched document exists");
        state.counter = snapshot.revision().get();
        if matches!(change, SourceChange::Initial | SourceChange::Modified) {
            state.last_emitted = Some(snapshot.clone());
        }
        state.pending = None;
        state.uncertain = false;
        self.dirty.retain(|queued| queued != key);
        tick.sources.push(SourceObservation {
            document: key.clone(),
            snapshot,
            change,
            trigger,
            observed_via: pending_sources.into_iter().collect(),
            eligibility: self.eligibility,
        });
    }

    fn resync_source(&mut self, key: &DocumentKey, now: ClockReading, tick: &mut ObserverTick) {
        let Some(state) = self.documents.get(key) else {
            return;
        };
        let previous = state.last_emitted.clone();
        let counter = state.counter;
        let read = match self.reader.read(key.target_path()) {
            Ok(read) => read,
            Err(reason) => {
                self.mark_unreadable_source(key, reason, now, tick);
                tick.recoveries.push(RecoveryReconciliation {
                    document: key.clone(),
                    previous,
                    current: None,
                    changed: false,
                });
                return;
            }
        };
        if !read.is_stable() {
            self.mark_unstable_source(key, now, tick);
            tick.recoveries.push(RecoveryReconciliation {
                document: key.clone(),
                previous,
                current: None,
                changed: false,
            });
            return;
        }
        if read.bytes().len() as u64 > self.targets.max_source_bytes {
            if let Some(state) = self.documents.get_mut(key) {
                state.uncertain = true;
            }
            tick.uncertainties
                .push(ObservationUncertainty::SourceTooLarge {
                    document: key.clone(),
                    bytes: read.bytes().len() as u64,
                    max: self.targets.max_source_bytes,
                    at: now.wall(),
                });
            tick.recoveries.push(RecoveryReconciliation {
                document: key.clone(),
                previous,
                current: None,
                changed: false,
            });
            return;
        }
        let digest = ContentDigest::sha256(read.bytes());
        let changed = previous
            .as_ref()
            .is_none_or(|snapshot| snapshot.digest() != &digest);
        let next = counter.saturating_add(1);
        let current = match SourceSnapshot::observe(previous.as_ref(), next, digest) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tick.uncertainties.push(ObservationUncertainty::Contract {
                    detail: error.to_string(),
                    at: now.wall(),
                });
                return;
            }
        };
        let state = self
            .documents
            .get_mut(key)
            .expect("watched document exists");
        state.counter = current.revision().get();
        state.last_emitted = Some(current.clone());
        state.pending = None;
        state.uncertain = false;
        self.dirty.retain(|queued| queued != key);
        tick.recoveries.push(RecoveryReconciliation {
            document: key.clone(),
            previous,
            current: Some(current),
            changed,
        });
    }

    fn mark_unstable_source(
        &mut self,
        key: &DocumentKey,
        now: ClockReading,
        tick: &mut ObserverTick,
    ) {
        if let Some(state) = self.documents.get_mut(key) {
            state.uncertain = true;
        }
        tick.uncertainties
            .push(ObservationUncertainty::UnstableRead {
                document: key.clone(),
                at: now.wall(),
            });
    }

    fn mark_unreadable_source(
        &mut self,
        key: &DocumentKey,
        reason: SourceReadError,
        now: ClockReading,
        tick: &mut ObserverTick,
    ) {
        if let Some(state) = self.documents.get_mut(key) {
            state.uncertain = true;
        }
        tick.uncertainties
            .push(ObservationUncertainty::UnreadableSource {
                document: key.clone(),
                reason,
                at: now.wall(),
            });
    }

    fn scan_dependencies(&mut self, now: ClockReading, tick: &mut ObserverTick) {
        for (kind, entries) in &self.dependencies {
            let mut observed = Vec::with_capacity(entries.len());
            let mut failed = false;
            for dependency in entries {
                let read = match self.reader.read(dependency.path()) {
                    Ok(read) => read,
                    Err(reason) => {
                        tick.uncertainties
                            .push(ObservationUncertainty::UnreadableDependency {
                                kind: *kind,
                                path: dependency.path().to_owned(),
                                reason,
                                at: now.wall(),
                            });
                        failed = true;
                        break;
                    }
                };
                if !read.is_stable() {
                    tick.uncertainties
                        .push(ObservationUncertainty::UnstableDependency {
                            kind: *kind,
                            path: dependency.path().to_owned(),
                            at: now.wall(),
                        });
                    failed = true;
                    break;
                }
                observed.push((dependency.path(), ContentDigest::sha256(read.bytes())));
            }
            if failed {
                continue;
            }
            let digest = dependency_fingerprint(*kind, observed);
            match self.dependency_digests.get(kind) {
                Some(previous) if previous != &digest => {
                    let before = previous.clone();
                    self.dependency_digests.insert(*kind, digest.clone());
                    let fingerprint = kind.fingerprint_kind();
                    let documents: Vec<DocumentKey> = self.documents.keys().cloned().collect();
                    for state in self.documents.values_mut() {
                        if state.stale.is_none() {
                            state.stale = Some(fingerprint);
                        }
                    }
                    tick.dependencies.push(DependencyInvalidation {
                        kind: fingerprint,
                        before,
                        after: digest,
                        documents,
                        reason: ApplicabilityReason::DependencyChanged { fingerprint },
                    });
                }
                Some(_) => {}
                None => {
                    self.dependency_digests.insert(*kind, digest);
                }
            }
        }
    }

    fn scan_companion_documents(
        &mut self,
        key: &DocumentKey,
        now: ClockReading,
        tick: &mut ObserverTick,
    ) {
        self.scan_companion_file(key, CompanionFileKind::Html, now, tick);
        self.scan_companion_file(key, CompanionFileKind::Receipt, now, tick);
    }

    fn scan_companion_file(
        &mut self,
        key: &DocumentKey,
        file: CompanionFileKind,
        now: ClockReading,
        tick: &mut ObserverTick,
    ) {
        let path = match file {
            CompanionFileKind::Html => key.companion_path(),
            CompanionFileKind::Receipt => html_evidence_path(key),
        };
        let read = match self.reader.read(&path) {
            Ok(read) => read,
            Err(SourceReadError::NotFound) => {
                let state = self
                    .documents
                    .get_mut(key)
                    .expect("watched document exists");
                let companion = match file {
                    CompanionFileKind::Html => &mut state.html,
                    CompanionFileKind::Receipt => &mut state.receipt,
                };
                let was_observed = companion.scanned && companion.digest.is_some();
                companion.scanned = true;
                companion.digest = None;
                if was_observed {
                    tick.companions.push(CompanionObservation {
                        document: key.clone(),
                        file,
                        path,
                        digest: None,
                        change: CompanionChange::Missing,
                    });
                }
                return;
            }
            Err(reason) => {
                tick.uncertainties
                    .push(ObservationUncertainty::UnreadableCompanion {
                        document: key.clone(),
                        file,
                        reason,
                        at: now.wall(),
                    });
                return;
            }
        };
        if !read.is_stable() {
            tick.uncertainties
                .push(ObservationUncertainty::UnreadableCompanion {
                    document: key.clone(),
                    file,
                    reason: SourceReadError::Io {
                        detail: "the companion changed during its read".to_owned(),
                    },
                    at: now.wall(),
                });
            return;
        }
        let digest = ContentDigest::sha256(read.bytes());
        let expected = self.expected_files.get(&path).cloned();
        let state = self
            .documents
            .get_mut(key)
            .expect("watched document exists");
        let companion = match file {
            CompanionFileKind::Html => &mut state.html,
            CompanionFileKind::Receipt => &mut state.receipt,
        };
        let previous = companion.digest.clone();
        let was_scanned = companion.scanned;
        let changed = was_scanned && previous.as_ref() != Some(&digest);
        companion.scanned = true;
        companion.digest = Some(digest.clone());
        if !changed {
            return;
        }
        let change = match expected {
            Some(expected)
                if expected.file == file
                    && expected.write.document == *key
                    && expected.digest == digest =>
            {
                CompanionChange::SelfNotification {
                    publication: expected.write.publication,
                    request: expected.write.request,
                }
            }
            _ => CompanionChange::External,
        };
        tick.companions.push(CompanionObservation {
            document: key.clone(),
            file,
            path,
            digest: Some(digest),
            change,
        });
    }
}

fn elapsed_millis(start: ClockReading, now: ClockReading) -> u64 {
    let monotonic = now
        .monotonic_millis()
        .saturating_sub(start.monotonic_millis());
    let wall = now
        .wall()
        .as_unix_millis()
        .saturating_sub(start.wall().as_unix_millis());
    monotonic.max(wall)
}

fn validate_relative_path(path: &str) -> Result<(), H3Error> {
    if path.is_empty() {
        return Err(H3Error::empty("path"));
    }
    if path.len() > MAX_DOCUMENT_PATH_BYTES {
        return Err(H3Error::invalid("path", "the path exceeds the byte limit"));
    }
    if path.starts_with('/') || path.contains('\\') {
        return Err(H3Error::invalid(
            "path",
            "the path must be project-relative with '/' separators",
        ));
    }
    if path.chars().any(char::is_control) {
        return Err(H3Error::invalid(
            "path",
            "control characters are not allowed",
        ));
    }
    if path
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(H3Error::invalid(
            "path",
            "the path must not contain empty, '.' or '..' components",
        ));
    }
    Ok(())
}
