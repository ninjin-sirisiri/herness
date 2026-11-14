//! H4's H3 required-document set and completion barrier.
//!
//! The required set is a **union**, never the plan's `htmlTargets` alone:
//!
//! * the documents the common-Target scan confirms were created or changed
//!   during the Task,
//! * the project canonical specs and the executing plan the Task references,
//! * the Task's declared `htmlTargets`,
//! * every document H3 recorded under a dependency fingerprint that has since
//!   changed (shared CSS, referenced resource, policy, or approved settings).
//!
//! When the set or a dependency cannot be determined this module widens to the
//! whole declared Target scope (plus every document H3 already stores) and only
//! falls back to a human wait when even that scope is unknown. It never narrows
//! silently and never trusts the JSON enumeration alone. A determined dependency
//! change pulls in only the documents H3 recorded under the old fingerprint, so
//! an unrelated declared Target is not dragged in.
//!
//! The decision side consumes H3's read-only [`H4Barrier`](herness_html_sync::H4Barrier)
//! through [`HtmlBarrierPort`]. H4 first captures the real file bytes, the saved
//! H3 source revision, every dependency fingerprint, and the current approval,
//! and then asserts the *exact revision it verified before H2 ran the checks*.
//! A saved `Synced` response or a repository receipt alone is not trusted:
//!
//! * bytes that changed after the pre-verification capture are a mismatch even
//!   when H3 still reports the old version as synced,
//! * a saved revision that advanced past the verified revision is a mismatch
//!   even when the file returned to exactly the earlier bytes, so a stale
//!   `Synced` is never resurrected,
//! * a changed HTML companion, CSS, resource, policy, or settings fingerprint is
//!   a mismatch,
//! * a deleted or moved source is `orphaned` and needs a human decision; H4
//!   never deletes or moves the old HTML.
//!
//! Missing bootstrap/authoring/assessment is H3's work. This module reports the
//! hold and the H3-required actions; it never authors, evaluates, deletes, or
//! commits anything. An unrelated, unchanged Target that fails in H3 is
//! observed but does not stop the Task.

use std::collections::{BTreeMap, BTreeSet};

use herness_core::{ProjectId, Timestamp};
use herness_html_sync::{
    BarrierDependency, BarrierOutcome, BarrierRequest, DocumentKey, FingerprintKind, H3State,
};
use herness_supervision::ContentDigest;

use crate::StopRecord;
use crate::error::SddExecutionError;
use crate::ports::HtmlBarrierPort;
use crate::state::{HtmlSyncReason, HumanAction, StopReason};

// ---------------------------------------------------------------------------
// Required set
// ---------------------------------------------------------------------------

/// Why one document is required before the Task may finalize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DocumentOrigin {
    /// The executing plan the Task belongs to.
    Plan,
    /// A project canonical spec the plan references.
    Specification,
    /// A declared `htmlTargets` entry.
    HtmlTarget,
    /// The common-Target scan confirmed a creation or change.
    ChangedTarget,
    /// The scan found the source of a stored document gone.
    DeletedTarget,
    /// Safe widening because the set or a dependency could not be determined.
    Widened,
    /// Added because an H3 dependency fingerprint changed.
    DependencyAffected,
}

impl DocumentOrigin {
    /// Stable label used in reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Specification => "specification",
            Self::HtmlTarget => "html_target",
            Self::ChangedTarget => "changed_target",
            Self::DeletedTarget => "deleted_target",
            Self::Widened => "widened",
            Self::DependencyAffected => "dependency_affected",
        }
    }
}

/// One required document and every reason it entered the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredDocument {
    path: String,
    origins: BTreeSet<DocumentOrigin>,
}

impl RequiredDocument {
    fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            origins: BTreeSet::new(),
        }
    }

    fn add(&mut self, origin: DocumentOrigin) {
        self.origins.insert(origin);
    }

    /// Canonical project-relative Markdown path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Every reason this document is required.
    pub fn origins(&self) -> impl Iterator<Item = DocumentOrigin> + '_ {
        self.origins.iter().copied()
    }

    /// Whether one reason applies.
    pub fn has_origin(&self, origin: DocumentOrigin) -> bool {
        self.origins.contains(&origin)
    }

    /// Whether the scan found this document's source gone.
    pub fn is_deleted(&self) -> bool {
        self.origins.contains(&DocumentOrigin::DeletedTarget)
    }
}

/// The union of every required document, in canonical path order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredDocumentSet {
    documents: Vec<RequiredDocument>,
    widened: bool,
}

impl RequiredDocumentSet {
    /// The required documents.
    pub fn documents(&self) -> &[RequiredDocument] {
        &self.documents
    }

    /// Canonical paths in order.
    pub fn paths(&self) -> Vec<String> {
        self.documents
            .iter()
            .map(|document| document.path.clone())
            .collect()
    }

    /// Whether the set was widened past the confirmed enumeration.
    pub const fn widened(&self) -> bool {
        self.widened
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// One required document by path.
    pub fn get(&self, path: &str) -> Option<&RequiredDocument> {
        self.documents.iter().find(|document| document.path == path)
    }
}

/// One saved H3 source revision and exact digest the scan compares against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTarget {
    path: String,
    digest: ContentDigest,
}

impl StoredTarget {
    /// Records one stored Target and its saved source digest.
    pub fn new(path: impl Into<String>, digest: ContentDigest) -> Self {
        Self {
            path: path.into(),
            digest,
        }
    }

    /// Target path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Saved source digest.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

/// One exact common-Target observation. `None` means the source is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedTarget {
    path: String,
    digest: Option<ContentDigest>,
}

impl ScannedTarget {
    /// Records one observed Target.
    pub fn new(path: impl Into<String>, digest: Option<ContentDigest>) -> Self {
        Self {
            path: path.into(),
            digest,
        }
    }

    /// Target path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Exact current source digest, or absent.
    pub const fn digest(&self) -> Option<&ContentDigest> {
        self.digest.as_ref()
    }
}

/// Everything the required-set union is built from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequiredSetInputs {
    /// The Task's declared `htmlTargets`.
    pub html_targets: Vec<String>,
    /// The executing plan path.
    pub plan_paths: Vec<String>,
    /// Project canonical specs the plan references.
    pub project_specs: Vec<String>,
    /// The declared common Target scope (the approved H3 Target set).
    pub declared_targets: Vec<String>,
    /// Documents H3 already stores for this project.
    pub stored: Vec<StoredTarget>,
    /// Exact observations taken before the Task started.
    ///
    /// This is the pre-Task side of the common-Target scan. When it is empty the
    /// saved H3 stored set is used instead, which is the last observation H3
    /// recorded for each Target.
    pub scanned_before: Vec<ScannedTarget>,
    /// Exact observations taken after the Task's child finished.
    pub scanned: Vec<ScannedTarget>,
    /// Dependency kinds whose fingerprint changed.
    pub dependency_changes: Vec<FingerprintKind>,
    /// Documents H3 recorded under a dependency fingerprint that has since
    /// changed. The dependency relationship is per document, so only these are
    /// affected — not every declared Target.
    pub dependency_affected: Vec<String>,
    /// Paths whose bytes or presence could not be determined.
    pub uncertain: Vec<String>,
}

/// Why the required set could not be established at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierHold {
    reason: HtmlSyncReason,
    documents: Vec<String>,
    detail: String,
    required_actions: Vec<String>,
}

impl BarrierHold {
    /// Creates a hold.
    pub fn new(
        reason: HtmlSyncReason,
        documents: Vec<String>,
        detail: impl Into<String>,
        required_actions: Vec<String>,
    ) -> Self {
        let mut documents = documents;
        documents.sort();
        documents.dedup();
        Self {
            reason,
            documents,
            detail: detail.into(),
            required_actions,
        }
    }

    /// Structured reason.
    pub const fn reason(&self) -> HtmlSyncReason {
        self.reason
    }

    /// Documents the hold covers.
    pub fn documents(&self) -> &[String] {
        &self.documents
    }

    /// Sanitized explanation. It never carries source bytes.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Actions H3 already asks for, when it named any.
    pub fn required_actions(&self) -> &[String] {
        &self.required_actions
    }

    /// The durable stop this hold becomes.
    pub fn stop(&self) -> Result<StopRecord, SddExecutionError> {
        StopRecord::new(self.reason.stop_reason(), Some(self.reason.human_action()))
    }
}

/// The union result: either a set, or an explicit human wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequiredSetOutcome {
    /// The union is established.
    Ready(RequiredDocumentSet),
    /// The union cannot be established; a human decides.
    HumanWait(BarrierHold),
}

/// Computes the required-document union.
///
/// The union is built from the Task's `htmlTargets`, the plan, the project
/// specs, every Target the scan found created or changed, and — when a
/// dependency changed or any path is uncertain — the whole declared Target
/// scope plus every document H3 already stores. A path is never dropped because
/// H3 does not know it yet.
pub fn required_documents(inputs: &RequiredSetInputs) -> RequiredSetOutcome {
    let mut documents: BTreeMap<String, RequiredDocument> = BTreeMap::new();
    let mut insert = |path: String, origin: DocumentOrigin| {
        documents
            .entry(path.clone())
            .or_insert_with(|| RequiredDocument::new(path))
            .add(origin);
    };

    for path in &inputs.plan_paths {
        insert(path.clone(), DocumentOrigin::Plan);
    }
    for path in &inputs.project_specs {
        insert(path.clone(), DocumentOrigin::Specification);
    }
    for path in &inputs.html_targets {
        insert(normalize_target(path), DocumentOrigin::HtmlTarget);
    }

    // The pre/post common-Target scan. A document whose bytes differ from the
    // pre-Task observation, a newly created Target, and a stored document whose
    // source vanished all enter the set. A document that is unchanged before and
    // after does not, so an unrelated failing Target cannot stop the Task.
    let stored: BTreeMap<&str, &ContentDigest> = inputs
        .stored
        .iter()
        .map(|entry| (entry.path(), &entry.digest))
        .collect();
    let before: BTreeMap<&str, Option<&ContentDigest>> = if inputs.scanned_before.is_empty() {
        stored
            .iter()
            .map(|(path, digest)| (*path, Some(*digest)))
            .collect()
    } else {
        inputs
            .scanned_before
            .iter()
            .map(|entry| (entry.path(), entry.digest()))
            .collect()
    };
    let scanned: BTreeMap<&str, Option<&ContentDigest>> = inputs
        .scanned
        .iter()
        .map(|entry| (entry.path(), entry.digest()))
        .collect();
    for (path, digest) in &scanned {
        match (digest, before.get(path)) {
            // Unchanged.
            (Some(current), Some(Some(prior))) if *current == *prior => {}
            // Changed.
            (Some(_), Some(Some(_))) => {
                insert((*path).to_owned(), DocumentOrigin::ChangedTarget);
            }
            // Created during the Task.
            (Some(_), Some(None)) => {
                insert((*path).to_owned(), DocumentOrigin::ChangedTarget);
            }
            // No pre-Task observation: the path was never part of the scan, so
            // the scan confirms nothing about it. Only an explicit reference
            // makes it required.
            (Some(_), None) => {}
            // Deleted during the Task.
            (None, Some(Some(_))) => {
                insert((*path).to_owned(), DocumentOrigin::DeletedTarget);
            }
            (None, Some(None)) | (None, None) => {}
        }
    }
    // A path the pre-Task scan observed but the post-Task scan no longer reports
    // is also gone.
    for (path, prior) in &before {
        if prior.is_some() && !scanned.contains_key(path) {
            insert((*path).to_owned(), DocumentOrigin::DeletedTarget);
        }
    }

    // A CSS, resource, policy, or settings change invalidates exactly the
    // documents H3 recorded under the old fingerprint. The relationship is per
    // document, so an unrelated Target that was never synced is not dragged in.
    for path in &inputs.dependency_affected {
        insert(path.clone(), DocumentOrigin::DependencyAffected);
    }
    // A changed dependency with no document it can be tied to is undetermined:
    // widen rather than assume nothing is affected.
    let dependency_undetermined =
        !inputs.dependency_changes.is_empty() && inputs.dependency_affected.is_empty();
    let widened = !inputs.uncertain.is_empty() || dependency_undetermined;
    if widened {
        // The dependency relationship or the scan is undetermined: widen safely
        // to the whole declared scope plus everything H3 stores rather than
        // guess.
        for path in &inputs.declared_targets {
            insert(normalize_target(path), DocumentOrigin::Widened);
        }
        for path in stored.keys() {
            insert((*path).to_owned(), DocumentOrigin::Widened);
        }
        for path in scanned.keys() {
            insert((*path).to_owned(), DocumentOrigin::Widened);
        }
        for path in &inputs.uncertain {
            insert(path.clone(), DocumentOrigin::Widened);
        }
    }

    let documents = documents.into_values().collect::<Vec<_>>();
    if documents.is_empty() {
        return RequiredSetOutcome::HumanWait(BarrierHold::new(
            HtmlSyncReason::Missing,
            Vec::new(),
            "the required HTML document set could not be determined: no plan, spec, htmlTarget, \
             declared Target, or stored document is available",
            vec!["confirm the approved Target scope and resume".to_owned()],
        ));
    }
    let nothing_to_widen_to = inputs.declared_targets.is_empty()
        && inputs.stored.is_empty()
        && inputs.scanned.is_empty()
        && inputs.scanned_before.is_empty()
        && inputs.html_targets.is_empty()
        && inputs.dependency_affected.is_empty()
        && inputs.plan_paths.is_empty()
        && inputs.project_specs.is_empty();
    if nothing_to_widen_to {
        // Only the uncertain paths themselves were known and there is no wider
        // scope to fall back to. Widening is not possible.
        return RequiredSetOutcome::HumanWait(BarrierHold::new(
            HtmlSyncReason::Missing,
            documents
                .iter()
                .map(|document| document.path.clone())
                .collect(),
            "the common-Target scan is uncertain and no declared Target scope exists to widen to",
            vec!["confirm the required HTML documents and resume".to_owned()],
        ));
    }
    RequiredSetOutcome::Ready(RequiredDocumentSet { documents, widened })
}

/// Maps a companion path to the Markdown source it documents.
fn normalize_target(path: &str) -> String {
    if let Some(stem) = path.strip_suffix(".html") {
        format!("{stem}.md")
    } else {
        path.to_owned()
    }
}

// ---------------------------------------------------------------------------
// Captured documents
// ---------------------------------------------------------------------------

/// The exact revision H4 verified before H2 ran the Task's checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentBaseline {
    revision: u64,
    digest: ContentDigest,
}

impl DocumentBaseline {
    /// Records the verified revision and the exact bytes it covered.
    pub fn new(revision: u64, digest: ContentDigest) -> Result<Self, SddExecutionError> {
        if revision == 0 {
            return Err(SddExecutionError::InvalidValue {
                field: "barrier.baseline.revision".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        Ok(Self { revision, digest })
    }

    /// Saved H3 source revision verified before the Task.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Exact source digest verified before the Task.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

/// The saved H3 state of one document, read before the barrier call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedDocument {
    revision: u64,
    digest: ContentDigest,
    state: H3State,
    html_digest: Option<ContentDigest>,
}

impl SavedDocument {
    /// Records one saved document view.
    pub fn new(
        revision: u64,
        digest: ContentDigest,
        state: H3State,
        html_digest: Option<ContentDigest>,
    ) -> Result<Self, SddExecutionError> {
        if revision == 0 {
            return Err(SddExecutionError::InvalidValue {
                field: "barrier.saved.revision".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        Ok(Self {
            revision,
            digest,
            state,
            html_digest,
        })
    }

    /// Saved source revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Saved source digest.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// Saved H3 state.
    pub const fn state(&self) -> H3State {
        self.state
    }

    /// Saved candidate HTML fingerprint, when one was recorded.
    pub const fn html_digest(&self) -> Option<&ContentDigest> {
        self.html_digest.as_ref()
    }
}

/// One exact capture of a document and its dependencies at one point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedDocument {
    document: DocumentKey,
    real_digest: Option<ContentDigest>,
    html_digest: Option<ContentDigest>,
    saved: Option<SavedDocument>,
    dependencies: Vec<BarrierDependency>,
    baseline: Option<DocumentBaseline>,
}

impl CapturedDocument {
    /// Creates one capture. `real_digest` is the exact current source bytes.
    pub fn new(
        document: DocumentKey,
        real_digest: Option<ContentDigest>,
        html_digest: Option<ContentDigest>,
        saved: Option<SavedDocument>,
        dependencies: Vec<BarrierDependency>,
    ) -> Self {
        Self {
            document,
            real_digest,
            html_digest,
            saved,
            dependencies,
            baseline: None,
        }
    }

    /// Attaches the revision captured before verification.
    pub fn with_baseline(mut self, baseline: DocumentBaseline) -> Self {
        self.baseline = Some(baseline);
        self
    }

    /// Document identity.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Exact current source bytes digest, or absent.
    pub const fn real_digest(&self) -> Option<&ContentDigest> {
        self.real_digest.as_ref()
    }

    /// Exact current HTML companion digest, or absent.
    pub const fn html_digest(&self) -> Option<&ContentDigest> {
        self.html_digest.as_ref()
    }

    /// Saved H3 document view, or absent.
    pub const fn saved(&self) -> Option<&SavedDocument> {
        self.saved.as_ref()
    }

    /// Current dependency fingerprints.
    pub fn dependencies(&self) -> &[BarrierDependency] {
        &self.dependencies
    }

    /// Pre-verification baseline, when one was captured.
    pub const fn baseline(&self) -> Option<&DocumentBaseline> {
        self.baseline.as_ref()
    }
}

/// One capture of a whole project: the union inputs, every document H4 read,
/// and the paths that could not be determined.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BarrierCapture {
    /// Inputs of the required-set union.
    pub inputs: RequiredSetInputs,
    /// Captures for every declarable document.
    pub documents: Vec<CapturedDocument>,
    /// Paths whose bytes or presence could not be determined.
    pub uncertain: Vec<String>,
}

impl BarrierCapture {
    /// Looks up one captured document.
    pub fn document(&self, path: &str) -> Option<&CapturedDocument> {
        self.documents
            .iter()
            .find(|document| document.document.target_path() == path)
    }

    /// Replaces one document's baseline.
    pub fn set_baseline(&mut self, path: &str, baseline: DocumentBaseline) {
        for document in &mut self.documents {
            if document.document.target_path() == path && document.baseline.is_none() {
                document.baseline = Some(baseline.clone());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Barrier decision
// ---------------------------------------------------------------------------

/// One document's barrier result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentBarrier {
    /// The verified revision, exact bytes, and every dependency are the saved
    /// synced state.
    Synced {
        /// Saved H3 source revision.
        source_revision: u64,
        /// Exact source digest.
        source_digest: ContentDigest,
        /// Approved settings version.
        settings_version: u64,
    },
    /// The document is not currently synced.
    Unsynced {
        /// Saved public state label.
        state: String,
        /// H3's own reason label.
        reason: String,
        /// Actions H3 requires.
        required_actions: Vec<String>,
    },
    /// The exact bytes, revision, or a dependency does not match.
    Mismatch {
        /// Sanitized mismatch detail.
        detail: String,
    },
    /// The settings or human approval are absent, disabled, stale, or tampered.
    NotApproved {
        /// Sanitized detail.
        detail: String,
    },
    /// No saved H3 document exists; H3 bootstrap/authoring is required.
    Missing,
    /// The source is gone while an old companion remains. A human decides.
    Orphaned,
}

impl DocumentBarrier {
    /// Whether the document is synced.
    pub const fn is_synced(&self) -> bool {
        matches!(self, Self::Synced { .. })
    }

    /// The structured reason this result holds for, when it is not synced.
    pub fn hold_reason(&self) -> Option<HtmlSyncReason> {
        match self {
            Self::Synced { .. } => None,
            Self::Unsynced { .. } => Some(HtmlSyncReason::Unsynced),
            Self::Mismatch { .. } => Some(HtmlSyncReason::Mismatch),
            Self::NotApproved { .. } => Some(HtmlSyncReason::NotApproved),
            Self::Missing => Some(HtmlSyncReason::Missing),
            Self::Orphaned => Some(HtmlSyncReason::Orphaned),
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::Synced { .. } => String::new(),
            Self::Unsynced {
                state,
                reason,
                required_actions,
            } => {
                if required_actions.is_empty() {
                    format!("the document is {state} ({reason})")
                } else {
                    format!(
                        "the document is {state} ({reason}); required actions: {}",
                        required_actions.join(", ")
                    )
                }
            }
            Self::Mismatch { detail } | Self::NotApproved { detail } => detail.clone(),
            Self::Missing => "no saved H3 document exists yet".to_owned(),
            Self::Orphaned => "the Markdown source is gone while the old HTML remains".to_owned(),
        }
    }
}

/// One required document and its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedDocument {
    path: String,
    result: DocumentBarrier,
    required_actions: Vec<String>,
}

impl CheckedDocument {
    /// Canonical path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Barrier result.
    pub const fn result(&self) -> &DocumentBarrier {
        &self.result
    }

    /// Actions H3 named for this document.
    pub fn required_actions(&self) -> &[String] {
        &self.required_actions
    }
}

/// The whole Task's barrier decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BarrierDecision {
    /// Every required document is synced at the verified revision.
    Synced {
        /// Required documents checked.
        documents: usize,
        /// Whether the required set was widened.
        widened: bool,
    },
    /// At least one required document is not synced.
    Hold(BarrierHold),
}

impl BarrierDecision {
    /// Whether every required document is synced.
    pub const fn is_synced(&self) -> bool {
        matches!(self, Self::Synced { .. })
    }

    /// The hold, when one exists.
    pub const fn hold(&self) -> Option<&BarrierHold> {
        match self {
            Self::Synced { .. } => None,
            Self::Hold(hold) => Some(hold),
        }
    }
}

/// The complete result of one barrier check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierReport {
    decision: BarrierDecision,
    required: Vec<CheckedDocument>,
    unrelated: Vec<String>,
}

impl BarrierReport {
    /// A report that holds before any document could be checked.
    pub fn hold_decision(hold: BarrierHold) -> Self {
        Self {
            decision: BarrierDecision::Hold(hold),
            required: Vec::new(),
            unrelated: Vec::new(),
        }
    }

    /// The Task decision.
    pub const fn decision(&self) -> &BarrierDecision {
        &self.decision
    }

    /// Every required document in path order.
    pub fn required(&self) -> &[CheckedDocument] {
        &self.required
    }

    /// Captured documents outside the required set. A failure there is observed
    /// but never stops this Task.
    pub fn unrelated(&self) -> &[String] {
        &self.unrelated
    }
}

/// Checks the required set against H3.
///
/// Every required document must have a capture. H4 supplies the exact revision
/// it verified before the Task, the exact current source bytes, the current HTML
/// companion bytes, and every dependency fingerprint; H3 decides whether that
/// is the saved synced state.
pub fn check_barrier(
    port: &mut dyn HtmlBarrierPort,
    project: ProjectId,
    required: &RequiredDocumentSet,
    capture: &BarrierCapture,
    now: Timestamp,
) -> Result<BarrierReport, SddExecutionError> {
    let mut checked = Vec::with_capacity(required.documents().len());
    let mut required_paths = BTreeSet::new();

    for required_document in required.documents() {
        let path = required_document.path();
        required_paths.insert(path.to_owned());
        let (result, actions) = match capture.document(path) {
            Some(document) => evaluate_document(port, project, required_document, document, now)?,
            None => (
                DocumentBarrier::Mismatch {
                    detail: format!(
                        "the current bytes of {path} could not be captured, so it cannot be \
                         verified"
                    ),
                },
                Vec::new(),
            ),
        };
        checked.push(CheckedDocument {
            path: path.to_owned(),
            result,
            required_actions: actions,
        });
    }

    let unrelated = capture
        .documents
        .iter()
        .filter(|document| !required_paths.contains(document.document.target_path()))
        .map(|document| document.document.target_path().to_owned())
        .collect::<Vec<_>>();

    if let Some(hold) = hold_for(&checked, &capture.uncertain) {
        return Ok(BarrierReport {
            decision: BarrierDecision::Hold(hold),
            required: checked,
            unrelated,
        });
    }
    Ok(BarrierReport {
        decision: BarrierDecision::Synced {
            documents: checked.len(),
            widened: required.widened(),
        },
        required: checked,
        unrelated,
    })
}

fn evaluate_document(
    port: &mut dyn HtmlBarrierPort,
    project: ProjectId,
    required: &RequiredDocument,
    document: &CapturedDocument,
    now: Timestamp,
) -> Result<(DocumentBarrier, Vec<String>), SddExecutionError> {
    let path = required.path();
    let Some(real_digest) = document.real_digest() else {
        return Ok(if required.is_deleted() {
            (
                DocumentBarrier::Orphaned,
                vec!["resolve_orphaned_html".to_owned()],
            )
        } else {
            (
                DocumentBarrier::Missing,
                vec![
                    "bootstrap_companion".to_owned(),
                    "author_companion".to_owned(),
                ],
            )
        });
    };
    let Some(saved) = document.saved() else {
        // No saved document yet: H3 bootstrap/authoring is required. H4 never
        // creates, authors, or publishes it.
        return Ok((
            DocumentBarrier::Missing,
            vec![
                "bootstrap_companion".to_owned(),
                "author_companion".to_owned(),
            ],
        ));
    };
    if saved.state() == H3State::Orphaned {
        return Ok((
            DocumentBarrier::Orphaned,
            vec!["resolve_orphaned_html".to_owned()],
        ));
    }

    // With a pre-verification baseline, the verified revision and exact bytes
    // are the contract: a later saved revision that returned to the same bytes
    // is not the verified version, and current bytes that differ from the
    // verified ones are stale even if H3 still calls the document synced.
    let requested_revision = match document.baseline() {
        Some(baseline) => {
            if real_digest != baseline.digest() {
                return Ok((
                    DocumentBarrier::Mismatch {
                        detail: format!(
                            "the current bytes of {path} differ from the bytes verified before \
                             the Task; the saved synced version is stale"
                        ),
                    },
                    Vec::new(),
                ));
            }
            if saved.revision() != baseline.revision() {
                return Ok((
                    DocumentBarrier::Mismatch {
                        detail: format!(
                            "the saved H3 revision of {path} moved from the verified revision {} \
                             to {}; a returned-to-earlier-bytes state is not the verified version",
                            baseline.revision(),
                            saved.revision()
                        ),
                    },
                    Vec::new(),
                ));
            }
            baseline.revision()
        }
        // A document that did not exist before the Task has no earlier verified
        // version. It must still be synced for exactly its current bytes and
        // current dependency fingerprints.
        None => saved.revision(),
    };
    if saved.digest() != real_digest {
        return Ok((
            DocumentBarrier::Mismatch {
                detail: format!(
                    "the saved source digest of {path} differs from the current file bytes"
                ),
            },
            Vec::new(),
        ));
    }
    if let Some(saved_html) = saved.html_digest() {
        match document.html_digest() {
            Some(current) if current == saved_html => {}
            Some(_) => {
                return Ok((
                    DocumentBarrier::Mismatch {
                        detail: format!(
                            "the HTML companion bytes of {path} differ from the saved synced \
                             version"
                        ),
                    },
                    Vec::new(),
                ));
            }
            None => {
                return Ok((
                    DocumentBarrier::Mismatch {
                        detail: format!(
                            "the saved HTML companion of {path} is missing from the checkout"
                        ),
                    },
                    Vec::new(),
                ));
            }
        }
    }

    let request = BarrierRequest::new(
        project,
        document.document().clone(),
        requested_revision,
        real_digest.clone(),
        document.dependencies().to_vec(),
    )
    .map_err(|error| SddExecutionError::InvalidValue {
        field: "barrier.request".to_owned(),
        detail: format!("{path}: {error}"),
    })?;
    let outcome = port.check(&request, now)?;
    Ok(match outcome {
        BarrierOutcome::Synced {
            source_revision,
            source_digest,
            settings_version,
            ..
        } => (
            DocumentBarrier::Synced {
                source_revision,
                source_digest,
                settings_version,
            },
            Vec::new(),
        ),
        BarrierOutcome::Unsynced {
            status,
            reason,
            required_actions,
        } => (
            DocumentBarrier::Unsynced {
                state: status.state().as_str().to_owned(),
                reason: reason.state().as_str().to_owned(),
                required_actions: required_actions
                    .iter()
                    .map(|action| action.as_str().to_owned())
                    .collect(),
            },
            required_actions
                .iter()
                .map(|action| action.as_str().to_owned())
                .collect(),
        ),
        BarrierOutcome::Mismatch { mismatches, .. } => (
            DocumentBarrier::Mismatch {
                detail: mismatches
                    .iter()
                    .map(|mismatch| mismatch.detail())
                    .collect::<Vec<_>>()
                    .join("; "),
            },
            Vec::new(),
        ),
        BarrierOutcome::NotApproved { detail, .. } => (DocumentBarrier::NotApproved { detail }, {
            vec!["approve_settings".to_owned()]
        }),
        BarrierOutcome::Missing { .. } => (DocumentBarrier::Missing, Vec::new()),
    })
}

/// Builds the request one saved document needs for a pre-verification check.
///
/// The gate and the final barrier share this exact shape, so the revision and
/// dependencies verified before the Task are the same values asserted after it.
pub fn verification_request(
    project: ProjectId,
    document: &CapturedDocument,
) -> Result<BarrierRequest, SddExecutionError> {
    let revision = document.saved().map(SavedDocument::revision).unwrap_or(1);
    let digest = document
        .real_digest()
        .cloned()
        .or_else(|| document.saved().map(|saved| saved.digest().clone()))
        .ok_or_else(|| SddExecutionError::InvalidValue {
            field: "barrier.verificationDigest".to_owned(),
            detail: format!(
                "{} has neither current bytes nor a saved source",
                document.document().target_path()
            ),
        })?;
    BarrierRequest::new(
        project,
        document.document().clone(),
        revision,
        digest,
        document.dependencies().to_vec(),
    )
    .map_err(|error| SddExecutionError::InvalidValue {
        field: "barrier.verificationRequest".to_owned(),
        detail: format!("{}: {error}", document.document().target_path()),
    })
}

fn hold_for(checked: &[CheckedDocument], uncertain: &[String]) -> Option<BarrierHold> {
    if !uncertain.is_empty() {
        let mut paths = uncertain.to_vec();
        paths.sort();
        paths.dedup();
        return Some(BarrierHold::new(
            HtmlSyncReason::Mismatch,
            paths,
            "one or more required paths or dependency fingerprints could not be read exactly",
            vec!["resolve the HTML synchronization state and resume".to_owned()],
        ));
    }
    let mut held = checked
        .iter()
        .filter(|document| !document.result.is_synced());
    let first = held.next()?;
    let reason = first.result.hold_reason()?;
    let mut documents = vec![first.path.clone()];
    let mut details = vec![format!("{}: {}", first.path, first.result.detail())];
    let mut actions = first.required_actions.clone();
    for document in held {
        documents.push(document.path.clone());
        details.push(format!("{}: {}", document.path, document.result.detail()));
        for action in &document.required_actions {
            if !actions.contains(action) {
                actions.push(action.clone());
            }
        }
    }
    Some(BarrierHold::new(
        reason,
        documents,
        details.join("; "),
        actions,
    ))
}

impl HtmlSyncReason {
    /// The durable H4 stop this reason becomes.
    pub const fn stop_reason(self) -> StopReason {
        match self {
            Self::NotApproved => StopReason::HtmlNotApproved,
            Self::Missing => StopReason::HtmlMissing,
            Self::Mismatch => StopReason::HtmlMismatch,
            Self::Unsynced => StopReason::HtmlUnsynced,
            Self::Orphaned => StopReason::HtmlOrphaned,
        }
    }

    /// The human action the hold requires.
    pub const fn human_action(self) -> HumanAction {
        match self {
            Self::Orphaned => HumanAction::ResolveOrphanedHtml,
            Self::NotApproved | Self::Missing | Self::Mismatch | Self::Unsynced => {
                HumanAction::ResolveHtmlSync
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> ContentDigest {
        ContentDigest::sha256(label.as_bytes())
    }

    #[test]
    fn the_union_includes_changed_targets_that_html_targets_miss() {
        let inputs = RequiredSetInputs {
            html_targets: vec!["docs/adr/0001.md".to_owned()],
            plan_paths: vec!["docs/sdd/plans/plan.md".to_owned()],
            project_specs: vec!["docs/sdd/specs/spec.md".to_owned()],
            declared_targets: vec!["docs/adr/0001.md".to_owned(), "docs/adr/0002.md".to_owned()],
            stored: vec![
                StoredTarget::new("docs/adr/0001.md", digest("a")),
                StoredTarget::new("docs/adr/0002.md", digest("b")),
            ],
            scanned: vec![
                ScannedTarget::new("docs/adr/0001.md", Some(digest("a"))),
                ScannedTarget::new("docs/adr/0002.md", Some(digest("changed"))),
            ],
            ..RequiredSetInputs::default()
        };
        let RequiredSetOutcome::Ready(set) = required_documents(&inputs) else {
            panic!("a set");
        };
        let paths = set.paths();
        assert!(paths.contains(&"docs/adr/0002.md".to_owned()));
        assert!(paths.contains(&"docs/sdd/plans/plan.md".to_owned()));
        assert!(paths.contains(&"docs/sdd/specs/spec.md".to_owned()));
        assert!(!set.widened());
        assert!(
            set.get("docs/adr/0002.md")
                .expect("changed target")
                .has_origin(DocumentOrigin::ChangedTarget)
        );
    }

    #[test]
    fn a_dependency_change_adds_only_the_h3_affected_documents() {
        let inputs = RequiredSetInputs {
            html_targets: vec!["docs/adr/0001.md".to_owned()],
            plan_paths: vec!["docs/sdd/plans/plan.md".to_owned()],
            project_specs: vec!["docs/sdd/specs/spec.md".to_owned()],
            declared_targets: vec!["docs/adr/0002.md".to_owned()],
            stored: vec![StoredTarget::new("docs/adr/0003.md", digest("c"))],
            dependency_changes: vec![FingerprintKind::Css],
            dependency_affected: vec!["docs/adr/0003.md".to_owned()],
            ..RequiredSetInputs::default()
        };
        let RequiredSetOutcome::Ready(set) = required_documents(&inputs) else {
            panic!("a set");
        };
        assert!(set.paths().contains(&"docs/adr/0003.md".to_owned()));
        assert!(
            !set.paths().contains(&"docs/adr/0002.md".to_owned()),
            "an unrelated declared Target is not dragged in by a determined change"
        );
        assert!(!set.widened());
        assert!(
            set.get("docs/adr/0003.md")
                .expect("affected")
                .has_origin(DocumentOrigin::DependencyAffected)
        );
    }

    #[test]
    fn a_changed_dependency_with_no_known_document_widens() {
        let inputs = RequiredSetInputs {
            html_targets: vec!["docs/adr/0001.md".to_owned()],
            plan_paths: vec!["docs/sdd/plans/plan.md".to_owned()],
            project_specs: vec!["docs/sdd/specs/spec.md".to_owned()],
            declared_targets: vec!["docs/adr/0002.md".to_owned()],
            stored: vec![StoredTarget::new("docs/adr/0002.md", digest("c"))],
            dependency_changes: vec![FingerprintKind::Css],
            ..RequiredSetInputs::default()
        };
        let RequiredSetOutcome::Ready(set) = required_documents(&inputs) else {
            panic!("a set");
        };
        assert!(
            set.widened(),
            "an unlinkable dependency change widens instead of narrowing"
        );
        assert!(set.paths().contains(&"docs/adr/0002.md".to_owned()));
    }

    #[test]
    fn an_uncertain_dependency_widens_to_the_whole_declared_scope() {
        let inputs = RequiredSetInputs {
            html_targets: vec!["docs/adr/0001.md".to_owned()],
            plan_paths: vec!["docs/sdd/plans/plan.md".to_owned()],
            project_specs: vec!["docs/sdd/specs/spec.md".to_owned()],
            declared_targets: vec!["docs/adr/0002.md".to_owned()],
            stored: vec![StoredTarget::new("docs/adr/0003.md", digest("c"))],
            uncertain: vec!["docs/sdd/assets/sdd.css".to_owned()],
            ..RequiredSetInputs::default()
        };
        let RequiredSetOutcome::Ready(set) = required_documents(&inputs) else {
            panic!("a set");
        };
        assert!(set.widened());
        assert!(set.paths().contains(&"docs/adr/0002.md".to_owned()));
        assert!(set.paths().contains(&"docs/adr/0003.md".to_owned()));
    }

    #[test]
    fn an_uncertain_scan_without_a_declared_scope_is_a_human_wait() {
        let inputs = RequiredSetInputs {
            uncertain: vec!["docs/adr/0009.md".to_owned()],
            ..RequiredSetInputs::default()
        };
        match required_documents(&inputs) {
            RequiredSetOutcome::HumanWait(hold) => {
                assert_eq!(hold.reason(), HtmlSyncReason::Missing);
            }
            other => panic!("expected a human wait, got {other:?}"),
        }
    }

    #[test]
    fn a_deleted_source_stays_in_the_set() {
        let inputs = RequiredSetInputs {
            declared_targets: vec!["docs/adr/0001.md".to_owned()],
            stored: vec![StoredTarget::new("docs/adr/0001.md", digest("a"))],
            scanned: vec![ScannedTarget::new("docs/adr/0001.md", None)],
            ..RequiredSetInputs::default()
        };
        let RequiredSetOutcome::Ready(set) = required_documents(&inputs) else {
            panic!("a set");
        };
        assert!(
            set.get("docs/adr/0001.md")
                .expect("deleted target")
                .is_deleted()
        );
    }

    #[test]
    fn a_companion_path_is_normalized_to_its_markdown_source() {
        assert_eq!(
            normalize_target("docs/adr/0001.html"),
            "docs/adr/0001.md".to_owned()
        );
        assert_eq!(
            normalize_target("docs/adr/0001.md"),
            "docs/adr/0001.md".to_owned()
        );
    }
}
