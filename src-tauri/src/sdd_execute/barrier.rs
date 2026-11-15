//! Desktop H3 required-set capture, verification-readiness gate, and the final
//! Task barrier.
//!
//! This module is the one place that turns a bound H4 Task into the exact H3
//! required-document union and checks it against the real H3 barrier:
//!
//! * [`DesktopH4BarrierGate`] captures the real checkout bytes, the saved H3
//!   source revision and HTML fingerprint, the current shared-CSS/resource
//!   fingerprints, the stored H3 documents, and the live settings approval. It
//!   computes the union through [`herness_sdd_execute::barrier::required_documents`]
//!   and records the **verified baseline** of every captured document.
//! * The same gate implements
//!   [`ReadinessDocumentSource`](crate::sdd_execute::readiness::ReadinessDocumentSource),
//!   so H2's pre-verification gate waits on exactly that union instead of a fixed
//!   list.
//! * [`DesktopH4BarrierGate::final_barrier`] re-captures everything immediately
//!   before Task finalization and asserts the verified baseline, so a source or
//!   dependency that moved during verification holds the Task instead of
//!   finalizing stale HTML.
//!
//! H4 never authors, evaluates, deletes, moves, or commits an HTML file here.
//! Missing bootstrap/authoring/assessment stays H3's work and is reported as a
//! hold with H3's own required actions; a deleted or moved source leaves an
//! orphan that needs a human decision.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use herness_core::{ProjectId, Timestamp};
use herness_html_sync::observer::{
    DependencyKind, DependencyPath, FileRead, SourceReadError, SourceReadPort,
    dependency_fingerprint,
};
use herness_html_sync::{
    BarrierRequest, DocumentKey, FingerprintKind, H3Settings, H3State, H3StorePort,
};
use herness_sdd_execute::barrier::{
    BarrierCapture, BarrierDecision, BarrierReport, CapturedDocument, DocumentBaseline,
    DocumentOrigin, RequiredDocumentSet, RequiredSetInputs, RequiredSetOutcome, SavedDocument,
    ScannedTarget, StoredTarget, check_barrier, required_documents, verification_request,
};
use herness_sdd_execute::{
    ExecutionApproval, FailureDetails, HtmlBarrierPort, SddExecutionError, TaskCompletion,
    TaskCompletionPort, TaskCompletionRequest, TaskRef, completion_wiring,
};
use herness_supervision::ContentDigest;
use herness_supervision::supervisor::{ReadinessRequest, VerificationReadinessPort};

use crate::html_sync::composition::DesktopH4Barrier;
use crate::sdd_execute::readiness::ReadinessDocumentSource;
use crate::supervision::store::StoreHandle;

/// Exact bytes read from the approved checkout.
///
/// A missing file is `Ok(None)`; an unreadable, non-regular, escaping, or
/// unstable file is an explicit error so the gate widens or waits instead of
/// treating it as absent.
struct CheckoutReader {
    root: PathBuf,
}

impl CheckoutReader {
    fn new(root: impl AsRef<Path>) -> Result<Self, SddExecutionError> {
        let canonical = std::fs::canonicalize(root.as_ref()).map_err(|error| {
            invalid(
                "checkout.root",
                format!("cannot canonicalize the checkout: {}", error.kind()),
            )
        })?;
        if !canonical.is_dir() {
            return Err(invalid("checkout.root", "must be a directory"));
        }
        Ok(Self { root: canonical })
    }

    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, SddExecutionError> {
        match SourceReadPort::read(self, path) {
            Ok(read) if read.is_stable() => Ok(Some(read.bytes().to_vec())),
            Ok(_) => Err(invalid(
                "checkout.read",
                format!("{path} changed while it was being read"),
            )),
            Err(SourceReadError::NotFound) => Ok(None),
            Err(error) => Err(invalid(
                "checkout.read",
                format!("{path} is not readable exactly ({})", error.as_str()),
            )),
        }
    }
}

impl SourceReadPort for CheckoutReader {
    fn read(&self, path: &str) -> Result<FileRead, SourceReadError> {
        let joined = self.root.join(path);
        let canonical = std::fs::canonicalize(&joined).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => SourceReadError::NotFound,
            _ => SourceReadError::Io {
                detail: error.to_string(),
            },
        })?;
        if !canonical.starts_with(&self.root) {
            return Err(SourceReadError::OutsideProject);
        }
        let before = std::fs::metadata(&canonical).map_err(|error| SourceReadError::Io {
            detail: error.to_string(),
        })?;
        if !before.is_file() {
            return Err(SourceReadError::NotRegularFile);
        }
        let bytes = std::fs::read(&canonical).map_err(|error| SourceReadError::Io {
            detail: error.to_string(),
        })?;
        let after = std::fs::metadata(&canonical).map_err(|error| SourceReadError::Io {
            detail: error.to_string(),
        })?;
        let stable = before.len() == after.len() && before.modified().ok() == after.modified().ok();
        Ok(FileRead::new(bytes, stable))
    }
}

/// A Task bound to the exact approval and checkout it will finalize in.
#[derive(Debug, Clone)]
pub struct BoundTask {
    task: TaskRef,
    plan_paths: Vec<String>,
    project_specs: Vec<String>,
    html_targets: Vec<String>,
}

impl BoundTask {
    /// Binds one Task of one approval.
    pub fn new(approval: &ExecutionApproval, task: TaskRef) -> Result<Self, SddExecutionError> {
        let approved =
            approval
                .content()
                .task(task.number())
                .ok_or(SddExecutionError::Conflict {
                    reason: herness_sdd_execute::ConflictReason::TaskNotReady,
                    details: FailureDetails::none().boxed(),
                })?;
        let mut project_specs = approved_plan_specs(approval);
        project_specs.sort();
        project_specs.dedup();
        let plan_paths = vec![approval.plan().plan_path().as_str().to_owned()];
        Ok(Self {
            task,
            plan_paths,
            project_specs,
            html_targets: approved.html_targets().to_vec(),
        })
    }

    /// The bound Task.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// The executing plan.
    pub fn plan_paths(&self) -> &[String] {
        &self.plan_paths
    }

    /// Project canonical specs the plan references.
    pub fn project_specs(&self) -> &[String] {
        &self.project_specs
    }

    /// The Task's declared `htmlTargets`.
    pub fn html_targets(&self) -> &[String] {
        &self.html_targets
    }
}

fn approved_plan_specs(approval: &ExecutionApproval) -> Vec<String> {
    approval
        .plan()
        .spec_refs()
        .iter()
        .filter(|spec_ref| spec_ref.source() == "project")
        .map(|spec_ref| spec_ref.path().to_owned())
        .collect()
}

/// One captured dependency fingerprint set for a document.
fn document_dependencies(
    reader: &CheckoutReader,
    dependencies: &[DependencyPath],
    settings: Option<&H3Settings>,
    uncertain: &mut Vec<String>,
) -> Result<Vec<herness_html_sync::BarrierDependency>, SddExecutionError> {
    let mut entries: Vec<(DependencyKind, Vec<(String, ContentDigest)>)> = Vec::new();
    for kind in [DependencyKind::Css, DependencyKind::Resource] {
        let mut set = Vec::new();
        for dependency in dependencies
            .iter()
            .filter(|dependency| dependency.kind() == kind)
        {
            match reader.read(dependency.path()) {
                Ok(Some(bytes)) => {
                    set.push((dependency.path().to_owned(), ContentDigest::sha256(&bytes)))
                }
                Ok(None) => {
                    // A declared dependency that is currently absent is a real
                    // invalidation, not an ignorable skip.
                    set.push((dependency.path().to_owned(), ContentDigest::sha256(b"")));
                }
                Err(error) => {
                    uncertain.push(dependency.path().to_owned());
                    return Err(error);
                }
            }
        }
        // Both kinds are always asserted, even when nothing is declared: H3
        // stores a fingerprint for every mandatory kind, so an empty set is a
        // real fingerprint and a later addition invalidates the sync.
        entries.push((kind, set));
    }
    let mut dependencies = entries
        .into_iter()
        .map(|(kind, set)| {
            let fingerprint = dependency_fingerprint(
                kind,
                set.iter()
                    .map(|(path, digest)| (path.as_str(), digest.clone())),
            );
            herness_html_sync::BarrierDependency::new(kind.fingerprint_kind(), fingerprint)
        })
        .collect::<Vec<_>>();
    // The approved settings fingerprint and the approved policy fingerprint are
    // current inputs too: an approval refresh or a policy change invalidates the
    // saved sync exactly like a CSS edit.
    if let Some(settings) = settings {
        dependencies.push(herness_html_sync::BarrierDependency::new(
            FingerprintKind::Settings,
            settings.fingerprint().clone(),
        ));
        if let Some(approval) = settings.approval() {
            dependencies.push(herness_html_sync::BarrierDependency::new(
                FingerprintKind::Policy,
                approval.versions().policy_fingerprint().clone(),
            ));
        }
    }
    Ok(dependencies)
}

fn dependency_kind_of(kind: FingerprintKind) -> Option<DependencyKind> {
    match kind {
        FingerprintKind::Css => Some(DependencyKind::Css),
        FingerprintKind::Resources => Some(DependencyKind::Resource),
        _ => None,
    }
}

/// The verified derived artifacts and tracked source documents of one Task.
///
/// `derived` is every H3-produced companion and receipt the final barrier just
/// verified at its recorded revision and digest. `tracked` is every required
/// source document with the exact digest the barrier asserted, or `None` when
/// its source is absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifiedDocuments {
    derived: Vec<(String, Vec<u8>)>,
    tracked: Vec<(String, Option<ContentDigest>)>,
}

impl VerifiedDocuments {
    /// The verified HTML companions and receipts, with their exact bytes.
    pub fn derived(&self) -> &[(String, Vec<u8>)] {
        &self.derived
    }

    /// The verified source documents and their exact digests.
    pub fn tracked(&self) -> &[(String, Option<ContentDigest>)] {
        &self.tracked
    }

    /// Builds one value from an already verified derived set.
    ///
    /// A test composition and a re-checking adapter both use this; the bytes are
    /// only ever the barrier's own verified bytes.
    pub fn from_derived(derived: Vec<(String, Vec<u8>)>) -> Self {
        Self {
            derived,
            tracked: Vec::new(),
        }
    }
}

/// A barrier gate that can also report what its last final check verified.
///
/// The commit half uses this instead of re-reading the checkout for document
/// bytes: the barrier already asserted them at the recorded revision.
pub trait VerifiedDocumentSource {
    /// The documents the last final barrier verified.
    fn verified_documents(&self) -> VerifiedDocuments;
}

/// The desktop H4 barrier gate: required-set union, readiness, and final check.
pub struct DesktopH4BarrierGate {
    store: StoreHandle,
    project: ProjectId,
    reader: CheckoutReader,
    dependencies: Vec<DependencyPath>,
    barrier: DesktopH4Barrier,
    bound: Option<BoundTask>,
    baselines: std::collections::BTreeMap<String, DocumentBaseline>,
    /// The common-Target observation taken before the Task's child ran.
    pre_scan: Vec<ScannedTarget>,
    /// Whether a pre-verification capture ever ran.
    verified: bool,
    /// The capture the last final barrier checked.
    final_capture: Option<VerifiedDocuments>,
}

impl DesktopH4BarrierGate {
    /// Creates one gate over the shared H3 store and the approved checkout.
    pub fn new(
        store: StoreHandle,
        project: ProjectId,
        checkout_root: impl AsRef<Path>,
        dependencies: Vec<DependencyPath>,
    ) -> Result<Self, SddExecutionError> {
        let barrier = DesktopH4Barrier::new(store.clone());
        Ok(Self {
            store,
            project,
            reader: CheckoutReader::new(checkout_root)?,
            dependencies,
            barrier,
            bound: None,
            baselines: std::collections::BTreeMap::new(),
            pre_scan: Vec::new(),
            verified: false,
            final_capture: None,
        })
    }

    /// Binds the Task this gate verifies. Any earlier baseline is discarded.
    pub fn bind_task(
        &mut self,
        approval: &ExecutionApproval,
        task: TaskRef,
    ) -> Result<(), SddExecutionError> {
        if approval.project_id() != self.project {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "barrier approval".to_owned(),
                expected: self.project,
                found: approval.project_id(),
            });
        }
        self.bound = Some(BoundTask::new(approval, task)?);
        self.baselines.clear();
        self.pre_scan.clear();
        self.verified = false;
        self.final_capture = None;
        Ok(())
    }

    /// The bound Task, when one exists.
    pub fn bound_task(&self) -> Option<TaskRef> {
        self.bound.as_ref().map(BoundTask::task)
    }

    /// The recorded verified baselines, keyed by canonical path.
    pub fn baselines(&self) -> &std::collections::BTreeMap<String, DocumentBaseline> {
        &self.baselines
    }

    /// Whether a pre-verification capture ran for the bound Task.
    pub const fn verified(&self) -> bool {
        self.verified
    }

    /// The shared H3 store handle the gate reads.
    pub fn store_handle(&self) -> StoreHandle {
        self.store.clone()
    }

    /// Captures every required input without recording new baselines.
    fn capture(&self) -> Result<BarrierCapture, SddExecutionError> {
        let bound = self.bound.as_ref().ok_or_else(|| {
            invalid(
                "barrier.task",
                "no Task is bound to the barrier gate; bind the current Task first",
            )
        })?;
        let settings = self
            .store
            .load_html_sync_settings(self.project)
            .map_err(store_error)?
            .map(|record| record.settings().clone());
        let stored = self
            .store
            .list_html_sync_documents(self.project)
            .map_err(store_error)?;

        let declared_targets = declared_targets(&settings, bound);
        let mut candidates = BTreeSet::new();
        candidates.extend(bound.plan_paths().iter().cloned());
        candidates.extend(bound.project_specs().iter().cloned());
        candidates.extend(
            bound
                .html_targets()
                .iter()
                .map(|target| normalize_target(target)),
        );
        candidates.extend(declared_targets.iter().cloned());
        candidates.extend(
            stored
                .iter()
                .map(|record| record.state().document_key().target_path().to_owned()),
        );

        let mut uncertain = Vec::new();
        let mut scanned = Vec::new();
        let mut input_stored = Vec::new();
        let mut dependency_changes: Vec<FingerprintKind> = Vec::new();
        let mut dependency_affected: Vec<String> = Vec::new();

        let current_dependencies = document_dependencies(
            &self.reader,
            &self.dependencies,
            settings.as_ref(),
            &mut uncertain,
        )?;

        // Compare the current dependency fingerprints with every saved synced
        // document. One changed kind widens the set to the whole declared scope.

        let mut documents = Vec::new();
        for path in &candidates {
            let real = match self.reader.read(path) {
                Ok(bytes) => bytes.map(|bytes| ContentDigest::sha256(&bytes)),
                Err(_) => {
                    uncertain.push(path.clone());
                    None
                }
            };
            scanned.push(ScannedTarget::new(path.clone(), real.clone()));
            let saved = stored
                .iter()
                .find(|record| record.state().document_key().target_path() == path);
            let saved_view = saved.map(|record| {
                let state = record.state();
                SavedDocument::new(
                    state.source().revision().get(),
                    state.source().digest().clone(),
                    state.state(),
                    state
                        .fingerprints()
                        .get(FingerprintKind::Candidate)
                        .cloned(),
                )
                .expect("a stored document has a positive source revision")
            });
            if let Some(record) = saved {
                input_stored.push(StoredTarget::new(
                    path.clone(),
                    record.state().source().digest().clone(),
                ));
                let state = record.state();
                for dependency in &current_dependencies {
                    let changed = state
                        .fingerprints()
                        .get(dependency.kind())
                        .is_some_and(|saved| saved != dependency.digest())
                        && state.state() == H3State::Synced
                        && dependency_kind_of(dependency.kind()).is_some();
                    if changed {
                        if !dependency_changes.contains(&dependency.kind()) {
                            dependency_changes.push(dependency.kind());
                        }
                        if !dependency_affected.contains(path) {
                            dependency_affected.push(path.clone());
                        }
                    }
                }
            }
            let document = DocumentKey::new(self.project, path.clone()).map_err(|error| {
                invalid(
                    "barrier.document",
                    format!("{path} is not a canonical Target path: {error}"),
                )
            })?;
            let html_digest = match self.reader.read(&document.companion_path()) {
                Ok(bytes) => bytes.map(|bytes| ContentDigest::sha256(&bytes)),
                Err(_) => {
                    uncertain.push(document.companion_path());
                    None
                }
            };
            documents.push(CapturedDocument::new(
                document,
                real,
                html_digest,
                saved_view,
                current_dependencies.clone(),
            ));
        }

        Ok(BarrierCapture {
            inputs: RequiredSetInputs {
                html_targets: bound.html_targets().to_vec(),
                plan_paths: bound.plan_paths().to_vec(),
                project_specs: bound.project_specs().to_vec(),
                declared_targets,
                stored: input_stored,
                scanned_before: self.pre_scan.clone(),
                scanned,
                dependency_changes,
                dependency_affected,
                uncertain: uncertain.clone(),
            },
            documents,
            uncertain,
        })
    }

    /// Captures the current bytes and records the verified baseline of every
    /// document the Task's approval references.
    ///
    /// A baseline is recorded once; a later readiness tick re-reads the bytes and
    /// compares them with it, so an edit during the wait stays visible.
    pub fn capture_verification(&mut self) -> Result<BarrierCapture, SddExecutionError> {
        let mut capture = self.capture()?;
        self.verified = true;
        if self.pre_scan.is_empty() {
            // The first capture is the pre-Task side of the common-Target scan:
            // it is what the post-Task capture is compared with.
            self.pre_scan = capture.inputs.scanned.clone();
            capture.inputs.scanned_before = self.pre_scan.clone();
        }
        for document in &capture.documents {
            if self
                .baselines
                .contains_key(document.document().target_path())
            {
                continue;
            }
            let (Some(real), Some(saved)) = (document.real_digest(), document.saved()) else {
                continue;
            };
            if let Ok(baseline) = DocumentBaseline::new(saved.revision(), real.clone()) {
                self.baselines
                    .insert(document.document().target_path().to_owned(), baseline);
            }
        }
        Ok(capture)
    }

    /// The required set of the current capture.
    pub fn required_set(
        capture: &BarrierCapture,
    ) -> Result<RequiredDocumentSet, herness_sdd_execute::barrier::BarrierHold> {
        match required_documents(&capture.inputs) {
            RequiredSetOutcome::Ready(set) => Ok(set),
            RequiredSetOutcome::HumanWait(hold) => Err(hold),
        }
    }

    /// Runs the final barrier check immediately before Task finalization.
    ///
    /// The verified baselines recorded by [`Self::capture_verification`] are
    /// asserted, so a source or dependency that moved during verification holds
    /// the Task even when H3 still stores the earlier `Synced`.
    pub fn final_barrier(
        &mut self,
        task: TaskRef,
        now: Timestamp,
    ) -> Result<BarrierReport, SddExecutionError> {
        if self.bound_task() != Some(task) {
            return Err(invalid(
                "barrier.task",
                "the final barrier Task is not the Task bound to this gate",
            ));
        }
        if !self.verified {
            return Ok(BarrierReport::hold_decision(
                herness_sdd_execute::barrier::BarrierHold::new(
                    herness_sdd_execute::HtmlSyncReason::Mismatch,
                    Vec::new(),
                    "the pre-verification capture never ran for this Task, so no saved synced \
                     state can be treated as the verified version; re-run the Task verification",
                    vec!["resolve_html_sync".to_owned()],
                ),
            ));
        }
        let mut capture = self.capture()?;
        for (path, baseline) in &self.baselines {
            capture.set_baseline(path, baseline.clone());
        }
        // A document with no recorded baseline was never covered by the
        // pre-verification gate. It is still checked against the saved H3
        // revision and exact bytes, but a baseline is never synthesized here:
        // doing so would let a document that was unsynced before verification
        // finalize on its own later state.
        let required = match required_documents(&capture.inputs) {
            RequiredSetOutcome::Ready(set) => set,
            RequiredSetOutcome::HumanWait(hold) => {
                return Ok(BarrierReport::hold_decision(hold));
            }
        };
        let report = check_barrier(&mut self.barrier, self.project, &required, &capture, now)?;
        self.final_capture = if report.decision().is_synced() {
            Some(self.capture_verified(&required, &capture))
        } else {
            None
        };
        Ok(report)
    }

    /// Collects the exact bytes and digests the final barrier verified.
    ///
    /// Only a synced document contributes: its companion must be the bytes the
    /// saved candidate fingerprint covers, and its receipt the file H3 wrote
    /// for that target. A document outside the synced set contributes nothing.
    fn capture_verified(
        &self,
        required: &RequiredDocumentSet,
        capture: &BarrierCapture,
    ) -> VerifiedDocuments {
        let mut derived = Vec::new();
        let mut tracked = Vec::new();
        for document in required.documents() {
            let path = document.path();
            let Some(captured) = capture.document(path) else {
                continue;
            };
            tracked.push((path.to_owned(), captured.real_digest().cloned()));
            if captured
                .saved()
                .and_then(SavedDocument::html_digest)
                .is_none()
            {
                continue;
            }
            let companion = captured.document().companion_path();
            if let Some(bytes) = self.reader.read(&companion).ok().flatten() {
                derived.push((companion, bytes));
            }
            let receipt = herness_html_sync::observer::html_evidence_path(captured.document());
            if let Some(bytes) = self.reader.read(&receipt).ok().flatten() {
                derived.push((receipt, bytes));
            }
        }
        derived.sort_by(|left, right| left.0.cmp(&right.0));
        derived.dedup_by(|left, right| left.0 == right.0);
        tracked.sort_by(|left, right| left.0.cmp(&right.0));
        VerifiedDocuments { derived, tracked }
    }
}

fn normalize_target(path: &str) -> String {
    match path.strip_suffix(".html") {
        Some(stem) => format!("{stem}.md"),
        None => path.to_owned(),
    }
}

/// The declared common Target scope.
///
/// The approved H3 settings are authoritative. Without them the union falls back
/// to the plan, the project specs, and the Task's `htmlTargets`, and a dependency
/// change then has no wider declared scope to widen to.
fn declared_targets(settings: &Option<H3Settings>, bound: &BoundTask) -> Vec<String> {
    if let Some(settings) = settings {
        return settings
            .target_paths()
            .iter()
            .map(|path| normalize_target(path))
            .collect();
    }
    let mut targets = bound.html_targets().to_vec();
    targets.extend(bound.plan_paths().iter().cloned());
    targets.extend(bound.project_specs().iter().cloned());
    targets
        .into_iter()
        .map(|target| normalize_target(&target))
        .collect()
}

fn invalid(field: &str, detail: impl Into<String>) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.into(),
    }
}

fn store_error(error: herness_html_sync::H3Error) -> SddExecutionError {
    SddExecutionError::Unavailable {
        feature: format!("h4.barrier.store: {error}"),
        details: FailureDetails::none().boxed(),
    }
}

// ---------------------------------------------------------------------------
// Pre-verification readiness
// ---------------------------------------------------------------------------

/// One barrier gate shared by the pre-verification wait and the final barrier.
///
/// The two must assert the same verified baseline, so they share one gate rather
/// than re-deriving it. The mutex is never held across a host call that could
/// re-enter the gate.
pub type SharedBarrierGate = Arc<Mutex<DesktopH4BarrierGate>>;

/// Shares one gate between the readiness port and the completion seam.
pub fn shared_gate(gate: DesktopH4BarrierGate) -> SharedBarrierGate {
    Arc::new(Mutex::new(gate))
}

fn lock_gate(gate: &SharedBarrierGate) -> std::sync::MutexGuard<'_, DesktopH4BarrierGate> {
    gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Binds the Task on a shared gate.
pub fn bind_shared_gate(
    gate: &SharedBarrierGate,
    approval: &ExecutionApproval,
    task: TaskRef,
) -> Result<(), SddExecutionError> {
    lock_gate(gate).bind_task(approval, task)
}

/// The required-document source of H2's pre-verification readiness gate.
///
/// It captures the real bytes on every call and returns one barrier request per
/// required document. When the union or a dependency cannot be determined it
/// refuses with the hold detail, so the gate blocks instead of passing.
pub struct H4RequiredDocuments {
    gate: SharedBarrierGate,
}

impl H4RequiredDocuments {
    /// Creates the source over one shared gate.
    pub fn new(gate: SharedBarrierGate) -> Self {
        Self { gate }
    }

    /// Creates the source over one owned gate.
    pub fn owned(gate: DesktopH4BarrierGate) -> Self {
        Self::new(shared_gate(gate))
    }

    /// The shared gate.
    pub fn gate(&self) -> &SharedBarrierGate {
        &self.gate
    }
}

impl ReadinessDocumentSource for H4RequiredDocuments {
    fn required(&mut self, request: &ReadinessRequest) -> Result<Vec<BarrierRequest>, String> {
        let mut gate = lock_gate(&self.gate);
        if request.project_id() != gate.project {
            return Err("the readiness request names another project".to_owned());
        }
        let project = gate.project;
        let capture = gate
            .capture_verification()
            .map_err(|error| error.to_string())?;
        let required = match DesktopH4BarrierGate::required_set(&capture) {
            Ok(required) => required,
            Err(hold) => return Err(hold.detail().to_owned()),
        };
        let mut requests = Vec::new();
        let mut missing = Vec::new();
        for document in required.documents() {
            match capture.document(document.path()) {
                Some(captured) => match verification_request(project, captured) {
                    Ok(request) => requests.push(request),
                    Err(_) => missing.push(document.path().to_owned()),
                },
                None => missing.push(document.path().to_owned()),
            }
        }
        if !missing.is_empty() {
            return Err(format!(
                "the current bytes of {} could not be captured",
                missing.join(", ")
            ));
        }
        if requests.is_empty() {
            return Err("the required HTML document set is empty".to_owned());
        }
        Ok(requests)
    }
}

// ---------------------------------------------------------------------------
// Completion seam
// ---------------------------------------------------------------------------

/// The commit half of one connected Task completion.
///
/// [`NotConnectedCommit`] is the explicit refusal used when no host commit
/// adapter is bound. The desktop host-commit adapter implements it over H4's
/// `finalize_task`, so a synced barrier reaches a real host commit.
pub trait HostCommitCompletion {
    /// Whether the real host commit is connected.
    fn commit_connected(&self) -> bool;

    /// The capability reported missing when the commit half is unconnected.
    fn feature(&self) -> herness_sdd_execute::CompletionFeature {
        herness_sdd_execute::CompletionFeature::HostCommit
    }

    /// Runs the host commit for a Task whose HTML barrier is synced.
    ///
    /// `verified` is what the final barrier just asserted, so the commit half
    /// stages only documents at their verified revision.
    fn commit(
        &mut self,
        request: &TaskCompletionRequest,
        verified: &VerifiedDocuments,
    ) -> Result<TaskCompletion, SddExecutionError>;
}

/// A host commit seam that is deliberately still unconnected.
///
/// A connected HTML barrier with this half still never reports a Task complete:
/// the commit half refuses explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NotConnectedCommit;

impl NotConnectedCommit {
    /// The explicit missing commit capability.
    pub const fn feature(self) -> herness_sdd_execute::CompletionFeature {
        herness_sdd_execute::CompletionFeature::HostCommit
    }
}

impl HostCommitCompletion for NotConnectedCommit {
    fn commit_connected(&self) -> bool {
        false
    }

    fn commit(
        &mut self,
        _request: &TaskCompletionRequest,
        _verified: &VerifiedDocuments,
    ) -> Result<TaskCompletion, SddExecutionError> {
        // The HTML barrier is satisfied. The commit half is still explicitly
        // missing and never becomes a fabricated completion.
        Ok(TaskCompletion::HumanWait {
            stop: herness_sdd_execute::StopRecord::new(
                herness_sdd_execute::StopReason::CapabilityUnavailable,
                Some(herness_sdd_execute::HumanAction::ProvideCapability),
            )?,
        })
    }
}

/// The HTML half of a connected Task completion.
///
/// The barrier runs first and a hold becomes a durable `waiting_human` stop. Only
/// a synced barrier reaches the bound commit half, which either commits and
/// reports the range or holds with its own reason.
pub struct HtmlBarrierCompletion<G, C = NotConnectedCommit> {
    gate: G,
    commit: C,
}

impl<G> HtmlBarrierCompletion<G, NotConnectedCommit> {
    /// Creates the completion seam over one barrier gate with no commit half.
    pub const fn new(gate: G) -> Self {
        Self {
            gate,
            commit: NotConnectedCommit,
        }
    }
}

impl<G, C> HtmlBarrierCompletion<G, C> {
    /// Creates the completion seam over one barrier gate and commit half.
    pub const fn with_commit(gate: G, commit: C) -> Self {
        Self { gate, commit }
    }

    /// The barrier gate.
    pub const fn gate(&self) -> &G {
        &self.gate
    }

    /// The barrier gate, mutably.
    pub const fn gate_mut(&mut self) -> &mut G {
        &mut self.gate
    }

    /// The commit half.
    pub const fn commit_half(&self) -> &C {
        &self.commit
    }

    /// The commit half, mutably.
    pub const fn commit_half_mut(&mut self) -> &mut C {
        &mut self.commit
    }
}

impl<G, C> TaskCompletionPort for HtmlBarrierCompletion<G, C>
where
    G: TaskBarrierGate + VerifiedDocumentSource,
    C: HostCommitCompletion,
{
    fn wiring(&self, _task: TaskRef) -> herness_sdd_execute::CompletionWiring {
        completion_wiring(true, self.commit.commit_connected(), self.commit.feature())
    }

    fn complete(
        &mut self,
        request: &TaskCompletionRequest,
    ) -> Result<TaskCompletion, SddExecutionError> {
        let report = self.gate.final_barrier(request.task(), Timestamp::now())?;
        if let Some(hold) = report.decision().hold() {
            return Ok(TaskCompletion::HumanWait { stop: hold.stop()? });
        }
        let verified = self.gate.verified_documents();
        self.commit.commit(request, &verified)
    }
}

/// The production host-completion seam.
///
/// Before any barrier gate is bound the seam reports `not connected` for the
/// HTML barrier, so nothing is inferred. Once a gate is bound, that still
/// explicit `not connected` is replaced by the real barrier over the real H3
/// store, and a non-synced result holds the Task.
pub enum DesktopTaskCompletion {
    /// Neither half is connected yet.
    NotConnected(herness_sdd_execute::NotConnectedCompletion),
    /// The HTML barrier is connected over an owned gate; the host commit is not.
    Barrier(Box<HtmlBarrierCompletion<DesktopH4BarrierGate>>),
    /// The HTML barrier is connected over the gate the readiness port shares.
    BarrierShared(Box<HtmlBarrierCompletion<SharedBarrierGate>>),
}

impl DesktopTaskCompletion {
    /// The unconnected default.
    pub const fn not_connected() -> Self {
        Self::NotConnected(herness_sdd_execute::NotConnectedCompletion::new())
    }

    /// Connects the HTML barrier over one owned gate.
    pub fn barrier(gate: DesktopH4BarrierGate) -> Self {
        Self::Barrier(Box::new(HtmlBarrierCompletion::new(gate)))
    }

    /// Connects the HTML barrier over the gate the readiness port shares.
    pub fn barrier_shared(gate: SharedBarrierGate) -> Self {
        Self::BarrierShared(Box::new(HtmlBarrierCompletion::new(gate)))
    }

    /// Whether the HTML barrier half is connected.
    pub const fn barrier_connected(&self) -> bool {
        !matches!(self, Self::NotConnected(_))
    }
}

impl Default for DesktopTaskCompletion {
    fn default() -> Self {
        Self::not_connected()
    }
}

impl TaskCompletionPort for DesktopTaskCompletion {
    fn wiring(&self, task: TaskRef) -> herness_sdd_execute::CompletionWiring {
        match self {
            Self::NotConnected(completion) => completion.wiring(task),
            Self::Barrier(completion) => completion.wiring(task),
            Self::BarrierShared(completion) => completion.wiring(task),
        }
    }

    fn complete(
        &mut self,
        request: &TaskCompletionRequest,
    ) -> Result<TaskCompletion, SddExecutionError> {
        match self {
            Self::NotConnected(completion) => completion.complete(request),
            Self::Barrier(completion) => completion.complete(request),
            Self::BarrierShared(completion) => completion.complete(request),
        }
    }
}

/// One Task's final barrier over the real gate.
pub trait TaskBarrierGate {
    /// Re-captures the current bytes and checks them against the verified
    /// baseline.
    fn final_barrier(
        &mut self,
        task: TaskRef,
        now: Timestamp,
    ) -> Result<BarrierReport, SddExecutionError>;
}

impl TaskBarrierGate for DesktopH4BarrierGate {
    fn final_barrier(
        &mut self,
        task: TaskRef,
        now: Timestamp,
    ) -> Result<BarrierReport, SddExecutionError> {
        DesktopH4BarrierGate::final_barrier(self, task, now)
    }
}

impl TaskBarrierGate for SharedBarrierGate {
    fn final_barrier(
        &mut self,
        task: TaskRef,
        now: Timestamp,
    ) -> Result<BarrierReport, SddExecutionError> {
        lock_gate(self).final_barrier(task, now)
    }
}

impl VerifiedDocumentSource for DesktopH4BarrierGate {
    fn verified_documents(&self) -> VerifiedDocuments {
        self.final_capture.clone().unwrap_or_default()
    }
}

impl VerifiedDocumentSource for SharedBarrierGate {
    fn verified_documents(&self) -> VerifiedDocuments {
        lock_gate(self).verified_documents()
    }
}

impl<T: VerifiedDocumentSource> VerifiedDocumentSource for Box<T> {
    fn verified_documents(&self) -> VerifiedDocuments {
        (**self).verified_documents()
    }
}

impl HtmlBarrierPort for DesktopH4Barrier {
    fn check(
        &mut self,
        request: &BarrierRequest,
        now: Timestamp,
    ) -> Result<herness_html_sync::BarrierOutcome, SddExecutionError> {
        DesktopH4Barrier::check(self, request, now).map_err(|detail| {
            SddExecutionError::Unavailable {
                feature: format!("h3.barrier: {detail}"),
                details: FailureDetails::none().boxed(),
            }
        })
    }
}

/// Whether a Task's barrier report allows finalization.
pub fn barrier_allows_finalization(report: &BarrierReport) -> bool {
    matches!(report.decision(), BarrierDecision::Synced { .. })
}

/// Every required document path of one report.
pub fn required_paths(report: &BarrierReport) -> Vec<String> {
    report
        .required()
        .iter()
        .map(|document| document.path().to_owned())
        .collect()
}

/// The origins of one required document, for reports.
pub fn origins_of(set: &RequiredDocumentSet, path: &str) -> Vec<DocumentOrigin> {
    set.get(path)
        .map(|document| document.origins().collect())
        .unwrap_or_default()
}

/// Runs the pre-verification gate over a bound Task.
pub fn readiness_port(
    gate: DesktopH4BarrierGate,
) -> crate::sdd_execute::readiness::DesktopH4Readiness<H4RequiredDocuments> {
    shared_readiness_port(shared_gate(gate))
}

/// The same readiness gate over a shared barrier gate.
///
/// Both the pre-verification wait and the final barrier take this same gate, so
/// they assert the same verified baseline.
pub fn shared_readiness_port(
    gate: SharedBarrierGate,
) -> crate::sdd_execute::readiness::DesktopH4Readiness<H4RequiredDocuments> {
    let barrier = DesktopH4Barrier::new(lock_gate(&gate).store_handle());
    crate::sdd_execute::readiness::DesktopH4Readiness::new(barrier, H4RequiredDocuments::new(gate))
}

/// The readiness port trait object used by the H2 supervisor.
pub fn as_readiness_port(gate: SharedBarrierGate) -> Box<dyn VerificationReadinessPort + Send> {
    Box::new(shared_readiness_port(gate))
}
