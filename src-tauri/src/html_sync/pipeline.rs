//! Real post-candidate H3 pipeline: verification, assessment, receipt and
//! publication.
//!
//! Task 16 stopped at candidate intake (`Verifying`). This module connects that
//! intake to the already-composed host services:
//!
//! 1. exact private candidate/source/CSS/resource reads;
//! 2. the real Common SDD structural/semantic/SVG check and the real
//!    non-privileged WKWebView render;
//! 3. the versioned evidence pack and the three Html assessment methods through
//!    the existing H2 send gate;
//! 4. the Task 19 final validation and journaled publication.
//!
//! The renderer is injected. Production supplies the in-process WKWebView port;
//! the acceptance tests supply the Task 17 hidden-window child capture. A
//! missing render is an explicit unavailable check, never a fabricated pass.
//! Loopback judges are labelled as scripted in tests; this module never claims
//! real-model quality evidence.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use herness_core::{ExpectedTargetVersion, FileVersion, ProjectId, Timestamp};
use herness_html_sync::ids::PublicationId;
use herness_html_sync::observer::{DependencyKind, DependencyPath, dependency_fingerprint};
use herness_html_sync::{
    AppliedEvaluation, CandidateArtifactStore, CandidateRecord, CheckSet, ConditionBinding,
    CycleLatch, CycleState, DocumentCommit, DocumentKey, EvidenceContentStore,
    EvidenceFingerprints, EvidencePack, EvidenceValidationError, GenerationRecord,
    H3DocumentRecord, H3DocumentState, H3Error, H3FailureCause, H3Reason, H3Settings,
    H3StateReasonKind, H3StorePort, HumanWaitCause, PublicationPolicyIdentity, RequiredAction,
    RubricSet, SourceSnapshot, document_state_event,
};
use herness_html_sync::{CandidatePublication, PublicationFileInput, PublicationFileReadPort};
use herness_supervision::conditions::{ConditionDigest, ConditionVersion};
use herness_supervision::evidence::TargetVersion;
use herness_supervision::profiles::ProfileBinding;
use herness_supervision::{ContentDigest, SupervisionId};

use crate::html_sync::assessment::HtmlAssessmentHost;
use crate::html_sync::policy::ConnectedPolicyBridge;
use crate::html_sync::publish::ProjectPublicationFiles;
use crate::html_sync::render::{
    CancellationToken, RENDER_HARD_TIMEOUT, RenderBudget, RenderEvidence, RenderJob,
    RenderResource, render_candidate,
};
use crate::html_sync::verification::{
    CandidateVerificationRequest as HostVerificationRequest, FingerprintCapture, verify_candidate,
};
use crate::supervision::plan::StoredPlan;
use crate::supervision::store::StoreHandle;

/// Exact candidate bytes for one render job.
#[derive(Debug, Clone)]
pub struct RenderInput {
    /// Host-issued opaque render job id.
    pub job_id: String,
    /// Exact candidate HTML.
    pub html: Vec<u8>,
    /// Exact shared CSS.
    pub css: Vec<u8>,
    /// Exact declared resources.
    pub resources: Vec<RenderResource>,
    /// Per-candidate timeout (bounded by the remaining cycle time by the host).
    pub timeout: Duration,
}

/// Host render boundary.
///
/// The production implementation runs the in-process hidden WKWebView. The
/// acceptance implementation runs the Task 17 child capture. Both return real
/// `wkwebview-native` evidence or an explicit failure.
pub trait CandidateRenderPort: Send + Sync {
    /// Captures one complete 8-configuration render.
    fn capture(&self, input: &RenderInput) -> Result<RenderEvidence, H3Error>;
}

/// In-process WKWebView render port.
#[derive(Clone)]
pub struct NativeRenderPort {
    app: tauri::AppHandle,
}

impl NativeRenderPort {
    /// Creates the production render port for one application handle.
    pub const fn new(app: tauri::AppHandle) -> Self {
        Self { app }
    }
}

impl CandidateRenderPort for NativeRenderPort {
    fn capture(&self, input: &RenderInput) -> Result<RenderEvidence, H3Error> {
        let job = RenderJob::new(
            input.job_id.clone(),
            input.html.clone(),
            input.css.clone(),
            input.resources.clone(),
        )
        .map_err(|error| H3Error::Unavailable {
            capability: "h3.render.job".to_owned(),
            detail: error.label(),
        })?;
        let budget =
            RenderBudget::new(input.timeout.min(RENDER_HARD_TIMEOUT), None).map_err(|error| {
                H3Error::Unavailable {
                    capability: "h3.render.budget".to_owned(),
                    detail: error.label(),
                }
            })?;
        let cancellation = CancellationToken::new();
        render_candidate(&self.app, &job, budget, &cancellation).map_err(|failure| {
            H3Error::Unavailable {
                capability: "h3.render".to_owned(),
                detail: failure.error().label(),
            }
        })
    }
}

/// Exact inputs frozen for one candidate attempt.
#[derive(Debug, Clone)]
pub struct PreparedCandidate {
    /// Document.
    pub document: DocumentKey,
    /// Current durable document record.
    pub record: H3DocumentRecord,
    /// Active generation with its candidate metadata.
    pub generation: GenerationRecord,
    /// Stored candidate record.
    pub candidate: CandidateRecord,
    /// Exact authored HTML.
    pub html: String,
    /// Exact authored provenance payload.
    pub provenance: String,
    /// Exact current source bytes.
    pub source: Vec<u8>,
    /// Exact current CSS inputs.
    pub css: Vec<PublicationFileInput>,
    /// Exact current declared resources.
    pub resources: Vec<PublicationFileInput>,
}

impl PreparedCandidate {
    /// Exact source snapshot.
    pub fn source_snapshot(&self) -> &SourceSnapshot {
        self.generation.source()
    }
}

/// Assessment context derived from the approved H2 target.
#[derive(Debug, Clone)]
pub struct AssessmentContext {
    /// Four H2 condition ids in H3 order.
    pub conditions: ConditionBinding,
    /// Approved condition version.
    pub condition_version: ConditionVersion,
    /// Approved condition digest.
    pub condition_digest: ConditionDigest,
    /// Approved target version.
    pub target_version: TargetVersion,
    /// Approved evidence target.
    pub target: herness_supervision::TargetScope,
    /// Approved Html profile.
    pub profile: ProfileBinding,
    /// Fixed rubric set.
    pub rubrics: RubricSet,
}

impl AssessmentContext {
    /// Builds the context from the stored approved H2 plan and the exact
    /// human-approved Html profile.
    pub fn from_plan(
        project: ProjectId,
        plan: &StoredPlan,
        profile: ProfileBinding,
    ) -> Result<Self, H3Error> {
        let ids = plan.conditions.condition_ids();
        if ids.len() != 4 {
            return Err(H3Error::invalid(
                "conditions",
                "the approved H2 target does not have exactly four H3 conditions",
            ));
        }
        let conditions = ConditionBinding::new(project, [ids[0], ids[1], ids[2], ids[3]])
            .map_err(H3Error::from)?;
        Ok(Self {
            conditions,
            condition_version: plan.conditions.condition_version(),
            condition_digest: plan.conditions.digest().clone(),
            target_version: plan.evidence_target.version(),
            target: plan.evidence_target.clone(),
            profile,
            rubrics: RubricSet::approved(),
        })
    }
}

/// Exact fingerprint capture for one candidate attempt.
#[derive(Debug, Clone)]
pub struct HostFingerprints {
    settings: ContentDigest,
    policy: ContentDigest,
    pack: ContentDigest,
    css: ContentDigest,
    resources: ContentDigest,
    candidate: ContentDigest,
    provenance: ContentDigest,
    source: ContentDigest,
    rubric: ContentDigest,
    profile: ProfileBinding,
    condition_version: ConditionVersion,
    condition_digest: ConditionDigest,
    target_version: TargetVersion,
}

impl HostFingerprints {
    /// Captures the current exact fingerprints for one prepared candidate.
    #[allow(clippy::too_many_arguments)]
    pub fn capture(
        settings: &H3Settings,
        approval_policy: &ContentDigest,
        approval_pack: &ContentDigest,
        prepared: &PreparedCandidate,
        context: &AssessmentContext,
    ) -> Result<Self, H3Error> {
        let css = dependency_fingerprint(
            DependencyKind::Css,
            prepared
                .css
                .iter()
                .map(|input| (input.path(), input.digest())),
        );
        let resources = dependency_fingerprint(
            DependencyKind::Resource,
            prepared
                .resources
                .iter()
                .map(|input| (input.path(), input.digest())),
        );
        Ok(Self {
            settings: settings.fingerprint().clone(),
            policy: approval_policy.clone(),
            pack: approval_pack.clone(),
            css,
            resources,
            candidate: ContentDigest::sha256(prepared.html.as_bytes()),
            provenance: ContentDigest::sha256(prepared.provenance.as_bytes()),
            source: ContentDigest::sha256(&prepared.source),
            rubric: context.rubrics.digest(),
            profile: context.profile,
            condition_version: context.condition_version,
            condition_digest: context.condition_digest.clone(),
            target_version: context.target_version,
        })
    }

    /// Converts to the versioned evidence fingerprint type.
    pub fn evidence(&self) -> EvidenceFingerprints {
        EvidenceFingerprints::new(
            self.settings.clone(),
            self.policy.clone(),
            self.pack.clone(),
            self.css.clone(),
            self.resources.clone(),
            self.candidate.clone(),
            self.provenance.clone(),
            self.source.clone(),
            self.rubric.clone(),
            self.profile,
            self.condition_version,
            self.condition_digest.clone(),
            self.target_version,
        )
    }

    /// Shared settings fingerprint.
    pub const fn settings(&self) -> &ContentDigest {
        &self.settings
    }

    /// Shared policy fingerprint.
    pub const fn policy(&self) -> &ContentDigest {
        &self.policy
    }

    /// Shared pack fingerprint.
    pub const fn pack(&self) -> &ContentDigest {
        &self.pack
    }

    /// Shared CSS fingerprint.
    pub const fn css(&self) -> &ContentDigest {
        &self.css
    }

    /// Shared resource fingerprint.
    pub const fn resources(&self) -> &ContentDigest {
        &self.resources
    }
}

impl FingerprintCapture for HostFingerprints {
    fn capture(&self) -> Result<EvidenceFingerprints, H3Error> {
        Ok(self.evidence())
    }
}

/// Outcome of one post-candidate attempt.
#[derive(Debug, Clone)]
pub enum PostCandidateOutcome {
    /// The publication path completed with the exact result.
    Publication(herness_html_sync::PublicationOutcome),
    /// Verification rejected the candidate before assessment.
    VerificationRejected {
        /// Sanitized detail.
        detail: String,
        /// Whether the same child could fix it.
        fixable: bool,
    },
    /// Conditions are unmet but fixable by the same child. No file was written.
    FixableUnmet {
        /// Unmet conditions.
        conditions: Vec<herness_html_sync::H3Condition>,
    },
    /// A human is required before another attempt.
    WaitingHuman {
        /// Wait cause.
        cause: HumanWaitCause,
        /// Sanitized detail.
        detail: String,
    },
    /// The generation is no longer the active one.
    Stale,
}

/// Reads exact candidate, source, and dependency bytes for one document.
pub fn load_prepared(
    store: &mut StoreHandle,
    files: &ProjectPublicationFiles,
    candidates: &CandidateArtifactStore,
    dependencies: &[DependencyPath],
    project: ProjectId,
    document: &DocumentKey,
) -> Result<PreparedCandidate, H3Error> {
    let record = store
        .load_html_sync_document(project, document)?
        .ok_or_else(|| H3Error::NotFound {
            record: "document state",
            id: document.target_path().to_owned(),
        })?;
    let generation_id = record
        .state()
        .generation()
        .ok_or_else(|| H3Error::NotFound {
            record: "active generation",
            id: document.target_path().to_owned(),
        })?;
    let generation = store
        .html_sync_generations(project, document)?
        .into_iter()
        .find(|generation| generation.generation_id() == generation_id)
        .ok_or_else(|| H3Error::NotFound {
            record: "generation",
            id: generation_id.to_string(),
        })?;
    if generation.status() != herness_html_sync::GenerationStatus::Active {
        return Err(H3Error::RecordConflict {
            record: "generation",
            id: generation_id.to_string(),
        });
    }
    let candidate = generation
        .candidate()
        .cloned()
        .ok_or_else(|| H3Error::NotFound {
            record: "candidate",
            id: generation_id.to_string(),
        })?;
    let (html, provenance) = candidates.read_candidate_record(&candidate)?;

    let source = files
        .read(document.target_path())?
        .ok_or_else(|| H3Error::NotFound {
            record: "source",
            id: document.target_path().to_owned(),
        })?;
    if ContentDigest::sha256(&source) != *generation.source().digest() {
        return Err(H3Error::Unavailable {
            capability: "h3.verification.source".to_owned(),
            detail: "the Markdown source changed after the candidate was authored".to_owned(),
        });
    }

    let mut css = Vec::new();
    let mut resources = Vec::new();
    for dependency in dependencies {
        let kind = dependency.kind();
        let Some(bytes) = files.read(dependency.path())? else {
            continue;
        };
        let input = PublicationFileInput::new(dependency.path(), bytes)?;
        match kind {
            DependencyKind::Css => css.push(input),
            DependencyKind::Resource => resources.push(input),
        }
    }
    let css_fingerprint = dependency_fingerprint(
        DependencyKind::Css,
        css.iter().map(|input| (input.path(), input.digest())),
    );
    let resource_fingerprint = dependency_fingerprint(
        DependencyKind::Resource,
        resources.iter().map(|input| (input.path(), input.digest())),
    );
    if Some(&css_fingerprint)
        != generation
            .fingerprints()
            .get(herness_html_sync::FingerprintKind::Css)
        || Some(&resource_fingerprint)
            != generation
                .fingerprints()
                .get(herness_html_sync::FingerprintKind::Resources)
    {
        return Err(H3Error::Unavailable {
            capability: "h3.verification.dependencies".to_owned(),
            detail: "a CSS or resource dependency changed after the candidate was authored"
                .to_owned(),
        });
    }

    Ok(PreparedCandidate {
        document: document.clone(),
        record,
        generation,
        candidate,
        html,
        provenance,
        source,
        css,
        resources,
    })
}

/// Builds the Task 17 render input for one prepared candidate.
pub fn render_input(prepared: &PreparedCandidate) -> Result<RenderInput, H3Error> {
    let css = prepared
        .css
        .first()
        .map(|input| input.bytes().to_vec())
        .unwrap_or_default();
    let resources = prepared
        .resources
        .iter()
        .map(|input| {
            RenderResource::new(
                input.path(),
                content_type_for(input.path()),
                input.bytes().to_vec(),
            )
            .map_err(|error| H3Error::invalid("renderResource", error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RenderInput {
        job_id: prepared.generation.generation_id().local_id().to_string(),
        html: prepared.html.as_bytes().to_vec(),
        css,
        resources,
        timeout: RENDER_HARD_TIMEOUT,
    })
}

fn content_type_for(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".svg") {
        "image/svg+xml"
    } else if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".webp") {
        "image/webp"
    } else if lower.ends_with(".woff2") {
        "font/woff2"
    } else {
        "font/woff"
    }
}

/// Runs the real structural/static and real render verification.
pub fn verify(
    bridge: &ConnectedPolicyBridge,
    render_port: &dyn CandidateRenderPort,
    prepared: &PreparedCandidate,
    context: &AssessmentContext,
    capture: &HostFingerprints,
    now: Timestamp,
) -> Result<crate::html_sync::verification::CandidateVerification, H3Error> {
    let render = render_port.capture(&render_input(prepared)?)?;
    let mut inputs = BTreeMap::new();
    inputs.insert(
        prepared.document.target_path().to_owned(),
        prepared.source.clone(),
    );
    inputs.insert(
        prepared.document.companion_path(),
        prepared.html.as_bytes().to_vec(),
    );
    for input in prepared.css.iter().chain(prepared.resources.iter()) {
        inputs.insert(input.path().to_owned(), input.bytes().to_vec());
    }
    let scope = herness_supervision::EvidenceScope::new(
        vec![prepared.document.target_path().to_owned()],
        vec![
            "one candidate verification; no repository or tool access".to_owned(),
            "structural evidence is the Common SDD pack; render evidence is wkwebview-native"
                .to_owned(),
        ],
    )
    .map_err(H3Error::from)?;
    let request = HostVerificationRequest {
        document: prepared.document.clone(),
        generation: prepared.generation.generation_id(),
        cycle: prepared.generation.cycle_id(),
        conditions: context.conditions.clone(),
        condition_version: context.condition_version,
        condition_digest: context.condition_digest.clone(),
        target_version: context.target_version,
        source: prepared.source_snapshot().clone(),
        source_bytes: &prepared.source,
        candidate_html: &prepared.html,
        candidate_digest: ContentDigest::sha256(prepared.html.as_bytes()),
        provenance_digest: ContentDigest::sha256(prepared.provenance.as_bytes()),
        css_digest: capture.css().clone(),
        render_css_digest: ContentDigest::sha256(
            prepared
                .css
                .first()
                .map(|input| input.bytes())
                .unwrap_or_default(),
        ),
        resources_digest: capture.resources().clone(),
        settings_digest: capture.settings().clone(),
        policy_digest: capture.policy().clone(),
        pack_digest: capture.pack().clone(),
        rubric_digest: context.rubrics.digest(),
        profile: context.profile,
        inputs: &inputs,
        structural_evidence_id: None,
        render_evidence_id: None,
        check_scope: scope,
        created_at: now,
    };
    verify_candidate(bridge, &request, Some(&render), capture)
}

/// Runs the three Html assessment methods over a usable evidence pack.
#[allow(clippy::too_many_arguments)]
pub fn assess(
    assessment: &mut HtmlAssessmentHost,
    pack: &EvidencePack,
    context: &AssessmentContext,
    supervision_id: SupervisionId,
    verification: &crate::html_sync::verification::CandidateVerification,
    capture: &HostFingerprints,
    now: Timestamp,
) -> Result<AppliedEvaluation, H3Error> {
    let binding = verification
        .binding
        .clone()
        .ok_or_else(|| H3Error::Unavailable {
            capability: "h3.assessment.binding".to_owned(),
            detail: "the verification has no before/after binding".to_owned(),
        })?;
    let profile_inputs = assessment.profile_inputs(context.profile)?;
    let before = binding.post_verification().clone();
    let after = capture.evidence();
    assessment.assess(
        pack,
        &context.rubrics,
        context.profile,
        profile_inputs,
        supervision_id,
        &context.target,
        binding,
        before,
        &|| Ok(after.clone()),
        false,
        now,
        1,
    )
}

/// Reads the current exact version or explicit absence of one formal file.
pub fn current_expected(
    files: &ProjectPublicationFiles,
    path: &str,
) -> Result<ExpectedTargetVersion, H3Error> {
    match files.read(path)? {
        Some(bytes) => {
            let version = FileVersion::new(ContentDigest::sha256(&bytes).as_str())
                .map_err(|error| H3Error::invalid("fileVersion", error.to_string()))?;
            Ok(ExpectedTargetVersion::present(version))
        }
        None => Ok(ExpectedTargetVersion::absent()),
    }
}

/// Builds one exact publication attempt from the evaluated candidate.
pub fn publication_attempt(
    files: &ProjectPublicationFiles,
    prepared: &PreparedCandidate,
    evaluation: &AppliedEvaluation,
    policy: &PublicationPolicyIdentity,
    _now: Timestamp,
) -> Result<CandidatePublication, H3Error> {
    let receipt_path = herness_html_sync::html_evidence_path(&prepared.document);
    CandidatePublication::new(
        PublicationId::new(prepared.document.project_id()),
        prepared.document.clone(),
        prepared.record.revision(),
        prepared.record.state().settings_version(),
        prepared.generation.clone(),
        prepared.html.clone(),
        prepared.provenance.clone(),
        prepared.source.clone(),
        prepared.css.clone(),
        prepared.resources.clone(),
        policy.clone(),
        evaluation.clone(),
        current_expected(files, &prepared.document.companion_path())?,
        current_expected(files, &receipt_path)?,
    )
}

/// Builds the approved policy identity from the stored human approval.
pub fn policy_identity(settings: &H3Settings) -> Result<PublicationPolicyIdentity, H3Error> {
    let approval = settings.approval().ok_or_else(|| H3Error::Unavailable {
        capability: "h3.publication.approval".to_owned(),
        detail: "the project settings carry no human approval".to_owned(),
    })?;
    PublicationPolicyIdentity::new(
        approval.versions().policy_version(),
        approval.versions().policy_fingerprint().clone(),
        approval.versions().pack_fingerprint().clone(),
    )
}

/// Commits one explicit document state update with an optional cycle latch.
pub fn commit_state(
    store: &mut StoreHandle,
    record: &H3DocumentRecord,
    reason: H3Reason,
    latch: Option<CycleLatch>,
    now: Timestamp,
) -> Result<H3DocumentRecord, H3Error> {
    let state = record.state();
    let next = H3DocumentState::new(
        state.document_key().clone(),
        state.settings_version(),
        state.job_id(),
        state.cycle_id(),
        state.generation(),
        state.source().clone(),
        state.fingerprints().clone(),
        reason,
        state.h2().cloned(),
        state.evidence().to_vec(),
        state.applicability().clone(),
        now,
    )?;
    let event = document_state_event(state.document_key(), Some(state.state()), &next, now)?;
    let mut commit = herness_html_sync::HtmlSyncCommit::new()
        .with_document(DocumentCommit::new(Some(record.revision()), next)?)
        .with_events(vec![event]);
    if let Some(cycle_id) = state.cycle_id()
        && let Some(mut cycle) = store.load_html_sync_cycle(state.project_id(), cycle_id)?
    {
        if let Some(latch) = latch {
            cycle = cycle.with_latch(latch);
        }
        commit = commit.with_cycle(cycle);
    }
    match store.commit_html_sync(commit)? {
        herness_html_sync::HtmlSyncCommitOutcome::Applied { document, .. } => {
            document.ok_or_else(|| H3Error::Storage {
                detail: "the state commit returned no document".to_owned(),
            })
        }
        herness_html_sync::HtmlSyncCommitOutcome::Duplicate { .. } => Err(H3Error::Storage {
            detail: "the state commit was reported as a duplicate".to_owned(),
        }),
    }
}

/// Marks the document as assessing. Publication requires this state.
pub fn mark_assessing(
    store: &mut StoreHandle,
    prepared: &PreparedCandidate,
    now: Timestamp,
) -> Result<H3DocumentRecord, H3Error> {
    let reason = H3Reason::new(
        H3StateReasonKind::Assessing {
            generation: prepared.generation.generation_id(),
        },
        Vec::new(),
    )?;
    commit_state(store, &prepared.record, reason, None, now)
}

/// Marks a rejected/unusable candidate. No formal file is written.
pub fn mark_rejected(
    store: &mut StoreHandle,
    prepared: &PreparedCandidate,
    cause: H3FailureCause,
    now: Timestamp,
) -> Result<H3DocumentRecord, H3Error> {
    let reason = H3Reason::new(
        H3StateReasonKind::Failed { cause },
        vec![RequiredAction::ReviewFailure],
    )?;
    commit_state(store, &prepared.record, reason, None, now)
}

/// Marks the document as waiting for an explicit human decision.
pub fn mark_waiting(
    store: &mut StoreHandle,
    prepared: &PreparedCandidate,
    cause: HumanWaitCause,
    actions: Vec<RequiredAction>,
    now: Timestamp,
) -> Result<H3DocumentRecord, H3Error> {
    let reason = H3Reason::new(H3StateReasonKind::WaitingHuman { cause }, actions)?;
    commit_state(
        store,
        &prepared.record,
        reason,
        Some(CycleLatch::WaitingHuman),
        now,
    )
}

/// Persists the exact assessment content for post-restart rehydration.
pub fn persist_evidence_root(root: &Path) -> Result<PathBuf, H3Error> {
    let mut hasher_path = PathBuf::from(root);
    hasher_path.push("evidence-content");
    Ok(hasher_path)
}

/// Saves the assessment content under one generation-scoped file.
pub fn persist_evidence(
    root: &Path,
    document: &DocumentKey,
    generation: herness_html_sync::GenerationId,
    content: &EvidenceContentStore,
) -> Result<PathBuf, H3Error> {
    let directory = persist_evidence_root(root)?;
    let file = directory.join(format!(
        "{}-{}.json",
        document.project_id(),
        generation.local_id()
    ));
    content.save(&file).map_err(H3Error::from)?;
    Ok(file)
}

/// Loads the persisted content for one generation. A missing file is empty.
pub fn load_evidence(
    root: &Path,
    document: &DocumentKey,
    generation: herness_html_sync::GenerationId,
) -> Result<EvidenceContentStore, H3Error> {
    let directory = persist_evidence_root(root)?;
    let file = directory.join(format!(
        "{}-{}.json",
        document.project_id(),
        generation.local_id()
    ));
    EvidenceContentStore::load(&file).map_err(H3Error::from)
}

/// Maps a verification failure to a sanitized detail and fixability.
pub fn verification_detail(
    verification: &crate::html_sync::verification::CandidateVerification,
) -> (String, bool) {
    if let Some(failure) = &verification.failure {
        let fixable = matches!(
            failure,
            EvidenceValidationError::RequiredCheckNotPass { .. }
                | EvidenceValidationError::UnitMissing { .. }
                | EvidenceValidationError::UnitDuplicate { .. }
                | EvidenceValidationError::UnitExtraneous { .. }
                | EvidenceValidationError::UnitMismatch { .. }
                | EvidenceValidationError::TargetMissing { .. }
                | EvidenceValidationError::TargetHidden { .. }
                | EvidenceValidationError::StrictValueMissing { .. }
                | EvidenceValidationError::ProvenanceInvalid { .. }
                | EvidenceValidationError::ProvenanceMissing
                | EvidenceValidationError::SourceDigestMismatch
        );
        (failure.to_string(), fixable)
    } else if !verification.is_usable() {
        let mut detail = if verification.checks.all_pass() {
            "the evidence pack was not built from the available checks".to_owned()
        } else {
            "a mandatory check did not pass".to_owned()
        };
        if let Some(check) = &verification.policy_check {
            detail.push_str(&format!(
                "; structural decision={:?} stage={} contract={} final={} violations={:?}",
                check.decision, check.stage, check.contract, check.final_pass, check.violations
            ));
        }
        for check in verification.checks.checks() {
            detail.push_str(&format!(
                "; check={} status={} origin={} result={}",
                check.kind().as_str(),
                check.status().as_str(),
                check.origin().as_str(),
                check.result()
            ));
        }
        detail.push_str(&format!(
            "; binding_current={}",
            verification
                .binding
                .as_ref()
                .is_some_and(herness_html_sync::EvaluationBinding::is_current)
        ));
        (detail, true)
    } else {
        ("the verification is usable".to_owned(), false)
    }
}

/// Expected structure of the checks used by the pipeline. Exposed for tests
/// that assert a fake render never produced a native pass.
pub fn checks_are_native(checks: &CheckSet) -> bool {
    checks
        .get(herness_html_sync::RequiredCheckKind::RealRender)
        .is_some_and(|check| check.origin().is_native_render())
}

/// Helper: exact cycle state used for a fixable-unmet continuation decision.
pub fn cycle_is_open(store: &mut StoreHandle, record: &H3DocumentRecord) -> Result<bool, H3Error> {
    let Some(cycle_id) = record.state().cycle_id() else {
        return Ok(false);
    };
    Ok(store
        .load_html_sync_cycle(record.state().project_id(), cycle_id)?
        .is_some_and(|cycle| cycle.state() == CycleState::Open))
}

/// Extracts the exact non-executed `#sdd-provenance` template payload from a
/// semantic-v1 HTML document. A missing template is an explicit error.
pub fn extract_provenance(html: &str) -> Result<String, H3Error> {
    let lower = html.to_ascii_lowercase();
    let marker = "id=\"sdd-provenance\"";
    let id_position = lower.find(marker).ok_or_else(|| {
        H3Error::invalid(
            "provenance",
            "the current HTML has no sdd-provenance template",
        )
    })?;
    let open_end = lower[id_position..]
        .find('>')
        .map(|offset| id_position + offset + 1)
        .ok_or_else(|| H3Error::invalid("provenance", "the provenance tag is not closed"))?;
    let close = lower[open_end..]
        .find("</template>")
        .map(|offset| open_end + offset)
        .ok_or_else(|| H3Error::invalid("provenance", "the provenance template is not closed"))?;
    Ok(html[open_end..close].to_owned())
}
