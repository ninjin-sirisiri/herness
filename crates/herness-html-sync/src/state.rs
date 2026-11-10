//! Versioned H3 document state, reasons, generations, cycles, settings, and
//! publication journal values.
//!
//! H3 states are separate from H1 run states and H2 supervision states. A
//! generation that completed in the past stays in history even when later
//! source, dependency, or HTML changes invalidate current applicability.

use herness_core::{
    ExpectedTargetVersion, HostActivityId, ProjectId, PublicationRequestId, RunId, Timestamp,
};
use herness_supervision::{
    ConditionVersion, ContentDigest, EvidenceId, RunGroupId, SupervisionId, SupervisionState,
    TargetVersion,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use uuid::Uuid;

use crate::config::{H3ConfigurationApproval, mix_approval_fingerprint};
use crate::document::{DocumentKey, FingerprintKind, FingerprintSet, SourceSnapshot};
use crate::error::H3Error;
use crate::ids::{CandidateId, CycleId, GenerationId, JobId, PublicationId};
use crate::version::{H3_FORMAT_VERSION, H3Record};

/// Every H3 document state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum H3State {
    /// Not approved or explicitly disabled; only discovery may run.
    Disabled,
    /// Unsynchronized; waiting for settled edits or a free authoring slot.
    Pending,
    /// Candidate authoring is active.
    Authoring,
    /// Common and render verification are active.
    Verifying,
    /// H2 condition assessment is active.
    Assessing,
    /// Every condition holds for the frozen candidate.
    ReadyToPublish,
    /// Version-checked publication and history saving are active.
    Publishing,
    /// The recorded source, HTML, and dependencies were published.
    Synced,
    /// External conflict, undecidable assessment, permission, capability, or
    /// capacity needs a human.
    WaitingHuman,
    /// Human stop, stagnation, budget, or unconfirmed stop.
    Stopped,
    /// Unrecoverable failure.
    Failed,
    /// Explicit cancellation.
    Cancelled,
    /// The Markdown is gone while the old companion remains.
    Orphaned,
}

impl H3State {
    /// Every H3 state in stable order.
    pub const ALL: [Self; 13] = [
        Self::Disabled,
        Self::Pending,
        Self::Authoring,
        Self::Verifying,
        Self::Assessing,
        Self::ReadyToPublish,
        Self::Publishing,
        Self::Synced,
        Self::WaitingHuman,
        Self::Stopped,
        Self::Failed,
        Self::Cancelled,
        Self::Orphaned,
    ];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Pending => "pending",
            Self::Authoring => "authoring",
            Self::Verifying => "verifying",
            Self::Assessing => "assessing",
            Self::ReadyToPublish => "ready_to_publish",
            Self::Publishing => "publishing",
            Self::Synced => "synced",
            Self::WaitingHuman => "waiting_human",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Orphaned => "orphaned",
        }
    }

    /// Whether this state means the current document is synchronized.
    pub const fn is_currently_synced(self) -> bool {
        matches!(self, Self::Synced)
    }

    /// Whether a human action is required before progress.
    pub const fn requires_human(self) -> bool {
        matches!(self, Self::WaitingHuman | Self::Stopped | Self::Disabled)
    }

    /// Whether this state is terminal without a successful sync.
    pub const fn is_terminal_without_sync(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled | Self::Orphaned)
    }
}

impl std::fmt::Display for H3State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A versioned human or host action needed before progress.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredAction {
    /// Approve or update the project settings.
    ApproveSettings,
    /// Wait for edits to settle before authoring.
    WaitForStableSource,
    /// Resume a stopped or cancelled cycle explicitly.
    ResumeCycle,
    /// Reassess the current candidate.
    ReassessCandidate,
    /// Regenerate the candidate for the current source.
    RegenerateCandidate,
    /// Resolve an external HTML or metadata conflict.
    ResolveHtmlConflict {
        /// Project-relative companion path.
        target: String,
    },
    /// Restore one historical generation.
    RestoreGeneration {
        /// Generation to restore.
        generation: GenerationId,
    },
    /// Review an unrecoverable failure.
    ReviewFailure,
    /// Free private capacity before publication.
    FreeCapacity,
    /// Reconcile an uncertain publication or recovery state.
    ReconcileRecovery,
}

impl RequiredAction {
    /// Stable action label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ApproveSettings => "approve_settings",
            Self::WaitForStableSource => "wait_for_stable_source",
            Self::ResumeCycle => "resume_cycle",
            Self::ReassessCandidate => "reassess_candidate",
            Self::RegenerateCandidate => "regenerate_candidate",
            Self::ResolveHtmlConflict { .. } => "resolve_html_conflict",
            Self::RestoreGeneration { .. } => "restore_generation",
            Self::ReviewFailure => "review_failure",
            Self::FreeCapacity => "free_capacity",
            Self::ReconcileRecovery => "reconcile_recovery",
        }
    }
}

/// Why a human is required in `waiting_human`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanWaitCause {
    /// The formal HTML changed outside H3.
    ExternalHtmlConflict,
    /// Evidence cannot decide an approved condition.
    UndecidableAssessment,
    /// The host permission path denied the operation.
    PermissionDenied,
    /// A connection needs re-authentication.
    AuthenticationRequired,
    /// An approved capability is missing.
    CapabilityMissing,
    /// Private capacity is insufficient before publication.
    CapacityInsufficient,
    /// Recovery needs reconciliation before sending or authoring.
    RecoveryReconciliation,
}

/// Why H3 stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum H3StopCause {
    /// A human requested the stop.
    HumanRequest,
    /// Consecutive evaluation cycles made no progress.
    Stagnation,
    /// The H2 budget limit was reached.
    BudgetLimit,
    /// A managed process stop was not confirmed.
    StopUnconfirmed,
    /// Recovery requires reconciliation before new work.
    RecoveryReconciliation,
}

/// Why H3 failed unrecoverably.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum H3FailureCause {
    /// The verification path is unavailable.
    VerificationUnavailable,
    /// The assessment path is unavailable.
    AssessmentUnavailable,
    /// The target or candidate is not stable enough to assess.
    TargetUnstable,
    /// Recovery found state it cannot reconcile.
    UnrecoverableRecovery,
    /// Rendering did not complete within the limit.
    RenderFailed,
    /// The SVG or document complexity exceeded the approved limit.
    ComplexityExceeded,
    /// The candidate could not satisfy the static contract.
    CandidateRejected,
}

/// Why H3 was cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum H3CancelCause {
    /// A human cancelled the cycle.
    HumanRequest,
}

/// Structured reason for the current H3 state.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum H3StateReasonKind {
    /// Settings are absent or disabled.
    Disabled,
    /// Waiting for a settled source snapshot.
    Pending {
        /// Observed source revision.
        source_revision: u64,
    },
    /// Authoring a generation.
    Authoring {
        /// Active generation.
        generation: GenerationId,
    },
    /// Running static or render checks.
    Verifying {
        /// Active generation.
        generation: GenerationId,
    },
    /// Running H2 condition assessment.
    Assessing {
        /// Active generation.
        generation: GenerationId,
    },
    /// All conditions hold for the candidate.
    ReadyToPublish {
        /// Active generation.
        generation: GenerationId,
        /// Publication journal entry prepared for this candidate.
        publication: PublicationId,
    },
    /// Publishing the candidate.
    Publishing {
        /// Active generation.
        generation: GenerationId,
        /// Publication journal entry in progress.
        publication: PublicationId,
    },
    /// The current document is synced.
    Synced {
        /// Generation that produced the current companion.
        generation: GenerationId,
        /// Source revision that generation was verified against.
        source_revision: u64,
        /// Exact source digest that generation was verified against.
        source_digest: ContentDigest,
    },
    /// A human action is required.
    WaitingHuman {
        /// Concrete wait cause.
        cause: HumanWaitCause,
    },
    /// Work is stopped.
    Stopped {
        /// Concrete stop cause.
        cause: H3StopCause,
    },
    /// Work failed.
    Failed {
        /// Concrete failure cause.
        cause: H3FailureCause,
    },
    /// Work was cancelled.
    Cancelled {
        /// Concrete cancel cause.
        cause: H3CancelCause,
    },
    /// The Markdown is gone while the old companion remains.
    Orphaned {
        /// Project-relative companion path left untouched.
        last_companion: String,
    },
}

impl H3StateReasonKind {
    /// H3 state this reason describes.
    pub const fn state(&self) -> H3State {
        match self {
            Self::Disabled => H3State::Disabled,
            Self::Pending { .. } => H3State::Pending,
            Self::Authoring { .. } => H3State::Authoring,
            Self::Verifying { .. } => H3State::Verifying,
            Self::Assessing { .. } => H3State::Assessing,
            Self::ReadyToPublish { .. } => H3State::ReadyToPublish,
            Self::Publishing { .. } => H3State::Publishing,
            Self::Synced { .. } => H3State::Synced,
            Self::WaitingHuman { .. } => H3State::WaitingHuman,
            Self::Stopped { .. } => H3State::Stopped,
            Self::Failed { .. } => H3State::Failed,
            Self::Cancelled { .. } => H3State::Cancelled,
            Self::Orphaned { .. } => H3State::Orphaned,
        }
    }
}

/// A versioned reason plus the actions a human may take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3Reason {
    format_version: u32,
    kind: H3StateReasonKind,
    required_actions: Vec<RequiredAction>,
}

impl H3Reason {
    /// Creates a validated reason.
    ///
    /// Disabled, waiting-human, stopped, and failed states must name at least
    /// one required action. Duplicate actions are rejected.
    pub fn new(
        kind: H3StateReasonKind,
        required_actions: Vec<RequiredAction>,
    ) -> Result<Self, H3Error> {
        let state = kind.state();
        if matches!(
            state,
            H3State::Disabled | H3State::WaitingHuman | H3State::Stopped | H3State::Failed
        ) && required_actions.is_empty()
        {
            return Err(H3Error::invalid(
                "requiredActions",
                "this state requires at least one human action",
            ));
        }
        for (index, action) in required_actions.iter().enumerate() {
            if required_actions[..index].contains(action) {
                return Err(H3Error::invalid(
                    "requiredActions",
                    "duplicate required actions are not allowed",
                ));
            }
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            kind,
            required_actions,
        })
    }

    /// Structured reason kind.
    pub const fn kind(&self) -> &H3StateReasonKind {
        &self.kind
    }

    /// State this reason describes.
    pub const fn state(&self) -> H3State {
        self.kind.state()
    }

    /// Actions a human may take.
    pub fn required_actions(&self) -> &[RequiredAction] {
        &self.required_actions
    }
}

impl H3Record for H3Reason {
    const RECORD: &'static str = "H3 reason";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Whether the recorded success still applies to the current document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Applicability {
    applicable: bool,
    reason: ApplicabilityReason,
}

impl Applicability {
    /// Current success applies to the current source and dependencies.
    pub const fn current_synced() -> Self {
        Self {
            applicable: true,
            reason: ApplicabilityReason::CurrentSynced,
        }
    }

    /// Current success does not apply for the stated reason.
    pub const fn not_applicable(reason: ApplicabilityReason) -> Self {
        Self {
            applicable: false,
            reason,
        }
    }

    /// Whether the stored success applies now.
    pub const fn is_applicable(&self) -> bool {
        self.applicable
    }

    /// Why applicability was retained or lost.
    pub const fn reason(&self) -> &ApplicabilityReason {
        &self.reason
    }
}

/// Why current applicability is true or false.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ApplicabilityReason {
    /// This generation is the current, verified companion.
    CurrentSynced,
    /// No successful generation exists yet.
    NeverPublished,
    /// A newer generation superseded the recorded success.
    Superseded {
        /// Newer generation.
        generation: GenerationId,
        /// Source revision that superseded it.
        source_revision: u64,
    },
    /// A later dependency fingerprint changed.
    DependencyChanged {
        /// First changed dependency kind.
        fingerprint: FingerprintKind,
    },
    /// The formal companion changed outside H3.
    HtmlChanged {
        /// Digest H3 recorded.
        expected: ContentDigest,
        /// Digest observed in the formal file.
        observed: ContentDigest,
    },
    /// The companion was restored from history and is not yet revalidated.
    Restored {
        /// Generation that supplied the restored bytes.
        generation: GenerationId,
    },
    /// The Markdown is gone.
    Orphaned,
}

/// A reference to an H2 supervision target and its snapshot versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H2Reference {
    format_version: u32,
    supervision_id: SupervisionId,
    run_group: Option<RunGroupId>,
    condition_version: Option<ConditionVersion>,
    target_version: Option<TargetVersion>,
    revision: Option<u64>,
    state: Option<SupervisionState>,
}

impl H2Reference {
    /// Creates a validated H2 reference bound to `project`.
    pub fn new(
        project: ProjectId,
        supervision_id: SupervisionId,
        run_group: Option<RunGroupId>,
        condition_version: Option<ConditionVersion>,
        target_version: Option<TargetVersion>,
        revision: Option<u64>,
        state: Option<SupervisionState>,
    ) -> Result<Self, H3Error> {
        supervision_id.validate_in(project).map_err(H3Error::from)?;
        if let Some(run_group) = run_group {
            run_group.validate_in(project).map_err(H3Error::from)?;
        }
        if revision == Some(0) {
            return Err(H3Error::must_be_positive("h2Revision"));
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            supervision_id,
            run_group,
            condition_version,
            target_version,
            revision,
            state,
        })
    }

    /// H2 supervision target identifier.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// H2 run group, when one exists.
    pub const fn run_group(&self) -> Option<RunGroupId> {
        self.run_group
    }

    /// H2 condition version observed.
    pub const fn condition_version(&self) -> Option<ConditionVersion> {
        self.condition_version
    }

    /// H2 target version observed.
    pub const fn target_version(&self) -> Option<TargetVersion> {
        self.target_version
    }

    /// H2 supervision record revision observed.
    pub const fn revision(&self) -> Option<u64> {
        self.revision
    }

    /// H2 state observed.
    pub const fn state(&self) -> Option<SupervisionState> {
        self.state
    }
}

impl H3Record for H2Reference {
    const RECORD: &'static str = "H2 reference";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Evidence category referenced by H3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Common SDD structural validation.
    StaticValidation,
    /// Isolated render capture.
    Render,
    /// H2 condition assessment.
    Assessment,
    /// Evaluation receipt.
    Receipt,
}

/// A durable H2 evidence reference with its exact digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRef {
    format_version: u32,
    evidence_id: EvidenceId,
    kind: EvidenceKind,
    digest: ContentDigest,
}

impl EvidenceRef {
    /// Creates a reference bound to `project`.
    pub fn new(
        project: ProjectId,
        evidence_id: EvidenceId,
        kind: EvidenceKind,
        digest: ContentDigest,
    ) -> Result<Self, H3Error> {
        evidence_id.validate_in(project).map_err(H3Error::from)?;
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            evidence_id,
            kind,
            digest,
        })
    }

    /// Evidence identifier.
    pub const fn evidence_id(&self) -> EvidenceId {
        self.evidence_id
    }

    /// Evidence category.
    pub const fn kind(&self) -> EvidenceKind {
        self.kind
    }

    /// Exact evidence digest.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

impl H3Record for EvidenceRef {
    const RECORD: &'static str = "evidence reference";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Opaque private storage namespace and token digest for one candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateStorageRef {
    format_version: u32,
    namespace: String,
    token_digest: ContentDigest,
}

impl CandidateStorageRef {
    /// Creates a storage reference from a host-computed namespace and token
    /// digest. The namespace is a 64-character lowercase SHA-256 hex value; it
    /// is never a model-supplied path.
    pub fn new(namespace: impl Into<String>, token_digest: ContentDigest) -> Result<Self, H3Error> {
        let namespace = namespace.into();
        if namespace.len() != 64
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(H3Error::invalid(
                "candidateNamespace",
                "the candidate namespace must be 64 lowercase hex characters",
            ));
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            namespace,
            token_digest,
        })
    }

    /// Opaque private namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// SHA-256 of the host-issued capability token.
    pub const fn token_digest(&self) -> &ContentDigest {
        &self.token_digest
    }
}

impl H3Record for CandidateStorageRef {
    const RECORD: &'static str = "candidate storage reference";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Persisted candidate HTML and provenance metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateRecord {
    format_version: u32,
    candidate_id: CandidateId,
    project_id: ProjectId,
    document_key: DocumentKey,
    generation_id: GenerationId,
    storage: CandidateStorageRef,
    html_digest: ContentDigest,
    provenance_digest: ContentDigest,
    authored_at: Timestamp,
    /// H1 run whose candidate artifact events produced these bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    h1_run: Option<RunId>,
}

impl CandidateRecord {
    /// Creates candidate metadata bound to one document and generation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate_id: CandidateId,
        document_key: DocumentKey,
        generation_id: GenerationId,
        storage: CandidateStorageRef,
        html_digest: ContentDigest,
        provenance_digest: ContentDigest,
        authored_at: Timestamp,
    ) -> Result<Self, H3Error> {
        candidate_id.validate_in(document_key.project_id())?;
        generation_id.validate_in(document_key.project_id())?;
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            candidate_id,
            project_id: document_key.project_id(),
            document_key,
            generation_id,
            storage,
            html_digest,
            provenance_digest,
            authored_at,
            h1_run: None,
        })
    }

    /// Candidate metadata identifier.
    pub const fn candidate_id(&self) -> CandidateId {
        self.candidate_id
    }

    /// Project that owns the candidate.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Document this candidate belongs to.
    pub const fn document_key(&self) -> &DocumentKey {
        &self.document_key
    }

    /// Generation this candidate was authored in.
    pub const fn generation_id(&self) -> GenerationId {
        self.generation_id
    }

    /// Opaque private storage reference.
    pub const fn storage(&self) -> &CandidateStorageRef {
        &self.storage
    }

    /// Exact candidate HTML digest.
    pub const fn html_digest(&self) -> &ContentDigest {
        &self.html_digest
    }

    /// Exact candidate provenance digest.
    pub const fn provenance_digest(&self) -> &ContentDigest {
        &self.provenance_digest
    }

    /// When the candidate was authored.
    pub const fn authored_at(&self) -> Timestamp {
        self.authored_at
    }

    /// H1 run whose candidate artifact events produced these bytes.
    pub const fn h1_run(&self) -> Option<RunId> {
        self.h1_run
    }

    /// Links this candidate to the H1 run that produced it.
    ///
    /// This link is persisted in the same H3 commit as the candidate metadata
    /// and generation state; the H1 artifact events remain the audit source.
    pub fn with_h1_run(mut self, run: RunId) -> Self {
        self.h1_run = Some(run);
        self
    }
}

impl H3Record for CandidateRecord {
    const RECORD: &'static str = "candidate record";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Lifecycle of one generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationStatus {
    /// The generation is the active one for its document.
    Active,
    /// A newer source or generation superseded it.
    Superseded,
    /// The generation completed successfully.
    Completed,
    /// The generation failed.
    Failed,
    /// The generation was cancelled.
    Cancelled,
    /// The source disappeared and the generation is historical only.
    Orphaned,
}

/// One immutable generation history entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationRecord {
    format_version: u32,
    generation_id: GenerationId,
    project_id: ProjectId,
    document_key: DocumentKey,
    generation: u64,
    cycle_id: CycleId,
    job_id: JobId,
    source: SourceSnapshot,
    fingerprints: FingerprintSet,
    status: GenerationStatus,
    completed: bool,
    candidate: Option<CandidateRecord>,
    h2: Option<H2Reference>,
    evidence: Vec<EvidenceRef>,
    publication: Option<PublicationId>,
    started_at: Timestamp,
    completed_at: Option<Timestamp>,
    superseded_at: Option<Timestamp>,
}

impl GenerationRecord {
    /// Creates a generation history entry.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        generation_id: GenerationId,
        document_key: DocumentKey,
        generation: u64,
        cycle_id: CycleId,
        job_id: JobId,
        source: SourceSnapshot,
        fingerprints: FingerprintSet,
        status: GenerationStatus,
        completed: bool,
        started_at: Timestamp,
    ) -> Result<Self, H3Error> {
        let project = document_key.project_id();
        generation_id.validate_in(project)?;
        cycle_id.validate_in(project)?;
        job_id.validate_in(project)?;
        if generation == 0 {
            return Err(H3Error::must_be_positive("generation"));
        }
        if status == GenerationStatus::Completed && !completed {
            return Err(H3Error::invalid(
                "completed",
                "a completed generation must record past success",
            ));
        }
        if completed
            && !matches!(
                status,
                GenerationStatus::Completed | GenerationStatus::Superseded | GenerationStatus::Orphaned
            )
        {
            return Err(H3Error::invalid(
                "completed",
                "past success may only be recorded for completed, superseded, or orphaned generations",
            ));
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            generation_id,
            project_id: project,
            document_key,
            generation,
            cycle_id,
            job_id,
            source,
            fingerprints,
            status,
            completed,
            candidate: None,
            h2: None,
            evidence: Vec::new(),
            publication: None,
            started_at,
            completed_at: None,
            superseded_at: None,
        })
    }

    /// Attaches the authored candidate.
    pub fn with_candidate(mut self, candidate: CandidateRecord) -> Result<Self, H3Error> {
        if candidate.generation_id() != self.generation_id
            || candidate.document_key() != &self.document_key
        {
            return Err(H3Error::invalid(
                "candidate",
                "the candidate does not belong to this generation",
            ));
        }
        self.candidate = Some(candidate);
        Ok(self)
    }

    /// Attaches the H2 reference.
    pub fn with_h2(mut self, h2: H2Reference) -> Self {
        self.h2 = Some(h2);
        self
    }

    /// Attaches evidence references.
    pub fn with_evidence(mut self, evidence: Vec<EvidenceRef>) -> Self {
        self.evidence = evidence;
        self
    }

    /// Attaches the publication journal identifier.
    pub fn with_publication(mut self, publication: PublicationId) -> Self {
        self.publication = Some(publication);
        self
    }

    /// Records successful completion at `at`.
    pub fn complete(mut self, at: Timestamp) -> Result<Self, H3Error> {
        if self.status != GenerationStatus::Active {
            return Err(H3Error::invalid(
                "generationStatus",
                "only an active generation can complete",
            ));
        }
        self.status = GenerationStatus::Completed;
        self.completed = true;
        self.completed_at = Some(at);
        Ok(self)
    }

    /// Marks an active generation failed. The immutable source, fingerprints,
    /// cycle, job, candidate, and H2 references are preserved.
    pub fn fail(mut self) -> Result<Self, H3Error> {
        if self.status != GenerationStatus::Active {
            return Err(H3Error::invalid(
                "generationStatus",
                "only an active generation can fail",
            ));
        }
        self.status = GenerationStatus::Failed;
        Ok(self)
    }

    /// Marks the generation superseded at `at`, preserving past success.
    pub fn supersede(mut self, at: Timestamp) -> Result<Self, H3Error> {
        if self.status == GenerationStatus::Superseded {
            return Ok(self);
        }
        self.status = GenerationStatus::Superseded;
        self.superseded_at = Some(at);
        Ok(self)
    }

    /// Generation identifier.
    pub const fn generation_id(&self) -> GenerationId {
        self.generation_id
    }

    /// Project that owns the generation.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Document this generation belongs to.
    pub const fn document_key(&self) -> &DocumentKey {
        &self.document_key
    }

    /// Monotonic generation number within the document.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Cycle that owns the generation.
    pub const fn cycle_id(&self) -> CycleId {
        self.cycle_id
    }

    /// Job that owns the generation.
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Source snapshot the generation was authored against.
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Dependency fingerprints recorded for the generation.
    pub const fn fingerprints(&self) -> &FingerprintSet {
        &self.fingerprints
    }

    /// Current history status.
    pub const fn status(&self) -> GenerationStatus {
        self.status
    }

    /// Whether this generation completed successfully in the past.
    ///
    /// This is independent of whether the document is currently synced.
    pub const fn completed(&self) -> bool {
        self.completed
    }

    /// Authored candidate, when one exists.
    pub const fn candidate(&self) -> Option<&CandidateRecord> {
        self.candidate.as_ref()
    }

    /// H2 reference, when one exists.
    pub const fn h2(&self) -> Option<&H2Reference> {
        self.h2.as_ref()
    }

    /// Evidence references.
    pub fn evidence(&self) -> &[EvidenceRef] {
        &self.evidence
    }

    /// Publication journal identifier, when one exists.
    pub const fn publication(&self) -> Option<PublicationId> {
        self.publication
    }

    /// When the generation started.
    pub const fn started_at(&self) -> Timestamp {
        self.started_at
    }

    /// When the generation completed.
    pub const fn completed_at(&self) -> Option<Timestamp> {
        self.completed_at
    }

    /// When the generation was superseded.
    pub const fn superseded_at(&self) -> Option<Timestamp> {
        self.superseded_at
    }
}

impl H3Record for GenerationRecord {
    const RECORD: &'static str = "generation record";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Persisted H3 document state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3DocumentState {
    format_version: u32,
    project_id: ProjectId,
    document_key: DocumentKey,
    settings_version: u64,
    job_id: Option<JobId>,
    cycle_id: Option<CycleId>,
    generation: Option<GenerationId>,
    source: SourceSnapshot,
    fingerprints: FingerprintSet,
    reason: H3Reason,
    h2: Option<H2Reference>,
    evidence: Vec<EvidenceRef>,
    applicable: Applicability,
    updated_at: Timestamp,
}

impl H3DocumentState {
    /// Creates a validated document state.
    ///
    /// A `synced` document must be currently applicable, and only a synced
    /// document may be currently applicable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        document_key: DocumentKey,
        settings_version: u64,
        job_id: Option<JobId>,
        cycle_id: Option<CycleId>,
        generation: Option<GenerationId>,
        source: SourceSnapshot,
        fingerprints: FingerprintSet,
        reason: H3Reason,
        h2: Option<H2Reference>,
        evidence: Vec<EvidenceRef>,
        applicable: Applicability,
        updated_at: Timestamp,
    ) -> Result<Self, H3Error> {
        if settings_version == 0 {
            return Err(H3Error::must_be_positive("settingsVersion"));
        }
        let project = document_key.project_id();
        if let Some(job) = job_id {
            job.validate_in(project)?;
        }
        if let Some(cycle) = cycle_id {
            cycle.validate_in(project)?;
        }
        if let Some(generation) = generation {
            generation.validate_in(project)?;
        }
        if let Some(h2) = &h2 {
            h2.supervision_id().validate_in(project)?;
        }
        for evidence in &evidence {
            evidence.evidence_id().validate_in(project)?;
        }
        let synced = reason.state() == H3State::Synced;
        if synced != applicable.is_applicable() {
            return Err(H3Error::invalid(
                "applicable",
                "only a synced state may be currently applicable, and synced must be applicable",
            ));
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            project_id: project,
            document_key,
            settings_version,
            job_id,
            cycle_id,
            generation,
            source,
            fingerprints,
            reason,
            h2,
            evidence,
            applicable,
            updated_at,
        })
    }

    /// Project that owns the state.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Document this state describes.
    pub const fn document_key(&self) -> &DocumentKey {
        &self.document_key
    }

    /// Approved settings version.
    pub const fn settings_version(&self) -> u64 {
        self.settings_version
    }

    /// Current job, when one exists.
    pub const fn job_id(&self) -> Option<JobId> {
        self.job_id
    }

    /// Current cycle, when one exists.
    pub const fn cycle_id(&self) -> Option<CycleId> {
        self.cycle_id
    }

    /// Current generation, when one exists.
    pub const fn generation(&self) -> Option<GenerationId> {
        self.generation
    }

    /// Monotonic source snapshot.
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Current dependency fingerprints.
    pub const fn fingerprints(&self) -> &FingerprintSet {
        &self.fingerprints
    }

    /// State and its versioned reason.
    pub const fn reason(&self) -> &H3Reason {
        &self.reason
    }

    /// Current state.
    pub const fn state(&self) -> H3State {
        self.reason.state()
    }

    /// H2 reference, when one exists.
    pub const fn h2(&self) -> Option<&H2Reference> {
        self.h2.as_ref()
    }

    /// Evidence references.
    pub fn evidence(&self) -> &[EvidenceRef] {
        &self.evidence
    }

    /// Whether the recorded success still applies now.
    pub const fn applicability(&self) -> &Applicability {
        &self.applicable
    }

    /// When the state was last updated.
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }
}

impl H3Record for H3DocumentState {
    const RECORD: &'static str = "document state";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Lifecycle of one sync cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleState {
    /// The cycle is active.
    Open,
    /// The cycle completed successfully.
    Completed,
    /// The cycle is stopped.
    Stopped,
    /// The cycle was cancelled.
    Cancelled,
    /// The cycle failed.
    Failed,
}

/// A latch that later source notifications must not clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleLatch {
    /// A human stop.
    HumanStop,
    /// A human-wait state.
    WaitingHuman,
    /// Consecutive evaluation stagnation.
    Stagnation,
    /// Budget exhaustion.
    BudgetLimit,
    /// Recovery reconciliation.
    RecoveryReconciliation,
}

/// One durable sync cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncCycle {
    format_version: u32,
    cycle_id: CycleId,
    project_id: ProjectId,
    document_key: DocumentKey,
    settings_version: u64,
    started_at: Timestamp,
    source_at_start: SourceSnapshot,
    supervision_id: Option<SupervisionId>,
    generation_count: u64,
    state: CycleState,
    latch: Option<CycleLatch>,
    ended_at: Option<Timestamp>,
}

impl SyncCycle {
    /// Creates a cycle. The H2 budget ledger is referenced, never copied.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cycle_id: CycleId,
        document_key: DocumentKey,
        settings_version: u64,
        started_at: Timestamp,
        source_at_start: SourceSnapshot,
        supervision_id: Option<SupervisionId>,
    ) -> Result<Self, H3Error> {
        let project = document_key.project_id();
        cycle_id.validate_in(project)?;
        if settings_version == 0 {
            return Err(H3Error::must_be_positive("settingsVersion"));
        }
        if let Some(supervision_id) = supervision_id {
            supervision_id.validate_in(project)?;
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            cycle_id,
            project_id: project,
            document_key,
            settings_version,
            started_at,
            source_at_start,
            supervision_id,
            generation_count: 0,
            state: CycleState::Open,
            latch: None,
            ended_at: None,
        })
    }

    /// Cycle identifier.
    pub const fn cycle_id(&self) -> CycleId {
        self.cycle_id
    }

    /// Project that owns the cycle.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Document this cycle belongs to.
    pub const fn document_key(&self) -> &DocumentKey {
        &self.document_key
    }

    /// Settings version approved for the cycle.
    pub const fn settings_version(&self) -> u64 {
        self.settings_version
    }

    /// When the cycle started.
    pub const fn started_at(&self) -> Timestamp {
        self.started_at
    }

    /// Source snapshot when the cycle started.
    pub const fn source_at_start(&self) -> &SourceSnapshot {
        &self.source_at_start
    }

    /// H2 supervision target that owns the budget ledger.
    pub const fn supervision_id(&self) -> Option<SupervisionId> {
        self.supervision_id
    }

    /// Number of generations created in this cycle.
    pub const fn generation_count(&self) -> u64 {
        self.generation_count
    }

    /// Current cycle state.
    pub const fn state(&self) -> CycleState {
        self.state
    }

    /// Latch that source notifications must not clear.
    pub const fn latch(&self) -> Option<CycleLatch> {
        self.latch
    }

    /// When the cycle ended.
    pub const fn ended_at(&self) -> Option<Timestamp> {
        self.ended_at
    }

    /// Records one more generation without resetting H2 consumption.
    pub fn count_generation(mut self) -> Result<Self, H3Error> {
        if self.state != CycleState::Open {
            return Err(H3Error::invalid(
                "cycleState",
                "generations may only be counted in an open cycle",
            ));
        }
        self.generation_count = self
            .generation_count
            .checked_add(1)
            .ok_or_else(|| H3Error::invalid("generationCount", "generation count overflow"))?;
        Ok(self)
    }

    /// Sets a latch. A later source notification never clears it.
    pub fn with_latch(mut self, latch: CycleLatch) -> Self {
        self.latch = Some(latch);
        self
    }

    /// Ends the cycle in `state`.
    pub fn end(mut self, state: CycleState, at: Timestamp) -> Result<Self, H3Error> {
        if self.state != CycleState::Open {
            return Err(H3Error::invalid(
                "cycleState",
                "only an open cycle can end",
            ));
        }
        if state == CycleState::Open {
            return Err(H3Error::invalid(
                "cycleState",
                "an ended cycle cannot remain open",
            ));
        }
        self.state = state;
        self.ended_at = Some(at);
        Ok(self)
    }
}

impl H3Record for SyncCycle {
    const RECORD: &'static str = "sync cycle";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Versioned H3 project settings with an optional human configuration
/// approval. Settings without an approval are scan-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3Settings {
    format_version: u32,
    project_id: ProjectId,
    version: u64,
    enabled: bool,
    target_paths: Vec<String>,
    auto_publish: bool,
    retain_history: bool,
    fingerprint: ContentDigest,
    approved_at: Timestamp,
    /// Human approval bound to this exact version. Settings without one are
    /// scan-only; a receipt or contract is never stored here as approval.
    #[serde(default)]
    approval: Option<H3ConfigurationApproval>,
}

impl H3Settings {
    /// Creates settings without a recorded human configuration approval.
    ///
    /// This value is persisted and may be scanned, but the H3 owner registry
    /// never mints authority from it. Use [`Self::approved`] for the normal
    /// human-approved path. Target paths are canonical, unique, and sorted; the
    /// fingerprint binds the exact stored scope.
    pub fn new(
        project_id: ProjectId,
        version: u64,
        enabled: bool,
        mut target_paths: Vec<String>,
        auto_publish: bool,
        retain_history: bool,
        approved_at: Timestamp,
    ) -> Result<Self, H3Error> {
        if version == 0 {
            return Err(H3Error::must_be_positive("settingsVersion"));
        }
        if target_paths.is_empty() {
            return Err(H3Error::empty("targetPaths"));
        }
        for path in &target_paths {
            DocumentKey::new(project_id, path.clone())?;
        }
        target_paths.sort();
        target_paths.dedup();
        let fingerprint = settings_fingerprint(project_id, version, &target_paths, auto_publish, retain_history);
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            project_id,
            version,
            enabled,
            target_paths,
            auto_publish,
            retain_history,
            fingerprint,
            approved_at,
            approval: None,
        })
    }

    /// Creates settings from one human configuration approval.
    ///
    /// The settings version, Target set, retention flag, and approval time all
    /// come from the approval. The fingerprint binds both the stored scope and
    /// the approval fingerprint, so removing, adding, or altering a Target
    /// without a new approval is detected.
    pub fn approved(
        approval: H3ConfigurationApproval,
        enabled: bool,
    ) -> Result<Self, H3Error> {
        let project_id = approval.project_id();
        let version = approval.settings_version();
        let targets = approval.targets().to_vec();
        let auto_publish = approval.auto_publish();
        let retain_history = approval.retain_history();
        let approved_at = approval.approved_at();
        Self::new(
            project_id,
            version,
            enabled,
            targets,
            auto_publish,
            retain_history,
            approved_at,
        )?
        .with_approval(approval)
    }

    /// Attaches one human approval to these settings.
    ///
    /// The approval must cover exactly this project, settings version, Target
    /// set, and retention flag. The fingerprint is recomputed with the
    /// approval fingerprint mixed in.
    pub fn with_approval(mut self, approval: H3ConfigurationApproval) -> Result<Self, H3Error> {
        approval.verify_fingerprint()?;
        if approval.project_id() != self.project_id {
            return Err(H3Error::CrossProject {
                id_kind: "configuration approval".to_owned(),
                expected: self.project_id,
                found: approval.project_id(),
            });
        }
        if approval.settings_version() != self.version {
            return Err(H3Error::invalid(
                "settingsVersion",
                "the approval does not cover this settings version",
            ));
        }
        if approval.targets() != self.target_paths {
            return Err(H3Error::invalid(
                "targetPaths",
                "the approval does not cover exactly this Target set",
            ));
        }
        if approval.auto_publish() != self.auto_publish {
            return Err(H3Error::invalid(
                "autoPublish",
                "the approval auto-publish setting differs from the settings",
            ));
        }
        if approval.retain_history() != self.retain_history {
            return Err(H3Error::invalid(
                "retainHistory",
                "the approval retention differs from the settings",
            ));
        }
        self.approval = Some(approval);
        self.fingerprint = self.compute_fingerprint();
        Ok(self)
    }

    /// Project these settings belong to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Human-approved settings version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Whether H3 automatic authoring is enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Approved Target-relative Markdown paths.
    pub fn target_paths(&self) -> &[String] {
        &self.target_paths
    }

    /// Whether an approved candidate may be published automatically.
    pub const fn auto_publish(&self) -> bool {
        self.auto_publish
    }

    /// Whether old versions must be retained. H3 never silently prunes them.
    pub const fn retain_history(&self) -> bool {
        self.retain_history
    }

    /// Fingerprint binding the exact approved scope.
    pub const fn fingerprint(&self) -> &ContentDigest {
        &self.fingerprint
    }

    /// When the version was approved.
    pub const fn approved_at(&self) -> Timestamp {
        self.approved_at
    }

    /// Human configuration approval bound to this version, when one exists.
    pub const fn approval(&self) -> Option<&H3ConfigurationApproval> {
        self.approval.as_ref()
    }

    /// Recomputes and verifies the stored scope fingerprint.
    pub fn verify_fingerprint(&self) -> bool {
        self.fingerprint == self.compute_fingerprint()
    }

    /// Returns a new enabled version with a fresh fingerprint.
    ///
    /// A settings version is part of the human approval. Enabling therefore
    /// records no approval until a human approves the new version; the previous
    /// approval never carries over silently.
    pub fn enable(self, at: Timestamp) -> Result<Self, H3Error> {
        let next = self
            .version
            .checked_add(1)
            .ok_or_else(|| H3Error::invalid("settingsVersion", "version overflow"))?;
        Self::new(
            self.project_id,
            next,
            true,
            self.target_paths,
            self.auto_publish,
            self.retain_history,
            at,
        )
    }

    fn compute_fingerprint(&self) -> ContentDigest {
        let base = settings_fingerprint(
            self.project_id,
            self.version,
            &self.target_paths,
            self.auto_publish,
            self.retain_history,
        );
        mix_approval_fingerprint(&base, self.approval.as_ref())
    }
}

fn settings_fingerprint(
    project_id: ProjectId,
    version: u64,
    target_paths: &[String],
    auto_publish: bool,
    retain_history: bool,
) -> ContentDigest {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"h3-settings\0");
    hasher.update(project_id.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(version.to_le_bytes());
    hasher.update([u8::from(auto_publish), u8::from(retain_history)]);
    for path in target_paths {
        hasher.update(b"\0");
        hasher.update(path.as_bytes());
    }
    ContentDigest::sha256(&hasher.finalize())
}

impl H3Record for H3Settings {
    const RECORD: &'static str = "H3 settings";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Publication journal status. This is H3 state, not an H1 publication record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStatus {
    /// Intent persisted; no side effect started.
    Prepared,
    /// Old versions were saved successfully.
    OldVersionSaved,
    /// The formal files are being replaced.
    Replacing,
    /// The formal files were replaced and observed.
    Published,
    /// Publication was refused before any replacement.
    NotPublished,
    /// The side effect may have happened but its result is unknown.
    Unverifiable,
    /// External changes require human conflict resolution.
    Conflict,
}

/// Which formal file one publication journal entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationFileRole {
    /// The formal HTML companion.
    Html,
    /// The versioned evaluation receipt under `docs/sdd/html-evidence/`.
    Receipt,
}

impl PublicationFileRole {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Receipt => "receipt",
        }
    }
}

/// Per-file state inside one publication journal entry.
///
/// H3 publishes the HTML and the receipt as two separate single-file H1
/// requests. This state records each file independently; it is never presented
/// as one atomic multi-file filesystem transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationFileStatus {
    /// The journal intends to publish this file but no side effect ran.
    Pending,
    /// The exact approved bytes were observed at the formal path.
    Published,
    /// The file was not replaced and the failure is known.
    NotPublished,
    /// The file may or may not have been replaced; reconciliation is required.
    Unverifiable,
}

impl PublicationFileStatus {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::NotPublished => "not_published",
            Self::Unverifiable => "unverifiable",
        }
    }
}

/// One file in the H3 publication sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationFileJournal {
    role: PublicationFileRole,
    path: String,
    expected: ExpectedTargetVersion,
    approved_digest: ContentDigest,
    h1_request_id: Option<PublicationRequestId>,
    status: PublicationFileStatus,
    observed_after: Option<ContentDigest>,
    updated_at: Timestamp,
}

impl PublicationFileJournal {
    /// Creates one pending file entry.
    pub fn pending(
        role: PublicationFileRole,
        path: impl Into<String>,
        expected: ExpectedTargetVersion,
        approved_digest: ContentDigest,
        h1_request_id: Option<PublicationRequestId>,
        at: Timestamp,
    ) -> Result<Self, H3Error> {
        let path = path.into();
        if path.is_empty() || path.starts_with('/') || path.contains('\\') {
            return Err(H3Error::invalid(
                "publicationFile.path",
                "the publication file path must be project-relative",
            ));
        }
        if path.split('/').any(|part| part.is_empty() || part == "..") {
            return Err(H3Error::invalid(
                "publicationFile.path",
                "the publication file path must be canonical",
            ));
        }
        Ok(Self {
            role,
            path,
            expected,
            approved_digest,
            h1_request_id,
            status: PublicationFileStatus::Pending,
            observed_after: None,
            updated_at: at,
        })
    }

    /// File role.
    pub const fn role(&self) -> PublicationFileRole {
        self.role
    }

    /// Project-relative formal path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Expected current version or explicit absence at the start of the attempt.
    pub const fn expected(&self) -> &ExpectedTargetVersion {
        &self.expected
    }

    /// Exact approved content digest.
    pub const fn approved_digest(&self) -> &ContentDigest {
        &self.approved_digest
    }

    /// H1 single-file publication request used for this file.
    pub const fn h1_request_id(&self) -> Option<&PublicationRequestId> {
        self.h1_request_id.as_ref()
    }

    /// Current per-file state.
    pub const fn status(&self) -> PublicationFileStatus {
        self.status
    }

    /// Exact digest observed after the side effect, when one was read.
    pub const fn observed_after(&self) -> Option<&ContentDigest> {
        self.observed_after.as_ref()
    }

    /// Last time this file entry changed.
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Records the exact post-write observation.
    pub fn observed(mut self, observed: ContentDigest, at: Timestamp) -> Self {
        self.status = if observed == self.approved_digest {
            PublicationFileStatus::Published
        } else {
            PublicationFileStatus::Unverifiable
        };
        self.observed_after = Some(observed);
        self.updated_at = at;
        self
    }

    /// Records a known failure without replacement.
    pub fn not_published(mut self, at: Timestamp) -> Self {
        self.status = PublicationFileStatus::NotPublished;
        self.updated_at = at;
        self
    }

    /// Records an unknown result after a possible side effect.
    pub fn unverifiable(mut self, at: Timestamp) -> Self {
        self.status = PublicationFileStatus::Unverifiable;
        self.updated_at = at;
        self
    }
}

/// One archived version reference supplied by the host archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArchivedVersionRef {
    reference: String,
    digest: ContentDigest,
}

impl ArchivedVersionRef {
    /// Creates a reference to one privately archived version. The reference is
    /// host-supplied, must be relative, and must not escape its private root.
    pub fn new(reference: impl Into<String>, digest: ContentDigest) -> Result<Self, H3Error> {
        let reference = reference.into();
        if reference.is_empty() || reference.contains('\0') || reference.chars().any(char::is_control) {
            return Err(H3Error::empty("archiveReference"));
        }
        if reference.starts_with('/') || reference.split('/').any(|part| part == "..") {
            return Err(H3Error::invalid(
                "archiveReference",
                "the archive reference must stay inside the private history root",
            ));
        }
        Ok(Self { reference, digest })
    }

    /// Private relative archive reference.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Exact archived version digest.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

/// Durable H3 publication journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationJournal {
    format_version: u32,
    publication_id: PublicationId,
    project_id: ProjectId,
    document_key: DocumentKey,
    generation_id: GenerationId,
    candidate_id: CandidateId,
    h1_request_id: PublicationRequestId,
    h1_record_key: Option<String>,
    expected_target: ExpectedTargetVersion,
    approved_html_digest: ContentDigest,
    provenance_digest: ContentDigest,
    old_html: Option<ArchivedVersionRef>,
    old_receipt: Option<ArchivedVersionRef>,
    status: PublicationStatus,
    observed_after_html: Option<ContentDigest>,
    source: SourceSnapshot,
    created_at: Timestamp,
    updated_at: Timestamp,
    detail: Option<String>,
    /// Canonical receipt path written by this attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_path: Option<String>,
    /// Expected receipt version or explicit absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_receipt: Option<ExpectedTargetVersion>,
    /// Exact receipt digest written by this attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_digest: Option<ContentDigest>,
    /// H1 single-file request used for the receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_request_id: Option<PublicationRequestId>,
    /// Exact receipt digest observed after the side effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_after_receipt: Option<ContentDigest>,
    /// Per-file states and sequence. Never presented as one filesystem
    /// transaction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    files: Vec<PublicationFileJournal>,
    /// Digest binding this attempt's exact request payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_fingerprint: Option<ContentDigest>,
    /// Final project sequence returned by the synced commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    final_project_sequence: Option<u64>,
}

impl PublicationJournal {
    /// Creates a journal entry linked to the H1 host publication request.
    ///
    /// H1 owns the publication events and record; this entry only references
    /// the request ID so the H3 journal and the H1 audit can be reconciled
    /// without duplicating either event stream.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        publication_id: PublicationId,
        document_key: DocumentKey,
        generation_id: GenerationId,
        candidate_id: CandidateId,
        h1_request_id: PublicationRequestId,
        expected_target: ExpectedTargetVersion,
        approved_html_digest: ContentDigest,
        provenance_digest: ContentDigest,
        source: SourceSnapshot,
        created_at: Timestamp,
    ) -> Result<Self, H3Error> {
        let project = document_key.project_id();
        publication_id.validate_in(project)?;
        generation_id.validate_in(project)?;
        candidate_id.validate_in(project)?;
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            publication_id,
            project_id: project,
            document_key,
            generation_id,
            candidate_id,
            h1_request_id,
            h1_record_key: None,
            expected_target,
            approved_html_digest,
            provenance_digest,
            old_html: None,
            old_receipt: None,
            status: PublicationStatus::Prepared,
            observed_after_html: None,
            source,
            created_at,
            updated_at: created_at,
            detail: None,
            receipt_path: None,
            expected_receipt: None,
            receipt_digest: None,
            receipt_request_id: None,
            observed_after_receipt: None,
            files: Vec::new(),
            request_fingerprint: None,
            final_project_sequence: None,
        })
    }

    /// Publication identifier.
    pub const fn publication_id(&self) -> PublicationId {
        self.publication_id
    }

    /// Project that owns the journal.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Document being published.
    pub const fn document_key(&self) -> &DocumentKey {
        &self.document_key
    }

    /// Generation being published.
    pub const fn generation_id(&self) -> GenerationId {
        self.generation_id
    }

    /// Candidate being published.
    pub const fn candidate_id(&self) -> CandidateId {
        self.candidate_id
    }

    /// H1 host publication request identifier.
    pub const fn h1_request_id(&self) -> &PublicationRequestId {
        &self.h1_request_id
    }

    /// Optional H1 host-state record key for recovery lookup.
    pub fn h1_record_key(&self) -> Option<&str> {
        self.h1_record_key.as_deref()
    }

    /// Expected formal target version at publication time.
    pub const fn expected_target(&self) -> &ExpectedTargetVersion {
        &self.expected_target
    }

    /// Approved candidate HTML digest.
    pub const fn approved_html_digest(&self) -> &ContentDigest {
        &self.approved_html_digest
    }

    /// Candidate provenance digest.
    pub const fn provenance_digest(&self) -> &ContentDigest {
        &self.provenance_digest
    }

    /// Archived old HTML version.
    pub const fn old_html(&self) -> Option<&ArchivedVersionRef> {
        self.old_html.as_ref()
    }

    /// Archived old receipt version.
    pub const fn old_receipt(&self) -> Option<&ArchivedVersionRef> {
        self.old_receipt.as_ref()
    }

    /// Journal status.
    pub const fn status(&self) -> PublicationStatus {
        self.status
    }

    /// Formal HTML digest observed after replacement.
    pub const fn observed_after_html(&self) -> Option<&ContentDigest> {
        self.observed_after_html.as_ref()
    }

    /// Source snapshot the publication was verified against.
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// When the journal entry was created.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// When the journal entry was last updated.
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Sanitized detail for a non-successful status.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// Canonical receipt path, when this attempt publishes one.
    pub fn receipt_path(&self) -> Option<&str> {
        self.receipt_path.as_deref()
    }

    /// Expected current receipt version or explicit absence.
    pub const fn expected_receipt(&self) -> Option<&ExpectedTargetVersion> {
        self.expected_receipt.as_ref()
    }

    /// Exact approved receipt digest.
    pub const fn receipt_digest(&self) -> Option<&ContentDigest> {
        self.receipt_digest.as_ref()
    }

    /// H1 request used for the receipt.
    pub const fn receipt_request_id(&self) -> Option<&PublicationRequestId> {
        self.receipt_request_id.as_ref()
    }

    /// Receipt digest observed after the side effect.
    pub const fn observed_after_receipt(&self) -> Option<&ContentDigest> {
        self.observed_after_receipt.as_ref()
    }

    /// Per-file journal entries in publication order.
    pub fn files(&self) -> &[PublicationFileJournal] {
        &self.files
    }

    /// One per-file entry by role.
    pub fn file(&self, role: PublicationFileRole) -> Option<&PublicationFileJournal> {
        self.files.iter().find(|file| file.role() == role)
    }

    /// Digest binding the exact attempt payload.
    pub const fn request_fingerprint(&self) -> Option<&ContentDigest> {
        self.request_fingerprint.as_ref()
    }

    /// Final project sequence of the synced commit.
    pub const fn final_project_sequence(&self) -> Option<u64> {
        self.final_project_sequence
    }

    /// Binds this attempt's exact payload fingerprint.
    pub fn with_request_fingerprint(mut self, fingerprint: ContentDigest) -> Self {
        self.request_fingerprint = Some(fingerprint);
        self
    }

    /// Records the receipt target and H1 request for this attempt.
    pub fn with_receipt(
        mut self,
        path: impl Into<String>,
        expected: ExpectedTargetVersion,
        digest: ContentDigest,
        request_id: PublicationRequestId,
        at: Timestamp,
    ) -> Result<Self, H3Error> {
        let path = path.into();
        if path.is_empty() || path.starts_with('/') || path.contains('\\') {
            return Err(H3Error::invalid(
                "receiptPath",
                "the receipt path must be project-relative",
            ));
        }
        if path.split('/').any(|part| part.is_empty() || part == "..") {
            return Err(H3Error::invalid(
                "receiptPath",
                "the receipt path must be canonical",
            ));
        }
        self.receipt_path = Some(path);
        self.expected_receipt = Some(expected);
        self.receipt_digest = Some(digest);
        self.receipt_request_id = Some(request_id);
        self.updated_at = at;
        Ok(self)
    }

    /// Records the ordered per-file journal entries.
    pub fn with_files(mut self, files: Vec<PublicationFileJournal>) -> Self {
        self.files = files;
        self
    }

    /// Adds or replaces one file entry after an observation.
    pub fn with_file(mut self, file: PublicationFileJournal) -> Result<Self, H3Error> {
        if let Some(index) = self.files.iter().position(|entry| entry.role() == file.role()) {
            self.files[index] = file;
        } else {
            self.files.push(file);
        }
        Ok(self)
    }

    /// Marks the attempt published after both exact files were observed.
    pub fn published_pair(
        mut self,
        observed_html: ContentDigest,
        observed_receipt: ContentDigest,
        final_project_sequence: Option<u64>,
        at: Timestamp,
    ) -> Result<Self, H3Error> {
        if self.status != PublicationStatus::Replacing {
            return Err(H3Error::invalid(
                "publicationStatus",
                "only a replacing journal can become published",
            ));
        }
        if observed_html != self.approved_html_digest {
            return Err(H3Error::invalid(
                "observedAfterHtml",
                "the observed HTML does not match the approved candidate",
            ));
        }
        if self.receipt_digest.as_ref() != Some(&observed_receipt) {
            return Err(H3Error::invalid(
                "observedAfterReceipt",
                "the observed receipt does not match the approved receipt",
            ));
        }
        self.status = PublicationStatus::Published;
        self.observed_after_html = Some(observed_html);
        self.observed_after_receipt = Some(observed_receipt);
        self.final_project_sequence = final_project_sequence;
        self.updated_at = at;
        Ok(self)
    }

    /// Marks a post-side-effect state that needs reconciliation.
    pub fn unverifiable(mut self, detail: impl Into<String>, at: Timestamp) -> Self {
        self.status = PublicationStatus::Unverifiable;
        self.detail = Some(detail.into());
        self.updated_at = at;
        self
    }

    /// Records the final project sequence assigned by the synced commit.
    pub fn with_final_project_sequence(mut self, sequence: u64) -> Self {
        self.final_project_sequence = Some(sequence);
        self
    }

    /// Records the H1 host-state record key.
    pub fn with_h1_record_key(mut self, key: impl Into<String>) -> Result<Self, H3Error> {
        let key = key.into();
        if key.trim().is_empty() || key.chars().any(char::is_control) {
            return Err(H3Error::empty("h1PublicationRecordKey"));
        }
        self.h1_record_key = Some(key);
        Ok(self)
    }

    /// Records successfully archived old versions.
    pub fn old_versions_saved(
        mut self,
        html: Option<ArchivedVersionRef>,
        receipt: Option<ArchivedVersionRef>,
        at: Timestamp,
    ) -> Result<Self, H3Error> {
        if matches!(self.expected_target, ExpectedTargetVersion::Present { .. }) && html.is_none() {
            return Err(H3Error::invalid(
                "oldHtml",
                "an existing formal HTML version must be archived before replacement",
            ));
        }
        self.old_html = html;
        self.old_receipt = receipt;
        self.status = PublicationStatus::OldVersionSaved;
        self.updated_at = at;
        Ok(self)
    }

    /// Marks replacement in progress.
    pub fn replacing(mut self, at: Timestamp) -> Result<Self, H3Error> {
        if !matches!(
            self.status,
            PublicationStatus::OldVersionSaved | PublicationStatus::Prepared
        ) {
            return Err(H3Error::invalid(
                "publicationStatus",
                "replacement requires a prepared or old-version-saved journal",
            ));
        }
        if matches!(self.expected_target, ExpectedTargetVersion::Present { .. })
            && self.old_html.is_none()
        {
            return Err(H3Error::invalid(
                "oldHtml",
                "an existing formal HTML version must be archived before replacement",
            ));
        }
        self.status = PublicationStatus::Replacing;
        self.updated_at = at;
        Ok(self)
    }

    /// Marks the publication successful with the observed HTML digest.
    pub fn published(mut self, observed_html: ContentDigest, at: Timestamp) -> Result<Self, H3Error> {
        if self.status != PublicationStatus::Replacing {
            return Err(H3Error::invalid(
                "publicationStatus",
                "only a replacing journal can become published",
            ));
        }
        self.status = PublicationStatus::Published;
        self.observed_after_html = Some(observed_html);
        self.updated_at = at;
        Ok(self)
    }

    /// Marks the publication unsuccessful with a sanitized detail.
    pub fn failed(
        mut self,
        status: PublicationStatus,
        detail: impl Into<String>,
        at: Timestamp,
    ) -> Result<Self, H3Error> {
        if matches!(
            status,
            PublicationStatus::Published | PublicationStatus::Replacing | PublicationStatus::Prepared
        ) {
            return Err(H3Error::invalid(
                "publicationStatus",
                "a failed journal must use a terminal or reconciliation status",
            ));
        }
        self.status = status;
        self.detail = Some(detail.into());
        self.updated_at = at;
        Ok(self)
    }
}

impl H3Record for PublicationJournal {
    const RECORD: &'static str = "publication journal";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Versioned public status for one H3 document.
///
/// The status combines the durable compare-and-swap revision with the current
/// document state and the final project sequence. It is the response shape H4
/// and H5 consume; they must not create their own success field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3DocumentStatus {
    format_version: u32,
    revision: u64,
    final_project_sequence: u64,
    document: H3DocumentState,
}

impl H3DocumentStatus {
    /// Creates a public status from a durable document record.
    pub fn new(
        revision: u64,
        final_project_sequence: u64,
        document: H3DocumentState,
    ) -> Result<Self, H3Error> {
        if revision == 0 {
            return Err(H3Error::must_be_positive("documentRevision"));
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            revision,
            final_project_sequence,
            document,
        })
    }

    /// Durable document revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Final project sequence observed by the current state.
    pub const fn final_project_sequence(&self) -> u64 {
        self.final_project_sequence
    }

    /// Project that owns the document.
    pub const fn project_id(&self) -> ProjectId {
        self.document.project_id()
    }

    /// Document key.
    pub const fn document_key(&self) -> &DocumentKey {
        self.document.document_key()
    }

    /// Current state.
    pub const fn state(&self) -> H3State {
        self.document.state()
    }

    /// Versioned reason and required actions.
    pub const fn reason(&self) -> &H3Reason {
        self.document.reason()
    }

    /// Current applicability of the recorded success.
    pub const fn applicability(&self) -> &Applicability {
        self.document.applicability()
    }

    /// Current source snapshot.
    pub const fn source(&self) -> &SourceSnapshot {
        self.document.source()
    }

    /// Current generation.
    pub const fn generation(&self) -> Option<GenerationId> {
        self.document.generation()
    }

    /// Current cycle.
    pub const fn cycle_id(&self) -> Option<CycleId> {
        self.document.cycle_id()
    }

    /// Current job.
    pub const fn job_id(&self) -> Option<JobId> {
        self.document.job_id()
    }

    /// Approved settings version.
    pub const fn settings_version(&self) -> u64 {
        self.document.settings_version()
    }

    /// H2 reference, when one exists.
    pub const fn h2(&self) -> Option<&H2Reference> {
        self.document.h2()
    }

    /// Evidence references.
    pub fn evidence(&self) -> &[EvidenceRef] {
        self.document.evidence()
    }

    /// When the state was last updated.
    pub const fn updated_at(&self) -> Timestamp {
        self.document.updated_at()
    }
}

impl H3Record for H3DocumentStatus {
    const RECORD: &'static str = "document status";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Deterministic host-activity ID for project-level H3 settings events.
pub fn project_activity_id(project: ProjectId) -> HostActivityId {
    let mut value = [0_u8; 16];
    value.copy_from_slice(
        &sha2::Sha256::digest(format!("h3-project-activity\0{project}").as_bytes())[..16],
    );
    HostActivityId::from_parts(project, Uuid::from_bytes(value))
}

/// Decodes a document state after checking its format version.
pub fn decode_document_state(bytes: &[u8]) -> Result<H3DocumentState, H3Error> {
    crate::version::decode_record::<H3DocumentState>(bytes)
}
