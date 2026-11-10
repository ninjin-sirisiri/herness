//! Serial authoring coordination for H3.
//!
//! One [`SyncCoordinator`] is shared by every open project. It enforces exactly
//! one app-wide authoring slot, one dirty queue in notification order, and a
//! single generation per document at a time. It owns the pure H3 lifecycle; the
//! host composition supplies the H1 candidate run, the H2 owner start, the
//! immutable workspace read, and the durable H3 store through ports.
//!
//! The coordinator never calls a provider, a Tauri command, a database, or the
//! H1 runtime directly. It also never accepts a parent-model tool call as a
//! start reason: a start exists only because an approved observer candidate was
//! queued and the saved H2/H3 state passed the gate again.
//!
//! Latches are never cleared by a new notification. A latched document stays
//! held until the host's human resume/recovery path changes the saved state;
//! this module only re-reads and reports it.

use std::collections::{BTreeMap, VecDeque};

use herness_core::{ArtifactHandle, ProjectId, RunId, Timestamp};
use herness_supervision::{
    BudgetPolicy, ConditionDigest, ConditionVersion, ConsentBinding, ContentDigest, ExecutionScope,
    ProfileBinding, SupervisionId, TargetVersion,
};

use crate::config::H3ApprovalLimits;
use crate::document::{DocumentKey, FingerprintSet, SourceSnapshot};
use crate::error::H3Error;
use crate::events::document_state_event;
use crate::ids::{CandidateId, CycleId, GenerationId, JobId};
use crate::observer::{DependencyPath, ObservationTrigger, SourceObservation};
use crate::ports::{
    DocumentCommit, H3DocumentRecord, H3SettingsRecord, H3StorePort, HtmlSyncCommit,
};
use crate::state::{
    Applicability, ApplicabilityReason, CandidateRecord, CandidateStorageRef, CycleLatch,
    CycleState, GenerationRecord, GenerationStatus, H2Reference, H3DocumentState, H3FailureCause,
    H3Reason, H3Settings, H3State, H3StateReasonKind, H3StopCause, HumanWaitCause, RequiredAction,
    SyncCycle,
};
use crate::workspace::{
    AuthoringPolicy, AuthoringSnapshot, AuthoringWorkspace, MAX_SHARED_CSS_BYTES,
    WorkspaceCaptureRequest,
};

/// The app-wide automatic authoring slot is exactly one.
pub const APP_WIDE_AUTHORING_CONCURRENCY: u32 = 1;
/// Candidate publication for one document is exactly one.
pub const DOCUMENT_PUBLICATION_CONCURRENCY: u32 = 1;

/// Approved owner and policy context for one project's H3 job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoringJob {
    project_id: ProjectId,
    job: JobId,
    job_label: String,
    supervision_id: SupervisionId,
    settings_version: u64,
    settings_fingerprint: ContentDigest,
    approval_fingerprint: ContentDigest,
    owner: herness_supervision::OwnerRef,
    condition_version: ConditionVersion,
    conditions_digest: ConditionDigest,
    execution_scope: ExecutionScope,
    budget_policy_version: u64,
    budget: BudgetPolicy,
    profile: ProfileBinding,
    consent: ConsentBinding,
    policy_version: String,
    policy_fingerprint: ContentDigest,
    pack_fingerprint: ContentDigest,
    limits: H3ApprovalLimits,
    targets: Vec<String>,
    auto_publish: bool,
    retain_history: bool,
    dependencies: Vec<DependencyPath>,
}

impl AuthoringJob {
    /// Builds the exact job context from one current, human-approved settings
    /// version and the host-owned H2 target mapping.
    ///
    /// This is a value builder, not an approval. The H2 owner start still mints
    /// its own [`herness_supervision::HostOwnerAuthority`] from the current
    /// registry immediately before the run.
    pub fn from_settings(
        settings: &H3Settings,
        supervision_id: SupervisionId,
        now: Timestamp,
    ) -> Result<Self, H3Error> {
        if !settings.verify_fingerprint() {
            return Err(H3Error::invalid(
                "settings",
                "the stored settings fingerprint does not match its approved scope",
            ));
        }
        if !settings.enabled() {
            return Err(H3Error::invalid(
                "enabled",
                "the approved settings are disabled",
            ));
        }
        let approval = settings.approval().ok_or_else(|| H3Error::Unavailable {
            capability: "h3.configuration_approval".to_owned(),
            detail: "settings without a human configuration approval are scan-only".to_owned(),
        })?;
        if approval.project_id() != settings.project_id()
            || approval.settings_version() != settings.version()
        {
            return Err(H3Error::invalid(
                "approval",
                "the configuration approval does not belong to this settings version",
            ));
        }
        if !approval.is_current_at(now) {
            return Err(H3Error::Unavailable {
                capability: "h3.configuration_approval".to_owned(),
                detail: "the configuration approval is revoked, superseded, or expired".to_owned(),
            });
        }
        approval.verify_fingerprint()?;
        if approval.owner_binding().execution_scope().allow_shell() {
            return Err(H3Error::invalid(
                "executionScope.allowShell",
                "the H3 authoring scope must never allow shell",
            ));
        }
        Ok(Self {
            project_id: settings.project_id(),
            job: JobId::new(settings.project_id()),
            job_label: approval.owner_binding().job_id().to_owned(),
            supervision_id,
            settings_version: settings.version(),
            settings_fingerprint: settings.fingerprint().clone(),
            approval_fingerprint: approval.fingerprint().clone(),
            owner: approval.owner_binding().owner().clone(),
            condition_version: approval.owner_binding().condition_version(),
            conditions_digest: approval.owner_binding().conditions_digest().clone(),
            execution_scope: approval.owner_binding().execution_scope().clone(),
            budget_policy_version: approval.owner_binding().budget_policy_version(),
            budget: approval.owner_binding().budget().clone(),
            profile: approval.authoring().profile(),
            consent: approval.authoring().consent(),
            policy_version: approval.versions().policy_version().to_owned(),
            policy_fingerprint: approval.versions().policy_fingerprint().clone(),
            pack_fingerprint: approval.versions().pack_fingerprint().clone(),
            limits: approval.limits().clone(),
            targets: approval.targets().to_vec(),
            auto_publish: approval.auto_publish(),
            retain_history: approval.retain_history(),
            dependencies: Vec::new(),
        })
    }

    /// Restores the durable H3 job identity from a stored generation.
    ///
    /// A restart must not hallucinate a new job identity for work that already
    /// has a generation. The host supplies the exact stored [`JobId`].
    pub fn with_durable_job_id(mut self, job: JobId) -> Result<Self, H3Error> {
        job.validate_in(self.project_id)?;
        self.job = job;
        Ok(self)
    }

    /// Adds the caller-supplied CSS/resource dependency set.
    ///
    /// The host supplies the same canonical paths the observer uses. The
    /// coordinator never discovers dependencies itself.
    pub fn with_dependencies(mut self, dependencies: Vec<DependencyPath>) -> Result<Self, H3Error> {
        let mut dependencies = dependencies;
        dependencies.sort_by(|left, right| {
            left.path()
                .cmp(right.path())
                .then_with(|| left.kind().as_str().cmp(right.kind().as_str()))
        });
        for pair in dependencies.windows(2) {
            if pair[0].path() == pair[1].path() {
                return Err(H3Error::invalid(
                    "dependencies",
                    "one authoring job cannot declare the same dependency twice",
                ));
            }
        }
        let css = dependencies
            .iter()
            .filter(|dependency| dependency.kind() == crate::observer::DependencyKind::Css)
            .count();
        if css > 1 {
            return Err(H3Error::invalid(
                "dependencies.css",
                "the candidate store exposes exactly one shared CSS snapshot",
            ));
        }
        self.dependencies = dependencies;
        Ok(self)
    }

    /// Re-checks that this job still matches the current stored settings.
    pub fn verify_against(&self, settings: &H3Settings, now: Timestamp) -> Result<(), H3Error> {
        if !settings.verify_fingerprint()
            || settings.version() != self.settings_version
            || settings.fingerprint() != &self.settings_fingerprint
            || !settings.enabled()
        {
            return Err(H3Error::Unavailable {
                capability: "h3.configuration_approval".to_owned(),
                detail: "the stored settings version no longer matches the job".to_owned(),
            });
        }
        let approval = settings.approval().ok_or_else(|| H3Error::Unavailable {
            capability: "h3.configuration_approval".to_owned(),
            detail: "the stored settings have no human approval".to_owned(),
        })?;
        if approval.fingerprint() != &self.approval_fingerprint
            || approval.project_id() != self.project_id
            || approval.settings_version() != self.settings_version
            || !approval.is_current_at(now)
        {
            return Err(H3Error::Unavailable {
                capability: "h3.configuration_approval".to_owned(),
                detail: "the configuration approval is no longer current".to_owned(),
            });
        }
        approval.verify_fingerprint()?;
        Ok(())
    }

    /// Whether the document is inside the approved Target set.
    pub fn covers(&self, document: &DocumentKey) -> bool {
        self.targets
            .iter()
            .any(|target| target == document.target_path())
    }

    /// Project that owns the job.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Opaque H3 job identity.
    pub const fn job(&self) -> JobId {
        self.job
    }

    /// Opaque job label covered by the H2 owner approval.
    pub fn job_label(&self) -> &str {
        &self.job_label
    }

    /// H2 supervision target that owns the budget and evidence.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Approved settings version.
    pub const fn settings_version(&self) -> u64 {
        self.settings_version
    }

    /// Approved settings fingerprint.
    pub const fn settings_fingerprint(&self) -> &ContentDigest {
        &self.settings_fingerprint
    }

    /// Approved owner.
    pub fn owner(&self) -> &herness_supervision::OwnerRef {
        &self.owner
    }

    /// Approved condition version.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Exact approved condition digest.
    pub const fn conditions_digest(&self) -> &ConditionDigest {
        &self.conditions_digest
    }

    /// Approved execution scope.
    pub const fn execution_scope(&self) -> &ExecutionScope {
        &self.execution_scope
    }

    /// Approved budget policy version.
    pub const fn budget_policy_version(&self) -> u64 {
        self.budget_policy_version
    }

    /// Approved finite budget policy.
    pub const fn budget(&self) -> &BudgetPolicy {
        &self.budget
    }

    /// Approved authoring profile binding.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Approved disclosure consent binding.
    pub const fn consent(&self) -> ConsentBinding {
        self.consent
    }

    /// Approved common SDD policy version.
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// Approved policy fingerprint.
    pub const fn policy_fingerprint(&self) -> &ContentDigest {
        &self.policy_fingerprint
    }

    /// Approved pack fingerprint.
    pub const fn pack_fingerprint(&self) -> &ContentDigest {
        &self.pack_fingerprint
    }

    /// Approved limits.
    pub const fn limits(&self) -> &H3ApprovalLimits {
        &self.limits
    }

    /// Approved Target set.
    pub fn targets(&self) -> &[String] {
        &self.targets
    }

    /// Caller-supplied dependency set.
    pub fn dependencies(&self) -> &[DependencyPath] {
        &self.dependencies
    }

    /// Whether an approved candidate may be published automatically.
    pub const fn auto_publish(&self) -> bool {
        self.auto_publish
    }

    /// Whether old versions are retained.
    pub const fn retain_history(&self) -> bool {
        self.retain_history
    }

    /// Policy context for the workspace capture.
    pub fn policy(&self) -> Result<AuthoringPolicy, H3Error> {
        AuthoringPolicy::new(
            self.settings_fingerprint.clone(),
            self.policy_version.clone(),
            self.policy_fingerprint.clone(),
            self.pack_fingerprint.clone(),
            self.condition_version,
            self.conditions_digest.clone(),
            self.limits.source_bytes(),
            MAX_SHARED_CSS_BYTES.min(self.limits.candidate_bytes()),
            self.limits.candidate_bytes(),
        )
    }
}

/// Re-check result from the host-owned H2/H1 boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthoringGate {
    /// The saved H2/H3 state permits one start now.
    Allowed {
        /// Exact H2 target reference observed before the start.
        h2: H2Reference,
        /// Target version the start should use.
        target_version: TargetVersion,
    },
    /// A persisted human stop, wait, stagnation, limit, or recovery latch.
    Latched {
        /// Cycle latch to persist, when a cycle exists.
        latch: Option<CycleLatch>,
        /// Exact H3 reason to persist.
        reason: H3Reason,
        /// Short non-secret explanation for the tick report.
        detail: String,
    },
    /// A required capability is missing or the H2 plan is not usable.
    Unavailable {
        /// Stable capability label.
        capability: String,
        /// Sanitized explanation.
        detail: String,
    },
    /// The saved H2 state is an unrecoverable failure.
    Failed {
        /// Concrete H3 failure cause.
        cause: H3FailureCause,
        /// Sanitized explanation.
        detail: String,
    },
}

/// One gate re-check request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerGateRequest {
    job: AuthoringJob,
    document: DocumentKey,
    source: SourceSnapshot,
    previous_target: Option<TargetVersion>,
}

impl OwnerGateRequest {
    /// Job context.
    pub const fn job(&self) -> &AuthoringJob {
        &self.job
    }

    /// Document about to be authored.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Exact source snapshot about to be used.
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Current target version when replacing a generation.
    pub const fn previous_target(&self) -> Option<TargetVersion> {
        self.previous_target
    }
}

/// One deterministic authoring packet instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoringBrief {
    instruction: String,
    digest: ContentDigest,
}

impl AuthoringBrief {
    /// Exact instruction text.
    pub fn instruction(&self) -> &str {
        &self.instruction
    }

    /// SHA-256 of the exact instruction.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

impl AuthoringBrief {
    /// Builds the exact brief including the host-issued candidate handle.
    ///
    /// The raw token is carried in the run input so the child can pass it back
    /// as the candidate tool argument. It is not persisted in H3; the H1
    /// checkpoint and the private candidate manifest own it.
    pub fn new(snapshot: &AuthoringSnapshot, handle: &ArtifactHandle) -> Result<Self, H3Error> {
        if handle.project_id() != snapshot.document().project_id() {
            return Err(H3Error::CrossProject {
                id_kind: "candidate handle".to_owned(),
                expected: snapshot.document().project_id(),
                found: handle.project_id(),
            });
        }
        let instruction = snapshot.brief_with_handle(handle);
        let digest = ContentDigest::sha256(instruction.as_bytes());
        Ok(Self {
            instruction,
            digest,
        })
    }
}

/// One first start request for the host-owned H2 owner path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerStartRequest {
    job: AuthoringJob,
    document: DocumentKey,
    cycle: CycleId,
    generation: GenerationId,
    generation_number: u64,
    target_version: TargetVersion,
    h2: H2Reference,
    snapshot: AuthoringSnapshot,
    brief: AuthoringBrief,
    handle: ArtifactHandle,
}

impl OwnerStartRequest {
    /// Job context.
    pub const fn job(&self) -> &AuthoringJob {
        &self.job
    }

    /// Document being authored.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Sync cycle that owns this generation.
    pub const fn cycle(&self) -> CycleId {
        self.cycle
    }

    /// Generation about to start.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Monotonic generation number within the document.
    pub const fn generation_number(&self) -> u64 {
        self.generation_number
    }

    /// H2 target version used for this start.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Exact H2 reference observed before the start.
    pub const fn h2(&self) -> &H2Reference {
        &self.h2
    }

    /// Exact immutable workspace snapshot.
    pub const fn snapshot(&self) -> &AuthoringSnapshot {
        &self.snapshot
    }

    /// Exact authoring brief.
    pub const fn brief(&self) -> &AuthoringBrief {
        &self.brief
    }

    /// Host-issued candidate handle bound to this exact generation.
    pub const fn handle(&self) -> &ArtifactHandle {
        &self.handle
    }
}

/// One same-target generation replacement request after a confirmed stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerSupersedeRequest {
    job: AuthoringJob,
    document: DocumentKey,
    cycle: CycleId,
    generation: GenerationId,
    generation_number: u64,
    previous_generation: GenerationId,
    previous_target: TargetVersion,
    target_version: TargetVersion,
    expected_h2_revision: Option<u64>,
    snapshot: AuthoringSnapshot,
    brief: AuthoringBrief,
    handle: ArtifactHandle,
}

impl OwnerSupersedeRequest {
    /// Job context.
    pub const fn job(&self) -> &AuthoringJob {
        &self.job
    }

    /// Document being authored.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Same cycle as the superseded generation.
    pub const fn cycle(&self) -> CycleId {
        self.cycle
    }

    /// New generation.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Monotonic generation number.
    pub const fn generation_number(&self) -> u64 {
        self.generation_number
    }

    /// Generation that was stopped and superseded.
    pub const fn previous_generation(&self) -> GenerationId {
        self.previous_generation
    }

    /// Target version that was replaced.
    pub const fn previous_target(&self) -> TargetVersion {
        self.previous_target
    }

    /// New target version the host must use for the replacement.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// H2 revision observed before the replacement.
    pub const fn expected_h2_revision(&self) -> Option<u64> {
        self.expected_h2_revision
    }

    /// Exact new immutable workspace snapshot.
    pub const fn snapshot(&self) -> &AuthoringSnapshot {
        &self.snapshot
    }

    /// Exact new authoring brief.
    pub const fn brief(&self) -> &AuthoringBrief {
        &self.brief
    }

    /// Host-issued candidate handle bound to the new generation.
    pub const fn handle(&self) -> &ArtifactHandle {
        &self.handle
    }
}

/// One host-started owner generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerStarted {
    h2: H2Reference,
    run: RunId,
    generation: GenerationId,
    handle: ArtifactHandle,
    storage: CandidateStorageRef,
    packet_version: u64,
    packet_fingerprint: ContentDigest,
}

impl OwnerStarted {
    /// Creates a started value. The coordinator verifies its generation before
    /// accepting it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        h2: H2Reference,
        run: RunId,
        generation: GenerationId,
        handle: ArtifactHandle,
        storage: CandidateStorageRef,
        packet_version: u64,
        packet_fingerprint: ContentDigest,
    ) -> Result<Self, H3Error> {
        if handle.project_id() != generation.project_id()
            || run.project_id() != generation.project_id()
        {
            return Err(H3Error::CrossProject {
                id_kind: "started owner".to_owned(),
                expected: generation.project_id(),
                found: handle.project_id(),
            });
        }
        if packet_version == 0 {
            return Err(H3Error::must_be_positive("packetVersion"));
        }
        Ok(Self {
            h2,
            run,
            generation,
            handle,
            storage,
            packet_version,
            packet_fingerprint,
        })
    }

    /// H2 reference observed after the start.
    pub const fn h2(&self) -> &H2Reference {
        &self.h2
    }

    /// Created H1 run.
    pub const fn run(&self) -> RunId {
        self.run
    }

    /// Generation this start belongs to.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Host-issued candidate handle bound to the generation.
    pub const fn handle(&self) -> &ArtifactHandle {
        &self.handle
    }

    /// Opaque private candidate storage reference.
    pub const fn storage(&self) -> &CandidateStorageRef {
        &self.storage
    }

    /// H2 work packet version that was started.
    pub const fn packet_version(&self) -> u64 {
        self.packet_version
    }

    /// H2 work packet fingerprint that was started.
    pub const fn packet_fingerprint(&self) -> &ContentDigest {
        &self.packet_fingerprint
    }
}

/// One candidate authored by the running child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateAuthored {
    generation: GenerationId,
    candidate: CandidateId,
    storage: CandidateStorageRef,
    html_digest: ContentDigest,
    provenance_digest: ContentDigest,
    authored_at: Timestamp,
    h1_run: RunId,
}

impl CandidateAuthored {
    /// Creates one candidate result. Exact bytes stay in the private store; H3
    /// receives only their digests and the opaque storage reference.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        generation: GenerationId,
        candidate: CandidateId,
        storage: CandidateStorageRef,
        html_digest: ContentDigest,
        provenance_digest: ContentDigest,
        authored_at: Timestamp,
        h1_run: RunId,
    ) -> Result<Self, H3Error> {
        candidate.validate_in(generation.project_id())?;
        if h1_run.project_id() != generation.project_id() {
            return Err(H3Error::CrossProject {
                id_kind: "candidate run".to_owned(),
                expected: generation.project_id(),
                found: h1_run.project_id(),
            });
        }
        Ok(Self {
            generation,
            candidate,
            storage,
            html_digest,
            provenance_digest,
            authored_at,
            h1_run,
        })
    }

    /// Generation the candidate belongs to.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Candidate identifier.
    pub const fn candidate(&self) -> CandidateId {
        self.candidate
    }

    /// Opaque private storage reference.
    pub const fn storage(&self) -> &CandidateStorageRef {
        &self.storage
    }

    /// Exact candidate HTML digest.
    pub const fn html_digest(&self) -> &ContentDigest {
        &self.html_digest
    }

    /// Exact provenance digest.
    pub const fn provenance_digest(&self) -> &ContentDigest {
        &self.provenance_digest
    }

    /// When the candidate finished.
    pub const fn authored_at(&self) -> Timestamp {
        self.authored_at
    }

    /// H1 run whose artifact events link to this candidate.
    pub const fn h1_run(&self) -> RunId {
        self.h1_run
    }
}

/// Poll result for one active owner generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerProgress {
    /// The child is still authoring.
    Running,
    /// The child authored a candidate.
    Authored(CandidateAuthored),
    /// The saved H2/H3 state stopped the work.
    Stopped {
        /// Cycle latch to persist.
        latch: Option<CycleLatch>,
        /// Exact H3 reason.
        reason: H3Reason,
        /// Short non-secret explanation.
        detail: String,
    },
    /// A human action is required.
    WaitingHuman {
        /// Concrete wait cause.
        cause: HumanWaitCause,
        /// Short non-secret explanation.
        detail: String,
    },
    /// The generation failed.
    Failed {
        /// Concrete failure cause.
        cause: H3FailureCause,
        /// Short non-secret explanation.
        detail: String,
    },
}

/// Result of one cooperative stop request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    /// H1 confirmed the run is stopped or idle.
    Confirmed,
    /// H1 could not confirm the stop. No replacement may start.
    Unconfirmed,
}

/// Active owner context passed to the control port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveOwner {
    job: AuthoringJob,
    document: DocumentKey,
    cycle: CycleId,
    generation: GenerationId,
    generation_number: u64,
    target_version: TargetVersion,
    h2: H2Reference,
    source: SourceSnapshot,
    run: RunId,
    handle: ArtifactHandle,
    storage: CandidateStorageRef,
    packet_version: u64,
}

impl ActiveOwner {
    /// Job context.
    pub const fn job(&self) -> &AuthoringJob {
        &self.job
    }

    /// Document being authored.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Sync cycle.
    pub const fn cycle(&self) -> CycleId {
        self.cycle
    }

    /// Active generation.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Monotonic generation number.
    pub const fn generation_number(&self) -> u64 {
        self.generation_number
    }

    /// H2 target version.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// H2 reference recorded before the start.
    pub const fn h2(&self) -> &H2Reference {
        &self.h2
    }

    /// Exact source snapshot bound to the generation.
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Active H1 run.
    pub const fn run(&self) -> RunId {
        self.run
    }

    /// Host-issued candidate handle.
    pub const fn handle(&self) -> &ArtifactHandle {
        &self.handle
    }

    /// Opaque private candidate storage.
    pub const fn storage(&self) -> &CandidateStorageRef {
        &self.storage
    }

    /// H2 work packet version that was started.
    pub const fn packet_version(&self) -> u64 {
        self.packet_version
    }
}

/// Host-owned H1/H2 boundary used by the coordinator.
///
/// Implementations must mint the H2 owner authority from the current approval
/// registry at the last host-owned moment and must never expose a serializable
/// or IPC path for it. A missing capability is an explicit error, never a
/// successful no-op.
pub trait AuthoringControlPort {
    /// Re-checks the saved H2/H3 state immediately before a start.
    fn gate(&mut self, request: &OwnerGateRequest) -> Result<AuthoringGate, H3Error>;

    /// Starts one first owner run.
    fn start(&mut self, request: &OwnerStartRequest) -> Result<OwnerStarted, H3Error>;

    /// Polls the active generation without starting a second run.
    fn poll(&mut self, active: &ActiveOwner) -> Result<OwnerProgress, H3Error>;

    /// Requests and reports a cooperative H1 stop.
    fn request_stop(&mut self, active: &ActiveOwner) -> Result<StopOutcome, H3Error>;

    /// Passes a new source version into the same H2 target/cycle after a
    /// confirmed stop.
    fn supersede(&mut self, request: &OwnerSupersedeRequest) -> Result<OwnerStarted, H3Error>;
}

/// Ports for one coordinator pass.
pub struct CoordinatorPorts<'a> {
    /// Durable H3 store.
    pub store: &'a mut dyn H3StorePort,
    /// Immutable workspace read.
    pub workspace: &'a dyn AuthoringWorkspace,
    /// Host H1/H2 owner boundary.
    pub control: &'a mut dyn AuthoringControlPort,
}

/// Queue result for one observer candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferOutcome {
    /// A new document entered the dirty queue.
    Queued,
    /// A queued document received a newer stable revision. Its original queue
    /// position is preserved.
    Updated,
    /// The document is the active generation and the bytes are unchanged.
    ActiveUnchanged,
    /// The source changed while the same document is being authored.
    ChangedDuringAuthoring,
    /// A persisted latch still holds the document.
    Held {
        /// Exact latch.
        latch: CycleLatch,
        /// Short non-secret explanation.
        detail: String,
    },
    /// The observation is unapproved, unchanged, or a recovery scan.
    Ignored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedAuthoring {
    job: AuthoringJob,
    document: DocumentKey,
    snapshot: SourceSnapshot,
    trigger: ObservationTrigger,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingChange {
    snapshot: AuthoringSnapshot,
    brief: AuthoringBrief,
    handle: ArtifactHandle,
    generation_number: u64,
    target_version: TargetVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveAuthoring {
    owner: ActiveOwner,
    snapshot: SourceSnapshot,
    pending: Option<PendingChange>,
    superseded: bool,
}

/// One started generation summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationStarted {
    /// Document.
    pub document: DocumentKey,
    /// New generation.
    pub generation: GenerationId,
    /// Cycle.
    pub cycle: CycleId,
    /// H1 run started by the host.
    pub run: RunId,
    /// H2 target version.
    pub target_version: TargetVersion,
}

/// One accepted candidate summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateIntake {
    /// Document.
    pub document: DocumentKey,
    /// Generation.
    pub generation: GenerationId,
    /// Candidate identifier.
    pub candidate: CandidateId,
    /// Exact HTML digest.
    pub html_digest: ContentDigest,
    /// Exact provenance digest.
    pub provenance_digest: ContentDigest,
    /// New document revision after the H3 commit.
    pub document_revision: u64,
}

/// One rejected stale candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleCandidate {
    /// Document.
    pub document: DocumentKey,
    /// Generation the delayed result belongs to.
    pub found: GenerationId,
    /// Current active generation, when one exists.
    pub expected: Option<GenerationId>,
}

/// One held document in a tick report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldAuthoring {
    /// Document.
    pub document: DocumentKey,
    /// Persisted latch, when one applies.
    pub latch: Option<CycleLatch>,
    /// Short non-secret explanation.
    pub detail: String,
}

/// One coordinator pass result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoordinatorTick {
    /// Newly started generation, when one started.
    pub started: Option<GenerationStarted>,
    /// Accepted candidate, when one was authored and persisted.
    pub candidate: Option<CandidateIntake>,
    /// Rejected delayed candidate, when one arrived for another generation.
    pub stale: Option<StaleCandidate>,
    /// Document held by a latch or unavailable capability.
    pub held: Option<HeldAuthoring>,
    /// Active generation after the pass, when one remains.
    pub active: Option<GenerationId>,
}

/// Result of a source change handled by the coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupersessionOutcome {
    /// No active generation for this document; the candidate was queued.
    Queued(OfferOutcome),
    /// The active generation already has exactly these bytes.
    Unchanged,
    /// The old generation was stopped and replaced in the same cycle/target.
    Superseded {
        /// Document.
        document: DocumentKey,
        /// Old generation.
        previous: GenerationId,
        /// New generation.
        current: GenerationId,
        /// New H1 run.
        run: RunId,
    },
    /// H1 did not confirm the stop. The app-wide slot is still held.
    StopUnconfirmed {
        /// Document.
        document: DocumentKey,
        /// Generation that must not be replaced yet.
        generation: GenerationId,
    },
    /// A persisted latch or unavailable capability prevented replacement.
    Held(HeldAuthoring),
}

/// App-wide serial authoring coordinator.
#[derive(Debug, Default)]
pub struct SyncCoordinator {
    jobs: BTreeMap<ProjectId, AuthoringJob>,
    queue: VecDeque<QueuedAuthoring>,
    active: Option<ActiveAuthoring>,
    latches: BTreeMap<(ProjectId, DocumentKey), HeldAuthoring>,
}

impl SyncCoordinator {
    /// Creates an empty coordinator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds one project's approved job context.
    pub fn bind_job(&mut self, job: AuthoringJob) {
        self.jobs.insert(job.project_id(), job);
    }

    /// Current job for one project.
    pub fn job(&self, project: ProjectId) -> Option<&AuthoringJob> {
        self.jobs.get(&project)
    }

    /// Whether the app-wide slot is in use.
    pub const fn is_authoring(&self) -> bool {
        self.active.is_some()
    }

    /// Active generation identifier, when one exists.
    pub fn active_generation(&self) -> Option<GenerationId> {
        self.active.as_ref().map(|active| active.owner.generation())
    }

    /// Active owner context, when one exists.
    ///
    /// The host composition uses this to install the same candidate handle for
    /// the H2 pump that starts/continues the child run.
    pub fn active_owner(&self) -> Option<&ActiveOwner> {
        self.active.as_ref().map(|active| &active.owner)
    }

    /// Documents in dirty notification order.
    pub fn queued_documents(&self) -> Vec<DocumentKey> {
        self.queue
            .iter()
            .map(|queued| queued.document.clone())
            .collect()
    }

    /// Current latch for a document, when one was observed in this process.
    pub fn latch(&self, document: &DocumentKey) -> Option<&HeldAuthoring> {
        self.latches.get(&(document.project_id(), document.clone()))
    }

    /// Seeds one persisted latch after a restart.
    ///
    /// Recovery calls this with the saved H3 document/cycle latch. It never
    /// queues, starts, sends, or clears anything; a new notification is still
    /// held until an explicit human resume calls [`Self::clear_latch`].
    pub fn seed_latch(&mut self, held: HeldAuthoring) {
        self.latches
            .insert((held.document.project_id(), held.document.clone()), held);
    }

    /// Clears one latch after an explicit human resume.
    ///
    /// This is host-only. It does not queue or start anything by itself; the
    /// next observer notification must pass the normal gate again.
    pub fn clear_latch(&mut self, document: &DocumentKey) -> Option<HeldAuthoring> {
        self.latches
            .remove(&(document.project_id(), document.clone()))
    }

    /// Removes and returns the active owner for one document after a confirmed
    /// human stop.
    ///
    /// This is host-only. It does not stop the H1 run, persist state, or clear
    /// a latch; the caller must have confirmed the stop first and must commit
    /// the stopped state itself. An active owner for another document is left
    /// untouched.
    pub fn take_active(&mut self, document: &DocumentKey) -> Option<ActiveOwner> {
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.owner.document() == document)
        {
            self.queue.retain(|queued| &queued.document != document);
            self.active.take().map(|active| active.owner)
        } else {
            None
        }
    }

    /// Every seeded/observed latch in canonical order.
    pub fn latches(&self) -> impl Iterator<Item = &HeldAuthoring> {
        self.latches.values()
    }

    /// Records one stable observer candidate.
    ///
    /// This never clears a latch and never starts anything. A duplicate
    /// notification for a queued document updates its snapshot without adding a
    /// second queue entry; its original notification position is preserved.
    pub fn offer(&mut self, observation: &SourceObservation) -> OfferOutcome {
        if !observation.is_authoring_candidate() {
            return OfferOutcome::Ignored;
        }
        let document = observation.document.clone();
        let project = document.project_id();
        if let Some(active) = &self.active
            && active.owner.document() == &document
        {
            if active.snapshot.digest() == observation.snapshot.digest() {
                return OfferOutcome::ActiveUnchanged;
            }
            return OfferOutcome::ChangedDuringAuthoring;
        }
        if let Some(held) = self.latches.get(&(project, document.clone())) {
            // A new notification is not a human resume.
            return OfferOutcome::Held {
                latch: held.latch.unwrap_or(CycleLatch::RecoveryReconciliation),
                detail: held.detail.clone(),
            };
        }
        let Some(job) = self.jobs.get(&project).cloned() else {
            return OfferOutcome::Ignored;
        };
        if !job.covers(&document) {
            return OfferOutcome::Ignored;
        }
        if let Some(existing) = self
            .queue
            .iter_mut()
            .find(|queued| queued.document == document)
        {
            existing.snapshot = observation.snapshot.clone();
            existing.trigger = observation.trigger;
            return OfferOutcome::Updated;
        }
        self.queue.push_back(QueuedAuthoring {
            job,
            document,
            snapshot: observation.snapshot.clone(),
            trigger: observation.trigger,
        });
        OfferOutcome::Queued
    }

    /// Runs one bounded pass: poll the active generation, or start the next
    /// dirty document when the app-wide slot is free.
    pub fn tick(
        &mut self,
        ports: &mut CoordinatorPorts<'_>,
        now: Timestamp,
    ) -> Result<CoordinatorTick, H3Error> {
        let mut report = CoordinatorTick {
            active: self.active_generation(),
            ..CoordinatorTick::default()
        };
        if let Some(active) = self.active.clone() {
            if active.pending.is_some() || active.superseded {
                self.finish_pending_change(ports, &active, false, &mut report, now)?;
                return Ok(report);
            }
            match ports.control.poll(&active.owner)? {
                OwnerProgress::Running => {
                    report.active = Some(active.owner.generation());
                    return Ok(report);
                }
                OwnerProgress::Authored(candidate) => {
                    if candidate.generation() != active.owner.generation() {
                        report.stale = Some(StaleCandidate {
                            document: active.owner.document().clone(),
                            found: candidate.generation(),
                            expected: Some(active.owner.generation()),
                        });
                        report.active = Some(active.owner.generation());
                        return Ok(report);
                    }
                    if let Some(intake) =
                        self.intake_candidate(ports.store, &active, &candidate, now)?
                    {
                        self.active = None;
                        report.candidate = Some(intake);
                        report.active = None;
                        return Ok(report);
                    }
                    report.stale = Some(StaleCandidate {
                        document: active.owner.document().clone(),
                        found: candidate.generation(),
                        expected: Some(active.owner.generation()),
                    });
                    report.active = Some(active.owner.generation());
                    return Ok(report);
                }
                OwnerProgress::Stopped {
                    latch,
                    reason,
                    detail,
                } => {
                    self.persist_latch(ports.store, &active, latch, reason, &detail, now)?;
                    self.active = None;
                    report.held = Some(HeldAuthoring {
                        document: active.owner.document().clone(),
                        latch,
                        detail,
                    });
                    report.active = None;
                    return Ok(report);
                }
                OwnerProgress::WaitingHuman { cause, detail } => {
                    let reason = H3Reason::new(
                        H3StateReasonKind::WaitingHuman { cause },
                        vec![RequiredAction::ReconcileRecovery],
                    )?;
                    self.persist_latch(
                        ports.store,
                        &active,
                        Some(CycleLatch::WaitingHuman),
                        reason,
                        &detail,
                        now,
                    )?;
                    self.active = None;
                    report.held = Some(HeldAuthoring {
                        document: active.owner.document().clone(),
                        latch: Some(CycleLatch::WaitingHuman),
                        detail,
                    });
                    report.active = None;
                    return Ok(report);
                }
                OwnerProgress::Failed { cause, detail } => {
                    let reason = H3Reason::new(
                        H3StateReasonKind::Failed { cause },
                        vec![RequiredAction::ReviewFailure],
                    )?;
                    self.persist_latch(ports.store, &active, None, reason, &detail, now)?;
                    self.active = None;
                    report.held = Some(HeldAuthoring {
                        document: active.owner.document().clone(),
                        latch: None,
                        detail,
                    });
                    report.active = None;
                    return Ok(report);
                }
            }
        }

        let (started, held) = self.start_next(ports, now)?;
        report.started = started;
        report.held = held;
        report.active = self.active_generation();
        Ok(report)
    }

    /// Handles one source change that arrived while the same document was
    /// being authored.
    ///
    /// The old generation is marked superseded first. The H1 stop is requested
    /// and must be confirmed before the new version is passed into the same H2
    /// target and sync cycle. A delayed candidate for the old generation is
    /// rejected by [`Self::tick`] because its generation is no longer active.
    pub fn source_changed(
        &mut self,
        ports: &mut CoordinatorPorts<'_>,
        observation: &SourceObservation,
        now: Timestamp,
    ) -> Result<SupersessionOutcome, H3Error> {
        let Some(active) = self.active.clone() else {
            return Ok(SupersessionOutcome::Queued(self.offer(observation)));
        };
        if active.owner.document() != &observation.document {
            return Ok(SupersessionOutcome::Queued(self.offer(observation)));
        }
        if active.snapshot.digest() == observation.snapshot.digest() {
            return Ok(SupersessionOutcome::Unchanged);
        }
        if let Some(held) = self.latches.get(&(
            active.owner.document().project_id(),
            active.owner.document().clone(),
        )) && held.latch.is_some()
        {
            return Ok(SupersessionOutcome::Held(held.clone()));
        }
        self.begin_source_change(ports, active, observation, now)
    }

    fn begin_source_change(
        &mut self,
        ports: &mut CoordinatorPorts<'_>,
        active: ActiveAuthoring,
        observation: &SourceObservation,
        now: Timestamp,
    ) -> Result<SupersessionOutcome, H3Error> {
        let document = active.owner.document().clone();
        let project = document.project_id();
        let settings_record = load_settings(ports.store, project)?;
        active
            .owner
            .job()
            .verify_against(settings_record.settings(), now)?;
        if !active.owner.job().covers(&document) {
            return Ok(SupersessionOutcome::Held(HeldAuthoring {
                document,
                latch: Some(CycleLatch::WaitingHuman),
                detail: "the document is outside the approved Target set".to_owned(),
            }));
        }
        let Some(document_record) = ports.store.load_html_sync_document(project, &document)? else {
            return Ok(SupersessionOutcome::Held(HeldAuthoring {
                document,
                latch: Some(CycleLatch::RecoveryReconciliation),
                detail: "the active generation has no stored document state".to_owned(),
            }));
        };
        let gate_request = OwnerGateRequest {
            job: active.owner.job().clone(),
            document: document.clone(),
            source: observation.snapshot.clone(),
            previous_target: Some(active.owner.target_version()),
        };
        let gate = ports.control.gate(&gate_request)?;
        let (_h2, target_version) = match gate {
            AuthoringGate::Allowed { h2, target_version } => (h2, target_version),
            AuthoringGate::Latched {
                latch,
                reason,
                detail,
            } => {
                self.persist_latch_on(ports.store, &document_record, latch, reason, &detail, now)?;
                let held = HeldAuthoring {
                    document,
                    latch,
                    detail,
                };
                self.latches
                    .insert((project, held.document.clone()), held.clone());
                return Ok(SupersessionOutcome::Held(held));
            }
            AuthoringGate::Unavailable { capability, detail } => {
                let reason = H3Reason::new(
                    H3StateReasonKind::WaitingHuman {
                        cause: HumanWaitCause::CapabilityMissing,
                    },
                    vec![RequiredAction::ReconcileRecovery],
                )?;
                let detail = format!("{capability}: {detail}");
                self.persist_latch_on(
                    ports.store,
                    &document_record,
                    Some(CycleLatch::WaitingHuman),
                    reason,
                    &detail,
                    now,
                )?;
                let held = HeldAuthoring {
                    document,
                    latch: Some(CycleLatch::WaitingHuman),
                    detail,
                };
                self.latches
                    .insert((project, held.document.clone()), held.clone());
                return Ok(SupersessionOutcome::Held(held));
            }
            AuthoringGate::Failed { cause, detail } => {
                let reason = H3Reason::new(
                    H3StateReasonKind::Failed { cause },
                    vec![RequiredAction::ReviewFailure],
                )?;
                self.persist_latch_on(ports.store, &document_record, None, reason, &detail, now)?;
                let held = HeldAuthoring {
                    document,
                    latch: None,
                    detail,
                };
                self.latches
                    .insert((project, held.document.clone()), held.clone());
                return Ok(SupersessionOutcome::Held(held));
            }
        };

        let policy = active.owner.job().policy()?;
        let workspace = ports.workspace.capture(&WorkspaceCaptureRequest::new(
            document.clone(),
            observation.snapshot.clone(),
            active.owner.job().dependencies().to_vec(),
            policy,
        )?)?;
        let generation_number = next_generation_number(ports.store, project, &document)?;
        let handle = ArtifactHandle::new(
            project,
            active.owner.job().job_label(),
            generation_number,
            uuid::Uuid::new_v4().to_string(),
        )
        .map_err(|error| H3Error::invalid("candidateHandle", error.to_string()))?;
        let brief = AuthoringBrief::new(&workspace, &handle)?;
        let workspace_fingerprints = workspace.fingerprints().clone();
        let pending = PendingChange {
            snapshot: workspace,
            brief,
            handle,
            generation_number,
            target_version,
        };

        // Mark the old generation superseded before stopping, so a delayed
        // candidate or evaluation from it can never be adopted.
        let old = load_generation(ports.store, project, &document, active.owner.generation())?;
        let superseded = old.supersede(now)?;
        let previous_state = document_record.state().state();
        let next_document = document_state(
            &document,
            document_record.state().settings_version(),
            document_record.state().job_id(),
            active.owner.cycle(),
            None,
            observation.snapshot.clone(),
            workspace_fingerprints,
            H3Reason::new(
                H3StateReasonKind::Pending {
                    source_revision: observation.snapshot.revision().get(),
                },
                vec![RequiredAction::WaitForStableSource],
            )?,
            document_record.state().h2().cloned(),
            document_record.state().evidence().to_vec(),
            lost_applicability(
                document_record.state().applicability().is_applicable(),
                None,
                observation.snapshot.revision().get(),
            ),
            now,
        )?;
        let event = document_state_event(&document, Some(previous_state), &next_document, now)?;
        ports.store.commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(
                    Some(document_record.revision()),
                    next_document,
                )?)
                .with_generation(superseded)
                .with_events(vec![event]),
        )?;

        let stopping = ActiveAuthoring {
            owner: active.owner,
            snapshot: active.snapshot,
            pending: Some(pending),
            superseded: true,
        };
        self.active = Some(stopping.clone());
        match ports.control.request_stop(&stopping.owner)? {
            StopOutcome::Unconfirmed => {
                let reason = H3Reason::new(
                    H3StateReasonKind::Stopped {
                        cause: H3StopCause::StopUnconfirmed,
                    },
                    vec![RequiredAction::ReconcileRecovery],
                )?;
                let document_record = ports
                    .store
                    .load_html_sync_document(project, &document)?
                    .ok_or_else(|| H3Error::NotFound {
                        record: "document state",
                        id: document.target_path().to_owned(),
                    })?;
                self.persist_latch_on(
                    ports.store,
                    &document_record,
                    Some(CycleLatch::RecoveryReconciliation),
                    reason,
                    "the H1 stop was not confirmed",
                    now,
                )?;
                return Ok(SupersessionOutcome::StopUnconfirmed {
                    document,
                    generation: stopping.owner.generation(),
                });
            }
            StopOutcome::Confirmed => {}
        }
        let mut report = CoordinatorTick::default();
        self.finish_pending_change(ports, &stopping, true, &mut report, now)?;
        match report.started {
            Some(started) => Ok(SupersessionOutcome::Superseded {
                document,
                previous: stopping.owner.generation(),
                current: started.generation,
                run: started.run,
            }),
            None => Ok(SupersessionOutcome::Held(HeldAuthoring {
                document,
                latch: report.held.as_ref().and_then(|held| held.latch),
                detail: report
                    .held
                    .map(|held| held.detail)
                    .unwrap_or_else(|| "the replacement did not start".to_owned()),
            })),
        }
    }

    fn finish_pending_change(
        &mut self,
        ports: &mut CoordinatorPorts<'_>,
        active: &ActiveAuthoring,
        stop_already_confirmed: bool,
        report: &mut CoordinatorTick,
        now: Timestamp,
    ) -> Result<(), H3Error> {
        let Some(pending) = &active.pending else {
            self.active = None;
            return Ok(());
        };
        if active.superseded && !stop_already_confirmed {
            match ports.control.request_stop(&active.owner)? {
                StopOutcome::Unconfirmed => {
                    report.active = Some(active.owner.generation());
                    report.held = Some(HeldAuthoring {
                        document: active.owner.document().clone(),
                        latch: Some(CycleLatch::RecoveryReconciliation),
                        detail: "the H1 stop is still unconfirmed".to_owned(),
                    });
                    return Ok(());
                }
                StopOutcome::Confirmed => {}
            }
        }
        let request = OwnerSupersedeRequest {
            job: active.owner.job().clone(),
            document: active.owner.document().clone(),
            cycle: active.owner.cycle(),
            generation: GenerationId::new(active.owner.document().project_id()),
            generation_number: pending.generation_number,
            previous_generation: active.owner.generation(),
            previous_target: active.owner.target_version(),
            target_version: pending.target_version,
            expected_h2_revision: active.owner.h2().revision(),
            snapshot: pending.snapshot.clone(),
            brief: pending.brief.clone(),
            handle: pending.handle.clone(),
        };
        let started = match ports.control.supersede(&request) {
            Ok(started) => started,
            Err(error) => {
                self.persist_failure(
                    ports.store,
                    &active.owner.document,
                    active.owner.cycle(),
                    active.owner.generation(),
                    H3FailureCause::TargetUnstable,
                    &error.to_string(),
                    now,
                )?;
                self.active = None;
                report.held = Some(HeldAuthoring {
                    document: active.owner.document().clone(),
                    latch: None,
                    detail: error.to_string(),
                });
                return Ok(());
            }
        };
        if started.generation() != request.generation {
            self.persist_failure(
                ports.store,
                &active.owner.document,
                active.owner.cycle(),
                active.owner.generation(),
                H3FailureCause::TargetUnstable,
                "the host started another generation than requested",
                now,
            )?;
            self.active = None;
            return Ok(());
        }
        self.record_replacement(ports.store, active, &request, &started, now, report)?;
        Ok(())
    }

    fn start_next(
        &mut self,
        ports: &mut CoordinatorPorts<'_>,
        now: Timestamp,
    ) -> Result<(Option<GenerationStarted>, Option<HeldAuthoring>), H3Error> {
        if self.active.is_some() {
            return Ok((None, None));
        }
        let Some(mut queued) = self.pop_next_eligible() else {
            return Ok((None, None));
        };
        let project = queued.document.project_id();
        let settings_record = load_settings(ports.store, project)?;
        let Some(job) = self.jobs.get(&project).cloned() else {
            return Ok((
                None,
                Some(HeldAuthoring {
                    document: queued.document,
                    latch: Some(CycleLatch::WaitingHuman),
                    detail: "the project has no approved H3 job".to_owned(),
                }),
            ));
        };
        if let Err(error) = job.verify_against(settings_record.settings(), now) {
            let held = HeldAuthoring {
                document: queued.document.clone(),
                latch: Some(CycleLatch::WaitingHuman),
                detail: error.to_string(),
            };
            self.latches
                .insert((project, queued.document.clone()), held.clone());
            return Ok((None, Some(held)));
        }
        if !job.covers(&queued.document) {
            return Ok((
                None,
                Some(HeldAuthoring {
                    document: queued.document,
                    latch: Some(CycleLatch::WaitingHuman),
                    detail: "the document is outside the approved Target set".to_owned(),
                }),
            ));
        }
        queued.job = job.clone();

        let existing_document = ports
            .store
            .load_html_sync_document(project, &queued.document)?;
        if let Some(record) = &existing_document
            && let Some((latch, detail)) = saved_hold(record.state())
        {
            let held = HeldAuthoring {
                document: queued.document.clone(),
                latch,
                detail,
            };
            self.latches
                .insert((project, queued.document.clone()), held.clone());
            return Ok((None, Some(held)));
        }

        let cycle = match self.resolve_cycle(ports.store, &queued) {
            Ok(cycle) => cycle,
            Err(error) => {
                let held = HeldAuthoring {
                    document: queued.document.clone(),
                    latch: Some(CycleLatch::RecoveryReconciliation),
                    detail: error.to_string(),
                };
                self.latches
                    .insert((project, queued.document.clone()), held.clone());
                return Ok((None, Some(held)));
            }
        };
        let generation_number = next_generation_number(ports.store, project, &queued.document)?;
        let policy = job.policy()?;
        let workspace = ports.workspace.capture(&WorkspaceCaptureRequest::new(
            queued.document.clone(),
            queued.snapshot.clone(),
            job.dependencies().to_vec(),
            policy,
        )?)?;
        let gate_request = OwnerGateRequest {
            job: job.clone(),
            document: queued.document.clone(),
            source: queued.snapshot.clone(),
            previous_target: None,
        };
        let gate = ports.control.gate(&gate_request)?;
        let (h2, target_version) = match gate {
            AuthoringGate::Allowed { h2, target_version } => (h2, target_version),
            AuthoringGate::Latched {
                latch,
                reason,
                detail,
            } => {
                self.persist_start_hold(
                    ports.store,
                    &queued,
                    &workspace,
                    existing_document.as_ref(),
                    cycle.as_ref(),
                    latch,
                    reason,
                    &detail,
                    now,
                )?;
                let held = HeldAuthoring {
                    document: queued.document.clone(),
                    latch,
                    detail,
                };
                self.latches
                    .insert((project, queued.document.clone()), held.clone());
                self.requeue(&queued);
                return Ok((None, Some(held)));
            }
            AuthoringGate::Unavailable { capability, detail } => {
                let reason = H3Reason::new(
                    H3StateReasonKind::WaitingHuman {
                        cause: HumanWaitCause::CapabilityMissing,
                    },
                    vec![RequiredAction::ApproveSettings],
                )?;
                let detail = format!("{capability}: {detail}");
                self.persist_start_hold(
                    ports.store,
                    &queued,
                    &workspace,
                    existing_document.as_ref(),
                    cycle.as_ref(),
                    Some(CycleLatch::WaitingHuman),
                    reason,
                    &detail,
                    now,
                )?;
                let held = HeldAuthoring {
                    document: queued.document.clone(),
                    latch: Some(CycleLatch::WaitingHuman),
                    detail,
                };
                self.latches
                    .insert((project, queued.document.clone()), held.clone());
                self.requeue(&queued);
                return Ok((None, Some(held)));
            }
            AuthoringGate::Failed { cause, detail } => {
                let reason = H3Reason::new(
                    H3StateReasonKind::Failed { cause },
                    vec![RequiredAction::ReviewFailure],
                )?;
                self.persist_start_hold(
                    ports.store,
                    &queued,
                    &workspace,
                    existing_document.as_ref(),
                    cycle.as_ref(),
                    None,
                    reason,
                    &detail,
                    now,
                )?;
                let held = HeldAuthoring {
                    document: queued.document.clone(),
                    latch: None,
                    detail,
                };
                self.latches
                    .insert((project, queued.document.clone()), held.clone());
                return Ok((None, Some(held)));
            }
        };

        let handle = ArtifactHandle::new(
            project,
            job.job_label(),
            generation_number,
            uuid::Uuid::new_v4().to_string(),
        )
        .map_err(|error| H3Error::invalid("candidateHandle", error.to_string()))?;
        let brief = AuthoringBrief::new(&workspace, &handle)?;
        let generation = GenerationId::new(project);
        let cycle = match cycle {
            Some(cycle) => cycle.count_generation()?,
            None => SyncCycle::new(
                CycleId::new(project),
                queued.document.clone(),
                job.settings_version(),
                now,
                queued.snapshot.clone(),
                Some(job.supervision_id()),
            )?
            .count_generation()?,
        };
        let generation_record = GenerationRecord::new(
            generation,
            queued.document.clone(),
            generation_number,
            cycle.cycle_id(),
            job.job(),
            queued.snapshot.clone(),
            workspace.fingerprints().clone(),
            GenerationStatus::Active,
            false,
            now,
        )?
        .with_h2(h2.clone());
        let previous_state = existing_document
            .as_ref()
            .map(|record| record.state().state());
        let document = document_state(
            &queued.document,
            job.settings_version(),
            Some(job.job()),
            cycle.cycle_id(),
            Some(generation),
            queued.snapshot.clone(),
            workspace.fingerprints().clone(),
            H3Reason::new(H3StateReasonKind::Authoring { generation }, Vec::new())?,
            Some(h2.clone()),
            existing_document
                .as_ref()
                .map(|record| record.state().evidence().to_vec())
                .unwrap_or_default(),
            lost_applicability(
                existing_document
                    .as_ref()
                    .is_some_and(|record| record.state().applicability().is_applicable()),
                Some(generation),
                queued.snapshot.revision().get(),
            ),
            now,
        )?;
        let event = document_state_event(&queued.document, previous_state, &document, now)?;
        let expected = existing_document.as_ref().map(H3DocumentRecord::revision);
        ports.store.commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(expected, document)?)
                .with_cycle(cycle.clone())
                .with_generation(generation_record)
                .with_events(vec![event]),
        )?;
        let start = OwnerStartRequest {
            job: job.clone(),
            document: queued.document.clone(),
            cycle: cycle.cycle_id(),
            generation,
            generation_number,
            target_version,
            h2,
            snapshot: workspace,
            brief,
            handle,
        };
        match ports.control.start(&start) {
            Ok(started) if started.generation() == generation => {
                let owner = ActiveOwner {
                    job,
                    document: queued.document.clone(),
                    cycle: cycle.cycle_id(),
                    generation,
                    generation_number,
                    target_version: started.h2().target_version().unwrap_or(target_version),
                    h2: started.h2().clone(),
                    source: queued.snapshot.clone(),
                    run: started.run(),
                    handle: started.handle().clone(),
                    storage: started.storage().clone(),
                    packet_version: started.packet_version(),
                };
                self.active = Some(ActiveAuthoring {
                    owner,
                    snapshot: queued.snapshot,
                    pending: None,
                    superseded: false,
                });
                Ok((
                    Some(GenerationStarted {
                        document: queued.document,
                        generation,
                        cycle: cycle.cycle_id(),
                        run: started.run(),
                        target_version,
                    }),
                    None,
                ))
            }
            Ok(_) => {
                self.persist_start_failure(
                    ports.store,
                    &queued,
                    &cycle,
                    generation,
                    generation_number,
                    &start.snapshot,
                    "the host started another generation than requested",
                    now,
                )?;
                Ok((None, None))
            }
            Err(error) => {
                self.persist_start_failure(
                    ports.store,
                    &queued,
                    &cycle,
                    generation,
                    generation_number,
                    &start.snapshot,
                    &error.to_string(),
                    now,
                )?;
                Ok((
                    None,
                    Some(HeldAuthoring {
                        document: queued.document,
                        latch: None,
                        detail: error.to_string(),
                    }),
                ))
            }
        }
    }

    fn record_replacement(
        &mut self,
        store: &mut dyn H3StorePort,
        previous: &ActiveAuthoring,
        request: &OwnerSupersedeRequest,
        started: &OwnerStarted,
        now: Timestamp,
        report: &mut CoordinatorTick,
    ) -> Result<(), H3Error> {
        let project = request.document.project_id();
        let existing = store
            .load_html_sync_document(project, &request.document)?
            .ok_or_else(|| H3Error::NotFound {
                record: "document state",
                id: request.document.target_path().to_owned(),
            })?;
        let cycle = self.resolve_replacement_cycle(store, request, now)?;
        let generation = GenerationRecord::new(
            request.generation,
            request.document.clone(),
            request.generation_number,
            cycle.cycle_id(),
            request.job.job(),
            request.snapshot.source().clone(),
            request.snapshot.fingerprints().clone(),
            GenerationStatus::Active,
            false,
            now,
        )?
        .with_h2(started.h2().clone());
        let document = document_state(
            &request.document,
            request.job.settings_version(),
            Some(request.job.job()),
            cycle.cycle_id(),
            Some(request.generation),
            request.snapshot.source().clone(),
            request.snapshot.fingerprints().clone(),
            H3Reason::new(
                H3StateReasonKind::Authoring {
                    generation: request.generation,
                },
                Vec::new(),
            )?,
            Some(started.h2().clone()),
            existing.state().evidence().to_vec(),
            lost_applicability(
                existing.state().applicability().is_applicable(),
                Some(request.generation),
                request.snapshot.source().revision().get(),
            ),
            now,
        )?;
        let event = document_state_event(
            &request.document,
            Some(existing.state().state()),
            &document,
            now,
        )?;
        store.commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(Some(existing.revision()), document)?)
                .with_cycle(cycle)
                .with_generation(generation)
                .with_events(vec![event]),
        )?;
        let owner = ActiveOwner {
            job: request.job.clone(),
            document: request.document.clone(),
            cycle: request.cycle,
            generation: request.generation,
            generation_number: request.generation_number,
            target_version: started
                .h2()
                .target_version()
                .unwrap_or(request.target_version),
            h2: started.h2().clone(),
            source: request.snapshot.source().clone(),
            run: started.run(),
            handle: started.handle().clone(),
            storage: started.storage().clone(),
            packet_version: started.packet_version(),
        };
        self.active = Some(ActiveAuthoring {
            owner,
            snapshot: request.snapshot.source().clone(),
            pending: None,
            superseded: false,
        });
        let _ = previous;
        report.started = Some(GenerationStarted {
            document: request.document.clone(),
            generation: request.generation,
            cycle: request.cycle,
            run: started.run(),
            target_version: request.target_version,
        });
        Ok(())
    }

    fn resolve_replacement_cycle(
        &self,
        store: &mut dyn H3StorePort,
        request: &OwnerSupersedeRequest,
        now: Timestamp,
    ) -> Result<SyncCycle, H3Error> {
        let project = request.document.project_id();
        let existing = store.load_html_sync_cycle(project, request.cycle)?;
        match existing {
            Some(cycle) if cycle.state() == CycleState::Open => cycle.count_generation(),
            Some(_) => Err(H3Error::Unavailable {
                capability: "h3.cycle".to_owned(),
                detail: "the sync cycle is no longer open".to_owned(),
            }),
            None => SyncCycle::new(
                request.cycle,
                request.document.clone(),
                request.job.settings_version(),
                now,
                request.snapshot.source().clone(),
                Some(request.job.supervision_id()),
            )?
            .count_generation(),
        }
    }

    fn resolve_cycle(
        &self,
        store: &mut dyn H3StorePort,
        queued: &QueuedAuthoring,
    ) -> Result<Option<SyncCycle>, H3Error> {
        let project = queued.document.project_id();
        let Some(document) = store.load_html_sync_document(project, &queued.document)? else {
            return Ok(None);
        };
        let Some(cycle_id) = document.state().cycle_id() else {
            return Ok(None);
        };
        match store.load_html_sync_cycle(project, cycle_id)? {
            Some(cycle) if cycle.state() == CycleState::Open => Ok(Some(cycle)),
            Some(cycle) if cycle.state() == CycleState::Completed => Ok(None),
            Some(cycle) if cycle.state() == CycleState::Cancelled => Err(H3Error::Unavailable {
                capability: "h3.cycle".to_owned(),
                detail: "a cancelled cycle requires an explicit human resume".to_owned(),
            }),
            Some(_) => Err(H3Error::Unavailable {
                capability: "h3.cycle".to_owned(),
                detail: "a stopped or failed cycle requires an explicit human resume".to_owned(),
            }),
            None => Ok(None),
        }
    }

    fn pop_next_eligible(&mut self) -> Option<QueuedAuthoring> {
        let index = self.queue.iter().position(|queued| {
            !self
                .latches
                .get(&(queued.document.project_id(), queued.document.clone()))
                .is_some_and(|held| held.latch.is_some())
        })?;
        self.queue.remove(index)
    }

    fn requeue(&mut self, queued: &QueuedAuthoring) {
        if !self
            .queue
            .iter()
            .any(|existing| existing.document == queued.document)
        {
            self.queue.push_back(queued.clone());
        }
    }

    fn intake_candidate(
        &mut self,
        store: &mut dyn H3StorePort,
        active: &ActiveAuthoring,
        candidate: &CandidateAuthored,
        now: Timestamp,
    ) -> Result<Option<CandidateIntake>, H3Error> {
        if active.superseded || active.pending.is_some() {
            return Ok(None);
        }
        if candidate.generation() != active.owner.generation() {
            return Ok(None);
        }
        let project = active.owner.document().project_id();
        let document_record = store
            .load_html_sync_document(project, active.owner.document())?
            .ok_or_else(|| H3Error::NotFound {
                record: "document state",
                id: active.owner.document().target_path().to_owned(),
            })?;
        if document_record.state().generation() != Some(active.owner.generation()) {
            return Ok(None);
        }
        let existing_generation = load_generation(
            store,
            project,
            active.owner.document(),
            active.owner.generation(),
        )?;
        if existing_generation.status() != GenerationStatus::Active
            || existing_generation.source() != &active.owner.source
        {
            return Ok(None);
        }
        let record = CandidateRecord::new(
            candidate.candidate(),
            active.owner.document().clone(),
            active.owner.generation(),
            candidate.storage().clone(),
            candidate.html_digest().clone(),
            candidate.provenance_digest().clone(),
            candidate.authored_at(),
        )?
        .with_h1_run(candidate.h1_run());
        let generation = existing_generation.clone().with_candidate(record.clone())?;
        let document = document_state(
            active.owner.document(),
            document_record.state().settings_version(),
            document_record.state().job_id(),
            active.owner.cycle(),
            Some(active.owner.generation()),
            active.owner.source.clone(),
            document_record
                .state()
                .fingerprints()
                .clone()
                .with_candidate(candidate.html_digest().clone())
                .with_provenance(candidate.provenance_digest().clone()),
            H3Reason::new(
                H3StateReasonKind::Verifying {
                    generation: active.owner.generation(),
                },
                Vec::new(),
            )?,
            Some(active.owner.h2().clone()),
            document_record.state().evidence().to_vec(),
            lost_applicability(
                document_record.state().applicability().is_applicable(),
                Some(active.owner.generation()),
                active.owner.source.revision().get(),
            ),
            now,
        )?;
        let event = document_state_event(
            active.owner.document(),
            Some(document_record.state().state()),
            &document,
            now,
        )?;
        let outcome = store.commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(
                    Some(document_record.revision()),
                    document,
                )?)
                .with_generation(generation)
                .with_candidate(record)
                .with_events(vec![event]),
        )?;
        let revision = match outcome {
            crate::ports::HtmlSyncCommitOutcome::Applied { document, .. } => document
                .map(|record| record.revision())
                .unwrap_or(document_record.revision()),
            crate::ports::HtmlSyncCommitOutcome::Duplicate { .. } => document_record.revision(),
        };
        Ok(Some(CandidateIntake {
            document: active.owner.document().clone(),
            generation: active.owner.generation(),
            candidate: candidate.candidate(),
            html_digest: candidate.html_digest().clone(),
            provenance_digest: candidate.provenance_digest().clone(),
            document_revision: revision,
        }))
    }

    fn persist_latch(
        &self,
        store: &mut dyn H3StorePort,
        active: &ActiveAuthoring,
        latch: Option<CycleLatch>,
        reason: H3Reason,
        detail: &str,
        now: Timestamp,
    ) -> Result<(), H3Error> {
        let project = active.owner.document().project_id();
        let Some(existing) = store.load_html_sync_document(project, active.owner.document())?
        else {
            return Ok(());
        };
        self.persist_latch_on(store, &existing, latch, reason, detail, now)
    }

    fn persist_latch_on(
        &self,
        store: &mut dyn H3StorePort,
        existing: &H3DocumentRecord,
        latch: Option<CycleLatch>,
        reason: H3Reason,
        detail: &str,
        now: Timestamp,
    ) -> Result<(), H3Error> {
        let project = existing.state().project_id();
        let document = document_state(
            existing.state().document_key(),
            existing.state().settings_version(),
            existing.state().job_id(),
            existing
                .state()
                .cycle_id()
                .ok_or_else(|| H3Error::invalid("cycle", "the document has no sync cycle"))?,
            existing.state().generation(),
            existing.state().source().clone(),
            existing.state().fingerprints().clone(),
            reason,
            existing.state().h2().cloned(),
            existing.state().evidence().to_vec(),
            lost_applicability(
                existing.state().applicability().is_applicable(),
                existing.state().generation(),
                existing.state().source().revision().get(),
            ),
            now,
        )?;
        let event = document_state_event(
            existing.state().document_key(),
            Some(existing.state().state()),
            &document,
            now,
        )?;
        let mut commit = HtmlSyncCommit::new()
            .with_document(DocumentCommit::new(Some(existing.revision()), document)?)
            .with_events(vec![event]);
        if let Some(cycle_id) = existing.state().cycle_id()
            && let Some(mut cycle) = store.load_html_sync_cycle(project, cycle_id)?
        {
            if let Some(latch) = latch {
                cycle = cycle.with_latch(latch);
            }
            commit = commit.with_cycle(cycle);
        }
        let _ = detail;
        store.commit_html_sync(commit)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_failure(
        &self,
        store: &mut dyn H3StorePort,
        document: &DocumentKey,
        cycle: CycleId,
        generation: GenerationId,
        cause: H3FailureCause,
        detail: &str,
        now: Timestamp,
    ) -> Result<(), H3Error> {
        let project = document.project_id();
        let Some(existing) = store.load_html_sync_document(project, document)? else {
            return Ok(());
        };
        let reason = H3Reason::new(
            H3StateReasonKind::Failed { cause },
            vec![RequiredAction::ReviewFailure],
        )?;
        let next = document_state(
            document,
            existing.state().settings_version(),
            existing.state().job_id(),
            cycle,
            Some(generation),
            existing.state().source().clone(),
            existing.state().fingerprints().clone(),
            reason,
            existing.state().h2().cloned(),
            existing.state().evidence().to_vec(),
            lost_applicability(
                existing.state().applicability().is_applicable(),
                Some(generation),
                existing.state().source().revision().get(),
            ),
            now,
        )?;
        let event = document_state_event(document, Some(existing.state().state()), &next, now)?;
        let commit = HtmlSyncCommit::new()
            .with_document(DocumentCommit::new(Some(existing.revision()), next)?)
            .with_events(vec![event]);
        let _ = (detail, cycle, project);
        store.commit_html_sync(commit)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_start_hold(
        &self,
        store: &mut dyn H3StorePort,
        queued: &QueuedAuthoring,
        workspace: &AuthoringSnapshot,
        existing: Option<&H3DocumentRecord>,
        cycle: Option<&SyncCycle>,
        latch: Option<CycleLatch>,
        reason: H3Reason,
        detail: &str,
        now: Timestamp,
    ) -> Result<(), H3Error> {
        match existing {
            Some(existing) => {
                let next = document_state(
                    &queued.document,
                    existing.state().settings_version(),
                    existing.state().job_id(),
                    cycle
                        .map(SyncCycle::cycle_id)
                        .or_else(|| existing.state().cycle_id())
                        .ok_or_else(|| {
                            H3Error::invalid("cycle", "the document has no sync cycle")
                        })?,
                    existing.state().generation(),
                    existing.state().source().clone(),
                    existing.state().fingerprints().clone(),
                    reason,
                    existing.state().h2().cloned(),
                    existing.state().evidence().to_vec(),
                    lost_applicability(
                        existing.state().applicability().is_applicable(),
                        existing.state().generation(),
                        existing.state().source().revision().get(),
                    ),
                    now,
                )?;
                let event = document_state_event(
                    &queued.document,
                    Some(existing.state().state()),
                    &next,
                    now,
                )?;
                let mut commit = HtmlSyncCommit::new()
                    .with_document(DocumentCommit::new(Some(existing.revision()), next)?)
                    .with_events(vec![event]);
                if let Some(mut cycle) = cycle.cloned() {
                    if let Some(latch) = latch {
                        cycle = cycle.with_latch(latch);
                    }
                    commit = commit.with_cycle(cycle);
                }
                let _ = detail;
                store.commit_html_sync(commit)?;
                Ok(())
            }
            None => {
                // The work was never started, but the held document still needs
                // a durable state and cycle for the UI, later recovery, and the
                // "new notification does not clear a latch" rule.
                let mut cycle = match cycle.cloned() {
                    Some(cycle) => cycle,
                    None => SyncCycle::new(
                        CycleId::new(queued.document.project_id()),
                        queued.document.clone(),
                        queued.job.settings_version(),
                        now,
                        queued.snapshot.clone(),
                        Some(queued.job.supervision_id()),
                    )?,
                };
                if let Some(latch) = latch {
                    cycle = cycle.with_latch(latch);
                }
                let next = document_state(
                    &queued.document,
                    queued.job.settings_version(),
                    Some(queued.job.job()),
                    cycle.cycle_id(),
                    None,
                    queued.snapshot.clone(),
                    workspace.fingerprints().clone(),
                    reason,
                    None,
                    Vec::new(),
                    lost_applicability(false, None, queued.snapshot.revision().get()),
                    now,
                )?;
                let event = document_state_event(&queued.document, None, &next, now)?;
                let _ = detail;
                store.commit_html_sync(
                    HtmlSyncCommit::new()
                        .with_document(DocumentCommit::new(None, next)?)
                        .with_cycle(cycle)
                        .with_events(vec![event]),
                )?;
                Ok(())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_start_failure(
        &self,
        store: &mut dyn H3StorePort,
        queued: &QueuedAuthoring,
        cycle: &SyncCycle,
        generation: GenerationId,
        generation_number: u64,
        snapshot: &AuthoringSnapshot,
        detail: &str,
        now: Timestamp,
    ) -> Result<(), H3Error> {
        let project = queued.document.project_id();
        let existing = store.load_html_sync_document(project, &queued.document)?;
        let reason = H3Reason::new(
            H3StateReasonKind::Failed {
                cause: H3FailureCause::TargetUnstable,
            },
            vec![RequiredAction::ReviewFailure],
        )?;
        let _ = (generation_number, snapshot);
        let failed_generation =
            load_generation(store, project, &queued.document, generation)?.fail()?;
        let next = document_state(
            &queued.document,
            queued.job.settings_version(),
            existing
                .as_ref()
                .and_then(|record| record.state().job_id())
                .or(Some(queued.job.job())),
            cycle.cycle_id(),
            Some(generation),
            snapshot.source().clone(),
            snapshot.fingerprints().clone(),
            reason,
            existing
                .as_ref()
                .and_then(|record| record.state().h2().cloned()),
            existing
                .as_ref()
                .map(|record| record.state().evidence().to_vec())
                .unwrap_or_default(),
            lost_applicability(
                existing
                    .as_ref()
                    .is_some_and(|record| record.state().applicability().is_applicable()),
                Some(generation),
                snapshot.source().revision().get(),
            ),
            now,
        )?;
        let event = document_state_event(
            &queued.document,
            existing.as_ref().map(|record| record.state().state()),
            &next,
            now,
        )?;
        let _ = detail;
        store.commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(
                    existing.as_ref().map(H3DocumentRecord::revision),
                    next,
                )?)
                .with_cycle(cycle.clone())
                .with_generation(failed_generation)
                .with_events(vec![event]),
        )?;
        Ok(())
    }
}

fn load_settings(
    store: &mut dyn H3StorePort,
    project: ProjectId,
) -> Result<H3SettingsRecord, H3Error> {
    store
        .load_html_sync_settings(project)?
        .ok_or_else(|| H3Error::Unavailable {
            capability: "h3.settings".to_owned(),
            detail: "the project has no stored H3 settings".to_owned(),
        })
}

fn load_generation(
    store: &mut dyn H3StorePort,
    project: ProjectId,
    document: &DocumentKey,
    generation: GenerationId,
) -> Result<GenerationRecord, H3Error> {
    store
        .html_sync_generations(project, document)?
        .into_iter()
        .find(|record| record.generation_id() == generation)
        .ok_or_else(|| H3Error::NotFound {
            record: "generation",
            id: generation.to_string(),
        })
}

fn next_generation_number(
    store: &mut dyn H3StorePort,
    project: ProjectId,
    document: &DocumentKey,
) -> Result<u64, H3Error> {
    let generations = store.html_sync_generations(project, document)?;
    Ok(generations
        .iter()
        .map(GenerationRecord::generation)
        .max()
        .unwrap_or(0)
        .saturating_add(1))
}

#[allow(clippy::too_many_arguments)]
fn document_state(
    document: &DocumentKey,
    settings_version: u64,
    job: Option<JobId>,
    cycle: CycleId,
    generation: Option<GenerationId>,
    source: SourceSnapshot,
    fingerprints: FingerprintSet,
    reason: H3Reason,
    h2: Option<H2Reference>,
    evidence: Vec<crate::state::EvidenceRef>,
    applicability: Applicability,
    now: Timestamp,
) -> Result<H3DocumentState, H3Error> {
    H3DocumentState::new(
        document.clone(),
        settings_version,
        job,
        Some(cycle),
        generation,
        source,
        fingerprints,
        reason,
        h2,
        evidence,
        applicability,
        now,
    )
}

fn lost_applicability(
    was_applicable: bool,
    generation: Option<GenerationId>,
    source_revision: u64,
) -> Applicability {
    match (was_applicable, generation) {
        (true, Some(generation)) => {
            Applicability::not_applicable(ApplicabilityReason::Superseded {
                generation,
                source_revision,
            })
        }
        _ => Applicability::not_applicable(ApplicabilityReason::NeverPublished),
    }
}

fn saved_hold(state: &H3DocumentState) -> Option<(Option<CycleLatch>, String)> {
    match state.state() {
        H3State::WaitingHuman => Some((
            Some(CycleLatch::WaitingHuman),
            "the saved H3 state is waiting for a human".to_owned(),
        )),
        H3State::Stopped => {
            let latch = match state.reason().kind() {
                H3StateReasonKind::Stopped {
                    cause: H3StopCause::HumanRequest,
                } => Some(CycleLatch::HumanStop),
                H3StateReasonKind::Stopped {
                    cause: H3StopCause::Stagnation,
                } => Some(CycleLatch::Stagnation),
                H3StateReasonKind::Stopped {
                    cause: H3StopCause::BudgetLimit,
                } => Some(CycleLatch::BudgetLimit),
                _ => Some(CycleLatch::RecoveryReconciliation),
            };
            Some((latch, "the saved H3 state is stopped".to_owned()))
        }
        H3State::Cancelled | H3State::Failed => Some((
            Some(CycleLatch::RecoveryReconciliation),
            "the saved H3 state is terminal".to_owned(),
        )),
        H3State::Authoring
        | H3State::Verifying
        | H3State::Assessing
        | H3State::ReadyToPublish
        | H3State::Publishing => Some((
            Some(CycleLatch::RecoveryReconciliation),
            "the saved state indicates an in-flight generation; a restart does not resume it"
                .to_owned(),
        )),
        _ => None,
    }
}
