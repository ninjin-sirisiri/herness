//! Versioned H3 configuration approval.
//!
//! One human approval binds the project, the exact Target set, the authoring
//! and assessment connections (identifier, origin, disclosure scope), the
//! rubric/profile/policy/pack versions, the Common SDD host-API identity, the
//! numeric limits, old-version retention, and the H2 owner binding into one
//! value. Settings without this approval are scan-only.
//!
//! This module deliberately has no constructor that accepts a receipt, a
//! repository file, a host contract, an environment value, or a model output.
//! The only way to produce an approval is
//! [`H3ConfigurationApproval::approve`], which records [`H3Approver::Human`].
//! Every field is private and immutable, so adding a Target, an origin, a data
//! kind, or changing a pack/policy/rubric/profile version requires a new human
//! approval value (a new settings version).
//!
//! H3 settings and H2 owner authority remain separate: this value is the
//! configuration approval; [`crate::ports::H3StorePort`] persists it inside
//! [`crate::state::H3Settings`], and
//! [`crate::config::StoreBackedOwnerApprovalRegistry`] projects the matching
//! owner fields into H2's [`herness_supervision::owner_launch::OwnerApproval`].

use std::collections::BTreeSet;

use herness_core::{ConnectionId, ProjectId, Timestamp};
use herness_supervision::owner_launch::OwnerApproval;
use herness_supervision::{
    BudgetPolicy, ConditionDigest, ConditionVersion, ConsentBinding, ContentDigest,
    DisclosureDataKind, DisclosureScope, ExecutionScope, OriginScheme, OwnerKind, OwnerRef,
    ProfileBinding, ProfilePurpose, ProviderOrigin, SupervisionError, TargetVersion,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::H3Error;
use crate::version::{H3_FORMAT_VERSION, H3Record};

/// Default maximum Markdown source size approved for H3 (2 MiB).
pub const MAX_APPROVED_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
/// Default maximum candidate HTML size approved for H3 (8 MiB).
pub const MAX_APPROVED_CANDIDATE_BYTES: u64 = 8 * 1024 * 1024;
/// Default maximum SVG element count per document.
pub const MAX_APPROVED_SVG_ELEMENTS: u32 = 5_000;
/// Default render timeout per candidate (30 seconds).
pub const MAX_APPROVED_RENDER_TIMEOUT_MS: u64 = 30_000;
/// Default edit-settle interval (750 ms).
pub const MAX_APPROVED_SETTLE_MS: u64 = 750;
/// Default periodic reconciliation interval (5 seconds).
pub const MAX_APPROVED_RECONCILE_INTERVAL_MS: u64 = 5_000;
/// Default cumulative active seconds in one H2 cycle (7,200).
pub const MAX_APPROVED_CYCLE_ACTIVE_SECONDS: u64 = 7_200;
/// Default additional runs in one H2 cycle (30).
pub const MAX_APPROVED_ADDITIONAL_RUNS: u32 = 30;
/// Default consecutive stagnation limit (3).
pub const MAX_APPROVED_CONSECUTIVE_STALLS: u32 = 3;
/// The approved app-wide automatic authoring concurrency (one).
pub const APPROVED_AUTHORING_CONCURRENCY: u32 = 1;
/// The approved per-document publication concurrency (one).
pub const APPROVED_DOCUMENT_PUBLICATION_CONCURRENCY: u32 = 1;

/// Stable pack policy version required by this build.
pub const PACK_POLICY_VERSION: &str = "sdd-html-policy-v1";
/// Stable pack integration schema required by this build.
pub const PACK_INTEGRATION_SCHEMA: &str = "sdd-herness-integration";
/// Stable pack integration host required by this build.
pub const PACK_INTEGRATION_HOST: &str = "herness";
/// Stable Common SDD host API protocol required by this build.
pub const HOST_API_PROTOCOL: &str = "sdd-html-host-api";
/// The only Common SDD host API version this build understands.
pub const HOST_API_VERSION: u32 = 1;

const APPROVAL_FINGERPRINT_DOMAIN: &[u8] = b"herness.h3.configuration-approval.v1\0";
const SETTINGS_APPROVAL_DOMAIN: &[u8] = b"herness.h3.settings-approval.v1\0";

/// Who approved one configuration version.
///
/// The only variant is human. There is no environment, document, receipt,
/// contract, RequestActor, OwnerKind, or model approver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum H3Approver {
    /// A human approved the exact configuration in the trusted host UI.
    Human,
}

/// Lifecycle of an approval. Scope is immutable; only the lifecycle changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum H3ApprovalState {
    /// The approval is current unless its optional expiry has passed.
    Approved,
    /// A human revoked the approval.
    Revoked {
        /// Revocation time.
        revoked_at: Timestamp,
    },
    /// A newer settings version replaced it.
    Superseded {
        /// Settings version that replaced this approval.
        by_settings_version: u64,
    },
}

impl H3ApprovalState {
    /// Whether the approval is lifecycle-current at `now`.
    pub fn is_current_at(self, now: Timestamp, expires_at: Option<Timestamp>) -> bool {
        if !matches!(self, Self::Approved) {
            return false;
        }
        match expires_at {
            Some(expiry) => now.as_unix_millis() < expiry.as_unix_millis(),
            None => true,
        }
    }
}

/// One approved authoring or assessment connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3ConnectionApproval {
    connection_id: ConnectionId,
    origin: ProviderOrigin,
    disclosure: DisclosureScope,
    profile: ProfileBinding,
    consent: ConsentBinding,
}

impl H3ConnectionApproval {
    /// Creates a validated connection approval.
    ///
    /// The profile, consent, and disclosure purpose must agree, the consent
    /// must be bound to the same target-scope version as the disclosure, and
    /// every disclosed Target must also be part of the approved Target set.
    pub fn new(
        project: ProjectId,
        connection_id: ConnectionId,
        origin: ProviderOrigin,
        disclosure: DisclosureScope,
        profile: ProfileBinding,
        consent: ConsentBinding,
    ) -> Result<Self, H3Error> {
        disclosure.validate()?;
        let purpose = disclosure.purpose();
        if profile.purpose() != purpose {
            return Err(H3Error::invalid(
                "profile.purpose",
                "the profile purpose must match the disclosure purpose",
            ));
        }
        if consent.purpose() != purpose {
            return Err(H3Error::invalid(
                "consent.purpose",
                "the consent purpose must match the disclosure purpose",
            ));
        }
        if consent.target_scope_version() != disclosure.target_scope_version() {
            return Err(H3Error::invalid(
                "consent.targetScopeVersion",
                "the consent must be bound to the approved target-scope version",
            ));
        }
        if consent.version() == 0 {
            return Err(H3Error::must_be_positive("consent.version"));
        }
        if consent.consent_id().project_id() != project
            || profile.profile_id().project_id() != project
        {
            return Err(H3Error::CrossProject {
                id_kind: "connection approval".to_owned(),
                expected: project,
                found: if consent.consent_id().project_id() != project {
                    consent.consent_id().project_id()
                } else {
                    profile.profile_id().project_id()
                },
            });
        }
        Ok(Self {
            connection_id,
            origin,
            disclosure,
            profile,
            consent,
        })
    }

    /// Approved connection identifier.
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Approved provider origin (scheme, host, port).
    pub const fn origin(&self) -> &ProviderOrigin {
        &self.origin
    }

    /// Exact approved disclosure scope.
    pub const fn disclosure(&self) -> &DisclosureScope {
        &self.disclosure
    }

    /// Fixed profile binding.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Fixed consent binding.
    pub const fn consent(&self) -> ConsentBinding {
        self.consent
    }
}

/// Pack, policy, rubric, and host-API versions bound by the approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3VersionBinding {
    integration_schema: String,
    integration_version: u32,
    integration_revision: u32,
    policy_version: String,
    policy_fingerprint: ContentDigest,
    rubric_version: u64,
    pack_fingerprint: ContentDigest,
    host_api_protocol: String,
    host_api_version: u32,
}

impl H3VersionBinding {
    /// Creates a validated version binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        integration_schema: impl Into<String>,
        integration_version: u32,
        integration_revision: u32,
        policy_version: impl Into<String>,
        policy_fingerprint: ContentDigest,
        rubric_version: u64,
        pack_fingerprint: ContentDigest,
        host_api_protocol: impl Into<String>,
        host_api_version: u32,
    ) -> Result<Self, H3Error> {
        let integration_schema = integration_schema.into();
        let policy_version = policy_version.into();
        let host_api_protocol = host_api_protocol.into();
        if integration_schema != PACK_INTEGRATION_SCHEMA {
            return Err(H3Error::invalid(
                "integration.schema",
                "the approved integration definition schema is not the common pack schema",
            ));
        }
        if integration_version == 0 || integration_revision == 0 {
            return Err(H3Error::must_be_positive("integration.version"));
        }
        if policy_version != PACK_POLICY_VERSION {
            return Err(H3Error::invalid(
                "policy.version",
                "the approved policy version is not the common SDD HTML policy",
            ));
        }
        if rubric_version == 0 {
            return Err(H3Error::must_be_positive("rubricVersion"));
        }
        if host_api_protocol != HOST_API_PROTOCOL || host_api_version != HOST_API_VERSION {
            return Err(H3Error::invalid(
                "hostApi",
                "the approved host API protocol or version is not supported",
            ));
        }
        Ok(Self {
            integration_schema,
            integration_version,
            integration_revision,
            policy_version,
            policy_fingerprint,
            rubric_version,
            pack_fingerprint,
            host_api_protocol,
            host_api_version,
        })
    }

    /// Integration definition schema.
    pub fn integration_schema(&self) -> &str {
        &self.integration_schema
    }

    /// Integration definition version.
    pub const fn integration_version(&self) -> u32 {
        self.integration_version
    }

    /// Integration definition revision.
    pub const fn integration_revision(&self) -> u32 {
        self.integration_revision
    }

    /// Common SDD HTML policy version.
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// Common SDD HTML policy fingerprint (exact module bytes).
    pub const fn policy_fingerprint(&self) -> &ContentDigest {
        &self.policy_fingerprint
    }

    /// Human-approved rubric version.
    pub const fn rubric_version(&self) -> u64 {
        self.rubric_version
    }

    /// Pack fingerprint covering the integration definition and policy identity.
    pub const fn pack_fingerprint(&self) -> &ContentDigest {
        &self.pack_fingerprint
    }

    /// Common SDD host API protocol name.
    pub fn host_api_protocol(&self) -> &str {
        &self.host_api_protocol
    }

    /// Common SDD host API version.
    pub const fn host_api_version(&self) -> u32 {
        self.host_api_version
    }
}

/// The exact numeric limits bound by the approval.
///
/// Values may be lowered but never raised above the approved H3 defaults. The
/// app-wide authoring and per-document publication concurrency remain one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3ApprovalLimits {
    source_bytes: u64,
    candidate_bytes: u64,
    svg_elements: u32,
    render_timeout_ms: u64,
    settle_ms: u64,
    reconcile_interval_ms: u64,
    authoring_concurrency: u32,
    document_publication_concurrency: u32,
    cycle_active_seconds: u64,
    additional_runs: u32,
    consecutive_stalls: u32,
}

impl H3ApprovalLimits {
    /// Creates validated limits. Every value must be positive and bounded by
    /// the approved H3 ceiling.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_bytes: u64,
        candidate_bytes: u64,
        svg_elements: u32,
        render_timeout_ms: u64,
        settle_ms: u64,
        reconcile_interval_ms: u64,
        authoring_concurrency: u32,
        document_publication_concurrency: u32,
        cycle_active_seconds: u64,
        additional_runs: u32,
        consecutive_stalls: u32,
    ) -> Result<Self, H3Error> {
        for (field, value) in [
            ("sourceBytes", source_bytes),
            ("candidateBytes", candidate_bytes),
            ("renderTimeoutMs", render_timeout_ms),
            ("settleMs", settle_ms),
            ("reconcileIntervalMs", reconcile_interval_ms),
            ("cycleActiveSeconds", cycle_active_seconds),
        ] {
            if value == 0 {
                return Err(H3Error::must_be_positive(field));
            }
        }
        if svg_elements == 0 {
            return Err(H3Error::must_be_positive("svgElements"));
        }
        if consecutive_stalls == 0 {
            return Err(H3Error::must_be_positive("consecutiveStalls"));
        }
        if source_bytes > MAX_APPROVED_SOURCE_BYTES
            || candidate_bytes > MAX_APPROVED_CANDIDATE_BYTES
            || svg_elements > MAX_APPROVED_SVG_ELEMENTS
            || render_timeout_ms > MAX_APPROVED_RENDER_TIMEOUT_MS
            || settle_ms > MAX_APPROVED_SETTLE_MS
            || reconcile_interval_ms > MAX_APPROVED_RECONCILE_INTERVAL_MS
            || cycle_active_seconds > MAX_APPROVED_CYCLE_ACTIVE_SECONDS
            || additional_runs > MAX_APPROVED_ADDITIONAL_RUNS
            || consecutive_stalls > MAX_APPROVED_CONSECUTIVE_STALLS
        {
            return Err(H3Error::invalid(
                "limits",
                "an approved limit exceeds the H3 ceiling; use the common defaults or lower them",
            ));
        }
        if authoring_concurrency != APPROVED_AUTHORING_CONCURRENCY {
            return Err(H3Error::invalid(
                "authoringConcurrency",
                "automatic authoring concurrency is fixed at one for the app",
            ));
        }
        if document_publication_concurrency != APPROVED_DOCUMENT_PUBLICATION_CONCURRENCY {
            return Err(H3Error::invalid(
                "documentPublicationConcurrency",
                "per-document publication concurrency is fixed at one",
            ));
        }
        Ok(Self {
            source_bytes,
            candidate_bytes,
            svg_elements,
            render_timeout_ms,
            settle_ms,
            reconcile_interval_ms,
            authoring_concurrency,
            document_publication_concurrency,
            cycle_active_seconds,
            additional_runs,
            consecutive_stalls,
        })
    }

    /// Maximum Markdown source bytes.
    pub const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    /// Maximum candidate HTML bytes.
    pub const fn candidate_bytes(&self) -> u64 {
        self.candidate_bytes
    }

    /// Maximum SVG elements per document.
    pub const fn svg_elements(&self) -> u32 {
        self.svg_elements
    }

    /// Render timeout per candidate in milliseconds.
    pub const fn render_timeout_ms(&self) -> u64 {
        self.render_timeout_ms
    }

    /// Edit-settle interval in milliseconds.
    pub const fn settle_ms(&self) -> u64 {
        self.settle_ms
    }

    /// Periodic reconciliation interval in milliseconds.
    pub const fn reconcile_interval_ms(&self) -> u64 {
        self.reconcile_interval_ms
    }

    /// App-wide automatic authoring concurrency.
    pub const fn authoring_concurrency(&self) -> u32 {
        self.authoring_concurrency
    }

    /// Per-document publication concurrency.
    pub const fn document_publication_concurrency(&self) -> u32 {
        self.document_publication_concurrency
    }

    /// Cumulative active seconds in one H2 cycle.
    pub const fn cycle_active_seconds(&self) -> u64 {
        self.cycle_active_seconds
    }

    /// Additional runs in one H2 cycle.
    pub const fn additional_runs(&self) -> u32 {
        self.additional_runs
    }

    /// Consecutive stagnation limit.
    pub const fn consecutive_stalls(&self) -> u32 {
        self.consecutive_stalls
    }
}

impl Default for H3ApprovalLimits {
    fn default() -> Self {
        Self {
            source_bytes: MAX_APPROVED_SOURCE_BYTES,
            candidate_bytes: MAX_APPROVED_CANDIDATE_BYTES,
            svg_elements: MAX_APPROVED_SVG_ELEMENTS,
            render_timeout_ms: MAX_APPROVED_RENDER_TIMEOUT_MS,
            settle_ms: MAX_APPROVED_SETTLE_MS,
            reconcile_interval_ms: MAX_APPROVED_RECONCILE_INTERVAL_MS,
            authoring_concurrency: APPROVED_AUTHORING_CONCURRENCY,
            document_publication_concurrency: APPROVED_DOCUMENT_PUBLICATION_CONCURRENCY,
            cycle_active_seconds: MAX_APPROVED_CYCLE_ACTIVE_SECONDS,
            additional_runs: MAX_APPROVED_ADDITIONAL_RUNS,
            consecutive_stalls: MAX_APPROVED_CONSECUTIVE_STALLS,
        }
    }
}

/// The H2 owner binding covered by one configuration approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3OwnerBinding {
    owner: OwnerRef,
    job_id: String,
    condition_version: ConditionVersion,
    conditions_digest: ConditionDigest,
    execution_scope: ExecutionScope,
    budget_policy_version: u64,
    budget: BudgetPolicy,
}

impl H3OwnerBinding {
    /// Creates a validated owner binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectId,
        owner: OwnerRef,
        job_id: impl Into<String>,
        condition_version: ConditionVersion,
        conditions_digest: ConditionDigest,
        execution_scope: ExecutionScope,
        budget_policy_version: u64,
        budget: BudgetPolicy,
    ) -> Result<Self, H3Error> {
        if owner.kind() != OwnerKind::H3HtmlJob {
            return Err(H3Error::invalid(
                "owner.kind",
                "an H3 configuration approval only covers an H3 HTML job",
            ));
        }
        let job_id = job_id.into();
        let trimmed = job_id.trim();
        if trimmed.is_empty() {
            return Err(H3Error::empty("owner.jobId"));
        }
        if trimmed.chars().count() > 256 {
            return Err(H3Error::invalid(
                "owner.jobId",
                "must contain at most 256 characters",
            ));
        }
        if budget_policy_version == 0 {
            return Err(H3Error::must_be_positive("budgetPolicyVersion"));
        }
        if execution_scope.project_id() != project {
            return Err(H3Error::CrossProject {
                id_kind: "owner execution scope".to_owned(),
                expected: project,
                found: execution_scope.project_id(),
            });
        }
        if execution_scope.allow_shell() {
            return Err(H3Error::invalid(
                "executionScope.allowShell",
                "the H3 authoring scope must not allow shell access",
            ));
        }
        budget.validate()?;
        Ok(Self {
            owner,
            job_id: trimmed.to_owned(),
            condition_version,
            conditions_digest,
            execution_scope,
            budget_policy_version,
            budget,
        })
    }

    /// Approved owner reference.
    pub const fn owner(&self) -> &OwnerRef {
        &self.owner
    }

    /// Opaque H3 job identifier.
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Covered condition version.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Exact covered condition digest.
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
}

/// Everything a human supplies to approve one H3 configuration version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3ConfigurationDraft {
    /// Project being approved.
    pub project_id: ProjectId,
    /// Positive settings version this approval covers.
    pub settings_version: u64,
    /// Non-empty host-owned approval identifier.
    pub approval_id: String,
    /// Optional expiry. A value at or after `expires_at` is stale.
    pub expires_at: Option<Timestamp>,
    /// Approved Target-relative Markdown paths.
    pub targets: Vec<String>,
    /// Authoring (Completion) connection, profile, consent, and disclosure.
    pub authoring: H3ConnectionApproval,
    /// HTML assessment (Html) connection, profile, consent, and disclosure.
    pub assessment: H3ConnectionApproval,
    /// Pack, policy, rubric, and host-API versions.
    pub versions: H3VersionBinding,
    /// Numeric limits.
    pub limits: H3ApprovalLimits,
    /// Whether an approved candidate may be published automatically.
    pub auto_publish: bool,
    /// Whether old versions are retained. H3 never silently prunes them.
    pub retain_history: bool,
    /// Whether the approved capability is the automatic companion.
    pub automatic_companion: bool,
    /// The H2 owner binding for the current job.
    pub owner: H3OwnerBinding,
}

/// One versioned, human-approved H3 configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3ConfigurationApproval {
    format_version: u32,
    project_id: ProjectId,
    settings_version: u64,
    approval_id: String,
    approved_by: H3Approver,
    approved_at: Timestamp,
    expires_at: Option<Timestamp>,
    state: H3ApprovalState,
    targets: Vec<String>,
    authoring: H3ConnectionApproval,
    assessment: H3ConnectionApproval,
    versions: H3VersionBinding,
    limits: H3ApprovalLimits,
    auto_publish: bool,
    retain_history: bool,
    automatic_companion: bool,
    owner: H3OwnerBinding,
    fingerprint: ContentDigest,
}

impl H3ConfigurationApproval {
    /// Records a human approval of one exact configuration.
    ///
    /// This is the only constructor. It accepts no receipt, contract, repo
    /// file, environment value, actor, owner kind, or model output.
    pub fn approve(
        draft: H3ConfigurationDraft,
        approver: H3Approver,
        approved_at: Timestamp,
    ) -> Result<Self, H3Error> {
        if approver != H3Approver::Human {
            return Err(H3Error::invalid(
                "approvedBy",
                "only a human may approve an H3 configuration",
            ));
        }
        if draft.settings_version == 0 {
            return Err(H3Error::must_be_positive("settingsVersion"));
        }
        let approval_id = draft.approval_id.trim();
        if approval_id.is_empty() {
            return Err(H3Error::empty("approvalId"));
        }
        if approval_id.chars().count() > 256 {
            return Err(H3Error::invalid(
                "approvalId",
                "must contain at most 256 characters",
            ));
        }
        if draft.targets.is_empty() {
            return Err(H3Error::empty("targets"));
        }
        let original_target_count = draft.targets.len();
        let mut targets = draft.targets;
        for path in &targets {
            crate::document::DocumentKey::new(draft.project_id, path.clone())?;
        }
        targets.sort();
        targets.dedup();
        if targets.len() != original_target_count {
            return Err(H3Error::invalid(
                "targets",
                "the approved Target set contains duplicates",
            ));
        }
        if draft.authoring.disclosure.purpose() != ProfilePurpose::Completion {
            return Err(H3Error::invalid(
                "authoring.disclosure.purpose",
                "the authoring connection must use the Completion purpose",
            ));
        }
        if draft.assessment.disclosure.purpose() != ProfilePurpose::Html {
            return Err(H3Error::invalid(
                "assessment.disclosure.purpose",
                "the assessment connection must use the Html purpose",
            ));
        }
        validate_disclosure_targets(&targets, &draft.authoring.disclosure, "authoring")?;
        validate_disclosure_targets(&targets, &draft.assessment.disclosure, "assessment")?;
        if draft.owner.owner.kind() != OwnerKind::H3HtmlJob {
            return Err(H3Error::invalid(
                "owner.kind",
                "an H3 configuration approval only covers an H3 HTML job",
            ));
        }
        if draft.owner.execution_scope.project_id() != draft.project_id {
            return Err(H3Error::CrossProject {
                id_kind: "owner execution scope".to_owned(),
                expected: draft.project_id,
                found: draft.owner.execution_scope.project_id(),
            });
        }
        for target in &targets {
            for path in draft.owner.execution_scope.write_paths() {
                let contains_target = target == path
                    || target
                        .strip_prefix(path.as_str())
                        .is_some_and(|suffix| suffix.starts_with('/'));
                if contains_target {
                    return Err(H3Error::invalid(
                        "executionScope.writePaths",
                        "the authoring scope must not write an approved Target or its parent",
                    ));
                }
            }
        }
        if !draft.automatic_companion {
            return Err(H3Error::invalid(
                "automaticCompanion",
                "the approved capability is the automatic HTML companion",
            ));
        }
        let mut approval = Self {
            format_version: H3_FORMAT_VERSION,
            project_id: draft.project_id,
            settings_version: draft.settings_version,
            approval_id: approval_id.to_owned(),
            approved_by: approver,
            approved_at,
            expires_at: draft.expires_at,
            state: H3ApprovalState::Approved,
            targets,
            authoring: draft.authoring,
            assessment: draft.assessment,
            versions: draft.versions,
            limits: draft.limits,
            auto_publish: draft.auto_publish,
            retain_history: draft.retain_history,
            automatic_companion: draft.automatic_companion,
            owner: draft.owner,
            fingerprint: ContentDigest::sha256(b"pending"),
        };
        approval.fingerprint = approval.compute_fingerprint()?;
        Ok(approval)
    }

    /// Project this approval covers.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Positive settings version this approval covers.
    pub const fn settings_version(&self) -> u64 {
        self.settings_version
    }

    /// Host-owned approval identifier.
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    /// Who approved it.
    pub const fn approved_by(&self) -> H3Approver {
        self.approved_by
    }

    /// When it was approved.
    pub const fn approved_at(&self) -> Timestamp {
        self.approved_at
    }

    /// Optional expiry.
    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Lifecycle state.
    pub const fn state(&self) -> H3ApprovalState {
        self.state
    }

    /// Approved Target set, sorted.
    pub fn targets(&self) -> &[String] {
        &self.targets
    }

    /// Authoring connection approval.
    pub const fn authoring(&self) -> &H3ConnectionApproval {
        &self.authoring
    }

    /// HTML assessment connection approval.
    pub const fn assessment(&self) -> &H3ConnectionApproval {
        &self.assessment
    }

    /// Pack, policy, rubric, and host-API versions.
    pub const fn versions(&self) -> &H3VersionBinding {
        &self.versions
    }

    /// Approved numeric limits.
    pub const fn limits(&self) -> &H3ApprovalLimits {
        &self.limits
    }

    /// Whether an approved candidate may be published automatically.
    pub const fn auto_publish(&self) -> bool {
        self.auto_publish
    }

    /// Whether old versions must be retained.
    pub const fn retain_history(&self) -> bool {
        self.retain_history
    }

    /// Whether the approved capability is the automatic companion.
    pub const fn automatic_companion(&self) -> bool {
        self.automatic_companion
    }

    /// H2 owner binding covered by this approval.
    pub const fn owner_binding(&self) -> &H3OwnerBinding {
        &self.owner
    }

    /// Fingerprint binding every approved field except the lifecycle state.
    pub const fn fingerprint(&self) -> &ContentDigest {
        &self.fingerprint
    }

    /// Whether the approval is usable at `now`.
    pub fn is_current_at(&self, now: Timestamp) -> bool {
        self.state.is_current_at(now, self.expires_at)
    }

    /// Recomputes and verifies the immutable scope fingerprint.
    pub fn verify_fingerprint(&self) -> Result<(), H3Error> {
        let expected = self.compute_fingerprint()?;
        if expected != self.fingerprint {
            return Err(H3Error::Corrupt {
                record: "H3 configuration approval",
                detail: "the approval fingerprint does not match its approved fields".to_owned(),
            });
        }
        Ok(())
    }

    /// Revokes the approval. The scope fields remain in history.
    pub fn revoke(mut self, at: Timestamp) -> Self {
        self.state = H3ApprovalState::Revoked { revoked_at: at };
        self
    }

    /// Marks the approval superseded by a newer settings version.
    pub fn supersede(mut self, by_settings_version: u64) -> Result<Self, H3Error> {
        if by_settings_version == 0 || by_settings_version <= self.settings_version {
            return Err(H3Error::must_be_positive("supersededBy"));
        }
        self.state = H3ApprovalState::Superseded {
            by_settings_version,
        };
        Ok(self)
    }

    /// Projects the approved pack identity for the policy bridge.
    pub fn pack_binding(&self) -> H3PackBinding {
        H3PackBinding::from_versions(&self.versions)
    }

    /// Classifies whether `requested` stays inside this approved scope.
    ///
    /// A new Target, a new origin, a new data kind, a changed pack/policy/
    /// rubric/profile version, or a looser limit requires a new human approval.
    /// The result is informational: this type never creates the new approval.
    pub fn scope_change(&self, requested: &H3ConfigurationDraft) -> H3ScopeChange {
        let mut changes = Vec::new();
        let requested_targets = {
            let mut targets = requested.targets.clone();
            targets.sort();
            targets.dedup();
            targets
        };
        if requested_targets != self.targets {
            changes.push(H3ScopeChangeKind::Targets);
        }
        if requested.authoring.origin != self.authoring.origin
            || requested.assessment.origin != self.assessment.origin
        {
            changes.push(H3ScopeChangeKind::Origins);
        }
        if requested.authoring.disclosure.data_kinds() != self.authoring.disclosure.data_kinds()
            || requested.assessment.disclosure.data_kinds()
                != self.assessment.disclosure.data_kinds()
        {
            changes.push(H3ScopeChangeKind::DataKinds);
        }
        if requested.authoring.disclosure.purpose() != self.authoring.disclosure.purpose()
            || requested.assessment.disclosure.purpose() != self.assessment.disclosure.purpose()
            || requested.authoring.disclosure.target_scope_version()
                != self.authoring.disclosure.target_scope_version()
            || requested.assessment.disclosure.target_scope_version()
                != self.assessment.disclosure.target_scope_version()
            || requested.authoring.connection_id != self.authoring.connection_id
            || requested.assessment.connection_id != self.assessment.connection_id
            || requested.authoring.profile() != self.authoring.profile
            || requested.assessment.profile() != self.assessment.profile
            || requested.authoring.consent() != self.authoring.consent
            || requested.assessment.consent() != self.assessment.consent
        {
            changes.push(H3ScopeChangeKind::Profiles);
        }
        if requested.versions != self.versions {
            changes.push(H3ScopeChangeKind::PackPolicyRubric);
        }
        if requested.limits != self.limits {
            changes.push(H3ScopeChangeKind::Limits);
        }
        if requested.auto_publish != self.auto_publish
            || requested.retain_history != self.retain_history
            || requested.automatic_companion != self.automatic_companion
        {
            changes.push(H3ScopeChangeKind::RetentionAndCapability);
        }
        if requested.owner != self.owner {
            changes.push(H3ScopeChangeKind::OwnerBinding);
        }
        H3ScopeChange { changes }
    }

    fn compute_fingerprint(&self) -> Result<ContentDigest, H3Error> {
        let mut hasher = Sha256::new();
        hasher.update(APPROVAL_FINGERPRINT_DOMAIN);
        mix_field(
            &mut hasher,
            b"project",
            self.project_id.to_string().as_bytes(),
        );
        mix_field(
            &mut hasher,
            b"settingsVersion",
            &self.settings_version.to_le_bytes(),
        );
        mix_field(&mut hasher, b"approvalId", self.approval_id.as_bytes());
        mix_field(&mut hasher, b"approvedBy", b"human");
        match self.expires_at {
            Some(expiry) => mix_field(
                &mut hasher,
                b"expires",
                &expiry.as_unix_millis().to_le_bytes(),
            ),
            None => mix_field(&mut hasher, b"expires", b"none"),
        }
        for target in &self.targets {
            mix_field(&mut hasher, b"target", target.as_bytes());
        }
        mix_field(&mut hasher, b"authoring", &record_bytes(&self.authoring)?);
        mix_field(&mut hasher, b"assessment", &record_bytes(&self.assessment)?);
        mix_field(&mut hasher, b"versions", &record_bytes(&self.versions)?);
        mix_field(&mut hasher, b"limits", &record_bytes(&self.limits)?);
        mix_field(&mut hasher, b"autoPublish", &[u8::from(self.auto_publish)]);
        mix_field(
            &mut hasher,
            b"retainHistory",
            &[u8::from(self.retain_history)],
        );
        mix_field(
            &mut hasher,
            b"automaticCompanion",
            &[u8::from(self.automatic_companion)],
        );
        mix_field(&mut hasher, b"owner", &record_bytes(&self.owner)?);
        Ok(finish_digest(hasher))
    }
}

impl H3Record for H3ConfigurationApproval {
    const RECORD: &'static str = "H3 configuration approval";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Pack identity the policy bridge must verify before any host-API call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3PackBinding {
    integration_schema: String,
    integration_version: u32,
    integration_revision: u32,
    policy_version: String,
    policy_fingerprint: ContentDigest,
    pack_fingerprint: ContentDigest,
    host_api_protocol: String,
    host_api_version: u32,
}

impl H3PackBinding {
    /// Creates a pack binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        integration_schema: impl Into<String>,
        integration_version: u32,
        integration_revision: u32,
        policy_version: impl Into<String>,
        policy_fingerprint: ContentDigest,
        pack_fingerprint: ContentDigest,
        host_api_protocol: impl Into<String>,
        host_api_version: u32,
    ) -> Result<Self, H3Error> {
        let binding = H3VersionBinding::new(
            integration_schema,
            integration_version,
            integration_revision,
            policy_version,
            policy_fingerprint,
            1,
            pack_fingerprint,
            host_api_protocol,
            host_api_version,
        )?;
        Ok(Self::from_versions(&binding))
    }

    fn from_versions(versions: &H3VersionBinding) -> Self {
        Self {
            integration_schema: versions.integration_schema.clone(),
            integration_version: versions.integration_version,
            integration_revision: versions.integration_revision,
            policy_version: versions.policy_version.clone(),
            policy_fingerprint: versions.policy_fingerprint.clone(),
            pack_fingerprint: versions.pack_fingerprint.clone(),
            host_api_protocol: versions.host_api_protocol.clone(),
            host_api_version: versions.host_api_version,
        }
    }

    /// Integration definition schema.
    pub fn integration_schema(&self) -> &str {
        &self.integration_schema
    }

    /// Integration definition version.
    pub const fn integration_version(&self) -> u32 {
        self.integration_version
    }

    /// Integration definition revision.
    pub const fn integration_revision(&self) -> u32 {
        self.integration_revision
    }

    /// Common SDD HTML policy version.
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// Common SDD HTML policy fingerprint.
    pub const fn policy_fingerprint(&self) -> &ContentDigest {
        &self.policy_fingerprint
    }

    /// Pack fingerprint.
    pub const fn pack_fingerprint(&self) -> &ContentDigest {
        &self.pack_fingerprint
    }

    /// Host API protocol name.
    pub fn host_api_protocol(&self) -> &str {
        &self.host_api_protocol
    }

    /// Host API version.
    pub const fn host_api_version(&self) -> u32 {
        self.host_api_version
    }
}

/// One kind of configuration change a new approval must cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum H3ScopeChangeKind {
    /// The approved Target set changed.
    Targets,
    /// A provider origin changed.
    Origins,
    /// A disclosure data-kind set changed.
    DataKinds,
    /// A profile, consent, or purpose changed.
    Profiles,
    /// The pack, policy, rubric, or host-API version changed.
    PackPolicyRubric,
    /// A numeric limit changed.
    Limits,
    /// Retention or the automatic-companion capability changed.
    RetentionAndCapability,
    /// The H2 owner, job, conditions, scope, or budget binding changed.
    OwnerBinding,
}

/// Informational scope comparison for the trusted approval UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3ScopeChange {
    changes: Vec<H3ScopeChangeKind>,
}

impl H3ScopeChange {
    /// Whether any field changed and a new human approval is required.
    pub fn requires_reapproval(&self) -> bool {
        !self.changes.is_empty()
    }

    /// Changed fields in stable order.
    pub fn changes(&self) -> &[H3ScopeChangeKind] {
        &self.changes
    }
}

fn validate_disclosure_targets(
    approved: &[String],
    disclosure: &DisclosureScope,
    label: &str,
) -> Result<(), H3Error> {
    for target in disclosure.targets() {
        if !approved.iter().any(|approved| approved == target) {
            return Err(H3Error::invalid(
                format!("{label}.disclosure.targets"),
                "every disclosed Target must be part of the approved Target set",
            ));
        }
    }
    Ok(())
}

/// Deterministic settings fingerprint extension when an approval is present.
pub(crate) fn mix_approval_fingerprint(
    fingerprint: &ContentDigest,
    approval: Option<&H3ConfigurationApproval>,
) -> ContentDigest {
    let Some(approval) = approval else {
        return fingerprint.clone();
    };
    let mut hasher = Sha256::new();
    hasher.update(SETTINGS_APPROVAL_DOMAIN);
    hasher.update(fingerprint.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(approval.fingerprint().as_str().as_bytes());
    finish_digest(hasher)
}

fn finish_digest(hasher: Sha256) -> ContentDigest {
    ContentDigest::parse(format!("{:x}", hasher.finalize()))
        .expect("a SHA-256 hex value is a valid content digest")
}

fn mix_field(hasher: &mut Sha256, tag: &[u8], bytes: &[u8]) {
    hasher.update(tag);
    hasher.update([0]);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn record_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, H3Error> {
    serde_json::to_vec(value).map_err(|error| H3Error::Corrupt {
        record: "H3 configuration approval",
        detail: error.to_string(),
    })
}

/// Convenience builder for the standard bounded disclosure used by H3.
pub fn h3_disclosure(
    purpose: ProfilePurpose,
    data_kinds: impl IntoIterator<Item = DisclosureDataKind>,
    targets: Vec<String>,
    target_scope_version: TargetVersion,
) -> Result<DisclosureScope, H3Error> {
    let kinds: BTreeSet<DisclosureDataKind> = data_kinds.into_iter().collect();
    DisclosureScope::new(purpose, kinds, targets, target_scope_version).map_err(H3Error::from)
}

/// Convenience origin constructor that keeps non-loopback HTTP out.
pub fn h3_origin(
    scheme: OriginScheme,
    host: impl AsRef<str>,
    port: u16,
) -> Result<ProviderOrigin, H3Error> {
    ProviderOrigin::new(scheme, host, port).map_err(H3Error::from)
}

/// Converts the approved owner binding to H2's registry value.
pub(crate) fn owner_approval_from_binding(
    project: ProjectId,
    binding: &H3OwnerBinding,
    profile: ProfileBinding,
    consent: ConsentBinding,
    settings_version: u64,
) -> Result<OwnerApproval, SupervisionError> {
    OwnerApproval::new(
        project,
        binding.owner.clone(),
        herness_supervision::approval::OwnerApprovalSource::H3ApprovedSettings,
        settings_version,
        binding.job_id.clone(),
        binding.condition_version,
        binding.conditions_digest.clone(),
        binding.execution_scope.clone(),
        profile,
        consent,
        binding.budget_policy_version,
        binding.budget.clone(),
    )
}

/// A registry backed by the approved H3 settings store.
///
/// `H3StorePort` is read-only here. A missing project, disabled/unapproved
/// settings, a revoked or superseded approval, an expired approval, another
/// owner, or tampered settings all yield no entry. Corrupt storage is an error,
/// never a synthetic approval.
pub struct StoreBackedOwnerApprovalRegistry<'a> {
    store: &'a dyn crate::ports::H3StorePort,
}

impl<'a> StoreBackedOwnerApprovalRegistry<'a> {
    /// Creates the registry over one store.
    pub const fn new(store: &'a dyn crate::ports::H3StorePort) -> Self {
        Self { store }
    }

    /// Loads the current settings record with its approval, if any.
    pub fn current_approval(
        &self,
        project: ProjectId,
        now: Timestamp,
    ) -> Result<Option<H3ConfigurationApproval>, H3Error> {
        let Some(record) = self.store.load_html_sync_settings(project)? else {
            return Ok(None);
        };
        let settings = record.settings();
        if settings.project_id() != project {
            return Err(H3Error::CrossProject {
                id_kind: "settings".to_owned(),
                expected: project,
                found: settings.project_id(),
            });
        }
        if !settings.verify_fingerprint() {
            return Err(H3Error::Corrupt {
                record: "H3 settings",
                detail: "the stored settings fingerprint does not match its fields".to_owned(),
            });
        }
        if !settings.enabled() {
            return Ok(None);
        }
        let Some(approval) = settings.approval() else {
            return Ok(None);
        };
        if approval.project_id() != project {
            return Err(H3Error::CrossProject {
                id_kind: "configuration approval".to_owned(),
                expected: project,
                found: approval.project_id(),
            });
        }
        if approval.settings_version() != settings.version() {
            return Err(H3Error::Corrupt {
                record: "H3 configuration approval",
                detail: "the approval does not cover the stored settings version".to_owned(),
            });
        }
        if approval.targets() != settings.target_paths() {
            return Err(H3Error::Corrupt {
                record: "H3 configuration approval",
                detail: "the approval does not cover the stored Target set".to_owned(),
            });
        }
        if approval.auto_publish() != settings.auto_publish() {
            return Err(H3Error::Corrupt {
                record: "H3 configuration approval",
                detail: "the approval auto-publish setting differs from the stored settings"
                    .to_owned(),
            });
        }
        if approval.retain_history() != settings.retain_history() {
            return Err(H3Error::Corrupt {
                record: "H3 configuration approval",
                detail: "the approval retention differs from the stored settings".to_owned(),
            });
        }
        approval.verify_fingerprint()?;
        if !approval.is_current_at(now) {
            return Ok(None);
        }
        Ok(Some(approval.clone()))
    }
}

impl herness_supervision::owner_launch::OwnerApprovalRegistryPort
    for StoreBackedOwnerApprovalRegistry<'_>
{
    fn current_owner_approval(
        &self,
        project_id: ProjectId,
        owner: &OwnerRef,
        now: Timestamp,
    ) -> Result<Option<OwnerApproval>, SupervisionError> {
        let approval = self.current_approval(project_id, now).map_err(|error| {
            SupervisionError::StorageFailure {
                detail: error.to_string(),
            }
        })?;
        let Some(approval) = approval else {
            return Ok(None);
        };
        if approval.owner_binding().owner() != owner {
            return Ok(None);
        }
        owner_approval_from_binding(
            project_id,
            approval.owner_binding(),
            approval.authoring().profile(),
            approval.authoring().consent(),
            approval.settings_version(),
        )
        .map(Some)
    }
}
