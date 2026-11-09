//! Immutable, versioned work packet for one supervised target.
//!
//! The packet is the owner-supplied initial instruction plus the approved
//! constraints that must accompany every first or additional child run. It is
//! created only when a contract is created or explicitly changed; no model or
//! tool input reaches these constructors. The SHA-256 fingerprint covers the
//! canonical field set, so a stored packet that was altered fails verification
//! instead of silently starting a different task.

use herness_core::contracts::ProjectId;
use serde::{Deserialize, Serialize};

use crate::budget::BudgetPolicy;
use crate::conditions::ConditionVersion;
use crate::consent::ConsentBinding;
use crate::contract::ExecutionScope;
use crate::error::{SupervisionError, WorkPacketRejection};
use crate::evidence::{ContentDigest, TargetScope, TargetVersion};
use crate::profiles::ProfileBinding;

/// Format version written by this build.
pub const WORK_PACKET_FORMAT_VERSION: u32 = 1;

/// Immutable owner packet sent to the first and every additional child run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkPacket {
    format_version: u32,
    packet_version: u64,
    instruction: String,
    project_id: ProjectId,
    target_version: TargetVersion,
    target_read_set: Vec<String>,
    target_digest: ContentDigest,
    read_set_digest: ContentDigest,
    execution_scope: ExecutionScope,
    condition_version: ConditionVersion,
    profile: ProfileBinding,
    consent: ConsentBinding,
    budget_policy_version: u64,
    budget: BudgetPolicy,
    fingerprint: ContentDigest,
}

impl WorkPacket {
    /// Creates a packet from the exact values approved for one target.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        packet_version: u64,
        instruction: impl AsRef<str>,
        project_id: ProjectId,
        target: &TargetScope,
        execution_scope: ExecutionScope,
        condition_version: ConditionVersion,
        profile: ProfileBinding,
        consent: ConsentBinding,
        budget_policy_version: u64,
        budget: BudgetPolicy,
    ) -> Result<Self, SupervisionError> {
        if packet_version == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "workPacket.version".to_owned(),
                detail: "packet versions start at 1".to_owned(),
            });
        }
        let instruction = instruction.as_ref().trim();
        if instruction.is_empty() {
            return Err(SupervisionError::InvalidValue {
                field: "workPacket.instruction".to_owned(),
                detail: "the owner instruction must not be empty".to_owned(),
            });
        }
        if budget_policy_version == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "workPacket.budgetPolicyVersion".to_owned(),
                detail: "budget policy versions start at 1".to_owned(),
            });
        }
        if target.project_id() != project_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "work packet target".to_owned(),
                expected: project_id,
                found: target.project_id(),
            });
        }
        if execution_scope.project_id() != project_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "work packet execution scope".to_owned(),
                expected: project_id,
                found: execution_scope.project_id(),
            });
        }

        let mut packet = Self {
            format_version: WORK_PACKET_FORMAT_VERSION,
            packet_version,
            instruction: instruction.to_owned(),
            project_id,
            target_version: target.version(),
            target_read_set: target.read_set().to_vec(),
            target_digest: target.snapshot_digest()?,
            read_set_digest: read_set_digest(target.read_set())?,
            execution_scope,
            condition_version,
            profile,
            consent,
            budget_policy_version,
            budget,
            fingerprint: ContentDigest::sha256(&[]),
        };
        packet.fingerprint = packet.compute_fingerprint()?;
        Ok(packet)
    }

    /// Packet format written by this build.
    pub const fn format_version(&self) -> u32 {
        self.format_version
    }

    /// Monotonic packet content version.
    pub const fn packet_version(&self) -> u64 {
        self.packet_version
    }

    /// Owner-supplied initial instruction, trimmed.
    pub fn instruction(&self) -> &str {
        &self.instruction
    }

    /// Project that owns the packet.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Approved target version referenced by the packet.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Approved bounded read set referenced by the packet.
    pub fn target_read_set(&self) -> &[String] {
        &self.target_read_set
    }

    /// Content reference of the approved target snapshot.
    pub const fn target_digest(&self) -> &ContentDigest {
        &self.target_digest
    }

    /// SHA-256 fingerprint of the exact read set.
    pub const fn read_set_digest(&self) -> &ContentDigest {
        &self.read_set_digest
    }

    /// Approved execution scope.
    pub const fn execution_scope(&self) -> &ExecutionScope {
        &self.execution_scope
    }

    /// Approved condition version.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Fixed assessment profile.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Fixed disclosure consent.
    pub const fn consent(&self) -> ConsentBinding {
        self.consent
    }

    /// Durable budget policy version.
    pub const fn budget_policy_version(&self) -> u64 {
        self.budget_policy_version
    }

    /// Approved finite budget policy.
    pub const fn budget(&self) -> &BudgetPolicy {
        &self.budget
    }

    /// SHA-256 fingerprint over the canonical packet fields.
    pub const fn fingerprint(&self) -> &ContentDigest {
        &self.fingerprint
    }

    /// Verifies the packet format and fingerprint before any use.
    pub fn verify(&self) -> Result<(), SupervisionError> {
        if self.format_version != WORK_PACKET_FORMAT_VERSION {
            return Err(SupervisionError::WorkPacketRejected {
                reason: WorkPacketRejection::UnsupportedFormat {
                    found: self.format_version,
                    expected: WORK_PACKET_FORMAT_VERSION,
                },
            });
        }
        if self.packet_version == 0 || self.instruction.trim().is_empty() {
            return Err(SupervisionError::InvalidValue {
                field: "workPacket".to_owned(),
                detail: "the packet version and owner instruction are required".to_owned(),
            });
        }
        if self.read_set_digest != read_set_digest(&self.target_read_set)? {
            return Err(SupervisionError::WorkPacketRejected {
                reason: WorkPacketRejection::Mismatch {
                    field: "readSetDigest".to_owned(),
                },
            });
        }
        let expected = self.compute_fingerprint()?;
        if self.fingerprint != expected {
            return Err(SupervisionError::WorkPacketRejected {
                reason: WorkPacketRejection::FingerprintMismatch,
            });
        }
        Ok(())
    }

    /// Verifies the packet and that every constraint matches the approved
    /// contract, target, and plan values.
    #[allow(clippy::too_many_arguments)]
    pub fn ensure_binding(
        &self,
        execution_scope: &ExecutionScope,
        condition_version: ConditionVersion,
        profile: ProfileBinding,
        consent: ConsentBinding,
        target: &TargetScope,
        budget: &BudgetPolicy,
    ) -> Result<(), SupervisionError> {
        self.verify()?;
        if self.project_id != target.project_id() {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "work packet".to_owned(),
                expected: target.project_id(),
                found: self.project_id,
            });
        }
        let mismatch = |field: &str| SupervisionError::WorkPacketRejected {
            reason: WorkPacketRejection::Mismatch {
                field: field.to_owned(),
            },
        };
        if execution_scope.project_id() != target.project_id() {
            return Err(mismatch("executionScope.projectId"));
        }
        if &self.execution_scope != execution_scope {
            return Err(mismatch("executionScope"));
        }
        if self.condition_version != condition_version {
            return Err(mismatch("conditionVersion"));
        }
        if self.profile != profile {
            return Err(mismatch("profile"));
        }
        if self.consent != consent {
            return Err(mismatch("consent"));
        }
        if self.target_version != target.version() {
            return Err(mismatch("targetVersion"));
        }
        if self.target_read_set != target.read_set() {
            return Err(mismatch("targetReadSet"));
        }
        if self.target_digest != target.snapshot_digest()? {
            return Err(mismatch("targetDigest"));
        }
        if self.budget != *budget {
            return Err(mismatch("budget"));
        }
        Ok(())
    }

    /// Whether two packets carry the same constraints (ignoring version and
    /// fingerprint).
    pub fn same_constraints(&self, other: &Self) -> bool {
        self.format_version == other.format_version
            && self.instruction == other.instruction
            && self.project_id == other.project_id
            && self.target_version == other.target_version
            && self.target_read_set == other.target_read_set
            && self.target_digest == other.target_digest
            && self.read_set_digest == other.read_set_digest
            && self.execution_scope == other.execution_scope
            && self.condition_version == other.condition_version
            && self.profile == other.profile
            && self.consent == other.consent
            && self.budget_policy_version == other.budget_policy_version
            && self.budget == other.budget
    }

    /// Exact initial-run text. It contains the owner instruction and the
    /// approved constraints; hosts must not replace it with a generic prompt.
    pub fn prompt(&self) -> String {
        let read_paths = join_paths(self.execution_scope.read_paths());
        let write_paths = join_paths(self.execution_scope.write_paths());
        let read_set = join_paths(&self.target_read_set);
        let shell = if self.execution_scope.allow_shell() {
            "allowed"
        } else {
            "not allowed"
        };
        let money = self.budget.money_cap().map_or_else(
            || "none".to_owned(),
            |cap| {
                format!(
                    "{} micro-dollars at {}",
                    cap.limit().micros(),
                    cap.price_version().as_str()
                )
            },
        );
        format!(
            "{instruction}\n\n\
             Immutable work packet (format {format}, version {version}, fingerprint {fingerprint}).\n\
             Approved constraints; do not change them:\n\
             - target version: {target}\n\
             - target snapshot: {target_digest}\n\
             - read set: {read_set}\n\
             - read paths: {read_paths}\n\
             - write paths: {write_paths}\n\
             - shell: {shell}\n\
             - condition version: {conditions}\n\
             - assessment profile: {profile} ({purpose})\n\
             - disclosure consent: {consent} version {consent_version} ({consent_purpose})\n\
             - budget policy version: {budget_version}\n\
             - budget: active seconds {active_seconds}, additional runs {additional_runs}, \
             money cap: {money}",
            instruction = self.instruction,
            format = self.format_version,
            version = self.packet_version,
            fingerprint = self.fingerprint,
            target = self.target_version.get(),
            target_digest = self.target_digest,
            read_set = read_set,
            read_paths = read_paths,
            write_paths = write_paths,
            shell = shell,
            conditions = self.condition_version.get(),
            profile = self.profile.profile_id(),
            purpose = self.profile.purpose().as_str(),
            consent = self.consent.consent_id(),
            consent_version = self.consent.version(),
            consent_purpose = self.consent.purpose().as_str(),
            budget_version = self.budget_policy_version,
            active_seconds = self.budget.active_seconds(),
            additional_runs = self.budget.additional_runs(),
            money = money,
        )
    }

    pub(crate) fn revised_conditions(
        &self,
        condition_version: ConditionVersion,
    ) -> Result<Self, SupervisionError> {
        self.revised(|packet| packet.condition_version = condition_version)
    }

    pub(crate) fn revised_profile(
        &self,
        profile: ProfileBinding,
    ) -> Result<Self, SupervisionError> {
        self.revised(|packet| packet.profile = profile)
    }

    pub(crate) fn revised_scope(
        &self,
        execution_scope: ExecutionScope,
    ) -> Result<Self, SupervisionError> {
        self.revised(|packet| packet.execution_scope = execution_scope)
    }

    pub(crate) fn revised_budget(
        &self,
        budget: BudgetPolicy,
        budget_policy_version: u64,
    ) -> Result<Self, SupervisionError> {
        self.revised(|packet| {
            packet.budget = budget;
            packet.budget_policy_version = budget_policy_version;
        })
    }

    fn revised(
        &self,
        update: impl FnOnce(&mut Self),
    ) -> Result<Self, SupervisionError> {
        let mut next = self.clone();
        next.packet_version = next.packet_version.saturating_add(1);
        update(&mut next);
        next.read_set_digest = read_set_digest(&next.target_read_set)?;
        next.fingerprint = next.compute_fingerprint()?;
        next.verify()?;
        Ok(next)
    }

    fn compute_fingerprint(&self) -> Result<ContentDigest, SupervisionError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Material<'a> {
            format_version: u32,
            packet_version: u64,
            instruction: &'a str,
            project_id: String,
            target_version: u64,
            target_read_set: &'a [String],
            target_digest: &'a ContentDigest,
            read_set_digest: &'a ContentDigest,
            execution_scope: &'a ExecutionScope,
            condition_version: u64,
            profile: ProfileBinding,
            consent: ConsentBinding,
            budget_policy_version: u64,
            budget: &'a BudgetPolicy,
        }

        let material = Material {
            format_version: self.format_version,
            packet_version: self.packet_version,
            instruction: &self.instruction,
            project_id: self.project_id.to_string(),
            target_version: self.target_version.get(),
            target_read_set: &self.target_read_set,
            target_digest: &self.target_digest,
            read_set_digest: &self.read_set_digest,
            execution_scope: &self.execution_scope,
            condition_version: self.condition_version.get(),
            profile: self.profile,
            consent: self.consent,
            budget_policy_version: self.budget_policy_version,
            budget: &self.budget,
        };
        let bytes =
            serde_json::to_vec(&material).map_err(|error| SupervisionError::InvalidValue {
                field: "workPacket.fingerprint".to_owned(),
                detail: format!("could not serialize the packet fingerprint material: {error}"),
            })?;
        Ok(ContentDigest::sha256(&bytes))
    }
}

/// Stable SHA-256 fingerprint of one read set.
///
/// Paths are sorted and deduplicated so the fingerprint describes the set, not
/// the enumeration order.
pub fn read_set_digest(paths: &[String]) -> Result<ContentDigest, SupervisionError> {
    let mut canonical = paths.iter().filter(|path| !path.trim().is_empty()).collect::<Vec<_>>();
    canonical.sort_unstable();
    canonical.dedup();
    let bytes = serde_json::to_vec(&canonical).map_err(|error| SupervisionError::InvalidValue {
        field: "workPacket.readSet".to_owned(),
        detail: format!("could not serialize the read-set fingerprint: {error}"),
    })?;
    Ok(ContentDigest::sha256(&bytes))
}

fn join_paths(paths: &[String]) -> String {
    if paths.is_empty() {
        "none".to_owned()
    } else {
        paths.join(", ")
    }
}
