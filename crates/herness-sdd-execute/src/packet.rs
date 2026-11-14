//! The immutable H4 Task packet: what every child of one Task receives.
//!
//! # Contents
//!
//! The packet is the *whole* context of one Task. It composes:
//!
//! 1. the exact Task body from the approved plan bytes;
//! 2. the verbatim `## Global Constraints` text of the approved plan;
//! 3. the applicable canonical-spec sections, each with its source alias, path,
//!    heading, and the snapshot text the human approved;
//! 4. prior interfaces, Rulings, and unresolved items of earlier Tasks;
//! 5. the approved scope (read paths, write paths, `allowShell`, HTML targets);
//! 6. the approved checks and conditions;
//! 7. the report requirements the child must satisfy; and
//! 8. the rule that the child performs no Git operation.
//!
//! It never contains the whole plan, another Task's body, or a diff. The plan is
//! represented by its path, revision, and digest only.
//!
//! # Determinism
//!
//! The same [`PacketInputs`] always produce the same bytes and the same
//! fingerprint. Every list is either carried in its approved order or sorted by
//! a stable key, and nothing is read from the clock, the environment, a random
//! source, or a map iteration.
//!
//! # Capacity
//!
//! The packet has explicit bounds: [`MAX_PACKET_SECTIONS`],
//! [`MAX_PACKET_SECTION_BYTES`], [`MAX_PACKET_CONTEXT_ENTRIES`], and
//! [`MAX_PACKET_BYTES`]. Exceeding any of them is a typed
//! [`PacketOutcome::HumanWait`] with reason [`PacketWaitReason::CapacityExceeded`].
//! The packet is never truncated: a child that received a silently shortened
//! Global Constraints or a dropped spec section would be working from different
//! conditions than the human approved.
//!
//! # First, continuation, and restore
//!
//! The packet value is immutable. H2's first run renders it with
//! [`TaskPacket::prompt`]; a continuation renders the same value plus its own
//! deficiency text, using the existing H2 mechanism (`WorkPacket::prompt` plus
//! the continuation suffix in `DesktopH1::continuation_input`), so the
//! constraints and the spec context are byte-identical across runs and only the
//! deficiency differs — this is exactly H2's own
//! `WorkPacket::replace_instruction` equivalence, where a replacement keeps every
//! other field and changes only the instruction slot. A restore re-uses the
//! identical value because it is rebuilt from the same approved plan revision and
//! the same stored prior state; [`TaskPacket::same_content`] proves equality and
//! [`TaskPacket::continuation_prompt`] builds the continuation from the same
//! bytes.

use std::collections::BTreeSet;

use herness_supervision::ExecutionScope;
use serde::{Deserialize, Serialize};

use crate::approval::{ApprovedCheck, ApprovedSpecRef, CommitPolicy, ConditionMode, TaskApproval};
use crate::error::SddExecutionError;
use crate::ids::{CommitSha, PlanRevision, RunInputRef, TaskRef};
use crate::plan::PlanPath;
use crate::report::{EvidenceField, MAX_REPORT_BYTES};
use crate::version::{PlanDigest, Sha256Digest};

/// Format version of the packet written by this build.
pub const TASK_PACKET_FORMAT_VERSION: u32 = 1;

/// Maximum applicable spec sections one packet carries.
pub const MAX_PACKET_SECTIONS: usize = 32;

/// Maximum bytes of one snapshot text carried by the packet.
pub const MAX_PACKET_SECTION_BYTES: usize = 256 * 1024;

/// Maximum prior-context entries (interfaces, Rulings, unresolved items) kept.
pub const MAX_PACKET_CONTEXT_ENTRIES: usize = 64;

/// Maximum rendered packet bytes.
///
/// One approved Task body plus its Global Constraints and the applied spec
/// sections fits comfortably below this. A larger packet is an explicit human
/// wait, never a truncation.
pub const MAX_PACKET_BYTES: usize = 1024 * 1024;

/// Maximum characters of one prior-context entry.
pub const MAX_CONTEXT_ENTRY_CHARS: usize = 2_000;

/// The child's rule about Git, stated verbatim in every packet.
pub const NO_GIT_RULE: &str = "Do not stage, commit, amend, reset, clean, switch branches, or rewrite history. The host owns the explicit-path stage, the repository hooks, and the commit. Do not claim a commit the host has not made. Do not push, merge, or publish.";

/// The compatibility report path of one Task, matching the pack's `.sdd` layout.
pub fn execution_report_path(task_number: u32) -> String {
    format!(".sdd/reports/task-{task_number}-report.md")
}

/// The required status words, stated verbatim in every packet.
pub const STATUS_RULE: &str = "End the report with exactly one status: DONE, BLOCKED, or NEEDS_CONTEXT. DONE alone is not completion; BLOCKED and NEEDS_CONTEXT stop and wait for a human decision, and must not be retried with the same prompt.";

/// The evidence rule, stated verbatim in every packet.
pub const EVIDENCE_RULE: &str = "For every approved check id, report all five evidence fields: Executor, Command, Actual result, Target change, and Scope. A missing field, a bare success claim, or stale evidence does not support completion.";

/// One applicable canonical-spec section and its approved snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PacketSpecSection {
    source: String,
    path: String,
    heading: String,
    digest: String,
    text: String,
}

impl PacketSpecSection {
    /// Creates one section.
    ///
    /// The text is the exact approved snapshot body of that heading. It must not
    /// be empty and must fit [`MAX_PACKET_SECTION_BYTES`].
    pub fn new(
        source: impl Into<String>,
        path: impl Into<String>,
        heading: impl Into<String>,
        digest: impl Into<String>,
        text: impl Into<String>,
    ) -> Result<Self, SddExecutionError> {
        let source = source.into();
        let path = path.into();
        let heading = heading.into();
        let text = text.into();
        if heading.trim().is_empty() {
            return Err(invalid(
                "packet.section.heading",
                "must name the applied spec heading",
            ));
        }
        if text.trim().is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "packet.section.text".to_owned(),
                detail: format!(
                    "section {heading:?} of {path:?} would be empty; a truncated or empty \
                     section is refused instead of being dropped silently"
                ),
            });
        }
        if text.len() > MAX_PACKET_SECTION_BYTES {
            return Err(SddExecutionError::InvalidValue {
                field: "packet.section.text".to_owned(),
                detail: format!(
                    "section {heading:?} of {path:?} is {} bytes; the maximum is \
                     {MAX_PACKET_SECTION_BYTES} and it is never truncated",
                    text.len()
                ),
            });
        }
        Ok(Self {
            source,
            path,
            heading,
            digest: digest.into(),
            text,
        })
    }

    /// `project` or a registered read-only alias.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Project-relative or alias-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Applied heading.
    pub fn heading(&self) -> &str {
        &self.heading
    }

    /// Digest of the exact approved snapshot bytes.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Exact snapshot body text.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// One prior-context entry carried into this Task.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PacketContextEntry {
    origin: String,
    text: String,
}

impl PacketContextEntry {
    /// Creates an entry.
    ///
    /// `origin` names where the entry came from (`Task 9`, `Ruling`, ...). The
    /// text is bounded and must not be empty.
    pub fn new(
        origin: impl Into<String>,
        text: impl Into<String>,
    ) -> Result<Self, SddExecutionError> {
        let origin = origin.into();
        let mut text = text.into();
        if text.trim().is_empty() {
            return Err(invalid("packet.context.text", "must not be empty"));
        }
        if text.chars().count() > MAX_CONTEXT_ENTRY_CHARS {
            return Err(SddExecutionError::InvalidValue {
                field: "packet.context.text".to_owned(),
                detail: format!(
                    "an entry from {origin:?} is longer than {MAX_CONTEXT_ENTRY_CHARS} \
                     characters; it is refused instead of being cut"
                ),
            });
        }
        text = text.trim().to_owned();
        Ok(Self { origin, text })
    }

    /// Where the entry came from.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The entry text.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// One earlier Task's verified result: what it committed and which runs
/// produced its evidence.
///
/// The packet carries this so a later child knows what already exists and does
/// not re-implement or re-derive it. Only references are carried, never a diff.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PacketPriorResult {
    task_number: u32,
    #[serde(default)]
    commit: Option<String>,
    #[serde(default)]
    evidence_runs: Vec<String>,
}

impl PacketPriorResult {
    /// Creates one earlier Task result.
    pub fn new(
        task_number: u32,
        commit: Option<CommitSha>,
        evidence_runs: Vec<RunInputRef>,
    ) -> Result<Self, SddExecutionError> {
        if task_number == 0 {
            return Err(invalid(
                "packet.priorResult.taskNumber",
                "Tasks start at one",
            ));
        }
        Ok(Self {
            task_number,
            commit: commit.map(|commit| commit.as_str().to_owned()),
            evidence_runs: evidence_runs
                .into_iter()
                .map(|run| match run.input_id() {
                    Some(input) => format!("{} / {}", run.run_id(), input),
                    None => run.run_id().to_string(),
                })
                .collect(),
        })
    }

    /// The earlier Task's number.
    pub const fn task_number(&self) -> u32 {
        self.task_number
    }

    /// Its host commit, when one was made.
    pub fn commit(&self) -> Option<&str> {
        self.commit.as_deref()
    }

    /// The H1 runs and inputs that produced its evidence.
    pub fn evidence_runs(&self) -> &[String] {
        &self.evidence_runs
    }
}

/// Prior-Task state one packet carries.
///
/// The lists are what an earlier Task handed forward: its public interfaces, its
/// reversible Rulings, the items it left unresolved, and its verified results.
/// They are accumulated by the host from earlier reports, so they are the same in
/// the first run, a continuation, and a restore.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PriorTaskContext {
    interfaces: Vec<PacketContextEntry>,
    rulings: Vec<PacketContextEntry>,
    unresolved: Vec<PacketContextEntry>,
    results: Vec<PacketPriorResult>,
}

impl PriorTaskContext {
    /// Creates the context from its lists.
    pub fn new(
        interfaces: Vec<PacketContextEntry>,
        rulings: Vec<PacketContextEntry>,
        unresolved: Vec<PacketContextEntry>,
    ) -> Result<Self, SddExecutionError> {
        Self::with_results(interfaces, rulings, unresolved, Vec::new())
    }

    /// Creates the context from its lists, including earlier Task results.
    pub fn with_results(
        interfaces: Vec<PacketContextEntry>,
        rulings: Vec<PacketContextEntry>,
        unresolved: Vec<PacketContextEntry>,
        results: Vec<PacketPriorResult>,
    ) -> Result<Self, SddExecutionError> {
        for (field, entries) in [
            ("packet.prior.interfaces", &interfaces),
            ("packet.prior.rulings", &rulings),
            ("packet.prior.unresolved", &unresolved),
        ] {
            if entries.len() > MAX_PACKET_CONTEXT_ENTRIES {
                return Err(SddExecutionError::InvalidValue {
                    field: field.to_owned(),
                    detail: format!(
                        "{} entries exceed the {MAX_PACKET_CONTEXT_ENTRIES} the packet carries",
                        entries.len()
                    ),
                });
            }
        }
        if results.len() > MAX_PACKET_CONTEXT_ENTRIES {
            return Err(SddExecutionError::InvalidValue {
                field: "packet.prior.results".to_owned(),
                detail: format!(
                    "{} results exceed the {MAX_PACKET_CONTEXT_ENTRIES} the packet carries",
                    results.len()
                ),
            });
        }
        Ok(Self {
            interfaces,
            rulings,
            unresolved,
            results,
        })
    }

    /// An empty context.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Earlier public interfaces.
    pub fn interfaces(&self) -> &[PacketContextEntry] {
        &self.interfaces
    }

    /// Earlier reversible Rulings.
    pub fn rulings(&self) -> &[PacketContextEntry] {
        &self.rulings
    }

    /// Items earlier Tasks left unresolved.
    pub fn unresolved(&self) -> &[PacketContextEntry] {
        &self.unresolved
    }

    /// Earlier Tasks' verified commits and evidence runs.
    pub fn results(&self) -> &[PacketPriorResult] {
        &self.results
    }

    /// Extends the context with one earlier Task's result, keeping it bounded.
    ///
    /// Adding an entry past [`MAX_PACKET_CONTEXT_ENTRIES`] is an explicit error
    /// rather than a silent drop.
    pub fn with_task(
        mut self,
        interfaces: Vec<PacketContextEntry>,
        rulings: Vec<PacketContextEntry>,
        unresolved: Vec<PacketContextEntry>,
    ) -> Result<Self, SddExecutionError> {
        for (field, target, extra) in [
            ("packet.prior.interfaces", &mut self.interfaces, interfaces),
            ("packet.prior.rulings", &mut self.rulings, rulings),
            ("packet.prior.unresolved", &mut self.unresolved, unresolved),
        ] {
            target.extend(extra);
            if target.len() > MAX_PACKET_CONTEXT_ENTRIES {
                return Err(SddExecutionError::InvalidValue {
                    field: field.to_owned(),
                    detail: format!(
                        "{} entries exceed the {MAX_PACKET_CONTEXT_ENTRIES} the packet carries; \
                         a human must consolidate them instead of dropping context",
                        target.len()
                    ),
                });
            }
        }
        Ok(self)
    }

    /// Extends the context with one earlier Task's verified result.
    pub fn with_result(mut self, result: PacketPriorResult) -> Result<Self, SddExecutionError> {
        self.results.push(result);
        if self.results.len() > MAX_PACKET_CONTEXT_ENTRIES {
            return Err(SddExecutionError::InvalidValue {
                field: "packet.prior.results".to_owned(),
                detail: format!(
                    "{} results exceed the {MAX_PACKET_CONTEXT_ENTRIES} the packet carries; \
                     a human must consolidate them instead of dropping context",
                    self.results.len()
                ),
            });
        }
        Ok(self)
    }

    /// Whether every list is empty.
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
            && self.rulings.is_empty()
            && self.unresolved.is_empty()
            && self.results.is_empty()
    }
}

/// The approved scope and plan identity one packet carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketScope {
    scope: ExecutionScope,
    html_targets: Vec<String>,
    commit_policy: CommitPolicy,
}

impl PacketScope {
    /// Creates the scope block.
    pub fn new(
        scope: ExecutionScope,
        html_targets: Vec<String>,
        commit_policy: CommitPolicy,
    ) -> Result<Self, SddExecutionError> {
        for target in &html_targets {
            crate::plan::validate_project_path("packet.htmlTargets", target)?;
        }
        Ok(Self {
            scope,
            html_targets,
            commit_policy,
        })
    }

    /// The H2-approved bounded scope.
    pub const fn scope(&self) -> &ExecutionScope {
        &self.scope
    }

    /// Explicit HTML targets.
    pub fn html_targets(&self) -> &[String] {
        &self.html_targets
    }

    /// Commit policy the Task was approved with.
    pub const fn commit_policy(&self) -> CommitPolicy {
        self.commit_policy
    }
}

/// Everything one packet is composed from.
///
/// The value is built from the approved plan revision, the approved Task, the
/// verified spec snapshots, and the earlier Tasks' stored results. It contains
/// no clock, environment, or random input, so the same value always produces the
/// same packet bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketInputs {
    task: TaskRef,
    title: String,
    body: String,
    plan_path: PlanPath,
    plan_revision: PlanRevision,
    plan_digest: PlanDigest,
    global_constraints: String,
    spec_refs: Vec<ApprovedSpecRef>,
    sections: Vec<PacketSpecSection>,
    prior: PriorTaskContext,
    scope: PacketScope,
    checks: Vec<ApprovedCheck>,
    conditions: Vec<crate::approval::ApprovedCondition>,
    report_path: String,
    writable_files: Vec<String>,
}

impl PacketInputs {
    /// Creates the inputs from approved values.
    ///
    /// `spec_refs` are the approved references the sections came from. They are
    /// required so the packet's spec-snapshot digest is the same composite the
    /// approved H2 owner launch binds, and so an approved reference with no
    /// section is refused instead of being silently dropped.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task: TaskRef,
        title: impl Into<String>,
        body: impl Into<String>,
        plan_path: PlanPath,
        plan_revision: PlanRevision,
        plan_digest: PlanDigest,
        global_constraints: impl Into<String>,
        spec_refs: Vec<ApprovedSpecRef>,
        sections: Vec<PacketSpecSection>,
        prior: PriorTaskContext,
        scope: PacketScope,
        checks: Vec<ApprovedCheck>,
        conditions: Vec<crate::approval::ApprovedCondition>,
        report_path: impl Into<String>,
    ) -> Result<Self, SddExecutionError> {
        let title = title.into();
        let body = body.into();
        let global_constraints = global_constraints.into();
        let report_path = report_path.into();
        if title.trim().is_empty() {
            return Err(invalid("packet.title", "must not be empty"));
        }
        if body.trim().is_empty() {
            return Err(invalid("packet.body", "must not be empty"));
        }
        if global_constraints.trim().is_empty() {
            return Err(invalid(
                "packet.globalConstraints",
                "the exact Global Constraints text is required; a packet without it is not a \
                 Task context",
            ));
        }
        if spec_refs.is_empty() {
            return Err(invalid(
                "packet.specRefs",
                "an approved Task always declares at least one spec reference",
            ));
        }
        for spec_ref in &spec_refs {
            if !sections.iter().any(|section| {
                section.source == spec_ref.source() && section.path == spec_ref.path()
            }) {
                return Err(invalid(
                    "packet.sections",
                    &format!(
                        "the approved reference {:?} {:?} has no section in the packet; an \
                         approved section is never dropped",
                        spec_ref.source(),
                        spec_ref.path()
                    ),
                ));
            }
        }
        if sections.len() > MAX_PACKET_SECTIONS {
            return Err(SddExecutionError::InvalidValue {
                field: "packet.sections".to_owned(),
                detail: format!(
                    "{} sections exceed the {MAX_PACKET_SECTIONS} the packet carries",
                    sections.len()
                ),
            });
        }
        if checks.is_empty() {
            return Err(invalid(
                "packet.checks",
                "an approved Task always has at least one check",
            ));
        }
        crate::plan::validate_project_path("packet.reportPath", &report_path)?;
        Ok(Self {
            task,
            title,
            body,
            plan_path,
            plan_revision,
            plan_digest,
            global_constraints,
            spec_refs,
            sections,
            prior,
            scope,
            checks,
            conditions,
            report_path,
            writable_files: Vec::new(),
        })
    }

    /// Records the project-relative files the Task must write.
    ///
    /// These are the approved deliverable paths, not the whole write scope. The
    /// packet lists them so the child knows what the host will commit.
    #[must_use]
    pub fn with_writable_files(mut self, files: Vec<String>) -> Self {
        self.writable_files = files;
        self
    }

    /// Builds the task approval's packet inputs from an approved Task.
    ///
    /// `specs` are the Task's approved spec references and `sections` their
    /// verified snapshot sections. They must agree, so an approved reference
    /// without a section is refused instead of being silently dropped.
    #[allow(clippy::too_many_arguments)]
    pub fn for_task(
        approval: &TaskApproval,
        plan_path: PlanPath,
        plan_revision: PlanRevision,
        plan_digest: PlanDigest,
        body: impl Into<String>,
        global_constraints: impl Into<String>,
        specs: Vec<ApprovedSpecRef>,
        sections: Vec<PacketSpecSection>,
        prior: PriorTaskContext,
        report_path: impl Into<String>,
    ) -> Result<Self, SddExecutionError> {
        let writable = approval
            .deliverables()
            .iter()
            .map(|deliverable| deliverable.path().to_owned())
            .collect();
        let scope = PacketScope::new(
            approval.scope().clone(),
            approval.html_targets().to_vec(),
            approval.commit_policy(),
        )?;
        let mut inputs = Self::new(
            approval.task(),
            approval.title(),
            body,
            plan_path,
            plan_revision,
            plan_digest,
            global_constraints,
            specs,
            sections,
            prior,
            scope,
            approval.checks().to_vec(),
            approval.conditions().to_vec(),
            report_path,
        )?;
        inputs.writable_files = writable;
        Ok(inputs)
    }

    /// Task identity.
    pub const fn task(&self) -> TaskRef {
        self.task
    }
}

/// One section of a verified snapshot: `(heading, digest, body)`.
pub type SnapshotSectionPart = (String, String, String);

/// One verified snapshot: `(source, path)` plus its sections.
type SnapshotEntry = (String, String, Vec<SnapshotSectionPart>);

/// The approved spec snapshots a packet needs, keyed by source and path.
///
/// The desktop adapter builds this from
/// [`VerifiedSpecSnapshot`](crate::import::VerifiedSpecSnapshot); this pure type
/// is what the packet reads so it needs no file system.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapshotSections {
    snapshots: Vec<SnapshotEntry>,
}

impl SnapshotSections {
    /// Creates an empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one verified snapshot: `(source, path)` plus
    /// `(heading, digest, body)` triples in declaration order.
    #[must_use]
    pub fn with_snapshot(
        mut self,
        source: impl Into<String>,
        path: impl Into<String>,
        sections: Vec<SnapshotSectionPart>,
    ) -> Self {
        self.snapshots.push((source.into(), path.into(), sections));
        self
    }

    /// Selects the applicable sections of `refs`.
    ///
    /// A reference whose snapshot is absent is an explicit error: the packet
    /// never invents context and never silently omits an approved section.
    pub fn select(
        &self,
        refs: &[ApprovedSpecRef],
    ) -> Result<Vec<PacketSpecSection>, SddExecutionError> {
        let mut sections = Vec::new();
        let mut seen = BTreeSet::new();
        for spec_ref in refs {
            let snapshot = self
                .snapshots
                .iter()
                .find(|(source, path, _)| source == spec_ref.source() && path == spec_ref.path())
                .ok_or_else(|| SddExecutionError::InvalidValue {
                    field: "packet.specRefs".to_owned(),
                    detail: format!(
                        "the approved reference {:?} {:?} has no verified snapshot to carry",
                        spec_ref.source(),
                        spec_ref.path()
                    ),
                })?;
            for heading in spec_ref.sections() {
                let Some((_, digest, body)) = snapshot
                    .2
                    .iter()
                    .find(|(candidate, _, _)| candidate == heading)
                else {
                    return Err(SddExecutionError::InvalidValue {
                        field: "packet.specRefs".to_owned(),
                        detail: format!(
                            "the approved section {heading:?} of {:?} is missing from the verified \
                             snapshot",
                            spec_ref.path()
                        ),
                    });
                };
                if digest != spec_ref.digest().as_str() {
                    return Err(SddExecutionError::InvalidValue {
                        field: "packet.specRefs".to_owned(),
                        detail: format!(
                            "the verified snapshot of {:?} is revision {digest}, but the approval \
                             bound {}; a later re-read must not replace the approved context",
                            spec_ref.path(),
                            spec_ref.digest()
                        ),
                    });
                }
                if !seen.insert((
                    spec_ref.source().to_owned(),
                    spec_ref.path().to_owned(),
                    heading.clone(),
                )) {
                    continue;
                }
                sections.push(PacketSpecSection::new(
                    spec_ref.source(),
                    spec_ref.path(),
                    heading.clone(),
                    digest.clone(),
                    body.clone(),
                )?);
                if sections.len() > MAX_PACKET_SECTIONS {
                    return Err(SddExecutionError::InvalidValue {
                        field: "packet.sections".to_owned(),
                        detail: format!(
                            "the applied sections exceed {MAX_PACKET_SECTIONS}; a human must \
                             narrow the spec references instead of dropping context"
                        ),
                    });
                }
            }
        }
        Ok(sections)
    }
}

/// Stable composite digest of the approved spec references of one Task.
///
/// The domain, the order, and the encoded fields are the input to the approved
/// H2 packet binding, so the owner launch and the Task packet agree on the same
/// bytes. It binds each approved `(source, path, file digest)` in approval order;
/// a change to any one reference changes the digest.
pub fn approved_spec_snapshot_digest(refs: &[ApprovedSpecRef]) -> Sha256Digest {
    let mut buffer = b"herness.h4.spec-snapshot\0".to_vec();
    for spec_ref in refs {
        buffer.extend_from_slice(spec_ref.source().as_bytes());
        buffer.push(0);
        buffer.extend_from_slice(spec_ref.path().as_bytes());
        buffer.push(0);
        buffer.extend_from_slice(spec_ref.digest().as_str().as_bytes());
        buffer.push(0);
    }
    Sha256Digest::sha256(&buffer)
}

/// The immutable Task packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPacket {
    inputs: PacketInputs,
    prompt: String,
    fingerprint: Sha256Digest,
}

impl TaskPacket {
    /// Composes the packet, or reports the explicit human wait.
    ///
    /// The outcome is `Ready` only when the whole context fits the packet's
    /// bounds. There is no partial packet.
    pub fn compose(inputs: PacketInputs) -> Result<PacketComposition, SddExecutionError> {
        let prompt = render(&inputs)?;
        if prompt.len() > MAX_PACKET_BYTES {
            return Ok(PacketComposition::TooLarge {
                limit: MAX_PACKET_BYTES,
                actual: prompt.len(),
                detail: format!(
                    "the packet for Task {} is {} bytes; the maximum is {MAX_PACKET_BYTES}",
                    inputs.task.number().get(),
                    prompt.len()
                ),
            });
        }
        let fingerprint = fingerprint_of(&prompt);
        Ok(PacketComposition::Ready(Box::new(Self {
            inputs,
            prompt,
            fingerprint,
        })))
    }

    /// Packet format written by this build.
    pub const fn format_version(&self) -> u32 {
        TASK_PACKET_FORMAT_VERSION
    }

    /// Task identity.
    pub const fn task(&self) -> TaskRef {
        self.inputs.task
    }

    /// Approved plan revision the packet was composed from.
    pub const fn plan_revision(&self) -> PlanRevision {
        self.inputs.plan_revision
    }

    /// Approved plan digest the packet was composed from.
    pub fn plan_digest(&self) -> &PlanDigest {
        &self.inputs.plan_digest
    }

    /// Applied spec sections in declaration order.
    pub fn sections(&self) -> &[PacketSpecSection] {
        &self.inputs.sections
    }

    /// Prior-Task context.
    pub fn prior(&self) -> &PriorTaskContext {
        &self.inputs.prior
    }

    /// Approved scope.
    pub fn scope(&self) -> &PacketScope {
        &self.inputs.scope
    }

    /// Approved checks.
    pub fn checks(&self) -> &[ApprovedCheck] {
        &self.inputs.checks
    }

    /// Report path the child writes.
    pub fn report_path(&self) -> &str {
        &self.inputs.report_path
    }

    /// SHA-256 fingerprint of the exact prompt bytes.
    ///
    /// It covers every value the child receives, so a stored packet that was
    /// altered fails comparison instead of starting different work.
    pub fn fingerprint(&self) -> &Sha256Digest {
        &self.fingerprint
    }

    /// The exact bytes the child receives on its first run, and the shared
    /// prefix of every continuation.
    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    /// The continuation input: the identical packet plus the current deficiency.
    ///
    /// H2 already renders a continuation as `packet.prompt()` plus a deficiency
    /// block; this is the same construction, so the constraints and spec context
    /// are byte-identical across runs and only the deficiency differs.
    pub fn continuation_prompt(&self, deficiency: &str) -> Result<String, SddExecutionError> {
        if deficiency.trim().is_empty() {
            return Err(invalid(
                "packet.continuation.deficiency",
                "a continuation must name what is still deficient",
            ));
        }
        Ok(format!(
            "{}\n\nCurrent deficiency:\n{}",
            self.prompt, deficiency
        ))
    }

    /// Whether two packets carry the same content for the child.
    ///
    /// Different packet *versions* of the same content are equivalent by this
    /// test, which is what the first/continuation/restore guarantee needs.
    pub fn same_content(&self, other: &Self) -> bool {
        self.prompt == other.prompt && self.fingerprint == other.fingerprint
    }

    /// Verifies the packet's own invariant before use.
    pub fn verify(&self) -> Result<(), SddExecutionError> {
        if self.fingerprint != fingerprint_of(&self.prompt) {
            return Err(SddExecutionError::InvalidSnapshot {
                field: "taskPacket.fingerprint".to_owned(),
                detail: "the stored fingerprint is not the digest of the packet bytes".to_owned(),
            });
        }
        Ok(())
    }

    /// The H2 packet binding of this packet: the exact Task body, the verbatim
    /// Global Constraints, and the composite of the approved spec references.
    ///
    /// The three digests are the same three values an approved H2 owner launch
    /// binds (`ApprovalDraft::packet_binding`), so the owner launch and the Task
    /// packet can never disagree about what the child received.
    pub fn binding_digests(&self) -> TaskPacketBinding {
        TaskPacketBinding {
            task_body: Sha256Digest::sha256(self.inputs.body.as_bytes()),
            global_constraints: Sha256Digest::sha256(self.inputs.global_constraints.as_bytes()),
            spec_snapshot: approved_spec_snapshot_digest(&self.inputs.spec_refs),
        }
    }

    /// The approved spec references the packet was composed from.
    pub fn spec_refs(&self) -> &[ApprovedSpecRef] {
        &self.inputs.spec_refs
    }
}

/// The three digests an H2 [`H4PacketBinding`](herness_supervision::H4PacketBinding)
/// is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPacketBinding {
    task_body: Sha256Digest,
    global_constraints: Sha256Digest,
    spec_snapshot: Sha256Digest,
}

impl TaskPacketBinding {
    /// Digest of the exact Task body.
    pub fn task_body(&self) -> &Sha256Digest {
        &self.task_body
    }

    /// Digest of the verbatim Global Constraints text.
    pub fn global_constraints(&self) -> &Sha256Digest {
        &self.global_constraints
    }

    /// Digest of the applied spec sections.
    pub fn spec_snapshot(&self) -> &Sha256Digest {
        &self.spec_snapshot
    }
}

/// The result of composing a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketComposition {
    /// The whole context fits and is immutable.
    Ready(Box<TaskPacket>),
    /// The context does not fit. A human must reduce the approved scope; the
    /// packet is never truncated.
    TooLarge {
        /// Accepted bytes.
        limit: usize,
        /// Observed bytes.
        actual: usize,
        /// Non-secret explanation.
        detail: String,
    },
}

impl PacketComposition {
    /// The packet, when it fits.
    pub fn packet(&self) -> Option<&TaskPacket> {
        match self {
            Self::Ready(packet) => Some(packet),
            Self::TooLarge { .. } => None,
        }
    }

    /// Converts the capacity shortage into the typed human-wait outcome.
    pub fn into_outcome(self) -> PacketOutcome {
        match self {
            Self::Ready(packet) => PacketOutcome::Ready(packet),
            Self::TooLarge { detail, .. } => PacketOutcome::HumanWait {
                reason: PacketWaitReason::CapacityExceeded,
                detail,
            },
        }
    }
}

/// Why a packet cannot be dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PacketWaitReason {
    /// The context does not fit the packet's bounds.
    CapacityExceeded,
}

impl PacketWaitReason {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapacityExceeded => "capacity_exceeded",
        }
    }

    /// The stop reason the coordinator records.
    pub const fn stop_reason(self) -> crate::state::StopReason {
        crate::state::StopReason::HumanDecisionRequired
    }

    /// The human action the coordinator requires.
    pub const fn human_action(self) -> crate::state::HumanAction {
        crate::state::HumanAction::ResolveHumanDecision
    }
}

/// The dispatch decision of one packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketOutcome {
    /// The child may be started with this exact immutable input.
    Ready(Box<TaskPacket>),
    /// A human must decide before any child starts.
    HumanWait {
        /// Why the wait is required.
        reason: PacketWaitReason,
        /// Non-secret explanation naming what does not fit.
        detail: String,
    },
}

impl PacketOutcome {
    /// Whether a child may start.
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }
}

/// One earlier Task's handoff, as the host stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskHandoff {
    task: TaskRef,
    interfaces: Vec<PacketContextEntry>,
    rulings: Vec<PacketContextEntry>,
    unresolved: Vec<PacketContextEntry>,
    commit: Option<CommitSha>,
    evidence_runs: Vec<RunInputRef>,
}

impl TaskHandoff {
    /// Creates one Task's handoff.
    pub fn new(
        task: TaskRef,
        interfaces: Vec<PacketContextEntry>,
        rulings: Vec<PacketContextEntry>,
        unresolved: Vec<PacketContextEntry>,
        commit: Option<CommitSha>,
        evidence_runs: Vec<RunInputRef>,
    ) -> Self {
        Self {
            task,
            interfaces,
            rulings,
            unresolved,
            commit,
            evidence_runs,
        }
    }

    /// The Task this handoff belongs to.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Its public interfaces.
    pub fn interfaces(&self) -> &[PacketContextEntry] {
        &self.interfaces
    }

    /// Its reversible Rulings.
    pub fn rulings(&self) -> &[PacketContextEntry] {
        &self.rulings
    }

    /// What it left unresolved.
    pub fn unresolved(&self) -> &[PacketContextEntry] {
        &self.unresolved
    }

    /// Its host commit, when one was made.
    pub fn commit(&self) -> Option<&CommitSha> {
        self.commit.as_ref()
    }

    /// The H1 runs that produced its evidence.
    pub fn evidence_runs(&self) -> &[RunInputRef] {
        &self.evidence_runs
    }

    /// This handoff as the reference entry a later packet carries.
    pub fn prior_result(
        &self,
        task_number: u32,
    ) -> Result<Option<PacketPriorResult>, SddExecutionError> {
        if task_number != self.task.number().get() {
            return Ok(None);
        }
        Ok(Some(PacketPriorResult::new(
            task_number,
            self.commit.clone(),
            self.evidence_runs.clone(),
        )?))
    }
}

/// Accumulates the prior context for one Task from the earlier handoffs.
///
/// Only handoffs of Tasks numbered before `task` are included, in Task order, so
/// a Task never sees its own or a later Task's result. Rulings are always
/// carried forward: they are the reversible decisions the next child must
/// respect.
pub fn prior_context_for(
    task: TaskRef,
    handoffs: &[TaskHandoff],
) -> Result<PriorTaskContext, SddExecutionError> {
    let mut ordered = handoffs
        .iter()
        .filter(|handoff| handoff.task().number() < task.number())
        .collect::<Vec<_>>();
    ordered.sort_by_key(|handoff| handoff.task().number());
    let mut prior = PriorTaskContext::empty();
    for handoff in ordered {
        let number = handoff.task().number().get();
        prior = prior.with_task(
            handoff.interfaces.clone(),
            handoff.rulings.clone(),
            handoff.unresolved.clone(),
        )?;
        if let Some(result) = handoff.prior_result(number)? {
            prior = prior.with_result(result)?;
        }
    }
    Ok(prior)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render(inputs: &PacketInputs) -> Result<String, SddExecutionError> {
    let mut out = String::with_capacity(4 * 1024);
    out.push_str("# H4 Task packet\n\n");
    out.push_str(&format!(
        "Task {}: {}\n\n",
        inputs.task.number().get(),
        inputs.title
    ));
    out.push_str("The packet is the whole context of this Task. Treat it as the approved brief. Do not pull in the rest of the plan, an earlier Task's body, or a past diff. If the context is not enough, report NEEDS_CONTEXT instead of guessing.\n\n");

    out.push_str("## Task body (exact)\n\n");
    out.push_str(inputs.body.trim_end());
    out.push_str("\n\n");

    out.push_str("## Global Constraints (exact)\n\n");
    out.push_str(inputs.global_constraints.trim_end());
    out.push_str("\n\n");

    out.push_str("## Canonical spec sections (approved snapshot)\n\n");
    out.push_str(&format!(
        "Plan: {} (revision {}, digest {}). The plan is referenced, not pasted.\n\n",
        inputs.plan_path.as_str(),
        inputs.plan_revision.get(),
        inputs.plan_digest
    ));
    if inputs.sections.is_empty() {
        out.push_str("No spec section was applied to this Task.\n\n");
    } else {
        for section in &inputs.sections {
            out.push_str(&format!(
                "### {} — {} ({})\n\n",
                section.path, section.heading, section.source
            ));
            out.push_str(&format!("Snapshot digest: {}\n\n", section.digest));
            out.push_str(section.text.trim_end());
            out.push_str("\n\n");
        }
    }

    out.push_str("## Prior decisions and interfaces\n\n");
    out.push_str(&context_block(
        "Interfaces from earlier Tasks",
        inputs.prior.interfaces(),
    ));
    out.push_str(&context_block(
        "Rulings retained for later Tasks",
        inputs.prior.rulings(),
    ));
    out.push_str(&context_block(
        "Unresolved items from earlier Tasks",
        inputs.prior.unresolved(),
    ));
    out.push_str(&results_block(inputs.prior.results()));

    out.push_str("## Approved scope\n\n");
    out.push_str(&format!(
        "- read paths: {}\n",
        join_or_none(inputs.scope.scope.read_paths())
    ));
    out.push_str(&format!(
        "- write paths: {}\n",
        join_or_none(inputs.scope.scope.write_paths())
    ));
    out.push_str(&format!(
        "- shell: {}\n",
        if inputs.scope.scope.allow_shell() {
            "allowed"
        } else {
            "not allowed"
        }
    ));
    out.push_str(&format!(
        "- HTML targets: {}\n",
        join_or_none(&inputs.scope.html_targets)
    ));
    out.push_str(&format!(
        "- commit policy: {}\n",
        inputs.scope.commit_policy.as_str()
    ));
    if !inputs.writable_files.is_empty() {
        out.push_str(&format!(
            "- files the host will commit: {}\n",
            inputs.writable_files.join(", ")
        ));
    }
    out.push('\n');

    out.push_str("## Approved conditions and checks\n\n");
    for condition in &inputs.conditions {
        out.push_str(&format!(
            "- condition {} ({}): {} — rubric: {}\n",
            condition.id(),
            mode_label(condition.mode()),
            condition.title(),
            condition.rubric()
        ));
    }
    for check in &inputs.checks {
        out.push_str(&format!(
            "- check {} for condition {}: {} (cwd {}, timeout {}s, inputs {})\n",
            check.id(),
            check.condition_id(),
            check.description(),
            check.cwd(),
            check.timeout_seconds(),
            join_or_none(check.input_paths())
        ));
    }
    out.push('\n');

    out.push_str("## Report requirements\n\n");
    out.push_str(&format!(
        "Write the report to {}. It must contain:\n\n",
        inputs.report_path
    ));
    out.push_str(&format!("- {STATUS_RULE}\n"));
    out.push_str("- Delivery: the deliverables, the files changed, and the unconfirmed scope.\n");
    out.push_str(&format!("- {EVIDENCE_RULE}\n"));
    out.push_str("- Canonical spec reflection: `Updated: none`, or the canonical spec path that was updated and why.\n");
    out.push_str("- Decisions that affect later phases, and reversible Rulings in the form `Ruling: <decision> — <why> — <cost if wrong>`.\n");
    out.push_str(
        "- Important unagreed items that need a human decision. Do not decide them yourself.\n",
    );
    out.push('\n');

    out.push_str("## Git\n\n");
    out.push_str(NO_GIT_RULE);
    out.push_str("\n\n");

    out.push_str(&format!(
        "Packet format {} (the fingerprint is carried beside these bytes, not inside them).\n",
        TASK_PACKET_FORMAT_VERSION
    ));
    Ok(out)
}

fn context_block(title: &str, entries: &[PacketContextEntry]) -> String {
    if entries.is_empty() {
        return format!("{title}: none.\n\n");
    }
    let mut out = format!("{title}:\n");
    for entry in entries {
        out.push_str(&format!("- [{}] {}\n", entry.origin, entry.text));
    }
    out.push('\n');
    out
}

fn results_block(results: &[PacketPriorResult]) -> String {
    if results.is_empty() {
        return "Verified results of earlier Tasks: none.\n\n".to_owned();
    }
    let mut out = String::from("Verified results of earlier Tasks (references only, no diff):\n");
    for result in results {
        let commit = result.commit().unwrap_or("no_change, no commit");
        let runs = if result.evidence_runs.is_empty() {
            "no recorded evidence run".to_owned()
        } else {
            result.evidence_runs.join(", ")
        };
        out.push_str(&format!(
            "- Task {}: commit {commit}; evidence runs {runs}\n",
            result.task_number()
        ));
    }
    out.push('\n');
    out
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(", ")
    }
}

fn mode_label(mode: ConditionMode) -> &'static str {
    match mode {
        ConditionMode::Checks => "checks",
        ConditionMode::Assessment => "assessment",
    }
}

fn invalid(field: &str, detail: &str) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.to_owned(),
    }
}

fn fingerprint_of(prompt: &str) -> Sha256Digest {
    let mut buffer = b"herness.h4.task-packet\0".to_vec();
    buffer.extend_from_slice(prompt.as_bytes());
    Sha256Digest::sha256(&buffer)
}

// ---------------------------------------------------------------------------
// Report-requirement helpers
// ---------------------------------------------------------------------------

/// The evidence fields the report requirement names.
pub fn required_evidence_fields() -> [EvidenceField; 5] {
    EvidenceField::REQUIRED
}

/// The number of report bytes the packet assumes the child can write.
///
/// The packet states the requirement; the reader enforces
/// [`MAX_REPORT_BYTES`]. Exposing it here keeps the two numbers one decision.
pub const fn report_byte_limit() -> usize {
    MAX_REPORT_BYTES
}
