//! The implementer report model, its parser, and the completion interpretation.
//!
//! Every H4 Task child writes one report file. H4 owns the requirements that
//! report must satisfy (the packet states them), and this module is the only
//! place that reads it back.
//!
//! # What the report must carry
//!
//! * a status of `DONE`, `BLOCKED`, or `NEEDS_CONTEXT`;
//! * the deliverables;
//! * one evidence block per approved check id, each carrying the five fields of
//!   the shared verification contract — executor, exact command, actual result,
//!   target change, and verification scope;
//! * the canonical-spec reflection status (`none`, or the updated path);
//! * decisions that affect later phases;
//! * reversible Rulings in the pack's `Ruling: <decision> — <why> — <cost if
//!   wrong>` form;
//! * important unagreed items that need a human;
//! * the unconfirmed scope.
//!
//! # What the interpretation refuses to do
//!
//! * `DONE` alone is never completion. A report is `Complete` only when every
//!   required check has all five evidence fields, the required deliverables and
//!   the spec reflection are present, no important unagreed item is open, and
//!   the child did not claim a commit.
//! * A missing evidence field is `Incomplete` with the exact gap, never a
//!   silent acceptance.
//! * `BLOCKED`, `NEEDS_CONTEXT`, an important unagreed item, or a commit claim
//!   is a human wait; the host never advances through it.
//! * An absent, empty, or unparseable report is not `DONE`.
//! * Prose that looks like an instruction is not followed: only labelled fields
//!   inside the named sections are read, and a `Ruling:` line outside the
//!   Rulings section is never turned into a Ruling.
//!
//! Even a `Complete` report only satisfies the report side of Task completion.
//! H2 conditions, the H3 barrier, the host commit, and the durable write remain
//! separate host decisions.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::state::{HumanAction, StopReason};

/// Maximum bytes of one report file H4 reads.
///
/// A larger report is refused explicitly instead of being parsed from a
/// truncated read. The child can split a genuinely huge report; H4 never
/// silently drops its tail.
pub const MAX_REPORT_BYTES: usize = 512 * 1024;

/// Maximum evidence blocks one report may carry.
pub const MAX_REPORT_EVIDENCE_BLOCKS: usize = 64;

/// Maximum bullets H4 keeps from one list section.
pub const MAX_REPORT_LIST_ENTRIES: usize = 128;

/// One report status. There is no other status; an unknown word is a parse
/// error, not a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// The child claims the work is done. Not completion by itself.
    Done,
    /// The child cannot proceed without a decision or a change it may not make.
    Blocked,
    /// The child needs context it does not have.
    NeedsContext,
}

impl ReportStatus {
    /// Every status.
    pub const ALL: [Self; 3] = [Self::Done, Self::Blocked, Self::NeedsContext];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Done => "DONE",
            Self::Blocked => "BLOCKED",
            Self::NeedsContext => "NEEDS_CONTEXT",
        }
    }

    /// Parses a status word. An unknown word returns `None`.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim().trim_matches(|character: char| {
            character.is_whitespace() || matches!(character, '*' | '`' | '.' | ':' | '-')
        });
        Self::ALL
            .into_iter()
            .find(|status| status.as_str().eq_ignore_ascii_case(value))
    }
}

impl fmt::Display for ReportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One of the five evidence fields of the shared verification contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceField {
    /// Who or what ran the check.
    Executor,
    /// The exact command or equivalent action.
    Command,
    /// The actual output, exit status, or observed result.
    ActualResult,
    /// The commit, revision, files, or diff the result covers.
    TargetChange,
    /// What the check covers and what it does not.
    Scope,
}

impl EvidenceField {
    /// The five required fields in report order.
    pub const REQUIRED: [Self; 5] = [
        Self::Executor,
        Self::Command,
        Self::ActualResult,
        Self::TargetChange,
        Self::Scope,
    ];

    /// Stable label used in the report and in packet requirements.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Executor => "Executor",
            Self::Command => "Command",
            Self::ActualResult => "Actual result",
            Self::TargetChange => "Target change",
            Self::Scope => "Scope",
        }
    }

    /// Normalized report label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Executor => "executor",
            Self::Command => "command",
            Self::ActualResult => "actual result",
            Self::TargetChange => "target change",
            Self::Scope => "scope",
        }
    }

    /// Maps a normalized report label onto a field.
    ///
    /// The aliases exist because the shared verification skill names the item
    /// "actual result" while older reports say "result" or "output". No other
    /// word is guessed into a field.
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "executor" | "who ran" => Some(Self::Executor),
            "command" | "exact command" => Some(Self::Command),
            "actual result" | "result" | "output" | "actual output" => Some(Self::ActualResult),
            "target change" | "target" | "target revision" => Some(Self::TargetChange),
            "scope" | "verification scope" | "coverage" => Some(Self::Scope),
            _ => None,
        }
    }
}

impl fmt::Display for EvidenceField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One labelled value inside one evidence block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceItem {
    field: EvidenceField,
    text: String,
}

impl EvidenceItem {
    /// Creates an evidence item. The text must not be empty.
    pub fn new(field: EvidenceField, text: impl Into<String>) -> Result<Self, ReportParseError> {
        let text = text.into();
        if text.trim().is_empty() {
            return Err(ReportParseError::InvalidField {
                field: field.as_str().to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        Ok(Self { field, text })
    }

    /// Which field this item fills.
    pub const fn field(&self) -> EvidenceField {
        self.field
    }

    /// Verbatim value.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// The evidence of one approved check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckEvidence {
    check: String,
    title: String,
    items: Vec<EvidenceItem>,
}

impl CheckEvidence {
    /// Creates one evidence block. The check id must not be empty.
    pub fn new(
        check: impl Into<String>,
        title: impl Into<String>,
        items: Vec<EvidenceItem>,
    ) -> Result<Self, ReportParseError> {
        let check = check.into();
        if check.trim().is_empty() {
            return Err(ReportParseError::InvalidField {
                field: "Check".to_owned(),
                detail: "an evidence block must name the approved check id".to_owned(),
            });
        }
        Ok(Self {
            check: check.trim().to_owned(),
            title: title.into(),
            items,
        })
    }

    /// Approved check id this block evidences.
    pub fn check(&self) -> &str {
        &self.check
    }

    /// Free-text title from the block heading.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The fields that are present.
    pub fn items(&self) -> &[EvidenceItem] {
        &self.items
    }

    /// Looks up one field.
    pub fn item(&self, field: EvidenceField) -> Option<&EvidenceItem> {
        self.items.iter().find(|item| item.field == field)
    }

    /// The five fields this block is missing, in contract order.
    pub fn missing_fields(&self) -> Vec<EvidenceField> {
        EvidenceField::REQUIRED
            .into_iter()
            .filter(|field| self.item(*field).is_none())
            .collect()
    }
}

/// One reversible decision recorded for later packets.
///
/// The pack ledger form is `Ruling: <decision> — <why> — <cost if wrong>`.
/// A Ruling is reversible by construction; an important unagreed decision is
/// not a Ruling and must go to a human instead.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ruling {
    decision: String,
    why: String,
    cost_if_wrong: String,
}

impl Ruling {
    /// Creates a Ruling from its three parts.
    pub fn new(
        decision: impl Into<String>,
        why: impl Into<String>,
        cost_if_wrong: impl Into<String>,
    ) -> Result<Self, ReportParseError> {
        let decision = decision.into();
        let why = why.into();
        let cost_if_wrong = cost_if_wrong.into();
        for (field, value) in [
            ("decision", &decision),
            ("why", &why),
            ("cost if wrong", &cost_if_wrong),
        ] {
            if value.trim().is_empty() {
                return Err(ReportParseError::InvalidRuling {
                    line: format!("the Ruling {field} is empty"),
                });
            }
        }
        Ok(Self {
            decision: decision.trim().to_owned(),
            why: why.trim().to_owned(),
            cost_if_wrong: cost_if_wrong.trim().to_owned(),
        })
    }

    /// The decision taken.
    pub fn decision(&self) -> &str {
        &self.decision
    }

    /// Why it was taken.
    pub fn why(&self) -> &str {
        &self.why
    }

    /// What it costs if the decision is wrong.
    pub fn cost_if_wrong(&self) -> &str {
        &self.cost_if_wrong
    }

    /// The pack ledger line for this Ruling.
    pub fn ledger_line(&self) -> String {
        format!(
            "Ruling: {} — {} — {}",
            self.decision, self.why, self.cost_if_wrong
        )
    }

    /// Parses one `Ruling:` line.
    ///
    /// The three parts are separated by an em dash or a double hyphen. A line
    /// with a missing part is refused instead of being partially recorded.
    pub fn parse(line: &str) -> Result<Self, ReportParseError> {
        let trimmed = line.trim();
        let trimmed = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
            .or_else(|| trimmed.strip_prefix("+ "))
            .unwrap_or(trimmed)
            .trim();
        let body = match strip_label(trimmed, "ruling") {
            Some(body) => body,
            None => {
                return Err(ReportParseError::InvalidRuling {
                    line: "a Ruling line must start with 'Ruling:'".to_owned(),
                });
            }
        };
        let parts = split_ruling(body);
        if parts.len() != 3 {
            return Err(ReportParseError::InvalidRuling {
                line: format!(
                    "expected 'Ruling: <decision> — <why> — <cost if wrong>', found {} part(s)",
                    parts.len()
                ),
            });
        }
        Self::new(parts[0], parts[1], parts[2])
    }
}

fn split_ruling(body: &str) -> Vec<&str> {
    // The pack ledger uses an em dash. Reports are hand-written, so a spaced
    // ASCII hyphen or a spaced double hyphen is accepted as the same separator.
    // A bare hyphen is not, because decisions legitimately contain one.
    let separator = if body.contains('—') {
        '—'
    } else if body.contains(" -- ") {
        return body.split(" -- ").map(str::trim).collect();
    } else {
        '-'
    };
    if separator == '-' {
        body.split(" - ").map(str::trim).collect()
    } else {
        body.split(separator).map(str::trim).collect()
    }
}

/// How the canonical spec relates to this Task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecReflection {
    /// The canonical spec did not change.
    None {
        /// Optional explanation after `none`.
        detail: Option<String>,
    },
    /// The canonical spec was updated at `path`.
    Updated {
        /// Project-relative spec path.
        path: String,
        /// Optional explanation.
        detail: Option<String>,
    },
}

impl SpecReflection {
    /// Whether the spec was updated.
    pub const fn is_updated(&self) -> bool {
        matches!(self, Self::Updated { .. })
    }

    /// The updated path, when the spec changed.
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::None { .. } => None,
            Self::Updated { path, .. } => Some(path),
        }
    }
}

/// The parsed report file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    status: ReportStatus,
    deliverables: Vec<String>,
    evidence: Vec<CheckEvidence>,
    spec_reflection: SpecReflection,
    spec_reflection_present: bool,
    decisions: Vec<String>,
    rulings: Vec<Ruling>,
    unagreed: Vec<String>,
    unconfirmed: Vec<String>,
    files_changed: Vec<String>,
    commit_claims: Vec<String>,
}

impl Report {
    /// The report status.
    pub const fn status(&self) -> ReportStatus {
        self.status
    }

    /// Reported deliverables in declaration order.
    pub fn deliverables(&self) -> &[String] {
        &self.deliverables
    }

    /// One evidence block per approved check.
    pub fn evidence(&self) -> &[CheckEvidence] {
        &self.evidence
    }

    /// Canonical-spec reflection status.
    pub const fn spec_reflection(&self) -> &SpecReflection {
        &self.spec_reflection
    }

    /// Decisions that affect later phases.
    pub fn decisions(&self) -> &[String] {
        &self.decisions
    }

    /// Reversible Rulings retained for later packets.
    pub fn rulings(&self) -> &[Ruling] {
        &self.rulings
    }

    /// Important unagreed items that need a human decision.
    pub fn unagreed(&self) -> &[String] {
        &self.unagreed
    }

    /// Unconfirmed scope carried forward as unresolved items.
    pub fn unconfirmed(&self) -> &[String] {
        &self.unconfirmed
    }

    /// Files the child reports it changed.
    pub fn files_changed(&self) -> &[String] {
        &self.files_changed
    }

    /// Commit claims found in the report.
    ///
    /// The child has no Git responsibility, so any claim is a contradiction the
    /// host must resolve with a human instead of believing.
    pub fn commit_claims(&self) -> &[String] {
        &self.commit_claims
    }

    /// Parses one report file.
    ///
    /// An empty report, a report without a status, an unknown status, or a
    /// malformed Ruling is an explicit parse failure. Nothing is defaulted and
    /// no prose is guessed into a field.
    pub fn parse(text: &str) -> Result<Self, ReportParseError> {
        if text.len() > MAX_REPORT_BYTES {
            return Err(ReportParseError::TooLarge {
                limit: MAX_REPORT_BYTES,
                actual: text.len(),
            });
        }
        if text.trim().is_empty() {
            return Err(ReportParseError::Empty);
        }
        let text = text.replace("\r\n", "\n");
        let sections = scan(&text);
        ensure_unique_sections(&sections)?;

        let status = parse_status(&sections)?;
        let deliverables = list_section(&sections, &["deliverables"]);
        let decisions = list_section(
            &sections,
            &[
                "decisions that affect later phases",
                "decisions affecting later phases",
                "decisions",
                "handoff decisions",
            ],
        );
        let unagreed = list_section(
            &sections,
            &[
                "important unagreed items",
                "unagreed items",
                "human decisions required",
            ],
        );
        let unconfirmed = list_section(
            &sections,
            &["unconfirmed scope", "unconfirmed", "limitations"],
        );
        let files_changed = list_section(&sections, &["files changed", "changed files"]);
        let rules = list_section(&sections, &["rulings", "ruling"]);
        let mut rulings = Vec::with_capacity(rules.len());
        for line in rules {
            rulings.push(Ruling::parse(&line)?);
        }
        let spec_reflection = parse_spec_reflection(&sections)?;
        let spec_reflection_present = spec_reflection.is_some();
        let spec_reflection = spec_reflection.unwrap_or(SpecReflection::None { detail: None });
        let evidence = parse_evidence(&sections)?;
        let commit_claims = commit_claims(&text);
        Ok(Self {
            status,
            deliverables,
            evidence,
            spec_reflection,
            spec_reflection_present,
            decisions,
            rulings,
            unagreed,
            unconfirmed,
            files_changed,
            commit_claims,
        })
    }

    /// Interprets the report against the approved Task's expectations.
    pub fn interpret(&self, expectations: &ReportExpectations) -> ReportOutcome {
        if self.status == ReportStatus::Blocked {
            return ReportOutcome::HumanWait {
                reason: ReportWaitReason::Blocked,
                report: self.clone(),
            };
        }
        if self.status == ReportStatus::NeedsContext {
            return ReportOutcome::HumanWait {
                reason: ReportWaitReason::NeedsContext,
                report: self.clone(),
            };
        }
        if !self.unagreed.is_empty() {
            return ReportOutcome::HumanWait {
                reason: ReportWaitReason::ImportantUnagreed,
                report: self.clone(),
            };
        }
        if !self.commit_claims.is_empty() {
            return ReportOutcome::HumanWait {
                reason: ReportWaitReason::ChildClaimedCommit,
                report: self.clone(),
            };
        }

        let mut gaps = Vec::new();
        for required in &expectations.required_checks {
            let Some(block) = self
                .evidence
                .iter()
                .find(|block| block.check() == required.as_str())
            else {
                gaps.push(ReportGap::MissingCheck {
                    check: required.clone(),
                });
                continue;
            };
            for field in block.missing_fields() {
                gaps.push(ReportGap::MissingEvidenceField {
                    check: required.clone(),
                    field,
                });
            }
        }
        if expectations.require_deliverables && self.deliverables.is_empty() {
            gaps.push(ReportGap::MissingDeliverables);
        }
        for required in &expectations.required_deliverables {
            if !self
                .deliverables
                .iter()
                .any(|line| line.contains(required.as_str()))
            {
                gaps.push(ReportGap::MissingDeliverable {
                    path: required.clone(),
                });
            }
        }
        if expectations.require_spec_reflection && self.spec_reflection_is_missing() {
            gaps.push(ReportGap::MissingSpecReflection);
        }
        if gaps.is_empty() {
            ReportOutcome::Complete(Box::new(self.clone()))
        } else {
            ReportOutcome::Incomplete {
                gaps,
                report: self.clone(),
            }
        }
    }

    /// A report without a spec-reflection section.
    fn spec_reflection_is_missing(&self) -> bool {
        !self.spec_reflection_present
    }
}

/// The expectations one Task's approval places on the report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReportExpectations {
    required_checks: Vec<String>,
    required_deliverables: Vec<String>,
    require_deliverables: bool,
    require_spec_reflection: bool,
}

impl ReportExpectations {
    /// Builds the expectations of one approved Task.
    pub fn for_task(task: &crate::approval::TaskApproval) -> Self {
        let mut required_checks = BTreeSet::new();
        for check in task.checks() {
            required_checks.insert(check.id().to_owned());
        }
        let required_deliverables = task
            .deliverables()
            .iter()
            .map(|deliverable| deliverable.path().to_owned())
            .collect::<Vec<_>>();
        Self {
            required_checks: required_checks.into_iter().collect(),
            require_deliverables: !required_deliverables.is_empty(),
            required_deliverables,
            require_spec_reflection: true,
        }
    }

    /// Explicit expectations.
    pub fn new(
        required_checks: Vec<String>,
        required_deliverables: Vec<String>,
        require_spec_reflection: bool,
    ) -> Self {
        Self {
            require_deliverables: !required_deliverables.is_empty(),
            required_checks,
            required_deliverables,
            require_spec_reflection,
        }
    }

    /// Approved check ids that need evidence.
    pub fn required_checks(&self) -> &[String] {
        &self.required_checks
    }

    /// Approved deliverable paths that must be reported.
    pub fn required_deliverables(&self) -> &[String] {
        &self.required_deliverables
    }

    /// Whether any deliverable must be reported.
    pub const fn require_deliverables(&self) -> bool {
        self.require_deliverables
    }

    /// Whether the spec reflection is required.
    pub const fn require_spec_reflection(&self) -> bool {
        self.require_spec_reflection
    }
}

/// Why a report needs a human before any further Task work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReportWaitReason {
    /// The child reported BLOCKED.
    Blocked,
    /// The child reported NEEDS_CONTEXT.
    NeedsContext,
    /// An important unagreed item needs a human decision.
    ImportantUnagreed,
    /// The child claimed a host commit it is not allowed to make.
    ChildClaimedCommit,
}

impl ReportWaitReason {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::NeedsContext => "needs_context",
            Self::ImportantUnagreed => "important_unagreed",
            Self::ChildClaimedCommit => "child_claimed_commit",
        }
    }

    /// The stop reason the coordinator records.
    pub const fn stop_reason(self) -> StopReason {
        match self {
            Self::Blocked => StopReason::Blocked,
            Self::NeedsContext => StopReason::NeedsContext,
            Self::ImportantUnagreed => StopReason::HumanDecisionRequired,
            Self::ChildClaimedCommit => StopReason::Conflict,
        }
    }

    /// The human action the coordinator requires.
    pub const fn human_action(self) -> HumanAction {
        match self {
            Self::Blocked => HumanAction::ResolveBlockedTask,
            Self::NeedsContext => HumanAction::ResolveNeedsContext,
            Self::ImportantUnagreed => HumanAction::ResolveHumanDecision,
            Self::ChildClaimedCommit => HumanAction::ResolveConflict,
        }
    }
}

/// One explicit reason a report is not completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportGap {
    /// A required check has no evidence block.
    MissingCheck {
        /// Approved check id.
        check: String,
    },
    /// A required evidence field is missing.
    MissingEvidenceField {
        /// Approved check id.
        check: String,
        /// Missing field.
        field: EvidenceField,
    },
    /// No deliverable was reported although the Task has approved deliverables.
    MissingDeliverables,
    /// One approved deliverable path was not reported.
    MissingDeliverable {
        /// Approved path.
        path: String,
    },
    /// The canonical-spec reflection section is absent.
    MissingSpecReflection,
}

impl fmt::Display for ReportGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCheck { check } => write!(f, "check {check:?} has no evidence"),
            Self::MissingEvidenceField { check, field } => {
                write!(f, "check {check:?} is missing {field}")
            }
            Self::MissingDeliverables => f.write_str("no deliverable is reported"),
            Self::MissingDeliverable { path } => {
                write!(f, "approved deliverable {path:?} is not reported")
            }
            Self::MissingSpecReflection => f.write_str("the canonical-spec reflection is missing"),
        }
    }
}

/// The interpretation of one report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportOutcome {
    /// Every report-side requirement is satisfied. H2, H3, and the host commit
    /// are still separate decisions.
    Complete(Box<Report>),
    /// A human must act before any further Task work.
    HumanWait {
        /// Why the wait is required.
        reason: ReportWaitReason,
        /// The parsed report.
        report: Report,
    },
    /// Required evidence is missing. It is not accepted and it is not a human
    /// wait yet: the same child may be asked to supply it within H2's limits.
    Incomplete {
        /// Every explicit gap.
        gaps: Vec<ReportGap>,
        /// The parsed report.
        report: Report,
    },
}

impl ReportOutcome {
    /// Whether a human must decide before the Task continues.
    pub const fn requires_human(&self) -> bool {
        matches!(self, Self::HumanWait { .. })
    }

    /// Whether the report side of completion is satisfied.
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete(_))
    }

    /// The parsed report, when one was parsed.
    pub fn report(&self) -> &Report {
        match self {
            Self::Complete(report) => report,
            Self::HumanWait { report, .. } | Self::Incomplete { report, .. } => report,
        }
    }
}

/// Why a report file could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportParseError {
    /// The report is larger than [`MAX_REPORT_BYTES`].
    TooLarge {
        /// Accepted bytes.
        limit: usize,
        /// Observed bytes.
        actual: usize,
    },
    /// The report is absent or only whitespace.
    Empty,
    /// No status line or section was found.
    MissingStatus,
    /// The status word is not `DONE`, `BLOCKED`, or `NEEDS_CONTEXT`.
    UnknownStatus {
        /// The rejected word.
        found: String,
    },
    /// The canonical-spec reflection is present but unusable.
    InvalidSpecReflection {
        /// What is wrong.
        detail: String,
    },
    /// One field is present but unusable.
    InvalidField {
        /// Field label.
        field: String,
        /// What is wrong.
        detail: String,
    },
    /// A `Ruling:` line is malformed.
    InvalidRuling {
        /// What is wrong.
        line: String,
    },
    /// The report has more evidence blocks than H4 reads.
    TooManyEvidenceBlocks {
        /// Accepted blocks.
        limit: usize,
    },
}

impl fmt::Display for ReportParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { limit, actual } => write!(
                f,
                "the report is {actual} bytes; the maximum is {limit} and it is never truncated"
            ),
            Self::Empty => f.write_str("the report is empty"),
            Self::MissingStatus => f.write_str("the report has no status"),
            Self::UnknownStatus { found } => {
                write!(
                    f,
                    "the report status {found:?} is not DONE, BLOCKED, or NEEDS_CONTEXT"
                )
            }
            Self::InvalidSpecReflection { detail } => {
                write!(f, "the canonical-spec reflection is invalid: {detail}")
            }
            Self::InvalidField { field, detail } => write!(f, "{field}: {detail}"),
            Self::InvalidRuling { line } => write!(f, "invalid Ruling: {line}"),
            Self::TooManyEvidenceBlocks { limit } => {
                write!(f, "the report has more than {limit} evidence blocks")
            }
        }
    }
}

impl std::error::Error for ReportParseError {}

/// How an absent or unparseable report is treated.
///
/// An absent report and an unparseable report are both "not DONE". The caller
/// must not turn a parse failure into a status.
pub fn interpret_unparseable(error: &ReportParseError) -> ReportOutcome {
    let report = Report {
        status: ReportStatus::NeedsContext,
        deliverables: Vec::new(),
        evidence: Vec::new(),
        spec_reflection: SpecReflection::None { detail: None },
        spec_reflection_present: false,
        decisions: Vec::new(),
        rulings: Vec::new(),
        unagreed: vec![format!("the report could not be read: {error}")],
        unconfirmed: Vec::new(),
        files_changed: Vec::new(),
        commit_claims: Vec::new(),
    };
    ReportOutcome::HumanWait {
        reason: ReportWaitReason::NeedsContext,
        report,
    }
}

// ---------------------------------------------------------------------------
// Section scanning
// ---------------------------------------------------------------------------

struct Section {
    title: String,
    body: String,
}

fn normalize(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut last_space = true;
    for character in value.trim().chars() {
        if character == '*' || character == '`' {
            continue;
        }
        if character.is_whitespace() {
            if !last_space {
                normalized.push(' ');
                last_space = true;
            }
            continue;
        }
        last_space = false;
        for lower in character.to_lowercase() {
            normalized.push(lower);
        }
    }
    normalized.trim().trim_end_matches(':').trim().to_owned()
}

/// Splits Markdown into sections by ATX headings outside fenced code blocks.
fn scan(text: &str) -> Vec<Section> {
    let lines: Vec<&str> = text.lines().collect();
    let mut heads: Vec<(usize, u8, String)> = Vec::new();
    let mut fence: Option<(u8, usize)> = None;
    for (index, line) in lines.iter().enumerate() {
        if let Some((marker, count)) = fence {
            let trimmed = line.trim_start_matches(' ');
            let leading = line.len() - trimmed.len();
            if leading <= 3 {
                let run = trimmed.bytes().take_while(|byte| *byte == marker).count();
                if run >= count && trimmed[run..].trim().is_empty() {
                    fence = None;
                }
            }
            continue;
        }
        if let Some(open) = fence_open(line) {
            fence = Some(open);
            continue;
        }
        if let Some((level, title)) = parse_atx(line) {
            heads.push((index, level, title));
        }
    }
    let mut sections = Vec::with_capacity(heads.len() + 1);
    if let Some((first, _, _)) = heads.first()
        && *first > 0
    {
        // The preamble before the first heading. A chat-style hand-back writes
        // `**Status:** DONE` there, so it must be readable.
        sections.push(Section {
            title: String::new(),
            body: lines[..*first].join("\n"),
        });
    }
    for (position, (line, level, title)) in heads.iter().enumerate() {
        let end = heads[position + 1..]
            .iter()
            .find(|(_, next_level, _)| next_level <= level)
            .map(|(next_line, _, _)| *next_line)
            .unwrap_or(lines.len());
        let body = lines[line + 1..end].join("\n");
        sections.push(Section {
            title: normalize(title),
            body,
        });
    }
    sections
}

fn fence_open(line: &str) -> Option<(u8, usize)> {
    let trimmed = line.trim_start_matches(' ');
    if line.len() - trimmed.len() > 3 {
        return None;
    }
    let marker = *trimmed.as_bytes().first()?;
    if marker != b'`' && marker != b'~' {
        return None;
    }
    let run = trimmed.bytes().take_while(|byte| *byte == marker).count();
    (run >= 3).then_some((marker, run))
}

fn parse_atx(line: &str) -> Option<(u8, String)> {
    let trimmed = line.trim_start_matches(' ');
    if line.len() - trimmed.len() > 3 {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let level = bytes.iter().take_while(|byte| **byte == b'#').count();
    if !(1..=6).contains(&level) || bytes.len() < level {
        return None;
    }
    if bytes
        .get(level)
        .is_some_and(|byte| *byte != b' ' && *byte != b'\t')
    {
        return None;
    }
    let title = trimmed[level..].trim().trim_end_matches('#').trim();
    (!title.is_empty()).then(|| (level as u8, title.to_owned()))
}

fn find_section<'a>(sections: &'a [Section], aliases: &[&str]) -> Option<&'a Section> {
    sections
        .iter()
        .find(|section| aliases.contains(&section.title.as_str()))
}

/// Refuses a report that repeats a section H4 reads.
///
/// Two `## Rulings` sections (or two `## Status` sections) would make the report
/// ambiguous: reading only the first could silently drop a recorded Ruling or a
/// status. An ambiguous report is an explicit parse failure instead.
fn ensure_unique_sections(sections: &[Section]) -> Result<(), ReportParseError> {
    const INTERPRETED: &[&str] = &[
        "status",
        "deliverables",
        "verification evidence",
        "evidence",
        "verification",
        "canonical spec reflection",
        "canonical spec",
        "spec reflection",
        "canonical specification",
        "decisions that affect later phases",
        "decisions affecting later phases",
        "decisions",
        "handoff decisions",
        "rulings",
        "ruling",
        "important unagreed items",
        "unagreed items",
        "human decisions required",
        "unconfirmed scope",
        "unconfirmed",
        "limitations",
        "files changed",
        "changed files",
    ];
    let mut seen = BTreeSet::new();
    for section in sections {
        if !INTERPRETED.contains(&section.title.as_str()) {
            continue;
        }
        if !seen.insert(section.title.as_str()) {
            return Err(ReportParseError::InvalidField {
                field: section.title.clone(),
                detail: "the section appears more than once, so the report is ambiguous".to_owned(),
            });
        }
    }
    Ok(())
}

/// A labelled value: `- Label: value`, `**Label:** value`, or
/// `- **Label:** value`.
fn labelled(line: &str) -> Option<(String, String)> {
    let mut text = line.trim();
    // Only a list marker is stripped, and only once, so a bold label keeps its
    // opening `**`.
    if let Some(rest) = text
        .strip_prefix("- ")
        .or_else(|| text.strip_prefix("* "))
        .or_else(|| text.strip_prefix("+ "))
    {
        text = rest.trim_start();
    }
    if let Some(rest) = text.strip_prefix("**") {
        let (label, after) = rest.split_once("**")?;
        let label = normalize(label);
        if label.is_empty() {
            return None;
        }
        let value = after.trim().trim_start_matches(':').trim();
        return Some((label, value.to_owned()));
    }
    let (label, value) = text.split_once(':')?;
    let label = normalize(label);
    if label.is_empty() || label.len() > 48 {
        return None;
    }
    Some((label, value.trim().to_owned()))
}

/// Strips a leading `Label:` from a line and returns the value.
fn strip_label<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let mut text = line.trim();
    // Only a list marker is stripped; the leading `*` of a bold label is not one.
    if let Some(rest) = text
        .strip_prefix("- ")
        .or_else(|| text.strip_prefix("* "))
        .or_else(|| text.strip_prefix("+ "))
    {
        text = rest.trim_start();
    }
    if let Some(rest) = text.strip_prefix("**") {
        let (candidate, after) = rest.split_once("**")?;
        if normalize(candidate) != label {
            return None;
        }
        let value = after.trim().trim_start_matches(':').trim();
        return (!value.is_empty()).then_some(value);
    }
    let (candidate, after) = text.split_once(':')?;
    if normalize(candidate) != label {
        return None;
    }
    let value = after.trim();
    (!value.is_empty()).then_some(value)
}

fn bullets(body: &str) -> Vec<String> {
    let mut items = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix(['-', '*', '+']) else {
            continue;
        };
        let value = rest.trim();
        if value.is_empty() || is_none(value) {
            continue;
        }
        items.push(value.to_owned());
        if items.len() >= MAX_REPORT_LIST_ENTRIES {
            break;
        }
    }
    items
}

fn is_none(value: &str) -> bool {
    let normalized = normalize(value).trim_end_matches('.').to_owned();
    matches!(
        normalized.as_str(),
        "none" | "no" | "n/a" | "nothing" | "なし" | "ありません"
    )
}

fn list_section(sections: &[Section], aliases: &[&str]) -> Vec<String> {
    find_section(sections, aliases)
        .map(|section| bullets(&section.body))
        .unwrap_or_default()
}

fn parse_status(sections: &[Section]) -> Result<ReportStatus, ReportParseError> {
    if let Some(section) = find_section(sections, &["status"]) {
        for line in section.body.lines() {
            if let Some((label, value)) = labelled(line)
                && label == "status"
            {
                return parse_status_word(&value);
            }
        }
        for line in section.body.lines() {
            let trimmed = line.trim().trim_start_matches(['-', '*', ' ']).trim();
            if !trimmed.is_empty() {
                return parse_status_word(trimmed);
            }
        }
    }
    // The chat hand-back uses `**Status:** DONE` without a heading. Accept that
    // form as well, but only near the top of the file so a status quoted deep in
    // the evidence is not mistaken for the report's own status.
    for line in sections
        .iter()
        .flat_map(|section| section.body.lines())
        .take(40)
    {
        if let Some((label, value)) = labelled(line)
            && label == "status"
        {
            return parse_status_word(&value);
        }
    }
    Err(ReportParseError::MissingStatus)
}

fn parse_status_word(value: &str) -> Result<ReportStatus, ReportParseError> {
    ReportStatus::parse(value).ok_or_else(|| ReportParseError::UnknownStatus {
        found: value.trim().to_owned(),
    })
}

fn parse_spec_reflection(sections: &[Section]) -> Result<Option<SpecReflection>, ReportParseError> {
    let Some(section) = find_section(
        sections,
        &[
            "canonical spec reflection",
            "canonical spec",
            "spec reflection",
            "canonical specification",
        ],
    ) else {
        return Ok(None);
    };
    for line in section.body.lines() {
        let Some((label, value)) = labelled(line) else {
            continue;
        };
        if label != "updated" && label != "canonical spec" {
            continue;
        }
        return parse_spec_value(&value).map(Some);
    }
    for line in section.body.lines() {
        let value = line.trim().trim_start_matches(['-', '*', ' ']).trim();
        if !value.is_empty() {
            return parse_spec_value(value).map(Some);
        }
    }
    Err(ReportParseError::InvalidSpecReflection {
        detail: "the section is present but carries no 'Updated:' value".to_owned(),
    })
}

fn parse_spec_value(value: &str) -> Result<SpecReflection, ReportParseError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ReportParseError::InvalidSpecReflection {
            detail: "'Updated:' needs 'none' or the updated path".to_owned(),
        });
    }
    let (first, rest) = match value.split_once(char::is_whitespace) {
        Some((first, rest)) => (first, Some(rest.trim())),
        None => (value, None),
    };
    let detail = rest.filter(|rest| !rest.is_empty()).map(str::to_owned);
    if is_none(first) {
        return Ok(SpecReflection::None { detail });
    }
    let path = first.trim_matches(|character: char| {
        matches!(
            character,
            '`' | '"' | '\'' | '(' | ')' | '[' | ']' | ',' | ';' | '.'
        )
    });
    if path.is_empty()
        || path.contains(char::is_whitespace)
        || path.chars().any(char::is_control)
        || !path.contains('/')
        || !path.ends_with(".md")
    {
        return Err(ReportParseError::InvalidSpecReflection {
            detail: format!(
                "{path:?} is not a project-relative .md path, and the only non-path value is 'none'"
            ),
        });
    }
    Ok(SpecReflection::Updated {
        path: path.to_owned(),
        detail,
    })
}

fn parse_evidence(sections: &[Section]) -> Result<Vec<CheckEvidence>, ReportParseError> {
    let Some(section) = find_section(
        sections,
        &["verification evidence", "evidence", "verification"],
    ) else {
        return Ok(Vec::new());
    };
    let blocks = scan(&section.body);
    if blocks.is_empty() {
        // A single unheaded evidence block is accepted when it names its check.
        let items = labelled_items(&section.body);
        let check = items
            .iter()
            .find(|(label, _)| label == "check")
            .map(|(_, value)| value.clone());
        let Some(check) = check else {
            return Ok(Vec::new());
        };
        let items = evidence_items(&items)?;
        return Ok(vec![CheckEvidence::new(check, "", items)?]);
    }
    if blocks.len() > MAX_REPORT_EVIDENCE_BLOCKS {
        return Err(ReportParseError::TooManyEvidenceBlocks {
            limit: MAX_REPORT_EVIDENCE_BLOCKS,
        });
    }
    let mut evidence = Vec::with_capacity(blocks.len());
    let mut seen = BTreeSet::new();
    for block in blocks {
        let pairs = labelled_items(&block.body);
        let check = pairs
            .iter()
            .find(|(label, _)| label == "check")
            .map(|(_, value)| value.clone());
        let Some(check) = check else {
            // A block that never names a check cannot evidence one. It is kept
            // out of the evidence list rather than matched by heading text.
            continue;
        };
        if !seen.insert(check.clone()) {
            return Err(ReportParseError::InvalidField {
                field: format!("evidence for check {check:?}"),
                detail: "the report carries more than one evidence block for it".to_owned(),
            });
        }
        evidence.push(CheckEvidence::new(
            check,
            block.title,
            evidence_items(&pairs)?,
        )?);
    }
    Ok(evidence)
}

fn labelled_items(body: &str) -> Vec<(String, String)> {
    let mut items = Vec::new();
    for line in body.lines() {
        if let Some(pair) = labelled(line) {
            items.push(pair);
        }
    }
    items
}

fn evidence_items(pairs: &[(String, String)]) -> Result<Vec<EvidenceItem>, ReportParseError> {
    let mut items = Vec::new();
    let mut seen = BTreeSet::new();
    for (label, value) in pairs {
        let Some(field) = EvidenceField::from_label(label) else {
            continue;
        };
        if !seen.insert(field) {
            return Err(ReportParseError::InvalidField {
                field: field.as_str().to_owned(),
                detail: "appears twice in one evidence block".to_owned(),
            });
        }
        items.push(EvidenceItem::new(field, value.clone())?);
    }
    // Keep contract order so the report value is deterministic.
    items.sort_by_key(|item| item.field);
    Ok(items)
}

fn commit_claims(text: &str) -> Vec<String> {
    let mut claims = Vec::new();
    let mut fence: Option<(u8, usize)> = None;
    for line in text.lines() {
        if let Some((marker, count)) = fence {
            let trimmed = line.trim_start_matches(' ');
            let leading = line.len() - trimmed.len();
            if leading <= 3 {
                let run = trimmed.bytes().take_while(|byte| *byte == marker).count();
                if run >= count && trimmed[run..].trim().is_empty() {
                    fence = None;
                }
            }
            continue;
        }
        if let Some(open) = fence_open(line) {
            fence = Some(open);
            continue;
        }
        let trimmed = line.trim();
        if let Some((label, value)) = labelled(trimmed)
            && (label == "commit" || label == "commit sha" || label == "committed")
            && !value.trim().is_empty()
            && !is_none(&value)
        {
            claims.push(trimmed.to_owned());
            continue;
        }
        let lowered = trimmed.to_lowercase();
        if [
            "committed as",
            "created commit",
            "i committed",
            "git commit -",
        ]
        .iter()
        .any(|phrase| lowered.contains(phrase))
        {
            claims.push(trimmed.to_owned());
        }
        if claims.len() >= MAX_REPORT_LIST_ENTRIES {
            break;
        }
    }
    claims
}
