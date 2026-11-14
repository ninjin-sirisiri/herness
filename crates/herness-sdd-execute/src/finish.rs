//! The finish handoff and the `ready_for_finish` decision.
//!
//! Every Task being `complete` in the snapshot is not enough to hand the
//! execution to `sdd-finish`. The last Task's `finalChecks` evidence must cover
//! the **current** final state, and the canonical-spec reflection must hold.
//! This module decides that from durable state only, and builds the handoff the
//! pack's herness section accepts.
//!
//! # The handoff
//!
//! [`FinishHandoff`] carries exactly what the amended `sdd-finish` section
//! requires and nothing it would have to reconstruct:
//!
//! * the implementation checkout, base branch, implementation branch, and the
//!   **full** `Branch baseline` SHA;
//! * the approved plan path, revision, digest, and the plan's `finalChecks` ids;
//! * the compatibility ledger content and every Task's actual range or
//!   `no_change`;
//! * the last Task's final-state `finalChecks` evidence, with the executor,
//!   exact command, actual result, target change, and scope of each check;
//! * the canonical-spec reflection status;
//! * the unconfirmed items.
//!
//! # The `ready_for_finish` rule
//!
//! [`decide`] returns `Ready` only when all of these hold:
//!
//! 1. every Task is complete, the state is not terminal-failed, and no stop
//!    record is open;
//! 2. the approval is the current one for the same plan digest and revision;
//! 3. the last Task's recorded evidence contains a block for **every** plan
//!    `finalChecks` id, each with all five fields;
//! 4. the evidence was observed for the current final state: the recorded
//!    evidence fingerprint equals the final-content fingerprint the caller
//!    supplies, and the last commit has not moved since (a post-commit hook
//!    change makes the evidence stale);
//! 5. the canonical-spec reflection is either `none` with no later-phase
//!    decision that needs the spec, or `updated` at a path that exists.
//!
//! Anything else is [`FinishDecision::NotReady`] with the exact reasons. A stale
//! evidence reference, an unreadable final state, a moved HEAD, or a missing
//! reflection never becomes ready.
//!
//! # What it never does
//!
//! It performs no Git operation, no push, no merge, and no publication. It has
//! no port that could: the caller passes observed facts in and receives a
//! decision and a rendered handoff. [`FinishHandoff::assert_no_side_effects`]
//! documents the invariant, and [`FinishDecision::Ready`] carries a
//! `human_choice_required` flag that is always `true`.

use crate::error::SddExecutionError;
use crate::ids::{Baseline, TaskRef};
use crate::journal::ProgressTaskLine;
use crate::ledger::{RenderedLedger, TaskArtifacts};
use crate::report::{CheckEvidence, EvidenceField, Report, SpecReflection};
use crate::snapshot::ExecutionSnapshot;
use crate::state::{ExecutionState, StopRecord, TaskProgression};
use crate::version::{PlanDigest, Sha256Digest};

/// One Task's actual completion in the handoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskCompletionEntry {
    /// HEAD advanced; the range is the recorded full `base..head`.
    Range {
        /// Task number.
        number: u32,
        /// Full base SHA.
        base: String,
        /// Full head SHA.
        head: String,
        /// The 7-character ledger form.
        short: String,
    },
    /// The Task changed no approved source content and has an empty range.
    NoChange {
        /// Task number.
        number: u32,
        /// Non-secret detail of the no-change evidence.
        detail: Option<String>,
    },
}

impl TaskCompletionEntry {
    /// Task number.
    pub const fn number(&self) -> u32 {
        match self {
            Self::Range { number, .. } | Self::NoChange { number, .. } => *number,
        }
    }

    /// Whether this Task has an empty commit range.
    pub const fn is_no_change(&self) -> bool {
        matches!(self, Self::NoChange { .. })
    }

    /// One `Task N: …` line for the handoff body.
    pub fn describe(&self) -> String {
        match self {
            Self::Range { number, short, .. } => {
                format!("Task {number}: complete (commits {short})")
            }
            Self::NoChange { number, .. } => format!("Task {number}: complete (no_change)"),
        }
    }
}

/// One approved final check the last Task had to evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalCheckEvidence {
    check: String,
    title: String,
    executor: String,
    command: String,
    actual_result: String,
    target_change: String,
    scope: String,
}

impl FinalCheckEvidence {
    /// Builds the five-field evidence of one final check.
    ///
    /// Every field is required; a block missing one is not evidence for
    /// `ready_for_finish` and the caller turns it into a [`FinishBlocker`].
    pub fn from_block(block: &CheckEvidence) -> Result<Self, Vec<EvidenceField>> {
        let mut missing = Vec::new();
        let mut field = |wanted: EvidenceField| match block.item(wanted) {
            Some(item) => item.text().to_owned(),
            None => {
                missing.push(wanted);
                String::new()
            }
        };
        let executor = field(EvidenceField::Executor);
        let command = field(EvidenceField::Command);
        let actual_result = field(EvidenceField::ActualResult);
        let target_change = field(EvidenceField::TargetChange);
        let scope = field(EvidenceField::Scope);
        if !missing.is_empty() {
            return Err(missing);
        }
        Ok(Self {
            check: block.check().to_owned(),
            title: block.title().to_owned(),
            executor,
            command,
            actual_result,
            target_change,
            scope,
        })
    }

    /// Approved check id.
    pub fn check(&self) -> &str {
        &self.check
    }

    /// Free-text title from the report.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Who or what ran the check.
    pub fn executor(&self) -> &str {
        &self.executor
    }

    /// The exact command.
    pub fn command(&self) -> &str {
        &self.command
    }

    /// The actual output or result.
    pub fn actual_result(&self) -> &str {
        &self.actual_result
    }

    /// The commit, revision, or files the result covers.
    pub fn target_change(&self) -> &str {
        &self.target_change
    }

    /// What the check covers and what it does not.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The five-field block, one `- Field: value` line each.
    pub fn describe(&self) -> String {
        format!(
            "- Check: {}\n  - Executor: {}\n  - Command: {}\n  - Actual result: {}\n  \
             - Target change: {}\n  - Scope: {}",
            self.check,
            self.executor,
            self.command,
            self.actual_result,
            self.target_change,
            self.scope
        )
    }
}

/// One reason the execution is not ready to finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishBlocker {
    /// A Task is not complete.
    TaskNotComplete {
        /// Task number.
        task: u32,
    },
    /// The execution is failed, cancelled, or otherwise unusable.
    ExecutionState {
        /// Current state label.
        state: String,
    },
    /// An open stop record needs a human before finish.
    OpenStop {
        /// Recorded stop reason label.
        reason: String,
    },
    /// The approval is not the current one.
    ApprovalStale {
        /// Non-secret explanation.
        detail: String,
    },
    /// A plan `finalChecks` id has no evidence block.
    MissingFinalCheck {
        /// Missing check id.
        check: String,
    },
    /// A final check's evidence block is missing a field.
    IncompleteFinalCheck {
        /// Check id.
        check: String,
        /// Missing fields.
        fields: Vec<EvidenceField>,
    },
    /// The recorded evidence was observed for another final state.
    StaleEvidence {
        /// Non-secret explanation.
        detail: String,
    },
    /// The canonical-spec reflection is missing or wrong.
    SpecReflection {
        /// Non-secret explanation.
        detail: String,
    },
}

impl FinishBlocker {
    /// A one-line, non-secret description.
    pub fn detail(&self) -> String {
        match self {
            Self::TaskNotComplete { task } => format!("Task {task} is not complete"),
            Self::ExecutionState { state } => {
                format!("the execution is in state {state}, not a finishable one")
            }
            Self::OpenStop { reason } => {
                format!("an open stop ({reason}) must be resolved before finish")
            }
            Self::ApprovalStale { detail } => format!("the approval is stale: {detail}"),
            Self::MissingFinalCheck { check } => {
                format!("the last Task has no finalChecks evidence for {check:?}")
            }
            Self::IncompleteFinalCheck { check, fields } => format!(
                "the finalChecks evidence for {check:?} is missing {}",
                fields
                    .iter()
                    .map(|field| field.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::StaleEvidence { detail } => {
                format!("the finalChecks evidence does not cover the final state: {detail}")
            }
            Self::SpecReflection { detail } => {
                format!("the canonical-spec reflection does not hold: {detail}")
            }
        }
    }
}

/// What the observed final state says about freshness.
///
/// The caller observes it from the approved checkout and the durable records; it
/// is never inferred from a saved notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalStateObservation {
    final_head: String,
    content_digest: Sha256Digest,
    evidence_content_digest: Sha256Digest,
    spec_paths_present: Vec<String>,
}

impl FinalStateObservation {
    /// Records the observed final state.
    ///
    /// `content_digest` is the digest of the final content (tracked bytes plus
    /// the verified derived documents). `evidence_content_digest` is the digest
    /// the final evidence was observed against; they must match for the evidence
    /// to cover the final state. `spec_paths_present` are the project-relative
    /// spec paths that currently exist.
    pub fn new(
        final_head: impl Into<String>,
        content_digest: Sha256Digest,
        evidence_content_digest: Sha256Digest,
        spec_paths_present: Vec<String>,
    ) -> Self {
        Self {
            final_head: final_head.into(),
            content_digest,
            evidence_content_digest,
            spec_paths_present,
        }
    }

    /// Observed final HEAD.
    pub fn final_head(&self) -> &str {
        &self.final_head
    }

    /// Digest of the final content.
    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }

    /// Digest the final evidence was observed against.
    pub fn evidence_content_digest(&self) -> &Sha256Digest {
        &self.evidence_content_digest
    }

    /// Project-relative spec paths that exist.
    pub fn spec_paths_present(&self) -> &[String] {
        &self.spec_paths_present
    }
}

/// The `ready_for_finish` decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishDecision {
    /// Every condition holds; the human still chooses the integration.
    Ready {
        /// The handoff to present.
        handoff: Box<FinishHandoff>,
        /// Always `true`: accepting the handoff is not permission for a side
        /// effect, and the integration menu is still the human's decision.
        human_choice_required: bool,
    },
    /// One or more conditions do not hold.
    NotReady {
        /// Every blocker, in a stable order.
        blockers: Vec<FinishBlocker>,
    },
}

impl FinishDecision {
    /// Whether the execution may hand off to finish.
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    /// The handoff, when ready.
    pub fn handoff(&self) -> Option<&FinishHandoff> {
        match self {
            Self::Ready { handoff, .. } => Some(handoff),
            Self::NotReady { .. } => None,
        }
    }

    /// The blockers, when not ready.
    pub fn blockers(&self) -> &[FinishBlocker] {
        match self {
            Self::Ready { .. } => &[],
            Self::NotReady { blockers } => blockers,
        }
    }
}

/// Everything `sdd-finish` needs, and nothing it must reconstruct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishHandoff {
    checkout: String,
    base_branch: String,
    branch: String,
    baseline: Baseline,
    plan_path: String,
    plan_revision: u64,
    plan_digest: PlanDigest,
    final_check_ids: Vec<String>,
    task_lines: Vec<String>,
    task_completions: Vec<TaskCompletionEntry>,
    final_evidence: Vec<FinalCheckEvidence>,
    spec_reflection: String,
    unconfirmed: Vec<String>,
    ledger: RenderedLedger,
}

impl FinishHandoff {
    /// Builds the handoff from durable state and the observed final state.
    ///
    /// It refuses a snapshot with an unfixed baseline, a Task without a
    /// completion record, and a non-complete Task: those are state defects, not
    /// a handoff with an invented value.
    pub fn build(
        snapshot: &ExecutionSnapshot,
        ledger: RenderedLedger,
        final_check_ids: Vec<String>,
        last_report: &Report,
        unconfirmed: Vec<String>,
        spec_reflection: String,
    ) -> Result<Self, SddExecutionError> {
        let baseline = snapshot.workspace().baseline().cloned().ok_or_else(|| {
            SddExecutionError::InvalidValue {
                field: "finish.baseline".to_owned(),
                detail: "the execution has no fixed baseline".to_owned(),
            }
        })?;
        let mut completions = Vec::new();
        for task in snapshot.tasks() {
            let number = task.task().number().get();
            if task.progression() != TaskProgression::Complete {
                return Err(SddExecutionError::InvalidValue {
                    field: "finish.tasks".to_owned(),
                    detail: format!("Task {number} is not complete"),
                });
            }
            match task.commit_range() {
                Some(range) => completions.push(TaskCompletionEntry::Range {
                    number,
                    base: range.base().to_string(),
                    head: range.head().to_string(),
                    short: range.short_range(),
                }),
                None => {
                    let detail = task
                        .no_change()
                        .and_then(|record| record.detail().map(str::to_owned));
                    completions.push(TaskCompletionEntry::NoChange { number, detail });
                }
            }
        }
        let mut final_evidence = Vec::new();
        for block in last_report.evidence() {
            if let Ok(evidence) = FinalCheckEvidence::from_block(block) {
                final_evidence.push(evidence);
            }
        }
        final_evidence.sort_by(|left, right| left.check.cmp(&right.check));
        let task_lines = completions
            .iter()
            .map(TaskCompletionEntry::describe)
            .collect::<Vec<_>>();
        Ok(Self {
            checkout: snapshot.workspace().canonical_checkout_root().to_owned(),
            base_branch: snapshot.workspace().base_branch().to_owned(),
            branch: snapshot.workspace().branch().to_owned(),
            baseline,
            plan_path: snapshot.plan().plan_path().as_str().to_owned(),
            plan_revision: snapshot.plan().approved_revision().get(),
            plan_digest: snapshot.plan().digest().clone(),
            final_check_ids,
            task_lines,
            task_completions: completions,
            final_evidence,
            spec_reflection,
            unconfirmed,
            ledger,
        })
    }

    /// Canonical implementation checkout.
    pub fn checkout(&self) -> &str {
        &self.checkout
    }

    /// Integration base branch.
    pub fn base_branch(&self) -> &str {
        &self.base_branch
    }

    /// Implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Full `Branch baseline` SHA.
    pub fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    /// Approved plan path.
    pub fn plan_path(&self) -> &str {
        &self.plan_path
    }

    /// Approved plan revision.
    pub const fn plan_revision(&self) -> u64 {
        self.plan_revision
    }

    /// Approved plan digest.
    pub fn plan_digest(&self) -> &PlanDigest {
        &self.plan_digest
    }

    /// Approved plan `finalChecks` ids.
    pub fn final_check_ids(&self) -> &[String] {
        &self.final_check_ids
    }

    /// Every Task's actual range or `no_change`.
    pub fn task_completions(&self) -> &[TaskCompletionEntry] {
        &self.task_completions
    }

    /// The last Task's final-state check evidence.
    pub fn final_evidence(&self) -> &[FinalCheckEvidence] {
        &self.final_evidence
    }

    /// Canonical-spec reflection status.
    pub fn spec_reflection(&self) -> &str {
        &self.spec_reflection
    }

    /// Unconfirmed items carried from the reports.
    pub fn unconfirmed(&self) -> &[String] {
        &self.unconfirmed
    }

    /// The compatibility ledger the handoff carries.
    pub fn ledger(&self) -> &RenderedLedger {
        &self.ledger
    }

    /// The stacked-PR incompatibility notice, when a Task recorded no change.
    pub fn stacked_pr_incompatibility(&self) -> Option<String> {
        self.ledger.stacked_pr_incompatibility()
    }

    /// Whether every Task has a non-empty range, so stacked PRs are possible.
    pub fn stacked_prs_available(&self) -> bool {
        self.stacked_pr_incompatibility().is_none()
    }

    /// The handoff as the text the finish skill reads.
    ///
    /// It is a plain record: presenting it is not permission for a Git side
    /// effect. The integration menu is still shown and the human still chooses.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# H4 finish handoff\n\n");
        out.push_str(&format!("Checkout: {}\n", self.checkout));
        out.push_str(&format!("Branch: {}\n", self.branch));
        out.push_str(&format!("Base branch: {}\n", self.base_branch));
        out.push_str(&format!("Branch baseline: {}\n", self.baseline));
        out.push_str(&format!("Plan: {}\n", self.plan_path));
        out.push_str(&format!("Plan revision: {}\n", self.plan_revision));
        out.push_str(&format!("Plan digest: {}\n", self.plan_digest));
        out.push_str(&format!(
            "finalChecks: {}\n",
            self.final_check_ids.join(", ")
        ));
        out.push_str("\n## Task ranges\n\n");
        for line in &self.task_lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str("\n## Final-state evidence\n\n");
        for evidence in &self.final_evidence {
            out.push_str(&evidence.describe());
            out.push('\n');
        }
        out.push_str("\n## Canonical-spec reflection\n\n");
        out.push_str(&self.spec_reflection);
        out.push('\n');
        out.push_str("\n## Unconfirmed\n\n");
        if self.unconfirmed.is_empty() {
            out.push_str("None.\n");
        } else {
            for item in &self.unconfirmed {
                out.push_str(&format!("- {item}\n"));
            }
        }
        out.push_str("\n## Ledger\n\n");
        out.push_str("```text\n");
        out.push_str(self.ledger.text());
        out.push_str("```\n");
        if let Some(notice) = self.stacked_pr_incompatibility() {
            out.push_str("\n## Stacked PRs\n\n");
            out.push_str(&notice);
            out.push('\n');
        }
        out
    }

    /// Reports the no-side-effect invariant as a value a test can assert.
    ///
    /// The handoff is a record. Accepting it enables nothing; the finish skill
    /// still shows the menu and waits for the human, so no push, merge, PR, or
    /// publication happens before the integration choice.
    pub const fn assert_no_side_effects(&self) -> HandoffSideEffectPolicy {
        HandoffSideEffectPolicy {
            push_allowed: false,
            merge_allowed: false,
            publish_allowed: false,
            human_choice_required: true,
        }
    }
}

/// The side-effect policy one handoff carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoffSideEffectPolicy {
    /// Whether the handoff grants a push.
    pub push_allowed: bool,
    /// Whether the handoff grants a merge.
    pub merge_allowed: bool,
    /// Whether the handoff grants a publication.
    pub publish_allowed: bool,
    /// Whether the human still chooses the integration.
    pub human_choice_required: bool,
}

/// The facts [`decide`] needs, all observed rather than remembered.
pub struct FinishInputs<'a> {
    /// Current durable snapshot.
    pub snapshot: &'a ExecutionSnapshot,
    /// Whether the approval is the current one for this plan.
    pub approval_current: bool,
    /// Non-secret approval detail, used when `approval_current` is false.
    pub approval_detail: String,
    /// Approved plan `finalChecks` ids.
    pub final_check_ids: Vec<String>,
    /// The last Task's accepted report.
    pub last_report: &'a Report,
    /// Observed final state.
    pub observation: &'a FinalStateObservation,
    /// Canonical-spec reflection status.
    pub spec_reflection: SpecReflection,
    /// Whether a later phase depends on this Task's decisions, so a `none`
    /// reflection is not enough.
    pub later_phase_depends: bool,
    /// Compatibility ledger to attach.
    pub ledger: RenderedLedger,
    /// Unconfirmed items carried from the reports.
    pub unconfirmed: Vec<String>,
}

/// Decides whether the execution may hand off to finish.
///
/// The order of the checks is the contract: state, Tasks, approval, final
/// evidence, freshness, reflection. Every failure is collected so a human sees
/// every reason at once, and no failure path returns `Ready`.
pub fn decide(inputs: FinishInputs<'_>) -> Result<FinishDecision, SddExecutionError> {
    let snapshot = inputs.snapshot;
    let mut blockers = Vec::new();

    // Only a completed execution may finish. `committing` is the transition
    // edge where every Task is already complete but the state has not advanced
    // yet; a `running` or `verifying` execution is still working and has no
    // finish handoff even if a corrupted snapshot says every Task is complete.
    if !matches!(
        snapshot.state(),
        ExecutionState::ReadyForFinish | ExecutionState::Committing
    ) {
        blockers.push(FinishBlocker::ExecutionState {
            state: snapshot.state().as_str().to_owned(),
        });
    }
    for task in snapshot.tasks() {
        if task.progression() != TaskProgression::Complete {
            blockers.push(FinishBlocker::TaskNotComplete {
                task: task.task().number().get(),
            });
        }
    }
    if let Some(stop) = snapshot.stop() {
        blockers.push(FinishBlocker::OpenStop {
            reason: stop.reason().as_str().to_owned(),
        });
    }
    if !inputs.approval_current {
        blockers.push(FinishBlocker::ApprovalStale {
            detail: inputs.approval_detail.clone(),
        });
    }

    // Final evidence: every finalChecks id needs a five-field block.
    let Some(last) = snapshot.tasks().last() else {
        return Err(SddExecutionError::InvalidValue {
            field: "finish.tasks".to_owned(),
            detail: "an execution always has at least one Task".to_owned(),
        });
    };
    let mut final_evidence = Vec::new();
    for check in &inputs.final_check_ids {
        let Some(block) = inputs
            .last_report
            .evidence()
            .iter()
            .find(|block| block.check() == check.as_str())
        else {
            blockers.push(FinishBlocker::MissingFinalCheck {
                check: check.clone(),
            });
            continue;
        };
        match FinalCheckEvidence::from_block(block) {
            Ok(evidence) => final_evidence.push(evidence),
            Err(fields) => blockers.push(FinishBlocker::IncompleteFinalCheck {
                check: check.clone(),
                fields,
            }),
        }
    }

    // Freshness: the evidence must be observed for exactly this final content,
    // and the last commit must not have moved since it was recorded.
    if inputs.observation.content_digest() != inputs.observation.evidence_content_digest() {
        blockers.push(FinishBlocker::StaleEvidence {
            detail: "the recorded evidence fingerprint differs from the current final content"
                .to_owned(),
        });
    }
    if let Some(range) = last.commit_range()
        && range.head().as_str() != inputs.observation.final_head()
    {
        blockers.push(FinishBlocker::StaleEvidence {
            detail: format!(
                "the last Task recorded head {} but the checkout is at {}; a post-commit change \
                 invalidates the evidence",
                range.head(),
                inputs.observation.final_head()
            ),
        });
    }

    // Canonical-spec reflection.
    match &inputs.spec_reflection {
        SpecReflection::None { .. } => {
            if inputs.later_phase_depends {
                blockers.push(FinishBlocker::SpecReflection {
                    detail: "a decision that affects a later phase is not reflected in the \
                             canonical spec"
                        .to_owned(),
                });
            }
        }
        SpecReflection::Updated { path, .. } => {
            if !inputs
                .observation
                .spec_paths_present()
                .iter()
                .any(|present| present == path)
            {
                blockers.push(FinishBlocker::SpecReflection {
                    detail: format!(
                        "the report says the canonical spec was updated at {path}, but that \
                         document does not exist in the final state"
                    ),
                });
            }
        }
    }

    if !blockers.is_empty() {
        return Ok(FinishDecision::NotReady { blockers });
    }

    let handoff = FinishHandoff::build(
        snapshot,
        inputs.ledger,
        inputs.final_check_ids,
        inputs.last_report,
        inputs.unconfirmed,
        describe_reflection(&inputs.spec_reflection),
    )?;
    Ok(FinishDecision::Ready {
        handoff: Box::new(handoff),
        human_choice_required: true,
    })
}

fn describe_reflection(reflection: &SpecReflection) -> String {
    match reflection {
        SpecReflection::None { detail } => match detail {
            Some(detail) => format!("none — {detail}"),
            None => "none".to_owned(),
        },
        SpecReflection::Updated { path, detail } => match detail {
            Some(detail) => format!("updated {path} — {detail}"),
            None => format!("updated {path}"),
        },
    }
}

/// The compatibility ledger lines the handoff carries, one per complete Task.
///
/// Kept next to the handoff because the pack parses exactly this list.
pub fn handoff_task_lines(completed: &[ProgressTaskLine]) -> Vec<String> {
    completed
        .iter()
        .map(|line| {
            let number = line.task().number().get();
            match line.range() {
                Some(range) => format!("Task {number}: complete (commits {})", range.short_range()),
                None => format!("Task {number}: complete (no_change)"),
            }
        })
        .collect()
}

/// The brief and report paths of every Task in the snapshot.
pub fn task_artifacts(
    snapshot: &ExecutionSnapshot,
) -> Result<Vec<TaskArtifacts>, SddExecutionError> {
    snapshot
        .tasks()
        .iter()
        .map(|task| TaskArtifacts::new(task.task().number().get()))
        .collect()
}

/// The last Task identity, which owns `finalChecks`.
pub fn final_task(snapshot: &ExecutionSnapshot) -> Option<TaskRef> {
    snapshot.tasks().last().map(|task| task.task())
}

/// The stop record that keeps an execution short of finish.
///
/// A stale-evidence or reflection blocker is a human decision, never a silent
/// retry: `sdd-finish` requires evidence that covers the final state.
pub fn not_ready_stop(_blockers: &[FinishBlocker]) -> StopRecord {
    StopRecord::new(
        crate::state::StopReason::HumanDecisionRequired,
        Some(crate::state::HumanAction::ResolveHumanDecision),
    )
    .expect("a not-ready finish always names the human action")
}
