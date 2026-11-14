//! The `.sdd/progress.md` compatibility ledger and the brief/report paths.
//!
//! The durable H4 store is the source of truth. This module is a **projection**
//! of it: the compatibility document the existing SDD pack and human read, plus
//! the per-Task brief/report paths the pack layout uses.
//!
//! # The emitted format
//!
//! ```text
//! # SDD Progress
//!
//! Worktree: created /abs/checkout
//! Branch: h4-sdd-execute
//! Branch baseline: <40 hex>
//!
//! Task 1: complete (commits aaaaaaa..bbbbbbb)
//! Task 2: complete (no_change)
//!
//! Ruling: <decision> — <why> — <cost if wrong>
//! ```
//!
//! * `Branch baseline:` prints the **full** SHA the snapshot fixed; the DB keeps
//!   that value and a resume never replaces it.
//! * `Task N: complete (commits base7..head7)` prints the 7-character form the
//!   pack's `parse_ledger` expects, derived from the recorded full range.
//! * A `no_change` Task prints `Task N: complete (no_change)`: an empty commit
//!   range is never filled with a fabricated one, and the pack's `parse_ledger`
//!   intentionally ignores that line. `stack-prs` therefore sees fewer Task
//!   lines than the plan has Tasks and refuses — the explicit stacked-PR
//!   incompatibility [`RenderedLedger::stacked_pr_incompatibility`] reports.
//! * Every `Ruling:` line uses the pack's three-part form.
//!
//! # What it never does
//!
//! * It does not read the plan, the Git log, or the existing ledger to decide
//!   what a Task's range is. The range comes from the snapshot only, and
//!   [`render`] refuses a Task list whose ranges are not contiguous from the
//!   fixed baseline.
//! * It does not treat an external `.sdd/progress.md` edit as approval or
//!   completion. [`plan_write`] refuses to replace a document whose lines the
//!   durable state does not reproduce, so a hand edit or another execution's
//!   ledger is a human wait instead of a silent overwrite.
//! * It does not touch Git. The document lives under `.sdd/`, which the
//!   workspace preparation ignores.
//!
//! # Idempotency
//!
//! The same snapshot renders the same bytes. [`write_progress`] records the
//! write intent, writes once, and records the observed result; a document that
//! already equals the projection is `Unchanged` and is not rewritten.

use crate::error::SddExecutionError;
use crate::ids::{Baseline, ExecutionRevision, ProgressKind, ProjectSequence};
use crate::journal::{
    ProgressContent, ProgressFailure, ProgressJournalEntry, ProgressTaskLine, ProgressWriteOutcome,
    RequestIdentity,
};
use crate::packet::execution_report_path;
use crate::ports::{ExecutionStorePort, ProgressLedgerPort};
use crate::report::Ruling;
use crate::snapshot::ExecutionSnapshot;
use crate::state::{HumanAction, StopReason, StopRecord, TaskProgression};
use crate::version::Sha256Digest;

/// Project-relative progress ledger path the pack and the human read.
pub const PROGRESS_LEDGER_PATH: &str = ".sdd/progress.md";

/// Heading line of the compatibility document.
pub const PROGRESS_HEADING: &str = "# SDD Progress";

/// Project-relative brief path of one Task, matching the pack's `.sdd` layout.
pub fn execution_brief_path(task_number: u32) -> String {
    format!(".sdd/briefs/task-{task_number}-brief.md")
}

/// The compatibility brief and report paths of one Task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskArtifacts {
    task_number: u32,
    brief_path: String,
    report_path: String,
}

impl TaskArtifacts {
    /// Names the brief and report files of one Task.
    pub fn new(task_number: u32) -> Result<Self, SddExecutionError> {
        if task_number == 0 {
            return Err(invalid("ledger.taskNumber", "Task numbers start at one"));
        }
        Ok(Self {
            task_number,
            brief_path: execution_brief_path(task_number),
            report_path: execution_report_path(task_number),
        })
    }

    /// Plan-assigned Task number.
    pub const fn task_number(&self) -> u32 {
        self.task_number
    }

    /// Project-relative brief path.
    pub fn brief_path(&self) -> &str {
        &self.brief_path
    }

    /// Project-relative report path.
    pub fn report_path(&self) -> &str {
        &self.report_path
    }
}

// ---------------------------------------------------------------------------
// The Worktree line
// ---------------------------------------------------------------------------

/// The one-time checkout decision recorded as the `Worktree:` line.
///
/// The existing pack honors an already recorded line, so this value can be read
/// back from a document instead of being re-decided.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "path", rename_all = "snake_case")]
pub enum LedgerWorktree {
    /// An isolated worktree was created at this path.
    Created(String),
    /// An already linked worktree at this path was used.
    Existing(String),
    /// The original checkout was used in place.
    InPlace,
}

impl LedgerWorktree {
    /// The exact `Worktree:` line, without the trailing newline.
    pub fn line(&self) -> String {
        match self {
            Self::Created(path) => format!("Worktree: created {path}"),
            Self::Existing(path) => format!("Worktree: existing {path}"),
            Self::InPlace => "Worktree: in-place".to_owned(),
        }
    }

    /// The recorded checkout path, absent for an in-place checkout.
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::Created(path) | Self::Existing(path) => Some(path),
            Self::InPlace => None,
        }
    }

    /// Reads the first `Worktree:` line of an existing document.
    ///
    /// An older ledger writes a bare path; both are honored, and a
    /// `(`-prefixed value is a comment rather than a decision.
    pub fn parse_existing(text: &str) -> Option<Self> {
        for line in text.lines() {
            let Some(value) = line.strip_prefix("Worktree:") else {
                continue;
            };
            let value = value.trim();
            if value.is_empty() || value.starts_with('(') {
                continue;
            }
            if let Some(path) = value.strip_prefix("created") {
                return Some(Self::Created(path.trim().to_owned()));
            }
            if let Some(path) = value.strip_prefix("existing") {
                return Some(Self::Existing(path.trim().to_owned()));
            }
            if value == "in-place" || value == "in_place" {
                return Some(Self::InPlace);
            }
            return Some(Self::Existing(value.to_owned()));
        }
        None
    }

    fn ensure_line_safe(&self) -> Result<(), SddExecutionError> {
        match self {
            Self::Created(path) | Self::Existing(path) => {
                ensure_single_line("ledger.worktree", path)
            }
            Self::InPlace => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// Everything the compatibility document says, taken from durable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerInput {
    worktree: LedgerWorktree,
    branch: String,
    baseline: Baseline,
    completed: Vec<ProgressTaskLine>,
    rulings: Vec<Ruling>,
}

impl LedgerInput {
    /// Creates a ledger projection.
    pub fn new(
        worktree: LedgerWorktree,
        branch: impl Into<String>,
        baseline: Baseline,
        completed: Vec<ProgressTaskLine>,
        rulings: Vec<Ruling>,
    ) -> Result<Self, SddExecutionError> {
        let branch = branch.into();
        if branch.trim().is_empty() {
            return Err(invalid("ledger.branch", "must not be empty"));
        }
        ensure_single_line("ledger.branch", &branch)?;
        worktree.ensure_line_safe()?;
        for ruling in &rulings {
            ensure_single_line("ledger.ruling", ruling.decision())?;
            ensure_single_line("ledger.ruling", ruling.why())?;
            ensure_single_line("ledger.ruling", ruling.cost_if_wrong())?;
        }
        Ok(Self {
            worktree,
            branch,
            baseline,
            completed,
            rulings,
        })
    }

    /// Projects one execution snapshot.
    ///
    /// Only complete Tasks are recorded, in plan order. A snapshot without a
    /// fixed baseline cannot produce the compatibility document, because the
    /// `Branch baseline:` line must never be invented.
    pub fn from_snapshot(
        snapshot: &ExecutionSnapshot,
        worktree: LedgerWorktree,
        rulings: Vec<Ruling>,
    ) -> Result<Self, SddExecutionError> {
        let baseline = snapshot.workspace().baseline().cloned().ok_or_else(|| {
            invalid(
                "ledger.baseline",
                "the execution has no fixed baseline, so the compatibility ledger cannot be written",
            )
        })?;
        let mut completed = Vec::new();
        for task in snapshot.tasks() {
            if task.progression() != TaskProgression::Complete {
                continue;
            }
            completed.push(ProgressTaskLine::new(
                task.task(),
                task.commit_range().cloned(),
                task.no_change().is_some(),
            )?);
        }
        Self::new(
            worktree,
            snapshot.workspace().branch(),
            baseline,
            completed,
            rulings,
        )
    }

    /// Replaces the `Worktree:` decision, so an already recorded line is honored.
    #[must_use]
    pub fn with_worktree(mut self, worktree: LedgerWorktree) -> Self {
        self.worktree = worktree;
        self
    }

    /// The recorded checkout decision.
    pub fn worktree(&self) -> &LedgerWorktree {
        &self.worktree
    }

    /// Implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Fixed baseline.
    pub fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    /// Complete Tasks in plan order.
    pub fn completed(&self) -> &[ProgressTaskLine] {
        &self.completed
    }

    /// Rulings retained from earlier Tasks.
    pub fn rulings(&self) -> &[Ruling] {
        &self.rulings
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The rendered compatibility document and the state it was rendered from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedLedger {
    text: String,
    digest: Sha256Digest,
    worktree: LedgerWorktree,
    branch: String,
    baseline: Baseline,
    completed: Vec<ProgressTaskLine>,
    ruling_lines: Vec<String>,
}

impl RenderedLedger {
    /// The exact document bytes, always ending with one newline.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// SHA-256 of [`Self::text`].
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// The document split into lines, without line endings.
    pub fn lines(&self) -> Vec<&str> {
        self.text.lines().collect()
    }

    /// The recorded checkout decision.
    pub fn worktree(&self) -> &LedgerWorktree {
        &self.worktree
    }

    /// Implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Full baseline SHA the document prints.
    pub fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    /// Complete Tasks in plan order.
    pub fn completed(&self) -> &[ProgressTaskLine] {
        &self.completed
    }

    /// `Ruling:` lines in document order.
    pub fn ruling_lines(&self) -> &[String] {
        &self.ruling_lines
    }

    /// The `Task N:` line of one Task, when it completed.
    pub fn task_line(&self, number: u32) -> Option<String> {
        self.completed
            .iter()
            .find(|line| line.task().number().get() == number)
            .map(task_line)
    }

    /// The durable journal content for exactly these bytes.
    pub fn progress_content(
        &self,
        output_path: impl Into<String>,
        final_project_sequence: Option<ProjectSequence>,
    ) -> Result<ProgressContent, SddExecutionError> {
        Ok(ProgressContent::new(
            output_path,
            self.worktree.path().unwrap_or("in-place"),
            &self.branch,
            self.baseline.clone(),
            self.completed.clone(),
            self.ruling_lines.clone(),
            final_project_sequence,
            self.digest.clone(),
        )?
        .with_worktree(self.worktree.clone()))
    }

    /// The explicit stacked-PR incompatibility, when a Task recorded no change.
    ///
    /// `stack-prs` requires a non-empty commit range for every ledger Task. A
    /// `no_change` Task has none, and no range is invented, so stacked PRs cannot
    /// be produced for this handoff.
    pub fn stacked_pr_incompatibility(&self) -> Option<String> {
        let no_change: Vec<u32> = self
            .completed
            .iter()
            .filter(|line| line.no_change())
            .map(|line| line.task().number().get())
            .collect();
        if no_change.is_empty() {
            return None;
        }
        let tasks = no_change
            .iter()
            .map(|number| format!("Task {number}"))
            .collect::<Vec<_>>()
            .join(", ");
        Some(format!(
            "Stacked PRs are incompatible with this ledger: {tasks} recorded no_change with an \
             empty commit range, and scripts/stack-prs requires a non-empty range per Task. No \
             range is invented; choose local merge, a single PR, or keeping the branch."
        ))
    }
}

/// Renders the compatibility document from durable state.
///
/// It refuses a Task list that is not contiguous from one, a commit range that
/// does not continue the previous Task's range, and a `no_change` Task that also
/// carries a range. Those are state defects: emitting a ledger for them would
/// invent or reorder history.
pub fn render(input: &LedgerInput) -> Result<RenderedLedger, SddExecutionError> {
    ensure_chain(&input.completed, &input.baseline)?;
    let mut lines = vec![
        PROGRESS_HEADING.to_owned(),
        String::new(),
        input.worktree.line(),
        format!("Branch: {}", input.branch),
        format!("Branch baseline: {}", input.baseline),
        String::new(),
    ];
    for line in &input.completed {
        lines.push(task_line(line));
    }
    let mut ruling_lines = Vec::new();
    if !input.rulings.is_empty() {
        lines.push(String::new());
        for ruling in &input.rulings {
            let line = ruling.ledger_line();
            ensure_single_line("ledger.ruling", &line)?;
            lines.push(line.clone());
            ruling_lines.push(line);
        }
    }
    build(
        lines,
        input.worktree.clone(),
        input.branch.clone(),
        input.baseline.clone(),
        input.completed.clone(),
        ruling_lines,
    )
}

/// Re-renders the exact document one stored progress content describes.
///
/// The desktop writer uses it to reproduce the bytes from the durable record, so
/// the digest recorded with the intent is the digest actually written.
pub fn render_content(content: &ProgressContent) -> Result<RenderedLedger, SddExecutionError> {
    ensure_chain(content.completed(), content.baseline())?;
    let worktree = match content.worktree() {
        Some(worktree) => worktree.clone(),
        None => match content.worktree_path() {
            "in-place" => LedgerWorktree::InPlace,
            path => LedgerWorktree::Existing(path.to_owned()),
        },
    };
    let mut lines = vec![
        PROGRESS_HEADING.to_owned(),
        String::new(),
        worktree.line(),
        format!("Branch: {}", content.branch()),
        format!("Branch baseline: {}", content.baseline()),
        String::new(),
    ];
    for line in content.completed() {
        lines.push(task_line(line));
    }
    let mut ruling_lines = Vec::new();
    if !content.rulings().is_empty() {
        lines.push(String::new());
        for ruling in content.rulings() {
            let line = if ruling.starts_with("Ruling: ") {
                ruling.clone()
            } else {
                format!("Ruling: {ruling}")
            };
            ensure_single_line("ledger.ruling", &line)?;
            lines.push(line.clone());
            ruling_lines.push(line);
        }
    }
    build(
        lines,
        worktree,
        content.branch().to_owned(),
        content.baseline().clone(),
        content.completed().to_vec(),
        ruling_lines,
    )
}

fn build(
    lines: Vec<String>,
    worktree: LedgerWorktree,
    branch: String,
    baseline: Baseline,
    completed: Vec<ProgressTaskLine>,
    ruling_lines: Vec<String>,
) -> Result<RenderedLedger, SddExecutionError> {
    let mut text = lines.join("\n");
    text.push('\n');
    let digest = Sha256Digest::sha256(text.as_bytes());
    Ok(RenderedLedger {
        text,
        digest,
        worktree,
        branch,
        baseline,
        completed,
        ruling_lines,
    })
}

fn task_line(line: &ProgressTaskLine) -> String {
    let number = line.task().number().get();
    match line.range() {
        Some(range) => format!("Task {number}: complete (commits {})", range.short_range()),
        None => format!("Task {number}: complete (no_change)"),
    }
}

fn ensure_chain(
    completed: &[ProgressTaskLine],
    baseline: &Baseline,
) -> Result<(), SddExecutionError> {
    let mut expected = baseline.clone();
    for (index, line) in completed.iter().enumerate() {
        let expected_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        if line.task().number().get() != expected_number {
            return Err(invalid(
                "ledger.completed",
                "only a contiguous prefix of Tasks from one can be recorded as complete",
            ));
        }
        match line.range() {
            Some(range) => {
                if range.base() != &expected {
                    return Err(invalid(
                        "ledger.completed",
                        "a Task's recorded range does not continue the previous Task's head",
                    ));
                }
                expected = Baseline::parse(range.head().as_str())?;
            }
            None => {
                if !line.no_change() {
                    return Err(invalid(
                        "ledger.completed",
                        "a Task line needs either a commit range or a no_change result",
                    ));
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Writing decisions
// ---------------------------------------------------------------------------

/// Why an existing document cannot be replaced.
///
/// Every variant is a human wait: the durable state is untouched and the next
/// Task does not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerConflict {
    /// The existing document prints another baseline.
    BaselineChanged {
        /// Baseline found in the document.
        recorded: String,
        /// Baseline the snapshot fixed.
        rendered: String,
    },
    /// The existing document records another range for a Task.
    CompletionRangeChanged {
        /// Task number.
        task: u32,
        /// Line found in the document.
        recorded: String,
        /// Line the snapshot renders.
        rendered: String,
    },
    /// The document carries a line the durable state does not reproduce.
    ExistingNotReproduced {
        /// The line, trimmed of trailing whitespace.
        line: String,
    },
    /// The document exists but cannot be read as a ledger.
    ExistingUnreadable {
        /// Non-secret explanation.
        detail: String,
    },
}

impl LedgerConflict {
    /// The stop record the host records for this conflict.
    pub fn stop(&self) -> StopRecord {
        StopRecord::new(StopReason::Conflict, Some(HumanAction::ResolveConflict))
            .expect("a conflict always names the human action")
    }

    /// A non-secret explanation.
    pub fn detail(&self) -> String {
        match self {
            Self::BaselineChanged { recorded, rendered } => format!(
                "the existing progress ledger prints Branch baseline {recorded}, but the \
                 execution fixed {rendered}; it is another execution's ledger"
            ),
            Self::CompletionRangeChanged {
                task,
                recorded,
                rendered,
            } => format!(
                "the existing progress ledger records Task {task} as {recorded:?}, but the \
                 durable state records {rendered:?}; a recorded completion range is never changed"
            ),
            Self::ExistingNotReproduced { line } => format!(
                "the existing progress ledger line {line:?} is not produced by the durable \
                 state; it was edited outside the host or belongs to another execution"
            ),
            Self::ExistingUnreadable { detail } => {
                format!("the existing progress ledger cannot be read as a ledger: {detail}")
            }
        }
    }
}

/// The action one planned write takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerWrite {
    /// The document does not exist yet.
    Create {
        /// Exact bytes to write.
        text: String,
    },
    /// The document is a reproduced prefix and is replaced as a whole.
    Replace {
        /// Exact bytes to write.
        text: String,
        /// Digest of the document the host is replacing.
        observed: Sha256Digest,
    },
    /// The document already equals the projection; nothing is written.
    Identical {
        /// Exact bytes already present.
        text: String,
    },
}

impl LedgerWrite {
    /// Exact bytes the document must carry after the write.
    pub fn text(&self) -> &str {
        match self {
            Self::Create { text } | Self::Replace { text, .. } | Self::Identical { text } => text,
        }
    }
}

/// Decides whether the existing document may be created, replaced, or left.
///
/// An absent document is created. A document that already equals the projection
/// is left alone. Any other document is replaced **only** when every non-empty
/// line it carries is reproduced by the projection: the same baseline, the same
/// recorded range for every Task it names, and no foreign line. Anything else is
/// a [`LedgerConflict`], never a silent overwrite.
pub fn plan_write(
    rendered: &RenderedLedger,
    existing: Option<&[u8]>,
) -> Result<LedgerWrite, LedgerConflict> {
    let Some(bytes) = existing else {
        return Ok(LedgerWrite::Create {
            text: rendered.text.clone(),
        });
    };
    if bytes == rendered.text.as_bytes() {
        return Ok(LedgerWrite::Identical {
            text: rendered.text.clone(),
        });
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Err(LedgerConflict::ExistingNotReproduced {
            line: "<the document is not valid UTF-8>".to_owned(),
        });
    };
    // The baseline is compared first, because another execution's ledger is the
    // most likely foreign document and deserves the most precise reason.
    for raw in text.lines() {
        let line = raw.trim_end();
        let Some(recorded) = line.strip_prefix("Branch baseline:") else {
            continue;
        };
        let recorded = recorded.trim();
        if recorded != rendered.baseline.as_str() {
            return Err(LedgerConflict::BaselineChanged {
                recorded: recorded.to_owned(),
                rendered: rendered.baseline.to_string(),
            });
        }
    }
    for raw in text.lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with("Branch baseline:") {
            continue;
        }
        if let Some(number) = parse_task_line(line) {
            match rendered.task_line(number) {
                Some(rendered_line) if rendered_line == line => continue,
                Some(rendered_line) => {
                    return Err(LedgerConflict::CompletionRangeChanged {
                        task: number,
                        recorded: line.to_owned(),
                        rendered: rendered_line,
                    });
                }
                None => {
                    return Err(LedgerConflict::ExistingNotReproduced {
                        line: line.to_owned(),
                    });
                }
            }
        }
        if !rendered.lines().contains(&line) {
            return Err(LedgerConflict::ExistingNotReproduced {
                line: line.to_owned(),
            });
        }
    }
    Ok(LedgerWrite::Replace {
        text: rendered.text.clone(),
        observed: Sha256Digest::sha256(bytes),
    })
}

/// Parses one `Task N: complete (...)` line, returning its number.
fn parse_task_line(line: &str) -> Option<u32> {
    let rest = line.strip_prefix("Task ")?;
    let (number, rest) = rest.split_once(':')?;
    let number: u32 = number.trim().parse().ok()?;
    let rest = rest.trim_start().strip_prefix("complete")?.trim_start();
    if !rest.starts_with('(') || !rest.ends_with(')') {
        return None;
    }
    Some(number)
}

// ---------------------------------------------------------------------------
// Writing through the ports
// ---------------------------------------------------------------------------

/// Why one progress write needs a human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressHoldReason {
    /// The existing document is not reproducible from durable state.
    Conflict(LedgerConflict),
    /// The document changed while it was being replaced.
    ExternalModification,
    /// The temporary file could not be written.
    TemporaryFileFailed,
    /// The replacement failed.
    ReplaceFailed,
    /// The write result could not be determined.
    ResultUnknown,
}

impl ProgressHoldReason {
    /// The stop record the host records for this hold.
    pub fn stop(&self) -> StopRecord {
        match self {
            Self::Conflict(conflict) => conflict.stop(),
            Self::ExternalModification => {
                StopRecord::new(StopReason::Conflict, Some(HumanAction::ResolveConflict))
                    .expect("a conflict always names the human action")
            }
            Self::TemporaryFileFailed | Self::ReplaceFailed => StopRecord::new(
                StopReason::InternalFailure,
                Some(HumanAction::ResolveInternalFailure),
            )
            .expect("an internal failure names the human action"),
            Self::ResultUnknown => StopRecord::new(
                StopReason::RecoveryRequired,
                Some(HumanAction::ConfirmRecovery),
            )
            .expect("a recovery always names the human action"),
        }
    }

    /// A non-secret explanation.
    pub fn detail(&self) -> String {
        match self {
            Self::Conflict(conflict) => conflict.detail(),
            Self::ExternalModification => {
                "the progress ledger changed while it was being written; the host does not \
                 overwrite an unknown document"
                    .to_owned()
            }
            Self::TemporaryFileFailed => {
                "the progress ledger temporary file could not be written".to_owned()
            }
            Self::ReplaceFailed => {
                "the progress ledger could not be replaced with the rendered document".to_owned()
            }
            Self::ResultUnknown => {
                "the progress ledger write result cannot be determined; reconcile the file \
                 before the next Task"
                    .to_owned()
            }
        }
    }
}

/// The result of one compatibility-ledger write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressLedgerOutcome {
    /// The document was written and its digest observed.
    Written {
        /// Digest of the document now on disk.
        digest: Sha256Digest,
    },
    /// The document already carried the projection; nothing was written.
    Unchanged {
        /// Digest of the document now on disk.
        digest: Sha256Digest,
    },
    /// The write is held and no next Task starts.
    HumanWait {
        /// Why the write is held.
        reason: ProgressHoldReason,
        /// Stop record to persist on the execution.
        stop: StopRecord,
    },
}

impl ProgressLedgerOutcome {
    /// Whether the document is present and no human is needed.
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Written { .. } | Self::Unchanged { .. })
    }

    /// The digest of the document, when it is present.
    pub fn digest(&self) -> Option<&Sha256Digest> {
        match self {
            Self::Written { digest } | Self::Unchanged { digest } => Some(digest),
            Self::HumanWait { .. } => None,
        }
    }

    /// The stop record the caller persists, when the write is held.
    pub fn stop(&self) -> Option<&StopRecord> {
        match self {
            Self::HumanWait { stop, .. } => Some(stop),
            _ => None,
        }
    }
}

/// One idempotent compatibility-ledger write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressWriteRequest {
    identity: RequestIdentity<ProgressKind>,
    input: LedgerInput,
    output_path: String,
    final_project_sequence: Option<ProjectSequence>,
}

impl ProgressWriteRequest {
    /// Creates one request over the execution's projection.
    pub fn new(
        identity: RequestIdentity<ProgressKind>,
        input: LedgerInput,
        output_path: impl Into<String>,
    ) -> Result<Self, SddExecutionError> {
        let output_path = output_path.into();
        crate::plan::validate_project_path("ledger.outputPath", &output_path)?;
        Ok(Self {
            identity,
            input,
            output_path,
            final_project_sequence: None,
        })
    }

    /// Records the last observed project sequence, so the journal keeps it.
    #[must_use]
    pub const fn with_project_sequence(mut self, sequence: Option<ProjectSequence>) -> Self {
        self.final_project_sequence = sequence;
        self
    }

    /// The mandatory request guard.
    pub const fn identity(&self) -> &RequestIdentity<ProgressKind> {
        &self.identity
    }

    /// The projection to write.
    pub fn input(&self) -> &LedgerInput {
        &self.input
    }

    /// Project-relative document path.
    pub fn output_path(&self) -> &str {
        &self.output_path
    }
}

/// Writes the compatibility ledger from durable state, exactly once.
///
/// Order: a re-delivered request returns its stored result; an intent recorded
/// without a result is reconciled by digest and never repeated blindly; the
/// existing document is read, an already recorded `Worktree:` line is honored,
/// the write is planned, then the intent, the write, and the result are recorded
/// in that order. Any failure or conflict is a [`ProgressLedgerOutcome::HumanWait`]
/// and the caller must not start the next Task.
pub fn write_progress(
    store: &mut dyn ExecutionStorePort,
    ledger: &mut dyn ProgressLedgerPort,
    request: &ProgressWriteRequest,
) -> Result<ProgressLedgerOutcome, SddExecutionError> {
    let identity = *request.identity();
    let project = identity.project_id();
    let execution = identity.execution_id();
    if let Some(entry) = store.progress_entry(project, execution, identity.request_id())? {
        return match entry.outcome() {
            Some(outcome) => Ok(outcome_of(outcome)),
            None => reconcile(store, ledger, entry),
        };
    }

    let existing = match ledger.read(request.output_path()) {
        Ok(existing) => existing,
        Err(error) => {
            // An unreadable destination is a human wait, not a crash: the host
            // will not replace a document it cannot identify.
            return Ok(held(ProgressHoldReason::Conflict(
                LedgerConflict::ExistingUnreadable {
                    detail: error.to_string(),
                },
            )));
        }
    };
    let mut input = request.input().clone();
    if let Some(text) = existing
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        && let Some(recorded) = LedgerWorktree::parse_existing(text)
    {
        // The existing pack behavior: an already recorded decision is honored.
        input = input.with_worktree(recorded);
    }
    let rendered = render(&input)?;
    let write = match plan_write(&rendered, existing.as_deref()) {
        Ok(write) => write,
        Err(conflict) => {
            return Ok(held(ProgressHoldReason::Conflict(conflict)));
        }
    };
    if matches!(write, LedgerWrite::Identical { .. }) {
        return Ok(ProgressLedgerOutcome::Unchanged {
            digest: rendered.digest.clone(),
        });
    }
    let expected = match &write {
        LedgerWrite::Create { .. } => None,
        LedgerWrite::Replace { observed, .. } => Some(observed.clone()),
        LedgerWrite::Identical { .. } => unreachable!("handled above"),
    };
    let content =
        rendered.progress_content(request.output_path(), request.final_project_sequence)?;
    let entry = ProgressJournalEntry::new(identity, content)?;
    store.record_progress(&entry)?;
    let outcome = ledger.write(&entry, expected.as_ref())?;
    let recorded = entry.record(outcome.clone());
    store.record_progress(&recorded)?;
    Ok(match outcome {
        ProgressWriteOutcome::Written { digest } => ProgressLedgerOutcome::Written { digest },
        ProgressWriteOutcome::Failed { reason } => held(reason_of(reason)),
        ProgressWriteOutcome::Unknown => held(ProgressHoldReason::ResultUnknown),
    })
}

/// Records a durable `waiting_human` hold without starting another Task.
///
/// The snapshot keeps every Task, range, and baseline it already had; only the
/// execution state and the stop record change. The revision advances by one with
/// a compare-and-swap, so a concurrent writer is refused instead of overwritten.
pub fn hold_next_task(
    store: &mut dyn ExecutionStorePort,
    snapshot: &ExecutionSnapshot,
    stop: StopRecord,
) -> Result<ExecutionRevision, SddExecutionError> {
    let held = snapshot.held_waiting_human(snapshot.revision().next(), stop)?;
    store.compare_and_swap(
        snapshot.project_id(),
        snapshot.execution_id(),
        Some(snapshot.revision()),
        &held,
    )
}

fn reconcile(
    store: &mut dyn ExecutionStorePort,
    ledger: &mut dyn ProgressLedgerPort,
    entry: ProgressJournalEntry,
) -> Result<ProgressLedgerOutcome, SddExecutionError> {
    let content = entry.content();
    let rendered = render_content(content)?;
    let existing = ledger.read(content.output_path())?;
    let matches_expected = existing
        .as_deref()
        .is_some_and(|bytes| Sha256Digest::sha256(bytes) == rendered.digest);
    if matches_expected {
        let outcome = ProgressWriteOutcome::Written {
            digest: rendered.digest.clone(),
        };
        store.record_progress(&entry.record(outcome))?;
        return Ok(ProgressLedgerOutcome::Written {
            digest: rendered.digest,
        });
    }
    store.record_progress(&entry.record(ProgressWriteOutcome::Unknown))?;
    Ok(held(ProgressHoldReason::ResultUnknown))
}

fn held(reason: ProgressHoldReason) -> ProgressLedgerOutcome {
    ProgressLedgerOutcome::HumanWait {
        stop: reason.stop(),
        reason,
    }
}

fn outcome_of(outcome: &ProgressWriteOutcome) -> ProgressLedgerOutcome {
    match outcome {
        ProgressWriteOutcome::Written { digest } => ProgressLedgerOutcome::Written {
            digest: digest.clone(),
        },
        ProgressWriteOutcome::Failed { reason } => held(reason_of(*reason)),
        ProgressWriteOutcome::Unknown => held(ProgressHoldReason::ResultUnknown),
    }
}

fn reason_of(reason: ProgressFailure) -> ProgressHoldReason {
    match reason {
        ProgressFailure::TemporaryFileFailed => ProgressHoldReason::TemporaryFileFailed,
        ProgressFailure::ReplaceFailed => ProgressHoldReason::ReplaceFailed,
        ProgressFailure::ExternalModification => ProgressHoldReason::ExternalModification,
        ProgressFailure::StaleState => {
            ProgressHoldReason::Conflict(LedgerConflict::ExistingNotReproduced {
                line: "<durable state no longer matches the rendered document>".to_owned(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ensure_single_line(field: &str, value: &str) -> Result<(), SddExecutionError> {
    if value.trim().is_empty() {
        return Err(invalid(field, "must not be empty"));
    }
    if value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return Err(invalid(
            field,
            "must not contain a line break or NUL, which would inject a ledger line",
        ));
    }
    Ok(())
}

fn invalid(field: &str, detail: &str) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.to_owned(),
    }
}
