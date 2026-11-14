//! Desktop adapter that turns one approved H4 Task into its immutable packet and
//! H2 binding.
//!
//! # What it composes
//!
//! [`task_packet`] is the single caller of
//! [`herness_sdd_execute::TaskPacket::compose`]. Task 15's coordinator calls it
//! once per Task, before the H2 target is created, so the packet exists before
//! any child does:
//!
//! 1. the exact Task body from the approved plan revision's parsed Tasks;
//! 2. the verbatim Global Constraints of that revision;
//! 3. the applied canonical-spec sections of the Task's own approved spec
//!    references, taken from the verified snapshot set the approval bound;
//! 4. the earlier Tasks' interfaces, Rulings, and unresolved items from the
//!    stored handoffs;
//! 5. the approved scope, HTML targets, commit policy, checks, and conditions;
//! 6. the report path and the report requirements.
//!
//! The result is either a ready packet or an explicit capacity human-wait. This
//! module never reads a file, starts a process, or starts a child.
//!
//! # Wiring into dispatch (Task 15)
//!
//! 1. build the packet from the current approval, the verified snapshot set, the
//!    stored handoffs, and the Task number;
//! 2. pass [`H4TaskPacket::prompt`] as `H4TaskLaunch::instructions` and
//!    [`H4TaskPacket::h2_binding`] as the `H4LaunchRequest` packet binding;
//! 3. H2 stores that prompt in the target's immutable `WorkPacket`, and every
//!    continuation and restore renders the stored value, so first run,
//!    continuation, and restore carry byte-identical constraints and spec
//!    context. The H4 path therefore never calls `bind_owner_instruction`, which
//!    exists for H3 generation supersession and refuses an H4 owner kind.
//! 4. after the host commit, build the Task's [`TaskHandoff`] from the accepted
//!    report so the next Task's packet carries its decisions and Rulings.

use herness_sdd_execute::{
    CommitSha, ExecutionApproval, PacketContextEntry, PacketInputs, PacketScope, PacketSpecSection,
    PriorTaskContext, Report, ReportExpectations, ReportOutcome, RunInputRef, SddExecutionError,
    SnapshotSections, TaskApproval, TaskHandoff, TaskNumber, TaskPacket, TaskPacketBinding,
    TaskRef, execution_report_path, interpret_unparseable, prior_context_for,
};
use herness_supervision::{H4PacketBinding, SupervisionError};

/// Why one Task has no packet yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskPacketRefusal {
    /// The approval has no Task with this number.
    UnknownTask {
        /// Plan-assigned Task number.
        number: u32,
    },
    /// The approved context cannot be composed as approved: a snapshot is
    /// missing, a section is not the approved revision, or a value is invalid.
    Context {
        /// Non-secret explanation.
        detail: String,
    },
    /// The context does not fit the packet's bounds. A human must narrow the
    /// approved scope; nothing is truncated.
    Capacity {
        /// Non-secret explanation naming what does not fit.
        detail: String,
    },
}

impl TaskPacketRefusal {
    /// The stop reason the coordinator records.
    pub fn stop_reason(&self) -> herness_sdd_execute::StopReason {
        match self {
            Self::UnknownTask { .. } => herness_sdd_execute::StopReason::Conflict,
            Self::Context { .. } | Self::Capacity { .. } => {
                herness_sdd_execute::StopReason::HumanDecisionRequired
            }
        }
    }

    /// The human action the coordinator requires.
    pub fn human_action(&self) -> herness_sdd_execute::HumanAction {
        match self {
            Self::UnknownTask { .. } => herness_sdd_execute::HumanAction::ResolveConflict,
            Self::Context { .. } | Self::Capacity { .. } => {
                herness_sdd_execute::HumanAction::ResolveHumanDecision
            }
        }
    }
}

/// One composed Task packet, ready for H2.
#[derive(Debug, Clone)]
pub struct H4TaskPacket {
    packet: TaskPacket,
    report_expectations: ReportExpectations,
}

impl H4TaskPacket {
    /// Wraps a composed packet with its Task's report expectations.
    pub fn new(packet: TaskPacket, report_expectations: ReportExpectations) -> Self {
        Self {
            packet,
            report_expectations,
        }
    }

    /// The immutable packet.
    pub const fn packet(&self) -> &TaskPacket {
        &self.packet
    }

    /// The exact first-run and shared-continuation text.
    pub fn prompt(&self) -> &str {
        self.packet.prompt()
    }

    /// The packet's report path.
    pub fn report_path(&self) -> &str {
        self.packet.report_path()
    }

    /// The report expectations of this Task.
    pub const fn report_expectations(&self) -> &ReportExpectations {
        &self.report_expectations
    }

    /// The H2 packet binding of this exact packet.
    pub fn h2_binding(&self) -> Result<H4PacketBinding, SddExecutionError> {
        packet_binding(&self.packet.binding_digests())
    }

    /// Interprets one report file against this Task's expectations.
    pub fn interpret_report(&self, text: &str) -> ReportOutcome {
        match Report::parse(text) {
            Ok(report) => report.interpret(&self.report_expectations),
            Err(error) => interpret_unparseable(&error),
        }
    }

    /// The two values Task 15 passes to H2's owner launch.
    ///
    /// The prompt is the `H4TaskLaunch::instructions` value and the binding is
    /// the `H4LaunchRequest` packet. Both come from the same immutable packet, so
    /// a launch that used a different text or a different binding cannot match
    /// the approved owner launch.
    pub fn dispatch_seam(&self) -> Result<TaskDispatchSeam, SddExecutionError> {
        Ok(TaskDispatchSeam {
            instructions: self.prompt().to_owned(),
            binding: self.h2_binding()?,
            report_path: self.report_path().to_owned(),
        })
    }
}

/// The exact H2 launch inputs of one composed packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskDispatchSeam {
    instructions: String,
    binding: H4PacketBinding,
    report_path: String,
}

impl TaskDispatchSeam {
    /// Exact first-run and continuation instruction text.
    pub fn instructions(&self) -> &str {
        &self.instructions
    }

    /// The H2 packet binding of the same text.
    pub const fn binding(&self) -> &H4PacketBinding {
        &self.binding
    }

    /// The report path the child writes and the host reads.
    pub fn report_path(&self) -> &str {
        &self.report_path
    }
}

/// The dispatch decision of one Task packet.
#[derive(Debug, Clone)]
pub enum TaskPacketOutcome {
    /// The child may be started with this exact immutable input.
    Ready(Box<H4TaskPacket>),
    /// A human must decide before any child starts.
    HumanWait {
        /// Why the wait is required.
        reason: TaskPacketRefusal,
        /// Non-secret explanation naming what does not fit.
        detail: String,
    },
}

impl TaskPacketOutcome {
    /// The packet, when one is ready.
    pub fn packet(&self) -> Option<&H4TaskPacket> {
        match self {
            Self::Ready(packet) => Some(packet),
            Self::HumanWait { .. } => None,
        }
    }

    /// Whether a child may start.
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    /// The stop reason, when the outcome is a wait.
    pub fn stop_reason(&self) -> Option<herness_sdd_execute::StopReason> {
        match self {
            Self::Ready(_) => None,
            Self::HumanWait { reason, .. } => Some(reason.stop_reason()),
        }
    }
}

/// Builds the H2 packet binding from the packet's three digests.
///
/// This is the one production caller of
/// [`h4_packet_binding`](crate::supervision::h4_launch::h4_packet_binding). H2
/// compares the result with the approved owner launch, so the comparison covers
/// the exact text the child receives.
pub fn packet_binding(binding: &TaskPacketBinding) -> Result<H4PacketBinding, SddExecutionError> {
    crate::supervision::h4_launch::h4_packet_binding(
        binding.task_body(),
        binding.global_constraints(),
        binding.spec_snapshot(),
    )
    .map_err(binding_error)
}

fn binding_error(error: SupervisionError) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: "h4TaskPacket.binding".to_owned(),
        detail: format!("{error}"),
    }
}

/// Builds one Task packet from the approved revision, the verified snapshots, and
/// the stored prior state.
///
/// `snapshots` must be the verified snapshot set of the same approval, because
/// the packet carries the exact approved section text. `handoffs` are the stored
/// handoffs of Tasks that already completed; only earlier numbers are used.
/// `task_spec_refs` is the Task's own approved spec-reference subset; when it is
/// `None` the plan's root references are used, which is never narrower than the
/// Task's own declaration.
pub fn task_packet(
    approval: &ExecutionApproval,
    snapshots: &SnapshotSections,
    task_number: u32,
    handoffs: &[TaskHandoff],
    task_spec_refs: Option<&[herness_sdd_execute::ApprovedSpecRef]>,
    report_path: Option<&str>,
) -> TaskPacketOutcome {
    let number = match TaskNumber::new(task_number) {
        Ok(number) => number,
        Err(_) => {
            return TaskPacketOutcome::HumanWait {
                reason: TaskPacketRefusal::UnknownTask {
                    number: task_number,
                },
                detail: format!("Task number {task_number} does not exist"),
            };
        }
    };
    let Some(task) = approval.content().task(number) else {
        return TaskPacketOutcome::HumanWait {
            reason: TaskPacketRefusal::UnknownTask {
                number: task_number,
            },
            detail: format!("the approval has no Task {task_number}"),
        };
    };
    let plan = approval.plan();
    let Some(parsed_task) = plan
        .parsed()
        .tasks()
        .iter()
        .find(|parsed| parsed.number() == task_number)
    else {
        return TaskPacketOutcome::HumanWait {
            reason: TaskPacketRefusal::UnknownTask {
                number: task_number,
            },
            detail: format!("the approved plan revision has no Task {task_number} body"),
        };
    };
    let refs = task_spec_refs.unwrap_or_else(|| plan.spec_refs());
    let sections = match snapshots.select(refs) {
        Ok(sections) => sections,
        Err(error) => return context(error),
    };
    let prior = match prior_context_for(task.task(), handoffs) {
        Ok(prior) => prior,
        Err(error) => return context(error),
    };
    let report_path = report_path
        .map(str::to_owned)
        .unwrap_or_else(|| execution_report_path(task_number));
    let inputs = match PacketInputs::for_task(
        task,
        plan.plan_path().clone(),
        plan.plan_revision(),
        plan.digest().clone(),
        parsed_task.body().text(),
        plan.parsed().global_constraints().text(),
        refs.to_vec(),
        sections,
        prior,
        report_path,
    ) {
        Ok(inputs) => inputs,
        Err(error) => return context(error),
    };
    let composition = match TaskPacket::compose(inputs) {
        Ok(composition) => composition,
        Err(error) => return context(error),
    };
    match composition.into_outcome() {
        herness_sdd_execute::PacketOutcome::Ready(packet) => TaskPacketOutcome::Ready(Box::new(
            H4TaskPacket::new(*packet, ReportExpectations::for_task(task)),
        )),
        herness_sdd_execute::PacketOutcome::HumanWait { detail, .. } => {
            TaskPacketOutcome::HumanWait {
                reason: TaskPacketRefusal::Capacity {
                    detail: detail.clone(),
                },
                detail,
            }
        }
    }
}

fn context(error: SddExecutionError) -> TaskPacketOutcome {
    TaskPacketOutcome::HumanWait {
        reason: TaskPacketRefusal::Context {
            detail: error.to_string(),
        },
        detail: error.to_string(),
    }
}

/// Builds the prior-Task context for one Task from stored handoffs.
///
/// Kept as a named entry point so a caller holding only the handoffs (for
/// example while planning a restore) can rebuild the same context the packet
/// used.
pub fn prior_context(
    task: TaskRef,
    handoffs: &[TaskHandoff],
) -> Result<PriorTaskContext, SddExecutionError> {
    prior_context_for(task, handoffs)
}

/// Builds one Task's handoff from its accepted report after the host commit.
///
/// The handoff is what a later Task's packet carries. Decisions and reversible
/// Rulings propagate; a commit claim cannot, because the child never makes a
/// commit and the host supplies the real `commit` value instead.
pub fn task_handoff(
    task: TaskRef,
    report: &Report,
    commit: Option<&CommitSha>,
    evidence_runs: Vec<RunInputRef>,
) -> Result<TaskHandoff, SddExecutionError> {
    let origin = format!("Task {}", task.number().get());
    let interfaces = report
        .decisions()
        .iter()
        .map(|decision| PacketContextEntry::new(origin.clone(), decision.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let rulings = report
        .rulings()
        .iter()
        .map(|ruling| PacketContextEntry::new("Ruling", ruling.ledger_line()))
        .collect::<Result<Vec<_>, _>>()?;
    let unresolved = report
        .unconfirmed()
        .iter()
        .chain(report.unagreed().iter())
        .map(|item| PacketContextEntry::new(origin.clone(), item.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TaskHandoff::new(
        task,
        interfaces,
        rulings,
        unresolved,
        commit.cloned(),
        evidence_runs,
    ))
}

/// Reads and interprets the report file of one Task inside its checkout.
///
/// The path is the packet's own project-relative report path, resolved under the
/// approved checkout root. The read is bounded by
/// [`herness_sdd_execute::MAX_REPORT_BYTES`] and never truncated: an oversize
/// report is an explicit human wait. An absent or unreadable report is a human
/// wait, never `DONE`.
pub fn read_report(
    checkout_root: &str,
    packet: &H4TaskPacket,
) -> Result<ReportOutcome, SddExecutionError> {
    let root = std::path::Path::new(checkout_root);
    if !root.is_absolute() {
        return Err(SddExecutionError::InvalidValue {
            field: "h4.taskPacket.checkoutRoot".to_owned(),
            detail: "must be the absolute approved checkout root".to_owned(),
        });
    }
    let relative = packet.report_path();
    let path = root.join(relative);
    let canonical_root =
        std::fs::canonicalize(root).map_err(|error| SddExecutionError::InvalidValue {
            field: "h4.taskPacket.checkoutRoot".to_owned(),
            detail: format!("the checkout is unreadable: {}", error.kind()),
        })?;
    let canonical = match std::fs::canonicalize(&path) {
        Ok(canonical) => canonical,
        // An absent report is "not DONE", never a parse success.
        Err(_) => {
            return Ok(interpret_unparseable(
                &herness_sdd_execute::ReportParseError::Empty,
            ));
        }
    };
    if !canonical.starts_with(&canonical_root) || canonical == canonical_root {
        return Err(SddExecutionError::InvalidValue {
            field: "h4.taskPacket.reportPath".to_owned(),
            detail: format!("{relative} resolves outside the approved checkout"),
        });
    }
    let metadata =
        std::fs::metadata(&canonical).map_err(|error| SddExecutionError::InvalidValue {
            field: "h4.taskPacket.reportPath".to_owned(),
            detail: format!("{relative} is unreadable: {}", error.kind()),
        })?;
    if !metadata.is_file() {
        return Ok(interpret_unparseable(
            &herness_sdd_execute::ReportParseError::Empty,
        ));
    }
    if metadata.len() > herness_sdd_execute::MAX_REPORT_BYTES as u64 {
        return Ok(interpret_unparseable(
            &herness_sdd_execute::ReportParseError::TooLarge {
                limit: herness_sdd_execute::MAX_REPORT_BYTES,
                actual: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
            },
        ));
    }
    let bytes = std::fs::read(&canonical).map_err(|error| SddExecutionError::InvalidValue {
        field: "h4.taskPacket.reportPath".to_owned(),
        detail: format!("{relative} could not be read: {}", error.kind()),
    })?;
    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(packet.interpret_report(text)),
        Err(_) => Ok(interpret_unparseable(
            &herness_sdd_execute::ReportParseError::InvalidField {
                field: "report".to_owned(),
                detail: "the report is not valid UTF-8".to_owned(),
            },
        )),
    }
}

/// The report path H4 uses for one Task number.
pub fn report_path(task_number: u32) -> String {
    execution_report_path(task_number)
}

/// The report expectations of one approved Task, without composing a packet.
pub fn report_expectations(task: &TaskApproval) -> ReportExpectations {
    ReportExpectations::for_task(task)
}

/// The scope and HTML targets a packet states.
pub fn packet_scope(task: &TaskApproval) -> Result<PacketScope, SddExecutionError> {
    PacketScope::new(
        task.scope().clone(),
        task.html_targets().to_vec(),
        task.commit_policy(),
    )
}

/// Builds snapshot sections from the verified snapshots of one import preview.
///
/// The desktop import already read and verified the exact bytes; this turns them
/// into the pure value the packet consumes, so the packet never opens a file.
pub fn snapshot_sections(preview: &crate::sdd_execute::pack::ImportPreview) -> SnapshotSections {
    let mut sections = SnapshotSections::new();
    for snapshot in preview.specs().snapshots() {
        let parts = snapshot
            .sections()
            .iter()
            .map(|section| {
                (
                    section.heading().to_owned(),
                    snapshot.digest().to_string(),
                    section.text().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        sections = sections.with_snapshot(snapshot.source(), snapshot.path(), parts);
    }
    sections
}

/// One spec section for a packet, built from a verified snapshot body.
pub fn spec_section(
    source: impl Into<String>,
    path: impl Into<String>,
    heading: impl Into<String>,
    digest: impl Into<String>,
    text: impl Into<String>,
) -> Result<PacketSpecSection, SddExecutionError> {
    PacketSpecSection::new(source, path, heading, digest, text)
}

/// The packet size bound, so a caller can explain a capacity wait.
pub const MAX_PACKET_BYTES: usize = herness_sdd_execute::MAX_PACKET_BYTES;
