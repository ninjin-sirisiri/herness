//! The finite Task budget: H2 supervision consumption plus the host's own
//! post-completion processing.
//!
//! One Task has one finite budget, fixed by the approved plan and never raised
//! by H4. It combines
//!
//! * the H2 supervision consumption of the Task's one child (cumulative active
//!   seconds and additional runs, re-read from H2's durable ledger), and
//! * the host's own processing after H2 completed for the Task (stage, hooks,
//!   commit, and Git/journal reconciliation),
//!
//! under the approved limits: 7,200 cumulative seconds, 30 additional runs, and
//! 3 consecutive stalls.
//!
//! # Monotonicity
//!
//! Every method here is monotonic: consumption only grows, and a resume, a
//! restart, or a plan re-approval rebuilds the value from the stored snapshot
//! instead of starting over. H2 reporting a completed Task is not a reason to
//! stop the Task's clock or to grant a fresh limit; the host processing that
//! follows a completion is charged to the same Task.
//!
//! # Combined bound
//!
//! The combined seconds are `max(stored combined, observed H2 cumulative)`.
//! H4 charges its own host processing only after H2 has completed for the Task,
//! so the H2 cumulative cannot grow past the stored bound afterwards. A resumed
//! Task therefore loses no consumption and double counts none.
//!
//! The value object performs no I/O and reads no clock. The coordinator supplies
//! H2's cumulative usage, the host's processing seconds, and the stored
//! consumption.

use herness_supervision::{BudgetLimit, Money};
use serde::{Deserialize, Serialize};

use crate::contract::ContinuationLimits;
use crate::error::SddExecutionError;
use crate::snapshot::BudgetConsumption;
use crate::state::{BudgetExhaustionReason, HumanAction, StopReason};

/// One exhausted Task budget with the exact limit and the consumed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskBudgetExhaustion {
    reason: BudgetExhaustionReason,
    limit: u64,
    consumed: u64,
}

impl TaskBudgetExhaustion {
    /// Creates one typed exhaustion.
    pub const fn new(reason: BudgetExhaustionReason, limit: u64, consumed: u64) -> Self {
        Self {
            reason,
            limit,
            consumed,
        }
    }

    /// Which finite limit was reached.
    pub const fn reason(self) -> BudgetExhaustionReason {
        self.reason
    }

    /// The limit value.
    pub const fn limit(self) -> u64 {
        self.limit
    }

    /// The consumed value at the moment of refusal.
    pub const fn consumed(self) -> u64 {
        self.consumed
    }

    /// The execution-level stop reason.
    ///
    /// A seconds or run cap is a budget stop; three consecutive stalls are the
    /// Task's stall stop, which a human clears instead of raising a budget.
    pub const fn stop_reason(self) -> StopReason {
        match self.reason {
            BudgetExhaustionReason::ConsecutiveStalls => StopReason::ChildStalled,
            BudgetExhaustionReason::ActiveSeconds
            | BudgetExhaustionReason::AdditionalRuns
            | BudgetExhaustionReason::MoneyCap => StopReason::BudgetExhausted,
        }
    }

    /// The human action the stop requires.
    pub const fn human_action(self) -> HumanAction {
        match self.reason {
            BudgetExhaustionReason::ConsecutiveStalls => HumanAction::ClearStall,
            BudgetExhaustionReason::ActiveSeconds
            | BudgetExhaustionReason::AdditionalRuns
            | BudgetExhaustionReason::MoneyCap => HumanAction::RaiseBudget,
        }
    }

    /// The typed H4 error for callers that report rather than record a stop.
    pub fn error(self) -> SddExecutionError {
        SddExecutionError::BudgetExhausted {
            reason: self.reason,
            details: crate::error::FailureDetails::none().boxed(),
        }
    }
}

/// The durable combined consumption of one Task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskBudgetConsumption {
    active_seconds: u64,
    additional_runs: u32,
    consecutive_stalls: u32,
    #[serde(default)]
    money: Option<Money>,
}

impl TaskBudgetConsumption {
    /// No consumption.
    pub const fn zero() -> Self {
        Self {
            active_seconds: 0,
            additional_runs: 0,
            consecutive_stalls: 0,
            money: None,
        }
    }

    /// Creates an explicit consumption value.
    pub const fn new(
        active_seconds: u64,
        additional_runs: u32,
        consecutive_stalls: u32,
        money: Option<Money>,
    ) -> Self {
        Self {
            active_seconds,
            additional_runs,
            consecutive_stalls,
            money,
        }
    }

    /// Combined H2 and host active seconds.
    pub const fn active_seconds(self) -> u64 {
        self.active_seconds
    }

    /// Additional H2 child runs after the first.
    pub const fn additional_runs(self) -> u32 {
        self.additional_runs
    }

    /// Consecutive stall count.
    pub const fn consecutive_stalls(self) -> u32 {
        self.consecutive_stalls
    }

    /// Optional money amount.
    pub const fn money(self) -> Option<Money> {
        self.money
    }

    /// The snapshot-shaped consumption of this Task.
    pub fn snapshot_consumption(self) -> BudgetConsumption {
        BudgetConsumption::new(self.active_seconds, self.additional_runs, self.money)
    }
}

/// One finite Task budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskBudget {
    limits: ContinuationLimits,
    consumption: TaskBudgetConsumption,
    h2_completed: bool,
}

impl TaskBudget {
    /// A fresh Task budget with the fixed H4 limits.
    pub const fn h4_default() -> Self {
        Self {
            limits: ContinuationLimits::h4_default(),
            consumption: TaskBudgetConsumption::zero(),
            h2_completed: false,
        }
    }

    /// A fresh Task budget with explicit limits.
    ///
    /// The limits are validated against the fixed H4 values by every admission
    /// call; H4 never raises them.
    pub const fn new(limits: ContinuationLimits) -> Self {
        Self {
            limits,
            consumption: TaskBudgetConsumption::zero(),
            h2_completed: false,
        }
    }

    /// Rebuilds a Task budget from stored consumption.
    ///
    /// This is the resume path: the stored combined consumption is kept as-is,
    /// so a resume, a restart, or a plan re-approval never refunds anything.
    pub const fn resumed(limits: ContinuationLimits, stored: TaskBudgetConsumption) -> Self {
        Self {
            limits,
            consumption: stored,
            h2_completed: false,
        }
    }

    /// Rebuilds from a stored snapshot consumption and a separate stall count.
    pub fn from_snapshot(
        limits: ContinuationLimits,
        stored: BudgetConsumption,
        consecutive_stalls: u32,
    ) -> Result<Self, SddExecutionError> {
        limits.validate()?;
        Ok(Self::resumed(
            limits,
            TaskBudgetConsumption::new(
                stored.active_seconds(),
                stored.additional_runs(),
                consecutive_stalls,
                stored.money(),
            ),
        ))
    }

    /// The approved limits.
    pub const fn limits(self) -> ContinuationLimits {
        self.limits
    }

    /// Current consumption.
    pub const fn consumption(self) -> TaskBudgetConsumption {
        self.consumption
    }

    /// Remaining combined seconds.
    pub const fn remaining_seconds(self) -> u64 {
        self.limits
            .max_time_seconds()
            .saturating_sub(self.consumption.active_seconds)
    }

    /// Remaining additional runs.
    pub const fn remaining_additional_runs(self) -> u32 {
        self.limits
            .max_additional_runs()
            .saturating_sub(self.consumption.additional_runs)
    }

    /// Whether H2 reported completion for this Task.
    pub const fn h2_completed(self) -> bool {
        self.h2_completed
    }

    /// Re-reads H2's cumulative consumption.
    ///
    /// Both values are cumulative and monotonic. The observed seconds raise the
    /// combined bound; they never lower it, so an H2 ledger that reports less
    /// after a restart cannot refund consumption.
    pub fn observe_h2(&mut self, active_seconds: u64, additional_runs: u32) {
        self.consumption.active_seconds = self.consumption.active_seconds.max(active_seconds);
        self.consumption.additional_runs = self.consumption.additional_runs.max(additional_runs);
    }

    /// Re-reads H2's consecutive stall count.
    ///
    /// H2 owns the stall counter; H4 mirrors it so the combined decision sees
    /// the same three consecutive cycles.
    pub fn observe_stalls(&mut self, consecutive_stalls: u32) {
        self.consumption.consecutive_stalls =
            self.consumption.consecutive_stalls.max(consecutive_stalls);
    }

    /// Charges host processing after H2 completed for the Task.
    ///
    /// The seconds are added to the same Task total; a completion never resets
    /// the clock and never grants a new limit.
    pub fn charge_host_processing(&mut self, seconds: u64) {
        self.consumption.active_seconds = self.consumption.active_seconds.saturating_add(seconds);
    }

    /// Records one progress event, clearing the consecutive stall count.
    pub fn record_progress(&mut self) {
        self.consumption.consecutive_stalls = 0;
    }

    /// Records one stall without new progress.
    pub fn record_stall(&mut self) {
        self.consumption.consecutive_stalls = self.consumption.consecutive_stalls.saturating_add(1);
    }

    /// Marks that H2 completed this Task.
    ///
    /// It changes no consumption and no limit. The host processing that follows
    /// is charged to the same budget.
    pub fn mark_h2_completed(&mut self) {
        self.h2_completed = true;
    }

    /// Whether one more dispatch, continuation, or completion may start.
    pub fn admit(self) -> Result<(), TaskBudgetExhaustion> {
        let limits = self.limits;
        if self.consumption.active_seconds >= limits.max_time_seconds() {
            return Err(TaskBudgetExhaustion::new(
                BudgetExhaustionReason::ActiveSeconds,
                limits.max_time_seconds(),
                self.consumption.active_seconds,
            ));
        }
        if self.consumption.consecutive_stalls >= limits.max_consecutive_stalls() {
            return Err(TaskBudgetExhaustion::new(
                BudgetExhaustionReason::ConsecutiveStalls,
                u64::from(limits.max_consecutive_stalls()),
                u64::from(self.consumption.consecutive_stalls),
            ));
        }
        Ok(())
    }

    /// Whether one more child run may start.
    ///
    /// The first run is not counted; the 30 approved additional runs are. A
    /// dispatch is refused once 30 additional runs were consumed.
    pub fn admit_run(self) -> Result<(), TaskBudgetExhaustion> {
        self.admit()?;
        let limits = self.limits;
        if self.consumption.additional_runs >= limits.max_additional_runs() {
            return Err(TaskBudgetExhaustion::new(
                BudgetExhaustionReason::AdditionalRuns,
                u64::from(limits.max_additional_runs()),
                u64::from(self.consumption.additional_runs),
            ));
        }
        Ok(())
    }

    /// Whether the host may start its post-completion processing.
    ///
    /// A Task whose budget is exhausted is refused even when H2 reports the
    /// conditions met: "met after the limit" is not completion.
    pub fn admit_completion(self) -> Result<(), TaskBudgetExhaustion> {
        self.admit()
    }

    /// Maps H2's own limit onto H4's typed exhaustion reason.
    pub const fn h2_limit_reason(limit: BudgetLimit) -> BudgetExhaustionReason {
        match limit {
            BudgetLimit::ActiveSeconds => BudgetExhaustionReason::ActiveSeconds,
            BudgetLimit::RunCount => BudgetExhaustionReason::AdditionalRuns,
            BudgetLimit::Money => BudgetExhaustionReason::MoneyCap,
        }
    }
}

impl Default for TaskBudget {
    fn default() -> Self {
        Self::h4_default()
    }
}
