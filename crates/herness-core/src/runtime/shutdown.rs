//! Explicit application shutdown control.
//!
//! The runtime owns the host-side half of the quit contract: it stops accepting
//! new runs and tool executions, requests coordinated engine stops, saves the
//! checkpoints it can save, and records what it could not confirm. It never
//! turns a forced shutdown into a save or stop success.
//!
//! The desktop lifecycle module owns the human-facing grace period and choice.
//! This module exposes only additive core values and methods; no SDK dispose is
//! used as a substitute for a saveable stop.

use serde::Serialize;

use crate::contracts::ids::{ProjectId, RunId};
use crate::contracts::run::RunState;
use crate::ports::engine::StopReport;

/// Result state of one explicit shutdown attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownOutcome {
    /// The quit flow started but did not record a final state in this process.
    InProgress,
    /// Every active run was stopped and every available checkpoint was saved.
    Completed,
    /// Every active run reached a terminal state, but at least one stop was
    /// unconfirmed or a checkpoint could not be saved.
    CompletedWithUnconfirmed,
    /// The human chose to quit before coordinated stops finished.
    Forced,
}

/// One run processed by an explicit shutdown attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShutdownRun {
    project_id: ProjectId,
    run_id: RunId,
    state: RunState,
    report: Option<StopReport>,
    checkpoint_saved: bool,
    failure: Option<String>,
}

impl ShutdownRun {
    /// Creates one shutdown run report. Host-owned; not a UI contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        run_id: RunId,
        state: RunState,
        report: Option<StopReport>,
        checkpoint_saved: bool,
        failure: Option<String>,
    ) -> Self {
        Self {
            project_id,
            run_id,
            state,
            report,
            checkpoint_saved,
            failure,
        }
    }

    /// Project that owns the run.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Run that was processed.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Run state recorded after the attempt.
    pub const fn state(&self) -> RunState {
        self.state
    }

    /// Engine stop report, when the stop request returned.
    pub const fn report(&self) -> Option<StopReport> {
        self.report
    }

    /// Whether a checkpoint was persisted with this stop.
    pub const fn checkpoint_saved(&self) -> bool {
        self.checkpoint_saved
    }

    /// Sanitized failure when the stop or its save failed.
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
}

/// Result of an explicit shutdown attempt.
///
/// `save_succeeded` is true only when every active run ended without an
/// unconfirmed stop and every available checkpoint was saved. A forced or
/// unconfirmed shutdown never reports success, even when nothing remains
/// running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShutdownReport {
    outcome: ShutdownOutcome,
    runs: Vec<ShutdownRun>,
    unconfirmed_runs: Vec<RunId>,
    remaining_runs: Vec<RunId>,
    discarded_deferred_messages: u64,
    save_failures: u32,
}

impl ShutdownReport {
    /// Creates a shutdown report. Host-owned; not a UI contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        outcome: ShutdownOutcome,
        runs: Vec<ShutdownRun>,
        unconfirmed_runs: Vec<RunId>,
        remaining_runs: Vec<RunId>,
        discarded_deferred_messages: u64,
        save_failures: u32,
    ) -> Self {
        Self {
            outcome,
            runs,
            unconfirmed_runs,
            remaining_runs,
            discarded_deferred_messages,
            save_failures,
        }
    }

    /// Final or in-progress outcome.
    pub const fn outcome(&self) -> ShutdownOutcome {
        self.outcome
    }

    /// Runs processed in this attempt.
    pub fn runs(&self) -> &[ShutdownRun] {
        &self.runs
    }

    /// Runs whose stop was unconfirmed or whose stop request failed.
    pub fn unconfirmed_runs(&self) -> &[RunId] {
        &self.unconfirmed_runs
    }

    /// Runs still active after the attempt.
    pub fn remaining_runs(&self) -> &[RunId] {
        &self.remaining_runs
    }

    /// In-memory host-result messages discarded rather than replayed.
    pub const fn discarded_deferred_messages(&self) -> u64 {
        self.discarded_deferred_messages
    }

    /// Number of stop or save failures recorded.
    pub const fn save_failures(&self) -> u32 {
        self.save_failures
    }

    /// Whether the shutdown fully saved and stopped every active run.
    pub fn save_succeeded(&self) -> bool {
        matches!(self.outcome, ShutdownOutcome::Completed)
            && self.unconfirmed_runs.is_empty()
            && self.remaining_runs.is_empty()
            && self.save_failures == 0
            && self.runs.iter().all(ShutdownRun::checkpoint_saved)
    }

    /// Whether every run is out of an active state.
    pub fn all_inactive(&self) -> bool {
        self.remaining_runs.is_empty()
    }
}
