//! Durable H2 budget ledger.
//!
//! The ledger owns one supervision target's cumulative active seconds, run
//! count, and optional money reservations. It never reads the wall or monotonic
//! clock directly and never opens a database: both are injected through
//! [`BudgetClockPort`] and [`BudgetStorePort`]. Every mutation is a
//! compare-and-set write, so a stale writer cannot spend the same budget twice.
//!
//! Time accounting is conservative. An interval that is still Active when the
//! host crashes is charged up to the next observation using the larger of the
//! monotonic and wall-clock elapsed values. Fractional seconds round up. Missing
//! usage and unknown send results keep their reservation; a preflight failure
//! that definitely did not send releases it.

use std::collections::BTreeMap;

use herness_core::contracts::{
    AttemptId, AuthMethod, ModelRequestObservation, ProjectId, RequestGateIntent, RequestId,
    Timestamp,
};
use serde::{Deserialize, Serialize};

use crate::budget::{
    BudgetClockState, BudgetLimit, BudgetPolicy, BudgetPriceReason, BudgetUsage, Money,
    PriceVersion, RequestBudgetEstimate,
};
use crate::error::SupervisionError;
use crate::ids::{BudgetRequestId, SupervisionId};
use crate::ports::BudgetStorePort;

/// Maximum compare-and-set attempts before a ledger write gives up.
pub const BUDGET_MAX_CAS_ATTEMPTS: u8 = 4;

/// One wall and monotonic reading taken at the same instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockReading {
    wall: Timestamp,
    monotonic_millis: u64,
}

impl ClockReading {
    /// Creates a paired reading.
    ///
    /// The monotonic value must come from a clock that never moves backwards
    /// within one process. Across a process restart the ledger falls back to
    /// the wall-clock difference when the monotonic value is smaller.
    pub const fn new(wall: Timestamp, monotonic_millis: u64) -> Self {
        Self {
            wall,
            monotonic_millis,
        }
    }

    /// Wall-clock timestamp.
    pub const fn wall(self) -> Timestamp {
        self.wall
    }

    /// Monotonic milliseconds within the current process.
    pub const fn monotonic_millis(self) -> u64 {
        self.monotonic_millis
    }
}

/// Injected wall and monotonic clock for the budget ledger.
pub trait BudgetClockPort {
    /// Reads both clocks at one instant.
    fn read(&self) -> ClockReading;
}

/// One open active-time interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveInterval {
    wall_start_millis: u64,
    monotonic_start_millis: u64,
}

impl ActiveInterval {
    fn at(reading: ClockReading) -> Self {
        Self {
            wall_start_millis: reading.wall.as_unix_millis(),
            monotonic_start_millis: reading.monotonic_millis,
        }
    }

    /// Wall-clock start in unix milliseconds.
    pub const fn wall_start_millis(self) -> u64 {
        self.wall_start_millis
    }

    /// Monotonic start in milliseconds.
    pub const fn monotonic_start_millis(self) -> u64 {
        self.monotonic_start_millis
    }

    fn elapsed_seconds(self, reading: ClockReading) -> u64 {
        let monotonic = reading
            .monotonic_millis
            .saturating_sub(self.monotonic_start_millis);
        let wall = reading
            .wall
            .as_unix_millis()
            .saturating_sub(self.wall_start_millis);
        // Taking the larger value is conservative across a monotonic reset, a
        // wall-clock jump, and ordinary elapsed time. Sub-second fractions
        // round up so many short intervals cannot hide a second.
        monotonic.max(wall).div_ceil(1_000)
    }
}

/// State of one run reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunReservationState {
    /// The run count is reserved but the run has not started.
    Reserved,
    /// The run count is consumed. This state survives a crash.
    Started,
    /// The run finished; its run count stays consumed.
    Finished,
}

/// One idempotent run reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunReservation {
    state: RunReservationState,
}

impl RunReservation {
    /// Current reservation state.
    pub const fn state(&self) -> RunReservationState {
        self.state
    }

    /// Whether the run count has been consumed.
    pub const fn consumed(&self) -> bool {
        matches!(
            self.state,
            RunReservationState::Started | RunReservationState::Finished
        )
    }
}

/// State of one money reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneyReservationState {
    /// Reserved before send and not yet settled.
    Reserved,
    /// Settled to at least the reserved local estimate.
    Settled {
        /// Amount accounted as consumed.
        amount: Money,
    },
    /// Sent, but usage or price is missing. The reservation keeps counting.
    Unresolved,
    /// Definitely not sent; the reservation was released.
    Released,
}

/// One money reservation keyed by send attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MoneyReservation {
    request_id: RequestId,
    estimate: Money,
    price_version: PriceVersion,
    state: MoneyReservationState,
}

impl MoneyReservation {
    /// Request this reservation belongs to.
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Conservative local estimate reserved before send.
    pub const fn estimate(&self) -> Money {
        self.estimate
    }

    /// Price version used for the estimate.
    pub fn price_version(&self) -> &PriceVersion {
        &self.price_version
    }

    /// Current reservation state.
    pub fn state(&self) -> &MoneyReservationState {
        &self.state
    }

    /// Whether this reservation still counts against the cap.
    pub fn keeps_counting(&self) -> bool {
        matches!(
            self.state,
            MoneyReservationState::Reserved | MoneyReservationState::Unresolved
        )
    }
}

/// Settlement decision for one attempted send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoneySettlement {
    /// The provider completed the request. The ledger consumes at least the
    /// reserved estimate; `actual` may be higher but never lower.
    Completed {
        /// Locally computed actual amount.
        actual: Money,
    },
    /// The send may have happened but usage or price is missing. The
    /// reservation becomes unresolved and keeps counting.
    Unresolved,
    /// The request definitely did not send. The reservation is released.
    NotSent,
    /// Sending started; keep the reservation reserved.
    Sent,
}

/// One persisted budget ledger payload.
///
/// The policy snapshot, usage counters, clock state, open interval, run
/// reservations, and money reservations are one value so a store can compare
/// and swap all of them together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BudgetLedgerRecord {
    policy: BudgetPolicy,
    policy_version: u64,
    usage: BudgetUsage,
    clock_state: BudgetClockState,
    open_interval: Option<ActiveInterval>,
    runs: BTreeMap<BudgetRequestId, RunReservation>,
    money: BTreeMap<AttemptId, MoneyReservation>,
}

impl BudgetLedgerRecord {
    /// Creates an empty record. Time starts excluded until a run or an explicit
    /// Active transition opens the first interval.
    pub fn new(policy: BudgetPolicy, policy_version: u64) -> Result<Self, SupervisionError> {
        policy.validate()?;
        if policy_version == 0 {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.policyVersion".to_owned(),
                detail: "the policy version must be positive".to_owned(),
            });
        }
        Ok(Self {
            policy,
            policy_version,
            usage: BudgetUsage::empty(),
            clock_state: BudgetClockState::AppStopped,
            open_interval: None,
            runs: BTreeMap::new(),
            money: BTreeMap::new(),
        })
    }

    /// Budget policy snapshot.
    pub const fn policy(&self) -> &BudgetPolicy {
        &self.policy
    }

    /// Policy snapshot version.
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// Persisted usage counters. This excludes the currently open interval.
    pub const fn usage(&self) -> BudgetUsage {
        self.usage
    }

    /// Current activity state.
    pub const fn clock_state(&self) -> BudgetClockState {
        self.clock_state
    }

    /// Open interval, when Active.
    pub const fn open_interval(&self) -> Option<ActiveInterval> {
        self.open_interval
    }

    /// Run reservations in stable order.
    pub fn run_reservations(&self) -> &BTreeMap<BudgetRequestId, RunReservation> {
        &self.runs
    }

    /// Money reservations in stable attempt order.
    pub fn money_reservations(&self) -> &BTreeMap<AttemptId, MoneyReservation> {
        &self.money
    }

    /// One money reservation.
    pub fn money_reservation(&self, attempt: AttemptId) -> Option<&MoneyReservation> {
        self.money.get(&attempt)
    }

    /// Replaces the finite policy snapshot and version.
    ///
    /// Used only by an explicit human limit change. The caller validates that
    /// the new version is newer and that consumed runs still fit.
    pub(crate) fn replace_policy(&mut self, policy: BudgetPolicy, policy_version: u64) {
        self.policy = policy;
        self.policy_version = policy_version;
    }

    /// Reservations whose usage or result is still unresolved.
    pub fn unresolved_charges(&self) -> Vec<MoneyReservation> {
        self.money
            .values()
            .filter(|reservation| matches!(reservation.state, MoneyReservationState::Unresolved))
            .cloned()
            .collect()
    }

    /// Reservations still counting against the cap, including unresolved ones.
    pub fn outstanding_charges(&self) -> Vec<MoneyReservation> {
        self.money
            .values()
            .filter(|reservation| reservation.keeps_counting())
            .cloned()
            .collect()
    }

    /// Charges active time up to `reading` and reopens the interval at that
    /// instant while the state is Active.
    pub fn charge_to(&mut self, reading: ClockReading) {
        if self.clock_state.counts_toward_active_time() {
            if let Some(interval) = self.open_interval {
                self.usage.active_seconds_consumed = self
                    .usage
                    .active_seconds_consumed
                    .saturating_add(interval.elapsed_seconds(reading));
            }
            self.open_interval = Some(ActiveInterval::at(reading));
        } else {
            self.open_interval = None;
        }
    }

    /// Usage after charging the currently open interval up to `reading`.
    pub fn effective_usage(&self, reading: ClockReading) -> BudgetUsage {
        let mut copy = self.clone();
        copy.charge_to(reading);
        copy.usage
    }

    /// Remaining active seconds after charging the open interval.
    pub fn remaining_active_seconds(&self, reading: ClockReading) -> u64 {
        self.effective_usage(reading)
            .remaining_active_seconds(&self.policy)
    }

    /// Assessment timeout: 60 seconds or the remaining active time, whichever
    /// is shorter.
    pub fn assessment_timeout_seconds(&self, reading: ClockReading) -> u64 {
        crate::budget::assessment_timeout_seconds(&self.policy, &self.effective_usage(reading))
    }

    /// Transitions the activity state. Only Active accrues time.
    pub fn set_clock_state(&mut self, state: BudgetClockState, reading: ClockReading) {
        self.charge_to(reading);
        self.clock_state = state;
        self.open_interval = state
            .counts_toward_active_time()
            .then(|| ActiveInterval::at(reading));
    }

    /// Rejects work while the ledger is not Active.
    pub fn require_active(&self) -> Result<(), SupervisionError> {
        if self.clock_state.counts_toward_active_time() {
            Ok(())
        } else {
            Err(SupervisionError::BudgetInactive {
                state: self.clock_state,
            })
        }
    }

    /// Reserves one run count. The first run is included and the total never
    /// exceeds the policy maximum.
    pub fn reserve_run(
        &mut self,
        request: BudgetRequestId,
    ) -> Result<RunReservation, SupervisionError> {
        if let Some(existing) = self.runs.get(&request) {
            return Ok(existing.clone());
        }
        if self
            .usage
            .runs_started
            .saturating_add(self.usage.runs_reserved)
            >= self.policy.max_total_runs()
        {
            return Err(SupervisionError::BudgetLimitReached {
                limit: BudgetLimit::RunCount,
            });
        }
        self.usage.runs_reserved =
            self.usage
                .runs_reserved
                .checked_add(1)
                .ok_or(SupervisionError::BudgetInvalid {
                    field: "budget.runsReserved".to_owned(),
                    detail: "the run reservation count overflowed".to_owned(),
                })?;
        let reservation = RunReservation {
            state: RunReservationState::Reserved,
        };
        self.runs.insert(request, reservation.clone());
        Ok(reservation)
    }

    /// Consumes one run count. A repeated start with the same request ID
    /// returns the recorded result instead of consuming again. A persisted
    /// start intent keeps the count consumed across a crash.
    pub fn start_run(
        &mut self,
        request: BudgetRequestId,
    ) -> Result<RunReservation, SupervisionError> {
        if let Some(existing) = self.runs.get(&request) {
            match existing.state {
                RunReservationState::Reserved => {
                    self.usage.runs_reserved = self.usage.runs_reserved.saturating_sub(1);
                    self.usage.runs_started =
                        self.usage.runs_started.checked_add(1).ok_or_else(|| {
                            SupervisionError::BudgetInvalid {
                                field: "budget.runsStarted".to_owned(),
                                detail: "the run count overflowed".to_owned(),
                            }
                        })?;
                    let started = RunReservation {
                        state: RunReservationState::Started,
                    };
                    self.runs.insert(request, started.clone());
                    return Ok(started);
                }
                RunReservationState::Started | RunReservationState::Finished => {
                    return Ok(existing.clone());
                }
            }
        }
        if self
            .usage
            .runs_started
            .saturating_add(self.usage.runs_reserved)
            >= self.policy.max_total_runs()
        {
            return Err(SupervisionError::BudgetLimitReached {
                limit: BudgetLimit::RunCount,
            });
        }
        self.usage.runs_started =
            self.usage
                .runs_started
                .checked_add(1)
                .ok_or(SupervisionError::BudgetInvalid {
                    field: "budget.runsStarted".to_owned(),
                    detail: "the run count overflowed".to_owned(),
                })?;
        let started = RunReservation {
            state: RunReservationState::Started,
        };
        self.runs.insert(request, started.clone());
        Ok(started)
    }

    /// Marks one started run finished. The consumed count is never returned.
    pub fn finish_run(
        &mut self,
        request: BudgetRequestId,
    ) -> Result<RunReservation, SupervisionError> {
        let Some(existing) = self.runs.get(&request) else {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.run".to_owned(),
                detail: "the run request has no recorded reservation".to_owned(),
            });
        };
        match existing.state {
            RunReservationState::Started | RunReservationState::Finished => {
                let finished = RunReservation {
                    state: RunReservationState::Finished,
                };
                self.runs.insert(request, finished.clone());
                Ok(finished)
            }
            RunReservationState::Reserved => Err(SupervisionError::BudgetInvalid {
                field: "budget.run".to_owned(),
                detail: "a reserved run must start before it can finish".to_owned(),
            }),
        }
    }

    /// Reserves one conservative request estimate under the money cap.
    ///
    /// Duplicate reservations with the same attempt, request, estimate, and
    /// price version are idempotent while still reserved. A settled or
    /// released attempt cannot be reserved again.
    pub fn reserve_money(
        &mut self,
        request: RequestId,
        attempt: AttemptId,
        estimate: Money,
        price_version: &PriceVersion,
    ) -> Result<MoneyReservation, SupervisionError> {
        let Some(cap) = self.policy.money_cap() else {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.moneyCap".to_owned(),
                detail: "no money cap is configured".to_owned(),
            });
        };
        if price_version != cap.price_version() {
            return Err(SupervisionError::BudgetPriceUnavailable {
                reason: BudgetPriceReason::PriceVersionMismatch {
                    expected: cap.price_version().clone(),
                    found: price_version.clone(),
                },
            });
        }
        if let Some((existing_attempt, _)) = self
            .money
            .iter()
            .find(|(_, reservation)| reservation.request_id == request)
            && *existing_attempt != attempt
        {
            return Err(SupervisionError::BudgetReservationConflict {
                attempt: attempt.to_string(),
            });
        }
        if let Some(existing) = self.money.get(&attempt) {
            if existing.request_id == request
                && existing.estimate == estimate
                && existing.price_version == *price_version
                && existing.state == MoneyReservationState::Reserved
            {
                return Ok(existing.clone());
            }
            return Err(SupervisionError::BudgetReservationConflict {
                attempt: attempt.to_string(),
            });
        }
        let total = self
            .usage
            .money_consumed
            .checked_add(self.usage.money_reserved)?
            .checked_add(estimate)?;
        if total.micros() > cap.limit().micros() {
            return Err(SupervisionError::BudgetLimitReached {
                limit: BudgetLimit::Money,
            });
        }
        self.usage.money_reserved = Money::from_micros(
            self.usage
                .money_reserved
                .micros()
                .checked_add(estimate.micros())
                .ok_or(SupervisionError::BudgetInvalid {
                    field: "budget.moneyReserved".to_owned(),
                    detail: "the reserved money amount overflowed".to_owned(),
                })?,
        );
        let reservation = MoneyReservation {
            request_id: request,
            estimate,
            price_version: price_version.clone(),
            state: MoneyReservationState::Reserved,
        };
        self.money.insert(attempt, reservation.clone());
        Ok(reservation)
    }

    /// Applies one settlement to a money reservation.
    ///
    /// A completed request consumes at least the reserved estimate. Unresolved
    /// usage keeps the reservation counting. Only a preflight failure that
    /// definitely did not send releases it.
    pub fn settle_money(
        &mut self,
        attempt: AttemptId,
        settlement: MoneySettlement,
    ) -> Result<MoneyReservation, SupervisionError> {
        let Some(existing) = self.money.get(&attempt).cloned() else {
            return Err(SupervisionError::UnknownBudgetReservation {
                attempt: attempt.to_string(),
            });
        };
        if settlement == MoneySettlement::Sent {
            return Ok(existing);
        }
        let next_state = match (&existing.state, settlement) {
            (
                MoneyReservationState::Reserved | MoneyReservationState::Unresolved,
                MoneySettlement::Completed { actual },
            ) => {
                let amount = Money::from_micros(existing.estimate.micros().max(actual.micros()));
                self.usage.money_reserved = Money::from_micros(
                    self.usage
                        .money_reserved
                        .micros()
                        .saturating_sub(existing.estimate.micros()),
                );
                self.usage.money_consumed = Money::from_micros(
                    self.usage
                        .money_consumed
                        .micros()
                        .checked_add(amount.micros())
                        .ok_or(SupervisionError::BudgetInvalid {
                            field: "budget.moneyConsumed".to_owned(),
                            detail: "the consumed money amount overflowed".to_owned(),
                        })?,
                );
                MoneyReservationState::Settled { amount }
            }
            (MoneyReservationState::Reserved, MoneySettlement::Unresolved) => {
                MoneyReservationState::Unresolved
            }
            (MoneyReservationState::Unresolved, MoneySettlement::Unresolved) => {
                return Ok(existing);
            }
            (MoneyReservationState::Reserved, MoneySettlement::NotSent) => {
                self.usage.money_reserved = Money::from_micros(
                    self.usage
                        .money_reserved
                        .micros()
                        .saturating_sub(existing.estimate.micros()),
                );
                MoneyReservationState::Released
            }
            (MoneyReservationState::Released, MoneySettlement::NotSent) => {
                return Ok(existing);
            }
            (MoneyReservationState::Settled { .. }, MoneySettlement::Completed { .. }) => {
                return Ok(existing);
            }
            _ => {
                return Err(SupervisionError::BudgetReservationConflict {
                    attempt: attempt.to_string(),
                });
            }
        };
        let settled = MoneyReservation {
            state: next_state,
            ..existing
        };
        self.money.insert(attempt, settled.clone());
        Ok(settled)
    }

    /// Revalidates the persisted record before a write or after a read.
    pub fn validate(&self) -> Result<(), SupervisionError> {
        self.policy.validate()?;
        if self.policy_version == 0 {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.policyVersion".to_owned(),
                detail: "the policy version must be positive".to_owned(),
            });
        }
        if self.clock_state.counts_toward_active_time() && self.open_interval.is_none() {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.openInterval".to_owned(),
                detail: "an Active ledger must have an open interval".to_owned(),
            });
        }
        if !self.clock_state.counts_toward_active_time() && self.open_interval.is_some() {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.openInterval".to_owned(),
                detail: "a non-Active ledger must not have an open interval".to_owned(),
            });
        }
        let started = self
            .runs
            .values()
            .filter(|reservation| reservation.consumed())
            .count();
        let reserved = self
            .runs
            .values()
            .filter(|reservation| reservation.state == RunReservationState::Reserved)
            .count();
        if u32::try_from(started).ok() != Some(self.usage.runs_started)
            || u32::try_from(reserved).ok() != Some(self.usage.runs_reserved)
        {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.runs".to_owned(),
                detail: "the run counters do not match their reservations".to_owned(),
            });
        }
        if self
            .usage
            .runs_started
            .saturating_add(self.usage.runs_reserved)
            > self.policy.max_total_runs()
        {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.runs".to_owned(),
                detail: "the run count exceeds the policy maximum".to_owned(),
            });
        }
        let mut consumed = Money::zero();
        let mut reserved_money = Money::zero();
        let mut request_ids = std::collections::BTreeSet::new();
        for reservation in self.money.values() {
            if !request_ids.insert(reservation.request_id) {
                return Err(SupervisionError::BudgetInvalid {
                    field: "budget.money".to_owned(),
                    detail: "one request ID is bound to several attempts".to_owned(),
                });
            }
            match reservation.state {
                MoneyReservationState::Reserved | MoneyReservationState::Unresolved => {
                    reserved_money = reserved_money.checked_add(reservation.estimate)?;
                }
                MoneyReservationState::Settled { amount } => {
                    if amount.micros() < reservation.estimate.micros() {
                        return Err(SupervisionError::BudgetInvalid {
                            field: "budget.money".to_owned(),
                            detail: "a settled request is below its reserved estimate".to_owned(),
                        });
                    }
                    consumed = consumed.checked_add(amount)?;
                }
                MoneyReservationState::Released => {}
            }
        }
        if consumed != self.usage.money_consumed || reserved_money != self.usage.money_reserved {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.money".to_owned(),
                detail: "the money counters do not match their reservations".to_owned(),
            });
        }
        Ok(())
    }
}

/// Durable ledger control for one supervision target.
pub struct BudgetLedger<S: BudgetStorePort, C: BudgetClockPort> {
    project: ProjectId,
    supervision: SupervisionId,
    store: S,
    clock: C,
    current: BudgetLedgerRecord,
    revision: Option<u64>,
}

impl<S: BudgetStorePort, C: BudgetClockPort> BudgetLedger<S, C> {
    /// Opens or creates one supervision ledger.
    ///
    /// An existing record must match the supplied policy snapshot. An active
    /// interval left open by a crash is charged conservatively to the current
    /// reading before the ledger becomes usable.
    pub fn open(
        store: S,
        project: ProjectId,
        supervision: SupervisionId,
        policy: BudgetPolicy,
        policy_version: u64,
        clock: C,
    ) -> Result<Self, SupervisionError> {
        supervision.validate_in(project)?;
        let fresh = BudgetLedgerRecord::new(policy, policy_version)?;
        let mut ledger = Self {
            project,
            supervision,
            store,
            clock,
            current: fresh.clone(),
            revision: None,
        };
        if let Some(stored) = ledger.store.load_budget(project, supervision)? {
            Self::check_policy(&fresh, stored.record())?;
            stored.record().validate()?;
            ledger.revision = Some(stored.revision());
            ledger.current = stored.into_record();
            ledger.charge_reopened_interval()?;
        }
        Ok(ledger)
    }

    fn check_policy(
        expected: &BudgetLedgerRecord,
        found: &BudgetLedgerRecord,
    ) -> Result<(), SupervisionError> {
        if expected.policy != found.policy || expected.policy_version != found.policy_version {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.policy".to_owned(),
                detail: "the stored policy snapshot differs from the supplied policy".to_owned(),
            });
        }
        Ok(())
    }

    fn reload(&mut self) -> Result<(), SupervisionError> {
        match self.store.load_budget(self.project, self.supervision)? {
            Some(stored) => {
                stored.record().validate()?;
                Self::check_policy(&self.current, stored.record())?;
                self.revision = Some(stored.revision());
                self.current = stored.into_record();
                Ok(())
            }
            None if self.revision.is_none() => Ok(()),
            None => Err(SupervisionError::StorageFailure {
                detail: "the durable budget record disappeared".to_owned(),
            }),
        }
    }

    fn charge_reopened_interval(&mut self) -> Result<(), SupervisionError> {
        if !self.current.clock_state.counts_toward_active_time()
            || self.current.open_interval.is_none()
        {
            return Ok(());
        }
        for _ in 0..BUDGET_MAX_CAS_ATTEMPTS {
            let reading = self.clock.read();
            let mut next = self.current.clone();
            next.charge_to(reading);
            next.validate()?;
            match self.store.compare_and_swap_budget(
                self.project,
                self.supervision,
                self.revision,
                &next,
            ) {
                Ok(revision) => {
                    self.current = next;
                    self.revision = Some(revision);
                    return Ok(());
                }
                Err(SupervisionError::RevisionConflict { .. }) => {
                    self.reload()?;
                    if !self.current.clock_state.counts_toward_active_time() {
                        return Ok(());
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(SupervisionError::StorageFailure {
            detail: "the reopened active interval could not be recorded".to_owned(),
        })
    }

    fn mutate<T>(
        &mut self,
        mut change: impl FnMut(&mut BudgetLedgerRecord, ClockReading) -> Result<T, SupervisionError>,
    ) -> Result<T, SupervisionError> {
        for _ in 0..BUDGET_MAX_CAS_ATTEMPTS {
            self.reload()?;
            let reading = self.clock.read();
            let mut next = self.current.clone();
            next.charge_to(reading);
            let output = change(&mut next, reading)?;
            next.validate()?;
            match self.store.compare_and_swap_budget(
                self.project,
                self.supervision,
                self.revision,
                &next,
            ) {
                Ok(revision) => {
                    self.current = next;
                    self.revision = Some(revision);
                    return Ok(output);
                }
                Err(SupervisionError::RevisionConflict { .. }) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(SupervisionError::StorageFailure {
            detail: "the budget compare-and-swap kept conflicting".to_owned(),
        })
    }

    /// Project this ledger belongs to.
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Supervision target this ledger belongs to.
    pub const fn supervision(&self) -> SupervisionId {
        self.supervision
    }

    /// Latest persisted record.
    pub const fn record(&self) -> &BudgetLedgerRecord {
        &self.current
    }

    /// Latest persisted revision, or `None` before the first write.
    pub const fn revision(&self) -> Option<u64> {
        self.revision
    }

    /// Injected store.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Injected store for host-side inspection after a call.
    pub const fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Charges the open interval to the current reading and persists it.
    pub fn settle_active(&mut self) -> Result<(), SupervisionError> {
        self.mutate(|_, _| Ok(()))
    }

    /// Transitions the activity state.
    pub fn set_clock_state(&mut self, state: BudgetClockState) -> Result<(), SupervisionError> {
        self.mutate(|record, reading| {
            record.set_clock_state(state, reading);
            Ok(())
        })
    }

    /// Opens an Active interval.
    pub fn begin_active(&mut self) -> Result<(), SupervisionError> {
        self.set_clock_state(BudgetClockState::Active)
    }

    /// Excludes human waiting from active time.
    pub fn wait_for_human(&mut self) -> Result<(), SupervisionError> {
        self.set_clock_state(BudgetClockState::WaitingHuman)
    }

    /// Starts an explicit human pause.
    pub fn pause(&mut self) -> Result<(), SupervisionError> {
        self.set_clock_state(BudgetClockState::Paused)
    }

    /// Excludes application-stopped time.
    pub fn app_stop(&mut self) -> Result<(), SupervisionError> {
        self.set_clock_state(BudgetClockState::AppStopped)
    }

    /// Changes the finite policy and its durable version after a human change.
    ///
    /// The new version must be strictly newer. A policy that would put already
    /// consumed runs above the new maximum is rejected, so the ledger invariant
    /// keeps holding. Consumed active seconds and money are never reset.
    pub fn change_policy(
        &mut self,
        policy: BudgetPolicy,
        policy_version: u64,
    ) -> Result<(), SupervisionError> {
        policy.validate()?;
        if policy_version == 0 {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.policyVersion".to_owned(),
                detail: "the policy version must be positive".to_owned(),
            });
        }
        self.mutate(|record, _| {
            if policy_version <= record.policy_version() {
                return Err(SupervisionError::BudgetInvalid {
                    field: "budget.policyVersion".to_owned(),
                    detail: "a changed policy version must be newer".to_owned(),
                });
            }
            if record.usage().runs_started > policy.max_total_runs() {
                return Err(SupervisionError::BudgetInvalid {
                    field: "budget.additionalRuns".to_owned(),
                    detail: "the new run limit is below the already consumed run count".to_owned(),
                });
            }
            record.replace_policy(policy.clone(), policy_version);
            Ok(())
        })
    }

    /// Reserves one run count without consuming it.
    pub fn reserve_run(
        &mut self,
        request: BudgetRequestId,
    ) -> Result<RunReservation, SupervisionError> {
        self.mutate(|record, _| record.reserve_run(request))
    }

    /// Consumes one run count and makes the ledger Active.
    pub fn start_run(
        &mut self,
        request: BudgetRequestId,
    ) -> Result<RunReservation, SupervisionError> {
        self.mutate(|record, reading| {
            record.set_clock_state(BudgetClockState::Active, reading);
            record.start_run(request)
        })
    }

    /// Marks one started run finished without returning its consumed count.
    pub fn finish_run(
        &mut self,
        request: BudgetRequestId,
    ) -> Result<RunReservation, SupervisionError> {
        self.mutate(|record, _| record.finish_run(request))
    }

    /// Reserves one money estimate directly. The gate uses the same operation
    /// atomically with the request intent.
    pub fn reserve_money(
        &mut self,
        request: RequestId,
        attempt: AttemptId,
        estimate: Money,
        price_version: &PriceVersion,
    ) -> Result<MoneyReservation, SupervisionError> {
        self.mutate(|record, _| record.reserve_money(request, attempt, estimate, price_version))
    }

    /// Settles one money reservation.
    pub fn settle_money(
        &mut self,
        attempt: AttemptId,
        settlement: MoneySettlement,
    ) -> Result<MoneyReservation, SupervisionError> {
        self.mutate(|record, _| record.settle_money(attempt, settlement))
    }

    /// Remaining active seconds after charging the open interval.
    pub fn remaining_active_seconds(&mut self) -> Result<u64, SupervisionError> {
        self.reload()?;
        Ok(self.current.remaining_active_seconds(self.clock.read()))
    }

    /// Effective usage including the open interval, without persisting it.
    pub fn effective_usage(&mut self) -> Result<BudgetUsage, SupervisionError> {
        self.reload()?;
        Ok(self.current.effective_usage(self.clock.read()))
    }

    /// Assessment timeout: 60 seconds or remaining active time, whichever is
    /// shorter.
    pub fn assessment_timeout(&mut self) -> Result<u64, SupervisionError> {
        self.reload()?;
        Ok(self.current.assessment_timeout_seconds(self.clock.read()))
    }

    /// Unresolved charges. They keep counting against the cap.
    pub fn unresolved_charges(&mut self) -> Result<Vec<MoneyReservation>, SupervisionError> {
        self.reload()?;
        Ok(self.current.unresolved_charges())
    }

    /// Admits one model request: checks Active state, the remaining active
    /// time, and (when configured) the money cap, then commits the request
    /// intent and money reservation in one atomic store operation.
    ///
    /// A duplicate attempt with an identical still-reserved estimate is
    /// idempotent. A settled or released attempt cannot be admitted again.
    pub fn admit_request(
        &mut self,
        intent: &RequestGateIntent,
        estimate: Option<&RequestBudgetEstimate>,
    ) -> Result<(), SupervisionError> {
        if intent.subject().project_id() != self.project {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "request subject".to_owned(),
                expected: self.project,
                found: intent.subject().project_id(),
            });
        }
        for _ in 0..BUDGET_MAX_CAS_ATTEMPTS {
            self.reload()?;
            let reading = self.clock.read();
            let mut next = self.current.clone();
            next.charge_to(reading);
            next.require_active()?;
            if next.remaining_active_seconds(reading) == 0 {
                return Err(SupervisionError::BudgetLimitReached {
                    limit: BudgetLimit::ActiveSeconds,
                });
            }
            if next.policy.money_cap().is_some() {
                let estimate = estimate.ok_or(SupervisionError::BudgetPriceUnavailable {
                    reason: BudgetPriceReason::MissingEstimate,
                })?;
                if estimate.auth_method() == AuthMethod::ChatGptLogin {
                    return Err(SupervisionError::BudgetPriceUnavailable {
                        reason: BudgetPriceReason::ChatGptLoginWithMoneyCap,
                    });
                }
                next.reserve_money(
                    intent.request_id(),
                    intent.attempt_id(),
                    estimate.estimate(),
                    estimate.price_version(),
                )?;
            }
            next.validate()?;
            match self.store.commit_budget_admission(
                self.project,
                self.supervision,
                self.revision,
                &next,
                intent,
                reading.wall(),
            ) {
                Ok(revision) => {
                    self.current = next;
                    self.revision = Some(revision);
                    return Ok(());
                }
                Err(SupervisionError::RevisionConflict { .. }) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(SupervisionError::StorageFailure {
            detail: "the budget admission compare-and-swap kept conflicting".to_owned(),
        })
    }

    /// Records one observation and applies its money settlement atomically.
    pub fn observe_request(
        &mut self,
        observation: &ModelRequestObservation,
        settlement: MoneySettlement,
    ) -> Result<(), SupervisionError> {
        if observation.request_id().project_id() != self.project
            || observation.attempt_id().project_id() != self.project
        {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "request observation".to_owned(),
                expected: self.project,
                found: observation.request_id().project_id(),
            });
        }
        for _ in 0..BUDGET_MAX_CAS_ATTEMPTS {
            self.reload()?;
            let reading = self.clock.read();
            let mut next = self.current.clone();
            next.charge_to(reading);
            let has_reservation = next.money.contains_key(&observation.attempt_id());
            if has_reservation {
                next.settle_money(observation.attempt_id(), settlement)?;
            } else if next.policy.money_cap().is_some() {
                return Err(SupervisionError::UnknownBudgetReservation {
                    attempt: observation.attempt_id().to_string(),
                });
            }
            next.validate()?;
            match self.store.commit_budget_observation(
                self.project,
                self.supervision,
                self.revision,
                &next,
                observation,
                reading.wall(),
            ) {
                Ok(revision) => {
                    self.current = next;
                    self.revision = Some(revision);
                    return Ok(());
                }
                Err(SupervisionError::RevisionConflict { .. }) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(SupervisionError::StorageFailure {
            detail: "the budget observation compare-and-swap kept conflicting".to_owned(),
        })
    }
}
