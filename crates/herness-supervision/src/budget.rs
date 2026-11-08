//! Finite supervision budget contract.
//!
//! The H2 defaults are 7,200 cumulative active seconds and 30 additional runs,
//! for at most 31 runs including the first. Active time includes the first run,
//! verification, assessment, permission evaluation, and retry waits; human
//! waiting, an explicit pause, and application shutdown are excluded. Task 9
//! implements the durable ledger; this module defines only the contract and
//! validation.

use std::fmt;

use herness_core::contracts::AuthMethod;
use serde::{Deserialize, Serialize};

use crate::error::SupervisionError;

pub mod gate;
pub mod ledger;

/// Cumulative active-time limit in seconds.
pub const H2_ACTIVE_SECONDS: u64 = 7_200;
/// Additional runs after the first.
pub const H2_ADDITIONAL_RUNS: u32 = 30;
/// Total runs including the first.
pub const H2_MAX_TOTAL_RUNS: u32 = H2_ADDITIONAL_RUNS + 1;
/// Consecutive evaluation cycles without progress before stopping.
pub const H2_STAGNATION_CYCLES: u32 = 3;
/// Per-request assessment timeout, or the remaining active time if shorter.
pub const H2_ASSESSMENT_TIMEOUT_SECONDS: u64 = 60;
/// Maximum additional retries for transient assessment failures.
pub const H2_MAX_ADDITIONAL_RETRIES: u8 = 2;
/// Retry wait basis in milliseconds. Jitter is added by the transport.
pub const H2_RETRY_DELAY_MILLIS: [u64; 2] = [1_000, 2_000];

/// A price version required whenever a money cap is configured.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PriceVersion(String);

impl PriceVersion {
    /// Creates a non-empty price version.
    pub fn new(value: impl AsRef<str>) -> Result<Self, SupervisionError> {
        let trimmed = value.as_ref().trim();
        if trimmed.is_empty() {
            return Err(SupervisionError::BudgetInvalid {
                field: "priceVersion".to_owned(),
                detail: "a price version is required when a money cap is set".to_owned(),
            });
        }
        if trimmed.chars().count() > 128 {
            return Err(SupervisionError::BudgetInvalid {
                field: "priceVersion".to_owned(),
                detail: "must contain at most 128 characters".to_owned(),
            });
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Version text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A finite USD amount stored as integer micro-dollars.
///
/// The value is a local estimate, not a guarantee of the provider's invoice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Money(u64);

impl Money {
    /// Zero USD.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Creates an amount from integer micro-dollars.
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    /// Parses a finite non-negative USD amount.
    ///
    /// `NaN`, infinities, negative values, and values that cannot be
    /// represented in integer micro-dollars are rejected.
    pub fn usd(amount: f64) -> Result<Self, SupervisionError> {
        if !amount.is_finite() || amount < 0.0 {
            return Err(SupervisionError::BudgetInvalid {
                field: "money.usd".to_owned(),
                detail: "must be a finite non-negative amount".to_owned(),
            });
        }
        let micros = amount * 1_000_000.0;
        if micros > u64::MAX as f64 {
            return Err(SupervisionError::BudgetInvalid {
                field: "money.usd".to_owned(),
                detail: "amount is too large".to_owned(),
            });
        }
        Ok(Self(micros.round() as u64))
    }

    /// Integer micro-dollars.
    pub const fn micros(self) -> u64 {
        self.0
    }

    /// Checked addition.
    pub fn checked_add(self, other: Self) -> Result<Self, SupervisionError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(SupervisionError::BudgetInvalid {
                field: "money".to_owned(),
                detail: "amount overflowed the representable range".to_owned(),
            })
    }
}

impl fmt::Display for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "${}.{:06}", self.0 / 1_000_000, self.0 % 1_000_000)
    }
}

/// A finite money cap and the price version used to estimate it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MoneyCap {
    limit: Money,
    price_version: PriceVersion,
}

impl MoneyCap {
    /// Creates a positive finite money cap.
    pub fn new(limit: Money, price_version: PriceVersion) -> Result<Self, SupervisionError> {
        if limit.micros() == 0 {
            return Err(SupervisionError::BudgetInvalid {
                field: "moneyCap.limit".to_owned(),
                detail: "a configured money cap must be greater than zero".to_owned(),
            });
        }
        Ok(Self {
            limit,
            price_version,
        })
    }

    /// Cap amount.
    pub const fn limit(&self) -> Money {
        self.limit
    }

    /// Price version used for all estimates.
    pub fn price_version(&self) -> &PriceVersion {
        &self.price_version
    }

    /// Revalidates a deserialized money cap.
    pub fn validate(&self) -> Result<(), SupervisionError> {
        if self.limit.micros() == 0 {
            return Err(SupervisionError::BudgetInvalid {
                field: "moneyCap.limit".to_owned(),
                detail: "a configured money cap must be greater than zero".to_owned(),
            });
        }
        PriceVersion::new(self.price_version.as_str())?;
        Ok(())
    }
}

/// Finite supervision budget policy.
///
/// There is no unbounded variant. `active_seconds` and `additional_runs` are
/// always finite; a money cap is optional but must be finite and carry a price
/// version when present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetPolicy {
    active_seconds: u64,
    additional_runs: u32,
    money_cap: Option<MoneyCap>,
}

impl BudgetPolicy {
    /// H2 default budget: 7,200 active seconds, 30 additional runs, no money cap.
    pub const fn h2_default() -> Self {
        Self {
            active_seconds: H2_ACTIVE_SECONDS,
            additional_runs: H2_ADDITIONAL_RUNS,
            money_cap: None,
        }
    }

    /// Creates a finite budget policy.
    pub fn new(
        active_seconds: u64,
        additional_runs: u32,
        money_cap: Option<MoneyCap>,
    ) -> Result<Self, SupervisionError> {
        if active_seconds == 0 {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.activeSeconds".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        if additional_runs.checked_add(1).is_none() {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.additionalRuns".to_owned(),
                detail: "the total run count overflowed".to_owned(),
            });
        }
        if let Some(cap) = &money_cap {
            cap.validate()?;
        }
        Ok(Self {
            active_seconds,
            additional_runs,
            money_cap,
        })
    }

    /// Cumulative active seconds.
    pub const fn active_seconds(&self) -> u64 {
        self.active_seconds
    }

    /// Additional runs after the first.
    pub const fn additional_runs(&self) -> u32 {
        self.additional_runs
    }

    /// Total runs including the first.
    pub const fn max_total_runs(&self) -> u32 {
        self.additional_runs.saturating_add(1)
    }

    /// Optional finite money cap.
    pub fn money_cap(&self) -> Option<&MoneyCap> {
        self.money_cap.as_ref()
    }

    /// Validates the policy again before a spend or run start.
    pub fn validate(&self) -> Result<(), SupervisionError> {
        Self::new(
            self.active_seconds,
            self.additional_runs,
            self.money_cap.clone(),
        )?;
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BudgetPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            active_seconds: u64,
            additional_runs: u32,
            #[serde(default)]
            money_cap: Option<MoneyCap>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.active_seconds, wire.additional_runs, wire.money_cap)
            .map_err(serde::de::Error::custom)
    }
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        Self::h2_default()
    }
}

/// Consumed and reserved budget shape.
///
/// Reserved amounts stay reserved when usage is missing or a send result is
/// unknown until reconciliation. Task 9 owns the durable ledger semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BudgetUsage {
    active_seconds_consumed: u64,
    active_seconds_reserved: u64,
    runs_started: u32,
    runs_reserved: u32,
    money_consumed: Money,
    money_reserved: Money,
}

impl BudgetUsage {
    /// Empty usage.
    pub const fn empty() -> Self {
        Self {
            active_seconds_consumed: 0,
            active_seconds_reserved: 0,
            runs_started: 0,
            runs_reserved: 0,
            money_consumed: Money::zero(),
            money_reserved: Money::zero(),
        }
    }

    /// Creates an explicit usage shape.
    pub const fn new(
        active_seconds_consumed: u64,
        active_seconds_reserved: u64,
        runs_started: u32,
        runs_reserved: u32,
        money_consumed: Money,
        money_reserved: Money,
    ) -> Self {
        Self {
            active_seconds_consumed,
            active_seconds_reserved,
            runs_started,
            runs_reserved,
            money_consumed,
            money_reserved,
        }
    }

    /// Active seconds already consumed.
    pub const fn active_seconds_consumed(&self) -> u64 {
        self.active_seconds_consumed
    }

    /// Active seconds currently reserved.
    pub const fn active_seconds_reserved(&self) -> u64 {
        self.active_seconds_reserved
    }

    /// Runs already started, including the first.
    pub const fn runs_started(&self) -> u32 {
        self.runs_started
    }

    /// Runs currently reserved but not yet started.
    pub const fn runs_reserved(&self) -> u32 {
        self.runs_reserved
    }

    /// Money already consumed.
    pub const fn money_consumed(&self) -> Money {
        self.money_consumed
    }

    /// Money currently reserved.
    pub const fn money_reserved(&self) -> Money {
        self.money_reserved
    }

    /// Remaining active seconds.
    pub fn remaining_active_seconds(&self, policy: &BudgetPolicy) -> u64 {
        policy.active_seconds.saturating_sub(
            self.active_seconds_consumed
                .saturating_add(self.active_seconds_reserved),
        )
    }

    /// Whether one more run may start under the finite run cap.
    pub fn permits_run_start(&self, policy: &BudgetPolicy) -> bool {
        self.runs_started.saturating_add(self.runs_reserved) < policy.max_total_runs()
    }

    /// Whether the consumed and reserved money stay within the configured cap.
    pub fn within_money_cap(&self, policy: &BudgetPolicy) -> bool {
        match policy.money_cap() {
            None => true,
            Some(cap) => self
                .money_consumed
                .checked_add(self.money_reserved)
                .is_ok_and(|total| total.micros() <= cap.limit().micros()),
        }
    }
}

impl Default for BudgetUsage {
    fn default() -> Self {
        Self::empty()
    }
}

/// Host activity state that determines whether elapsed time counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetClockState {
    /// The supervised run, verification, assessment, or permission evaluation
    /// is active.
    Active,
    /// Waiting for a human decision.
    WaitingHuman,
    /// Explicitly paused by a human.
    Paused,
    /// The application is stopped or shutting down.
    AppStopped,
}

impl BudgetClockState {
    /// Whether elapsed time in this state counts toward the active limit.
    pub const fn counts_toward_active_time(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Counts only activity that belongs to the finite active-time budget.
pub const fn billed_active_seconds(state: BudgetClockState, elapsed_seconds: u64) -> u64 {
    if state.counts_toward_active_time() {
        elapsed_seconds
    } else {
        0
    }
}

/// The limit that has been reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetLimit {
    /// Cumulative active seconds.
    ActiveSeconds,
    /// Total run count including the first.
    RunCount,
    /// The configured money cap.
    Money,
}

/// Per-request assessment timeout: 60 seconds or the remaining active time,
/// whichever is shorter.
pub fn assessment_timeout_seconds(policy: &BudgetPolicy, usage: &BudgetUsage) -> u64 {
    H2_ASSESSMENT_TIMEOUT_SECONDS.min(usage.remaining_active_seconds(policy))
}

/// Validates that a proposed assessment spend fits the remaining policy.
pub fn validate_assessment_spend(
    policy: &BudgetPolicy,
    usage: &BudgetUsage,
    estimated_money: Option<Money>,
    estimated_seconds: u64,
) -> Result<(), SupervisionError> {
    policy.validate()?;
    if estimated_seconds > usage.remaining_active_seconds(policy) {
        return Err(SupervisionError::BudgetInvalid {
            field: "budget.activeSeconds".to_owned(),
            detail: "the assessment would exceed the remaining active time".to_owned(),
        });
    }
    if let Some(cap) = policy.money_cap() {
        let estimate = estimated_money.ok_or(SupervisionError::BudgetInvalid {
            field: "budget.money".to_owned(),
            detail: "a money cap requires an estimate for every model request".to_owned(),
        })?;
        let total = usage
            .money_consumed
            .checked_add(usage.money_reserved)?
            .checked_add(estimate)?;
        if total.micros() > cap.limit().micros() {
            return Err(SupervisionError::BudgetInvalid {
                field: "budget.money".to_owned(),
                detail: "the assessment would exceed the configured money cap".to_owned(),
            });
        }
    }
    Ok(())
}

/// Whether a finite money cap may be used for a ChatGPT-login connection.
///
/// A ChatGPT login has no local price estimate, so it is unusable whenever a
/// money cap is configured.
pub const fn chatgpt_login_allowed_with_money_cap(policy: &BudgetPolicy) -> bool {
    policy.money_cap.is_none()
}

/// Why a money-capped request could not be priced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum BudgetPriceReason {
    /// The caller supplied no estimate for a request under a money cap.
    MissingEstimate,
    /// The estimate used a price version other than the budget's fixed version.
    PriceVersionMismatch {
        /// Price version required by the budget.
        expected: PriceVersion,
        /// Price version supplied with the estimate.
        found: PriceVersion,
    },
    /// The connection authenticates with a ChatGPT login, which has no local
    /// price estimate.
    ChatGptLoginWithMoneyCap,
}

/// One conservative local request-cost estimate supplied before a send.
///
/// This is the only shape the ledger accepts under a money cap. It is a local
/// estimate, not a provider invoice guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBudgetEstimate {
    estimate: Money,
    price_version: PriceVersion,
    auth_method: AuthMethod,
}

impl RequestBudgetEstimate {
    /// Creates a price estimate bound to one auth method and price version.
    pub fn new(estimate: Money, price_version: PriceVersion, auth_method: AuthMethod) -> Self {
        Self {
            estimate,
            price_version,
            auth_method,
        }
    }

    /// Estimated amount reserved before send.
    pub const fn estimate(&self) -> Money {
        self.estimate
    }

    /// Price version used for the estimate.
    pub fn price_version(&self) -> &PriceVersion {
        &self.price_version
    }

    /// Authentication method of the connection that would send the request.
    pub const fn auth_method(&self) -> AuthMethod {
        self.auth_method
    }
}
