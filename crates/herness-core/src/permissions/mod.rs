//! Permission-mode and policy-version contracts shared by later tasks.
//!
//! H1 starts in [`PermissionMode::Configured`]. [`PermissionMode::Automatic`]
//! is only usable when an evaluator reports [`EvaluatorAvailability::Available`];
//! there is no fallback to unconditional execution or another model.
//!
//! The human administration surface is [`PolicyAdmin`]. Model and tool input
//! cannot reach it: rules and policies have no deserialization path, and an
//! operation request carries only a [`crate::tools::ToolName`] plus validated
//! arguments.

pub mod approval;
pub mod capability;
pub mod control;
pub mod decision;
pub mod evaluator;
pub mod grant;
pub mod policy;
pub mod protected;
pub mod rules;
pub mod run_context;
pub mod service;

use std::fmt;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::contracts::errors::CoreError;

pub use approval::{ApprovalError, ApprovalRequest, Authorization};
pub use capability::{AutomaticModeCapability, AutomaticModeUnavailableReason};
pub use control::RunControl;
pub use decision::{ArgumentsDigest, DecisionBinding, DecisionStatus, InvalidationReason};
pub use evaluator::{BoundedPermissionEvaluator, DEFAULT_EVALUATION_TIMEOUT};
pub use grant::{GrantScope, GrantWidening};
pub use policy::{PermissionPolicy, PolicyAdmin, SharedPolicy};
pub use protected::ProtectedBoundary;
pub use rules::{MatchMethod, PermissionRule, RuleEffect, RuleTarget, SimpleCommand};
pub use run_context::RunPermissionContext;
pub use service::{
    DenialReason, EvaluationContext, EvaluatorFailure, HumanWaitReason, PermissionOutcome,
    PermissionService,
};

/// Monotonic version of the host-owned permission policy.
///
/// A decision is bound to the policy version captured in its frozen operation.
/// A later policy version invalidates unused decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion(u64);

impl PolicyVersion {
    /// The first policy version.
    pub const INITIAL: Self = Self(1);

    /// Creates a policy version. Zero is not a valid version.
    pub fn new(value: u64) -> Result<Self, CoreError> {
        if value == 0 {
            Err(CoreError::InvalidPolicyVersion { value })
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric version.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next version, or `None` on overflow.
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl Default for PolicyVersion {
    fn default() -> Self {
        Self::INITIAL
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for PolicyVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for PolicyVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// How tool permission is decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionMode {
    /// Use host-configured allow/deny/ask rules. This is the H1 default.
    #[default]
    Configured,
    /// Ask the evaluator for every operation not resolved by deny/ask rules.
    Automatic,
}

impl PermissionMode {
    /// Automatic mode requires an evaluator. Configured mode does not.
    pub const fn requires_evaluator(self) -> bool {
        matches!(self, Self::Automatic)
    }

    /// Whether the mode can be used with the supplied evaluator availability.
    pub const fn is_usable_with(self, availability: EvaluatorAvailability) -> bool {
        match self {
            Self::Configured => true,
            Self::Automatic => availability.is_available(),
        }
    }
}

impl fmt::Display for PermissionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configured => f.write_str("configured"),
            Self::Automatic => f.write_str("automatic"),
        }
    }
}

/// Whether a permission evaluator can currently be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluatorAvailability {
    /// An evaluator is connected and usable.
    Available,
    /// No evaluator is connected; automatic mode must be shown as unavailable.
    Unavailable,
}

impl EvaluatorAvailability {
    /// Returns true only for [`EvaluatorAvailability::Available`].
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Decision returned by a permission evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    /// The operation may run under the policy version it was evaluated with.
    Allow,
    /// The operation must not run.
    Deny,
    /// The operation must wait for a human decision.
    Ask,
}
