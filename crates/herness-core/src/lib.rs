//! Host-owned public contracts and ports for the herness H1 runtime.
//!
//! `herness-core` is the dependency direction root: it never depends on the
//! store, the engine adapter, or Tauri. Public values carry stable identifiers,
//! versioned events, sanitized errors, and no provider tokens or raw provider
//! errors. Checkpoint bodies are versioned opaque data owned by the engine
//! adapter.

pub mod contracts;
pub mod permissions;
pub mod ports;
pub mod tools;

pub use contracts::*;
pub use permissions::{
    ApprovalError, ApprovalRequest, ArgumentsDigest, Authorization, AutomaticModeCapability,
    AutomaticModeUnavailableReason, DecisionBinding, DecisionStatus, DenialReason,
    EvaluationContext, EvaluatorAvailability, EvaluatorFailure, GrantScope, GrantWidening,
    HumanWaitReason, InvalidationReason, MatchMethod, PermissionDecision, PermissionMode,
    PermissionOutcome, PermissionPolicy, PermissionRule, PermissionService, PolicyAdmin,
    PolicyVersion, ProtectedBoundary, RuleEffect, RuleTarget, SimpleCommand,
};
pub use ports::*;
pub use tools::{
    BashArgs, EditArgs, FileVersion, GatewayError, MAX_REASON_SCALARS, NonEmptyText, Purpose,
    Rationale, ReadArgs, ReasonField, ReasonViolation, SearchArgs, ToolArguments, ToolExecutor,
    ToolGateway, ToolName, WriteArgs,
};
