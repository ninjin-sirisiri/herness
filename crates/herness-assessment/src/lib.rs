//! Tool-less assessment transport, normal-LLM condition adapter, and sanitized
//! common errors for H2.
//!
//! This crate owns no supervision state machine, store, budget ledger, or Tauri
//! boundary. It reuses the H1 connection registry and credential port, and
//! exposes the request mechanics that every assessment adapter must share,
//! plus the normal-LLM condition-by-condition adapter:
//!
//! * tool-less payload validation,
//! * a timeout of at most 60 seconds or the shorter remaining run deadline,
//! * cooperative cancellation,
//! * a limited same-connection retry policy,
//! * exact-origin credential attachment with no redirect following,
//! * input-modality capability checks,
//! * caller-provided image bytes only,
//! * sanitized errors that never contain a credential, authorization header,
//!   request body, or raw provider response body,
//! * a strict normal-LLM condition schema with explicit inconclusive reasons,
//! * a Jev System One choice adapter with fixed-model, distribution, native
//!   confidence, image, and input-limit validation,
//! * an OpenAI Decisions choice adapter with the fixed `gpt-6-luna` model,
//!   ordered probability validation, refusal handling, and caller-byte images.
//!
//! Money reservation and billing/cost records belong to the upper H2 request
//! gate and budget ledger. The transport neither reserves nor records money.

#![deny(missing_docs)]

mod image;

pub mod decisions;
pub mod error;
pub mod jev;
pub mod llm;
pub mod permission;
pub mod transport;

pub use decisions::{
    DECISIONS_CONFIDENCE_SCALE, DECISIONS_REQUEST_MODEL, DecisionsAssessment,
    DecisionsAssessmentAdapter, DecisionsRejection, DecisionsUsage, decisions_question_id,
};
pub use error::{AssessmentError, AssessmentErrorKind};
pub use jev::{
    JEV_CONFIDENCE_SCALE, JEV_REQUEST_MODEL, JevAssessment, JevAssessmentAdapter, JevRejection,
    JevUsage, jev_question_id,
};
pub use llm::{
    EvidenceContent, EvidenceDocument, InconclusiveReason, LlmAssessment, LlmAssessmentAdapter,
};
pub use permission::{
    PermissionBudgetScope, PermissionConsentHandle, PermissionEvaluator, PermissionEvaluatorConfig,
    SharedModelRequestGate, permission_question_id,
};
pub use transport::{
    AssessmentEndpoints, AssessmentRequest, AssessmentResponse, AssessmentTransport, CancelToken,
    ImageInput, ImageSource, MAX_ADDITIONAL_RETRIES, MAX_ASSESSMENT_TIMEOUT, RetryPolicy,
    ToolLessPayload, TransportControl,
};
