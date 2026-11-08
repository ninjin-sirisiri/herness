//! Tool-less assessment transport and sanitized common errors for H2.
//!
//! This crate owns no provider wire schema, supervision state machine, store,
//! budget ledger, or Tauri boundary. It reuses the H1 connection registry and
//! credential port, and exposes only the request mechanics that every
//! assessment adapter must share:
//!
//! * tool-less payload validation,
//! * a timeout of at most 60 seconds or the shorter remaining run deadline,
//! * cooperative cancellation,
//! * a limited same-connection retry policy,
//! * exact-origin credential attachment with no redirect following,
//! * input-modality capability checks,
//! * caller-provided image bytes only,
//! * sanitized errors that never contain a credential, authorization header,
//!   request body, or raw provider response body.
//!
//! Money reservation and billing/cost records belong to the upper H2 request
//! gate and budget ledger. The transport neither reserves nor records money.

#![deny(missing_docs)]

pub mod error;
pub mod transport;

pub use error::{AssessmentError, AssessmentErrorKind};
pub use transport::{
    AssessmentEndpoints, AssessmentRequest, AssessmentResponse, AssessmentTransport, CancelToken,
    ImageInput, ImageSource, MAX_ADDITIONAL_RETRIES, MAX_ASSESSMENT_TIMEOUT, RetryPolicy,
    ToolLessPayload, TransportControl,
};
