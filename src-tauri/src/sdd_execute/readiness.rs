//! H4 verification-readiness gate over H3's saved synchronization state.
//!
//! H2 consults [`VerificationReadinessPort`](herness_supervision::supervisor::VerificationReadinessPort)
//! exactly at the completed-input/idle boundary, before any required check or
//! condition assessment. This adapter maps H4's required `H4Barrier` requests to
//! a ready/pending/blocked decision through the existing
//! [`DesktopH4Barrier`]. It never reimplements H3 policy, writes a document,
//! starts a Task, or decides completion.
//!
//! The required-document set is H4-owned. The production source is
//! [`H4RequiredDocuments`](crate::sdd_execute::barrier::H4RequiredDocuments),
//! which computes the union of the Task's `htmlTargets`, the plan, the project
//! specs, the common-Target scan changes, and every H3 dependency-affected
//! document. [`FixedReadinessDocuments`] remains only as an explicit test input.
//! If the set cannot be produced, or the saved H3 state cannot be read, the gate
//! is `blocked`; it is never `ready`.

use herness_html_sync::{BarrierOutcome, BarrierRequest};
use herness_supervision::SupervisionError;
use herness_supervision::supervisor::{
    ReadinessDecision, ReadinessRequest, VerificationReadinessPort,
};

use crate::html_sync::composition::DesktopH4Barrier;

/// Supplies the exact documents H4 requires before verification.
///
/// Each request already carries the source revision/digest and dependent
/// fingerprints H4 observed. Implementations must be read-only and must not
/// guess a document set.
pub trait ReadinessDocumentSource {
    /// Returns one barrier request per required document.
    ///
    /// An error, an empty set, or an unreadable dependency means readiness
    /// cannot be established.
    fn required(&mut self, request: &ReadinessRequest) -> Result<Vec<BarrierRequest>, String>;
}

/// A fixed required-document set.
///
/// This is an explicit test/gate input only. The production composition installs
/// [`H4RequiredDocuments`](crate::sdd_execute::barrier::H4RequiredDocuments) so
/// the gate waits on the real required union instead of a fixed list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FixedReadinessDocuments {
    requests: Vec<BarrierRequest>,
}

impl FixedReadinessDocuments {
    /// Creates a fixed set in the caller's order.
    pub fn new(requests: Vec<BarrierRequest>) -> Self {
        Self { requests }
    }

    /// The fixed requests.
    pub fn requests(&self) -> &[BarrierRequest] {
        &self.requests
    }
}

impl ReadinessDocumentSource for FixedReadinessDocuments {
    fn required(&mut self, _request: &ReadinessRequest) -> Result<Vec<BarrierRequest>, String> {
        Ok(self.requests.clone())
    }
}

/// Read-only readiness gate over the real H3 barrier.
pub struct DesktopH4Readiness<D> {
    barrier: DesktopH4Barrier,
    documents: D,
}

impl<D: ReadinessDocumentSource> DesktopH4Readiness<D> {
    /// Creates one gate over the shared H3 barrier and a document source.
    pub const fn new(barrier: DesktopH4Barrier, documents: D) -> Self {
        Self { barrier, documents }
    }
}

impl<D: ReadinessDocumentSource> VerificationReadinessPort for DesktopH4Readiness<D> {
    fn readiness(
        &mut self,
        request: &ReadinessRequest,
    ) -> Result<ReadinessDecision, SupervisionError> {
        let documents = match self.documents.required(request) {
            Ok(documents) => documents,
            Err(detail) => {
                return blocked(
                    format!("the required HTML document set could not be determined: {detail}"),
                    "confirm the required HTML documents and resume",
                    Vec::new(),
                );
            }
        };
        if documents.is_empty() {
            return blocked(
                "the required HTML document set is empty",
                "confirm the required HTML documents and resume",
                Vec::new(),
            );
        }

        let mut awaiting = Vec::new();
        let mut blocked_documents = Vec::new();
        let mut pending_reasons = Vec::new();
        let mut block_reasons = Vec::new();
        let mut actions = Vec::new();

        for document in &documents {
            let key = document.document().target_path().to_owned();
            match self.barrier.check(document, request.observed_at()) {
                Ok(BarrierOutcome::Synced { .. }) => {}
                Ok(BarrierOutcome::Missing { .. }) => {
                    awaiting.push(key.clone());
                    pending_reasons.push(format!("{key} has no saved H3 document yet"));
                }
                Ok(BarrierOutcome::Unsynced {
                    status,
                    required_actions,
                    ..
                }) => {
                    if status.state().requires_human() || status.state().is_terminal_without_sync()
                    {
                        blocked_documents.push(key.clone());
                        block_reasons.push(format!(
                            "{key} is {} ({})",
                            status.state().as_str(),
                            action_labels(&required_actions)
                        ));
                        actions.extend(
                            required_actions
                                .iter()
                                .map(|action| action.as_str().to_owned()),
                        );
                    } else {
                        awaiting.push(key.clone());
                        pending_reasons.push(format!("{key} is {}", status.state().as_str()));
                    }
                }
                Ok(BarrierOutcome::Mismatch {
                    status, mismatches, ..
                }) => {
                    let detail = mismatches
                        .iter()
                        .map(|mismatch| mismatch.detail())
                        .collect::<Vec<_>>()
                        .join("; ");
                    if status.state().requires_human() || status.state().is_terminal_without_sync()
                    {
                        blocked_documents.push(key.clone());
                        block_reasons.push(format!(
                            "{key} is {} and its saved state does not match: {detail}",
                            status.state().as_str()
                        ));
                    } else {
                        awaiting.push(key.clone());
                        pending_reasons.push(format!("{key} must be synchronized again: {detail}"));
                    }
                }
                Ok(BarrierOutcome::NotApproved { detail, .. }) => {
                    blocked_documents.push(key.clone());
                    block_reasons.push(format!("{key}: {detail}"));
                    actions.push("approve_settings".to_owned());
                }
                Err(detail) => {
                    return blocked(
                        format!("the saved H3 state for {key} could not be read: {detail}"),
                        "resolve the HTML synchronization state and resume",
                        vec![key],
                    );
                }
            }
        }

        if !blocked_documents.is_empty() {
            let action = if actions.is_empty() {
                "resolve the HTML synchronization state and resume".to_owned()
            } else {
                actions.join(", ")
            };
            return blocked(block_reasons.join("; "), action, blocked_documents);
        }
        if !awaiting.is_empty() {
            return ReadinessDecision::pending(pending_reasons.join("; "), awaiting);
        }
        Ok(ReadinessDecision::ready())
    }
}

fn blocked(
    reason: impl Into<String>,
    required_action: impl Into<String>,
    documents: Vec<String>,
) -> Result<ReadinessDecision, SupervisionError> {
    let reason: String = reason.into();
    let required_action: String = required_action.into();
    ReadinessDecision::blocked(reason, required_action, documents)
}

fn action_labels(actions: &[herness_html_sync::RequiredAction]) -> String {
    if actions.is_empty() {
        return "no automatic progress".to_owned();
    }
    actions
        .iter()
        .map(herness_html_sync::RequiredAction::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}
