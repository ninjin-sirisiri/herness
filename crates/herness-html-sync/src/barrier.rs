//! H4 completion barrier port.
//!
//! H4 may only treat a requested document version as complete when the saved H3
//! state still records that exact source revision/digest, the current human
//! approval covers the settings version, and every dependent input it supplies
//! is still the fingerprint H3 recorded. This module is a read-only check: it
//! never starts a Task, writes a file, sends a request, or decides completion
//! itself. H4 owns its own completion decision.

use herness_core::{ProjectId, Timestamp};
use herness_supervision::ContentDigest;
use serde::{Deserialize, Serialize};

use crate::document::{DocumentKey, FingerprintKind};
use crate::error::H3Error;
use crate::ports::H3StorePort;
use crate::state::{H3DocumentState, H3DocumentStatus, H3Reason, RequiredAction};

/// One dependent input the caller currently has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BarrierDependency {
    kind: FingerprintKind,
    digest: ContentDigest,
}

impl BarrierDependency {
    /// Creates one exact dependency fingerprint.
    pub const fn new(kind: FingerprintKind, digest: ContentDigest) -> Self {
        Self { kind, digest }
    }

    /// Fingerprint kind.
    pub const fn kind(&self) -> FingerprintKind {
        self.kind
    }

    /// Exact digest supplied by the caller.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

/// One H4 barrier request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BarrierRequest {
    project_id: ProjectId,
    document: DocumentKey,
    source_revision: u64,
    source_digest: ContentDigest,
    #[serde(default)]
    dependencies: Vec<BarrierDependency>,
}

impl BarrierRequest {
    /// Creates a validated request.
    ///
    /// `dependencies` may name any fingerprint kind except the source itself;
    /// duplicate kinds are rejected rather than silently merged.
    pub fn new(
        project_id: ProjectId,
        document: DocumentKey,
        source_revision: u64,
        source_digest: ContentDigest,
        dependencies: Vec<BarrierDependency>,
    ) -> Result<Self, H3Error> {
        if source_revision == 0 {
            return Err(H3Error::must_be_positive("sourceRevision"));
        }
        document.validate_in(project_id)?;
        for (index, dependency) in dependencies.iter().enumerate() {
            if dependencies[..index]
                .iter()
                .any(|earlier| earlier.kind == dependency.kind)
            {
                return Err(H3Error::invalid(
                    "dependencies",
                    "one barrier request cannot name the same fingerprint twice",
                ));
            }
        }
        Ok(Self {
            project_id,
            document,
            source_revision,
            source_digest,
            dependencies,
        })
    }

    /// Project that owns the requested document.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Requested document.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Source revision the caller believes is complete.
    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    /// Exact source digest the caller believes is complete.
    pub const fn source_digest(&self) -> &ContentDigest {
        &self.source_digest
    }

    /// Current dependent inputs supplied by the caller.
    pub fn dependencies(&self) -> &[BarrierDependency] {
        &self.dependencies
    }
}

/// Why a requested barrier did not match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BarrierMismatchKind {
    /// The requested source revision differs from the saved revision.
    SourceRevision,
    /// The requested source bytes differ from the saved digest.
    SourceDigest,
    /// The saved settings version differs from the requested/current approval.
    SettingsVersion,
    /// One dependent input fingerprint differs from the saved fingerprint.
    Dependency,
    /// The saved fingerprint set does not contain this dependency kind.
    DependencyNotRecorded,
}

/// One version or dependency mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BarrierMismatch {
    kind: BarrierMismatchKind,
    field: String,
    requested: Option<String>,
    current: Option<String>,
    detail: String,
}

impl BarrierMismatch {
    fn new(
        kind: BarrierMismatchKind,
        field: impl Into<String>,
        requested: Option<String>,
        current: Option<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            field: field.into(),
            requested,
            current,
            detail: detail.into(),
        }
    }

    /// Mismatch category.
    pub const fn kind(&self) -> &BarrierMismatchKind {
        &self.kind
    }

    /// Fingerprint kind or source field.
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Value the caller supplied.
    pub fn requested(&self) -> Option<&str> {
        self.requested.as_deref()
    }

    /// Value saved by H3.
    pub fn current(&self) -> Option<&str> {
        self.current.as_deref()
    }

    /// Human-readable explanation. It never carries source bytes.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Result of one H4 barrier check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BarrierOutcome {
    /// The requested version and every supplied dependency are the saved
    /// synced state. H4 still owns its completion decision.
    Synced {
        /// Saved public document status.
        status: H3DocumentStatus,
        /// Exact source revision.
        source_revision: u64,
        /// Exact source digest.
        source_digest: ContentDigest,
        /// Approved settings version.
        settings_version: u64,
        /// Last project sequence observed by the saved state.
        final_project_sequence: u64,
    },
    /// The saved document is not currently synced.
    Unsynced {
        /// Saved public document status.
        status: H3DocumentStatus,
        /// Saved reason.
        reason: H3Reason,
        /// Actions H3 requires before a retry.
        required_actions: Vec<RequiredAction>,
    },
    /// The requested version or dependent input does not match the saved state.
    Mismatch {
        /// Saved public document status.
        status: H3DocumentStatus,
        /// Every mismatch found.
        mismatches: Vec<BarrierMismatch>,
    },
    /// The saved settings/approval are absent, disabled, stale, or tampered.
    NotApproved {
        /// Saved public document status when a document exists.
        status: Option<H3DocumentStatus>,
        /// Sanitized reason.
        detail: String,
    },
    /// No saved document exists for the request.
    Missing {
        /// Requested document.
        document: DocumentKey,
    },
}

/// Read-only H4 barrier over the H3 store port.
pub struct H4Barrier<'a> {
    store: &'a dyn H3StorePort,
}

impl<'a> H4Barrier<'a> {
    /// Creates a barrier over the shared H3 store.
    pub const fn new(store: &'a dyn H3StorePort) -> Self {
        Self { store }
    }

    /// Checks the requested source version and dependent inputs.
    ///
    /// The check is read-only and never mutates the document, settings, cycle,
    /// generation, budget, or project sequence.
    pub fn check(
        &self,
        request: &BarrierRequest,
        now: Timestamp,
    ) -> Result<BarrierOutcome, H3Error> {
        let project = request.project_id();
        if request.document.project_id() != project {
            return Err(H3Error::CrossProject {
                id_kind: "barrier document".to_owned(),
                expected: project,
                found: request.document.project_id(),
            });
        }
        let Some(record) = self
            .store
            .load_html_sync_document(project, &request.document)?
        else {
            return Ok(BarrierOutcome::Missing {
                document: request.document.clone(),
            });
        };
        let status = record.status();
        let state = record.state();
        if let Some(detail) = approval_block(self.store, project, state, now)? {
            return Ok(BarrierOutcome::NotApproved {
                status: Some(status),
                detail,
            });
        }
        let mismatches = mismatches(state, request);
        if !mismatches.is_empty() {
            return Ok(BarrierOutcome::Mismatch { status, mismatches });
        }
        if state.state().is_currently_synced() && state.applicability().is_applicable() {
            return Ok(BarrierOutcome::Synced {
                status,
                source_revision: state.source().revision().get(),
                source_digest: state.source().digest().clone(),
                settings_version: state.settings_version(),
                final_project_sequence: record.last_sequence(),
            });
        }
        Ok(BarrierOutcome::Unsynced {
            status,
            reason: state.reason().clone(),
            required_actions: state.reason().required_actions().to_vec(),
        })
    }
}

fn approval_block(
    store: &dyn H3StorePort,
    project: ProjectId,
    state: &H3DocumentState,
    now: Timestamp,
) -> Result<Option<String>, H3Error> {
    let Some(settings_record) = store.load_html_sync_settings(project)? else {
        return Ok(Some(
            "the project has no stored H3 settings or human approval".to_owned(),
        ));
    };
    let settings = settings_record.settings();
    if !settings.verify_fingerprint() {
        return Ok(Some(
            "the stored H3 settings do not match their approved fingerprint".to_owned(),
        ));
    }
    if !settings.enabled() {
        return Ok(Some("H3 is disabled for this project".to_owned()));
    }
    if settings.version() != state.settings_version() {
        return Ok(Some(format!(
            "the document was recorded under settings version {}, but the approved settings version is {}",
            state.settings_version(),
            settings.version()
        )));
    }
    let Some(approval) = settings.approval() else {
        return Ok(Some(
            "the stored H3 settings carry no human configuration approval".to_owned(),
        ));
    };
    if !approval.is_current_at(now) {
        return Ok(Some(
            "the human configuration approval is revoked, superseded, or expired".to_owned(),
        ));
    }
    Ok(None)
}

fn mismatches(state: &H3DocumentState, request: &BarrierRequest) -> Vec<BarrierMismatch> {
    let mut mismatches = Vec::new();
    if state.source().revision().get() != request.source_revision {
        mismatches.push(BarrierMismatch::new(
            BarrierMismatchKind::SourceRevision,
            "sourceRevision",
            Some(request.source_revision.to_string()),
            Some(state.source().revision().get().to_string()),
            "the requested document version is not the saved source revision",
        ));
    }
    if state.source().digest() != &request.source_digest {
        mismatches.push(BarrierMismatch::new(
            BarrierMismatchKind::SourceDigest,
            "sourceDigest",
            Some(request.source_digest.as_str().to_owned()),
            Some(state.source().digest().as_str().to_owned()),
            "the requested source bytes differ from the saved source digest",
        ));
    }
    for dependency in &request.dependencies {
        match state.fingerprints().get(dependency.kind) {
            Some(saved) if saved == &dependency.digest => {}
            Some(saved) => mismatches.push(BarrierMismatch::new(
                BarrierMismatchKind::Dependency,
                dependency.kind.as_str(),
                Some(dependency.digest.as_str().to_owned()),
                Some(saved.as_str().to_owned()),
                format!(
                    "the current {} input differs from the saved synced fingerprint",
                    dependency.kind.as_str()
                ),
            )),
            None => mismatches.push(BarrierMismatch::new(
                BarrierMismatchKind::DependencyNotRecorded,
                dependency.kind.as_str(),
                Some(dependency.digest.as_str().to_owned()),
                None,
                format!(
                    "the saved synced state has no {} fingerprint",
                    dependency.kind.as_str()
                ),
            )),
        }
    }
    mismatches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_rejects_duplicate_dependency_kinds_and_a_foreign_document() {
        let project = ProjectId::new();
        let document = DocumentKey::new(project, "docs/adr/0001.md").expect("document");
        let digest = ContentDigest::sha256(b"input");
        assert!(
            BarrierRequest::new(
                project,
                document,
                1,
                digest.clone(),
                vec![
                    BarrierDependency::new(FingerprintKind::Css, digest.clone()),
                    BarrierDependency::new(FingerprintKind::Css, digest.clone()),
                ],
            )
            .is_err()
        );
    }
}
