//! Host-only, version-checked publication of one approved formal companion.
//!
//! The writer is composed directly by the trusted host. It is deliberately not
//! a [`crate::tools::ToolExecutor`], has no [`crate::tools::ToolName`] variant,
//! accepts no run or operation identifier, and is never installed in a gateway.
//! A model tool or IPC payload therefore cannot reach it.
//!
//! The writer performs one file replacement. It persists an intent before any
//! filesystem side effect, re-checks project root/symlink, the expected version
//! or absence, host permission, and stop control immediately before the side
//! effect, saves the exact old version to the host archive, replaces the file
//! through a same-directory temporary file and rename, re-reads the result, and
//! persists the outcome. Duplicate request ids return the stored result and do
//! not publish twice; pending or unknown outcomes require reconciliation and
//! are never retried as a success.
//!
//! Publishing HTML and a receipt is two requests coordinated by the H3 journal.
//! This module does not claim a multi-file filesystem transaction.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;

use crate::contracts::errors::{FileFailure, PublicationFailure};
use crate::contracts::events::{EventDraft, EventKind, EventPayload};
use crate::contracts::ids::{HostActivityId, ProjectId};
use crate::contracts::path::AbsolutePath;
use crate::contracts::publication::{
    ArchivedVersion, ExpectedTargetVersion, OldVersionArchive, OldVersionSave,
    PUBLICATION_ACTIVITY_KIND, PUBLICATION_EVENT_KIND, PUBLICATION_INTENDED_EVENT_KIND,
    PublicationRecord, PublicationRequest, PublicationRequestId, PublicationResult,
    PublicationStatus, PublicationUnit,
};
use crate::contracts::time::Timestamp;
use crate::permissions::RunControl;
use crate::ports::publish::{PublicationArchivePort, PublicationGatePort, PublicationRecordPort};
use crate::tools::diff::line_diff;
use crate::tools::files::{FileLockRegistry, atomic_write};
use crate::tools::path::{ProjectRoot, ResolvedPath};
use crate::tools::{FileVersion, hash_bytes};

/// Current format of one private archived-version file.
const ARCHIVE_FORMAT: u32 = 1;

/// The state observed at the formal target for one check.
#[derive(Debug)]
struct InspectedTarget {
    resolved: ResolvedPath,
    version: Option<FileVersion>,
    content: Option<String>,
}

/// Host-only writer for one project's formal companion publications.
#[derive(Debug)]
pub struct PublicationWriter<S, A, G> {
    project_id: ProjectId,
    root: ProjectRoot,
    root_cwd: AbsolutePath,
    records: S,
    archive: A,
    gate: G,
    control: RunControl,
    locks: Arc<FileLockRegistry>,
}

impl<S, A, G> PublicationWriter<S, A, G> {
    /// Creates a writer with its own in-process file lock registry.
    pub fn new(
        project_id: ProjectId,
        root: ProjectRoot,
        records: S,
        archive: A,
        gate: G,
        control: RunControl,
    ) -> Result<Self, crate::contracts::errors::CoreError> {
        Self::with_lock_registry(
            project_id,
            root,
            records,
            archive,
            gate,
            control,
            Arc::new(FileLockRegistry::new()),
        )
    }

    /// Creates a writer sharing a lock registry with native file writers.
    ///
    /// Sharing the registry is what serializes a duplicate publication request
    /// against another in-process writer targeting the same companion path.
    /// External processes can still change the file between the final check and
    /// the rename; this is not an OS-level isolation claim.
    #[allow(clippy::too_many_arguments)]
    pub fn with_lock_registry(
        project_id: ProjectId,
        root: ProjectRoot,
        records: S,
        archive: A,
        gate: G,
        control: RunControl,
        locks: Arc<FileLockRegistry>,
    ) -> Result<Self, crate::contracts::errors::CoreError> {
        let root_cwd = AbsolutePath::new(root.as_path().to_string_lossy().into_owned())?;
        Ok(Self {
            project_id,
            root,
            root_cwd,
            records,
            archive,
            gate,
            control,
            locks,
        })
    }

    /// Project this writer is bound to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Canonical project root used for path checks.
    pub const fn project_root(&self) -> &ProjectRoot {
        &self.root
    }

    /// Publication record store.
    pub const fn records(&self) -> &S {
        &self.records
    }

    /// Mutable publication record store.
    pub const fn records_mut(&mut self) -> &mut S {
        &mut self.records
    }

    /// Old-version archive.
    pub const fn archive(&self) -> &A {
        &self.archive
    }

    /// Mutable old-version archive.
    pub const fn archive_mut(&mut self) -> &mut A {
        &mut self.archive
    }

    /// Host permission gate.
    pub const fn gate(&self) -> &G {
        &self.gate
    }

    /// Shared stop/deadline control for this publication boundary.
    pub const fn control(&self) -> &RunControl {
        &self.control
    }
}

impl<S: PublicationRecordPort, A: PublicationArchivePort, G: PublicationGatePort>
    PublicationWriter<S, A, G>
{
    /// Publishes one approved companion or returns its already stored result.
    pub fn publish(
        &mut self,
        request: PublicationRequest,
    ) -> Result<PublicationResult, PublicationFailure> {
        if request.project_id() != self.project_id {
            return Err(PublicationFailure::CrossProject {
                expected: self.project_id,
                found: request.project_id(),
            });
        }
        let key = publication_record_key(request.project_id(), request.request_id());
        if let Some(record) = self.records.load_publication(&key)? {
            return duplicate_result(record, &request);
        }

        let initial = match self.inspect_target(&request) {
            Ok(initial) => initial,
            Err(failure) => return self.reject_without_intent(&key, &request, failure),
        };
        let registry = Arc::clone(&self.locks);
        let _guard = registry.acquire(initial.resolved.lock_key());

        // Re-read under the target lock so two host writers sharing the
        // registry cannot both persist an intent for one request id.
        if let Some(record) = self.records.load_publication(&key)? {
            return duplicate_result(record, &request);
        }

        let before = match self.inspect_target(&request) {
            Ok(before) => before,
            Err(failure) => return self.reject_without_intent(&key, &request, failure),
        };

        let now = Timestamp::now();
        let activity_kind = publication_activity_kind();
        let activity_id = HostActivityId::new(request.project_id());
        let pending = PublicationRecord::pending(
            &request,
            before.version.clone(),
            activity_kind,
            activity_id,
            now,
        );
        let intended = self.audit_event(
            PUBLICATION_INTENDED_EVENT_KIND,
            "intended",
            &request,
            &pending,
            Some(&before),
            None,
            None,
        )?;
        if let Err(error) = self
            .records
            .save_publication(&key, &pending, vec![intended])
        {
            return Err(PublicationFailure::NotExecutable {
                detail: error.to_string(),
            });
        }

        // Re-check the path, symlink, and version immediately before the first
        // side effect.
        let checked = match self.inspect_target(&request) {
            Ok(checked) => checked,
            Err(failure) => {
                return self.finish_without_replace(
                    &key,
                    &request,
                    &pending,
                    &before,
                    failure,
                    OldVersionSave::NotAttempted,
                );
            }
        };
        if let Err(failure) = self.gate.authorize_publication(&request) {
            return self.finish_without_replace(
                &key,
                &request,
                &pending,
                &before,
                failure,
                OldVersionSave::NotAttempted,
            );
        }
        if !self.control.permits_side_effect() {
            return self.finish_without_replace(
                &key,
                &request,
                &pending,
                &before,
                stop_failure(&self.control),
                OldVersionSave::NotAttempted,
            );
        }

        let old_version_save = match (checked.version.as_ref(), checked.content.as_ref()) {
            (Some(version), Some(content)) => {
                let archive = OldVersionArchive::new(
                    request.request_id(),
                    request.project_id(),
                    request.target().as_str(),
                    version,
                    content,
                );
                match self.archive.save_old_version(&archive) {
                    Ok(archived) => OldVersionSave::from(archived),
                    Err(failure) => {
                        let old_save = old_version_save_from_failure(&failure);
                        let failure = match failure {
                            PublicationFailure::Unverifiable { detail } => {
                                PublicationFailure::OldVersionSaveFailed { detail }
                            }
                            other => other,
                        };
                        return self.finish_without_replace(
                            &key, &request, &pending, &before, failure, old_save,
                        );
                    }
                }
            }
            (None, None) => OldVersionSave::NotApplicable,
            _ => {
                let failure = PublicationFailure::Unverifiable {
                    detail: "the inspected target has inconsistent version and content state"
                        .to_owned(),
                };
                return self.finish_without_replace(
                    &key,
                    &request,
                    &pending,
                    &before,
                    failure,
                    OldVersionSave::Unknown {
                        detail: "the old version could not be determined".to_owned(),
                    },
                );
            }
        };

        // Final path/symlink/version, permission, and stop check immediately
        // before the rename. Permission and stop are read-only checks; a host
        // implementation must not treat them as an approval that is consumed.
        let final_target = match self.inspect_target(&request) {
            Ok(final_target) => final_target,
            Err(failure) => {
                return self.finish_without_replace(
                    &key,
                    &request,
                    &pending,
                    &before,
                    failure,
                    old_version_save,
                );
            }
        };
        if let Err(failure) = self.gate.authorize_publication(&request) {
            return self.finish_without_replace(
                &key,
                &request,
                &pending,
                &before,
                failure,
                old_version_save,
            );
        }
        if !self.control.permits_side_effect() {
            return self.finish_without_replace(
                &key,
                &request,
                &pending,
                &before,
                stop_failure(&self.control),
                old_version_save,
            );
        }

        if let Err(error) = atomic_write(
            final_target.resolved.absolute(),
            request.content().as_bytes(),
            true,
        ) {
            let failure = classify_write_error(&request, &final_target, &error);
            return match failure {
                PublicationFailure::Unverifiable { .. } => self.finish_after_write(
                    &key,
                    &request,
                    &pending,
                    &before,
                    old_version_save,
                    failure,
                    None,
                ),
                other => self.finish_without_replace(
                    &key,
                    &request,
                    &pending,
                    &before,
                    other,
                    old_version_save,
                ),
            };
        }

        let observed = match fs::read(final_target.resolved.absolute()) {
            Ok(bytes) => bytes,
            Err(error) => {
                let failure = PublicationFailure::Unverifiable {
                    detail: format!(
                        "the replaced target could not be re-read: {:?}",
                        error.kind()
                    ),
                };
                return self.finish_after_write(
                    &key,
                    &request,
                    &pending,
                    &before,
                    old_version_save,
                    failure,
                    None,
                );
            }
        };
        let observed_version = hash_bytes(&observed);
        if observed != request.content().as_bytes()
            || observed_version != *request.approved_version()
        {
            let failure = PublicationFailure::Unverifiable {
                detail: format!(
                    "the re-read target does not match the approved bytes; observed version {observed_version}"
                ),
            };
            return self.finish_after_write(
                &key,
                &request,
                &pending,
                &before,
                old_version_save,
                failure,
                Some(observed_version),
            );
        }

        self.finish_published(
            &key,
            &request,
            &pending,
            &before,
            old_version_save,
            observed_version,
        )
    }

    /// Loads one stored request record by its stable identifier.
    pub fn load_publication(
        &self,
        request_id: &PublicationRequestId,
    ) -> Result<Option<PublicationRecord>, PublicationFailure> {
        self.records
            .load_publication(&publication_record_key(self.project_id, request_id))
    }
}

impl<S, A, G> PublicationWriter<S, A, G> {
    fn inspect_target(
        &self,
        request: &PublicationRequest,
    ) -> Result<InspectedTarget, PublicationFailure> {
        match request.expected_version() {
            ExpectedTargetVersion::Absent => {
                match self
                    .root
                    .creatable_file(&self.root_cwd, request.target().as_str())
                {
                    Ok(resolved) => Ok(InspectedTarget {
                        resolved,
                        version: None,
                        content: None,
                    }),
                    Err(FileFailure::AlreadyExists { .. }) => {
                        let resolved = self
                            .root
                            .existing_file(&self.root_cwd, request.target().as_str())
                            .map_err(|failure| PublicationFailure::Path { failure })?;
                        let bytes = fs::read(resolved.absolute()).map_err(|error| {
                            PublicationFailure::Path {
                                failure: FileFailure::Io {
                                    path: resolved.relative_display(),
                                    error_kind: format!("{:?}", error.kind()),
                                },
                            }
                        })?;
                        Err(PublicationFailure::ExpectedAbsentButPresent {
                            target: request.target().as_str().to_owned(),
                            actual: hash_bytes(&bytes),
                        })
                    }
                    Err(failure) => Err(PublicationFailure::Path { failure }),
                }
            }
            ExpectedTargetVersion::Present { version: expected } => {
                match self
                    .root
                    .existing_file(&self.root_cwd, request.target().as_str())
                {
                    Ok(resolved) => {
                        let bytes = fs::read(resolved.absolute()).map_err(|error| {
                            PublicationFailure::Path {
                                failure: FileFailure::Io {
                                    path: resolved.relative_display(),
                                    error_kind: format!("{:?}", error.kind()),
                                },
                            }
                        })?;
                        let actual = hash_bytes(&bytes);
                        if actual != *expected {
                            return Err(PublicationFailure::VersionConflict {
                                target: request.target().as_str().to_owned(),
                                expected: expected.clone(),
                                actual,
                            });
                        }
                        let content = String::from_utf8(bytes).map_err(|_| {
                            PublicationFailure::InvalidUtf8 {
                                target: request.target().as_str().to_owned(),
                            }
                        })?;
                        Ok(InspectedTarget {
                            resolved,
                            version: Some(actual),
                            content: Some(content),
                        })
                    }
                    Err(FileFailure::NotFound { .. }) => {
                        Err(PublicationFailure::ExpectedPresentButAbsent {
                            target: request.target().as_str().to_owned(),
                            expected: expected.clone(),
                        })
                    }
                    Err(failure) => Err(PublicationFailure::Path { failure }),
                }
            }
        }
    }
}

impl<S, A, G> PublicationWriter<S, A, G> {
    fn reject_without_intent(
        &mut self,
        key: &str,
        request: &PublicationRequest,
        failure: PublicationFailure,
    ) -> Result<PublicationResult, PublicationFailure>
    where
        S: PublicationRecordPort,
    {
        let detail = failure.to_string();
        let record = PublicationRecord::rejected(
            request,
            publication_activity_kind(),
            HostActivityId::new(request.project_id()),
            detail.clone(),
            Timestamp::now(),
        );
        if let Ok(event) = self.audit_event(
            PUBLICATION_EVENT_KIND,
            PublicationStatus::NotPublished.as_str(),
            request,
            &record,
            None,
            None,
            Some(&detail),
        ) {
            let _ = self.records.save_publication(key, &record, vec![event]);
        }
        Err(failure)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_without_replace(
        &mut self,
        key: &str,
        request: &PublicationRequest,
        pending: &PublicationRecord,
        before: &InspectedTarget,
        failure: PublicationFailure,
        old_version_save: OldVersionSave,
    ) -> Result<PublicationResult, PublicationFailure>
    where
        S: PublicationRecordPort,
    {
        let detail = failure.to_string();
        let record = pending.with_result(
            PublicationStatus::NotPublished,
            None,
            old_version_save,
            Some(detail.clone()),
            Timestamp::now(),
        );
        if let Ok(event) = self.audit_event(
            PUBLICATION_EVENT_KIND,
            PublicationStatus::NotPublished.as_str(),
            request,
            &record,
            Some(before),
            None,
            Some(&detail),
        ) {
            // If even this record fails, the pending intent remains visible to
            // reconciliation. The caller still receives the original failure.
            let _ = self.records.save_publication(key, &record, vec![event]);
        }
        Err(failure)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_after_write(
        &mut self,
        key: &str,
        request: &PublicationRequest,
        pending: &PublicationRecord,
        before: &InspectedTarget,
        old_version_save: OldVersionSave,
        failure: PublicationFailure,
        observed_after_version: Option<FileVersion>,
    ) -> Result<PublicationResult, PublicationFailure>
    where
        S: PublicationRecordPort,
    {
        let detail = failure.to_string();
        let record = pending.with_result(
            PublicationStatus::Unverifiable,
            observed_after_version.clone(),
            old_version_save,
            Some(detail.clone()),
            Timestamp::now(),
        );
        if let Ok(event) = self.audit_event(
            PUBLICATION_EVENT_KIND,
            PublicationStatus::Unverifiable.as_str(),
            request,
            &record,
            Some(before),
            observed_after_version.as_ref(),
            Some(&detail),
        ) {
            let _ = self.records.save_publication(key, &record, vec![event]);
        }
        Err(failure)
    }

    fn finish_published(
        &mut self,
        key: &str,
        request: &PublicationRequest,
        pending: &PublicationRecord,
        before: &InspectedTarget,
        old_version_save: OldVersionSave,
        observed_after_version: FileVersion,
    ) -> Result<PublicationResult, PublicationFailure>
    where
        S: PublicationRecordPort,
    {
        let record = pending.with_result(
            PublicationStatus::Published,
            Some(observed_after_version.clone()),
            old_version_save,
            None,
            Timestamp::now(),
        );
        let event = match self.audit_event(
            PUBLICATION_EVENT_KIND,
            PublicationStatus::Published.as_str(),
            request,
            &record,
            Some(before),
            Some(&observed_after_version),
            None,
        ) {
            Ok(event) => event,
            Err(error) => {
                return Err(PublicationFailure::Unverifiable {
                    detail: format!(
                        "the publication was applied but its audit event could not be built: {error}"
                    ),
                });
            }
        };
        let receipt = match self.records.save_publication(key, &record, vec![event]) {
            Ok(receipt) => receipt,
            Err(error) => {
                return Err(PublicationFailure::Unverifiable {
                    detail: format!(
                        "the publication was applied but its result could not be persisted: {error}"
                    ),
                });
            }
        };
        let Some(notification) = receipt.events().first().cloned() else {
            return Err(PublicationFailure::Unverifiable {
                detail: "the publication was applied and recorded but no audit event was committed"
                    .to_owned(),
            });
        };
        Ok(PublicationResult::from_record(
            &record,
            false,
            Some(notification),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn audit_event(
        &self,
        kind: &str,
        outcome: &'static str,
        request: &PublicationRequest,
        record: &PublicationRecord,
        before: Option<&InspectedTarget>,
        observed_after_version: Option<&FileVersion>,
        detail: Option<&str>,
    ) -> Result<EventDraft, PublicationFailure> {
        let old_content = before
            .and_then(|before| before.content.as_deref())
            .unwrap_or("");
        let diff = line_diff(old_content, request.content(), request.target().as_str());
        let payload = PublicationAuditPayload {
            actor: "host",
            request_id: request.request_id().as_str(),
            project_id: request.project_id(),
            purpose: request.purpose().as_str(),
            target: request.target().as_str(),
            unit: PublicationUnit::SingleFile.as_str(),
            expected_version: request.expected_version(),
            approved_version: request.approved_version(),
            before_version: before.and_then(|before| before.version.as_ref()),
            observed_after_version,
            old_version_save: record.old_version_save(),
            outcome,
            detail,
            diff: diff.text(),
            diff_truncated: diff.is_truncated(),
        };
        let value =
            serde_json::to_value(&payload).map_err(|error| PublicationFailure::NotExecutable {
                detail: format!("publication audit payload: {error}"),
            })?;
        let event_kind =
            EventKind::new(kind).map_err(|error| PublicationFailure::NotExecutable {
                detail: format!("publication audit kind: {error}"),
            })?;
        EventDraft::for_host_activity(
            request.project_id(),
            record.activity_kind().clone(),
            record.activity_id(),
            event_kind,
            Timestamp::now(),
            EventPayload::new(value),
        )
        .map_err(|error| PublicationFailure::NotExecutable {
            detail: format!("publication host-activity subject: {error}"),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicationAuditPayload<'a> {
    actor: &'static str,
    request_id: &'a str,
    project_id: ProjectId,
    purpose: &'a str,
    target: &'a str,
    unit: &'static str,
    expected_version: &'a ExpectedTargetVersion,
    approved_version: &'a FileVersion,
    before_version: Option<&'a FileVersion>,
    observed_after_version: Option<&'a FileVersion>,
    old_version_save: &'a OldVersionSave,
    outcome: &'static str,
    detail: Option<&'a str>,
    diff: &'a str,
    diff_truncated: bool,
}

fn publication_record_key(project_id: ProjectId, request_id: &PublicationRequestId) -> String {
    let digest = hash_bytes(request_id.as_str().as_bytes());
    format!("herness.publication.{project_id}.{}", digest.as_str())
}

fn publication_activity_kind() -> EventKind {
    EventKind::new(PUBLICATION_ACTIVITY_KIND).expect("the publication activity kind is non-empty")
}

fn stop_failure(control: &RunControl) -> PublicationFailure {
    let detail = match control.stop_reason() {
        Some(reason) => format!("the host stop control is set to {reason:?}"),
        None => "the host deadline has been reached".to_owned(),
    };
    PublicationFailure::Stopped { detail }
}

fn duplicate_result(
    record: PublicationRecord,
    request: &PublicationRequest,
) -> Result<PublicationResult, PublicationFailure> {
    let expected = request.fingerprint();
    if record.request_fingerprint() != &expected {
        return Err(PublicationFailure::RequestConflict {
            request_id: request.request_id().to_string(),
        });
    }
    match record.status() {
        PublicationStatus::Published | PublicationStatus::NotPublished => {
            Ok(PublicationResult::from_record(&record, true, None))
        }
        PublicationStatus::Pending => Err(PublicationFailure::ReconciliationRequired {
            request_id: request.request_id().to_string(),
            detail: "the request has a durable intent but no durable result".to_owned(),
        }),
        PublicationStatus::Unverifiable => Err(PublicationFailure::ReconciliationRequired {
            request_id: request.request_id().to_string(),
            detail: "the previous attempt is unverifiable; reconcile before retrying".to_owned(),
        }),
    }
}

fn old_version_save_from_failure(failure: &PublicationFailure) -> OldVersionSave {
    match failure {
        PublicationFailure::Unverifiable { detail } => OldVersionSave::Unknown {
            detail: detail.clone(),
        },
        other => OldVersionSave::Failed {
            detail: other.to_string(),
        },
    }
}

fn classify_write_error(
    request: &PublicationRequest,
    target: &InspectedTarget,
    error: &std::io::Error,
) -> PublicationFailure {
    let detail = format!("atomic replacement failed: {:?}", error.kind());
    match fs::symlink_metadata(target.resolved.absolute()) {
        Err(metadata_error) if metadata_error.kind() == std::io::ErrorKind::NotFound => {
            if target.version.is_none() {
                PublicationFailure::NotExecutable { detail }
            } else {
                PublicationFailure::Unverifiable {
                    detail: format!("{detail}; the old target disappeared"),
                }
            }
        }
        Ok(metadata) if metadata.file_type().is_symlink() => PublicationFailure::Unverifiable {
            detail: format!("{detail}; the target is now a symlink"),
        },
        Ok(metadata) if !metadata.is_file() => PublicationFailure::Unverifiable {
            detail: format!("{detail}; the target is no longer a regular file"),
        },
        Ok(_) => match fs::read(target.resolved.absolute()) {
            Ok(bytes) if bytes == request.content().as_bytes() => {
                PublicationFailure::Unverifiable {
                    detail: format!(
                        "{detail}; the target already has the approved bytes and may have been replaced"
                    ),
                }
            }
            Ok(bytes) => {
                let current = hash_bytes(&bytes);
                if target
                    .version
                    .as_ref()
                    .is_some_and(|before| before == &current)
                {
                    PublicationFailure::NotExecutable { detail }
                } else {
                    PublicationFailure::Unverifiable {
                        detail: format!(
                            "{detail}; the target content matches neither the before nor the approved state"
                        ),
                    }
                }
            }
            Err(read_error) => PublicationFailure::Unverifiable {
                detail: format!(
                    "{detail}; the target could not be re-read: {:?}",
                    read_error.kind()
                ),
            },
        },
        Err(metadata_error) => PublicationFailure::Unverifiable {
            detail: format!(
                "{detail}; the target could not be inspected: {:?}",
                metadata_error.kind()
            ),
        },
    }
}

/// Old-version archive rooted in one host-supplied private app-area directory.
///
/// Each request stores one JSON file containing the exact old text and its
/// metadata. The reference returned to the record is relative so the absolute
/// private app path never enters public event payloads.
#[derive(Debug)]
pub struct PrivateAppArchive {
    root: PathBuf,
}

impl PrivateAppArchive {
    /// Creates an archive under `root`, creating the directory when needed.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, PublicationFailure> {
        let root = root.as_ref();
        if root.as_os_str().is_empty() {
            return Err(PublicationFailure::ArchiveUnavailable {
                detail: "the private archive root is empty".to_owned(),
            });
        }
        fs::create_dir_all(root).map_err(|error| PublicationFailure::ArchiveUnavailable {
            detail: format!("cannot create the private archive root: {:?}", error.kind()),
        })?;
        let root =
            fs::canonicalize(root).map_err(|error| PublicationFailure::ArchiveUnavailable {
                detail: format!(
                    "cannot canonicalize the private archive root: {:?}",
                    error.kind()
                ),
            })?;
        let metadata =
            fs::metadata(&root).map_err(|error| PublicationFailure::ArchiveUnavailable {
                detail: format!("cannot read the private archive root: {:?}", error.kind()),
            })?;
        if !metadata.is_dir() {
            return Err(PublicationFailure::ArchiveUnavailable {
                detail: "the private archive root is not a directory".to_owned(),
            });
        }
        Ok(Self { root })
    }

    /// Canonical private archive root.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl PublicationArchivePort for PrivateAppArchive {
    fn save_old_version(
        &mut self,
        archive: &OldVersionArchive<'_>,
    ) -> Result<ArchivedVersion, PublicationFailure> {
        let content_version = hash_bytes(archive.content().as_bytes());
        if content_version != *archive.version() {
            return Err(PublicationFailure::OldVersionSaveFailed {
                detail: "the archive request version does not match its content bytes".to_owned(),
            });
        }

        let directory = self.root.join(archive.project_id().to_string());
        ensure_private_directory(&directory)?;
        let file_name = format!(
            "{}.json",
            hash_bytes(archive.request_id().as_str().as_bytes()).as_str()
        );
        let path = directory.join(&file_name);
        let stored = ArchivedVersionFile {
            format: ARCHIVE_FORMAT,
            project_id: archive.project_id(),
            request_id: archive.request_id().clone(),
            target: archive.target().to_owned(),
            version: archive.version().clone(),
            content: archive.content().to_owned(),
        };
        let reference = format!("{}/{}", archive.project_id(), file_name);

        if path.exists() {
            let existing =
                fs::read(&path).map_err(|error| PublicationFailure::OldVersionSaveFailed {
                    detail: format!("cannot read the existing archive entry: {:?}", error.kind()),
                })?;
            let existing: ArchivedVersionFile =
                serde_json::from_slice(&existing).map_err(|error| {
                    PublicationFailure::OldVersionSaveFailed {
                        detail: format!("the existing archive entry is corrupt: {error}"),
                    }
                })?;
            if existing.format != ARCHIVE_FORMAT {
                return Err(PublicationFailure::OldVersionSaveFailed {
                    detail: format!(
                        "the existing archive entry has unsupported format {}",
                        existing.format
                    ),
                });
            }
            if existing.project_id == stored.project_id
                && existing.request_id == stored.request_id
                && existing.target == stored.target
                && existing.version == stored.version
                && existing.content == stored.content
            {
                return ArchivedVersion::new(stored.version, reference).map_err(|error| {
                    PublicationFailure::OldVersionSaveFailed {
                        detail: error.to_string(),
                    }
                });
            }
            return Err(PublicationFailure::OldVersionSaveFailed {
                detail: "the archive entry already exists with different content".to_owned(),
            });
        }

        let bytes = serde_json::to_vec(&stored).map_err(|error| {
            PublicationFailure::OldVersionSaveFailed {
                detail: format!("cannot encode the archive entry: {error}"),
            }
        })?;
        atomic_write(&path, &bytes, false).map_err(|error| {
            PublicationFailure::OldVersionSaveFailed {
                detail: format!("the old version archive write failed: {:?}", error.kind()),
            }
        })?;
        ArchivedVersion::new(stored.version, reference).map_err(|error| {
            PublicationFailure::OldVersionSaveFailed {
                detail: error.to_string(),
            }
        })
    }
}

#[derive(Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArchivedVersionFile {
    format: u32,
    project_id: ProjectId,
    request_id: PublicationRequestId,
    target: String,
    version: FileVersion,
    content: String,
}

fn ensure_private_directory(directory: &Path) -> Result<(), PublicationFailure> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(PublicationFailure::ArchiveUnavailable {
                detail: "the private archive project directory is a symlink".to_owned(),
            })
        }
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(PublicationFailure::ArchiveUnavailable {
            detail: "the private archive project path is not a directory".to_owned(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(directory)
            .map_err(|error| PublicationFailure::ArchiveUnavailable {
                detail: format!(
                    "cannot create the private archive project directory: {:?}",
                    error.kind()
                ),
            }),
        Err(error) => Err(PublicationFailure::ArchiveUnavailable {
            detail: format!(
                "cannot inspect the private archive project directory: {:?}",
                error.kind()
            ),
        }),
    }
}
