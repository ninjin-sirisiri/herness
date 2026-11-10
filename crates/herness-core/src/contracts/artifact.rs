//! Host-issued candidate artifact handles and opaque snapshots.
//!
//! An artifact handle binds one candidate authoring context to a project, job,
//! and generation. H1 treats the handle as opaque capability data: it never
//! interprets the job or derives storage paths from it. The host artifact port
//! is the only component that knows how a handle maps to private storage.
//!
//! Candidate artifacts are addressed by [`ArtifactSlot`], never by a
//! model-supplied project path. Writes and edits accept only the candidate
//! slots; immutable source snapshots and the formal companion/CSS surfaces are
//! read-only.

use std::fmt;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::ids::ProjectId;
use crate::tools::NonEmptyText;
use crate::tools::arguments::FileVersion;

/// Host-issued handle for one candidate authoring context.
///
/// The handle is bound to the project, H3 job, and generation that the host
/// approved. The token is an opaque capability value; it is never a filesystem
/// path. A stale or foreign handle is rejected before any artifact is read or
/// changed.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ArtifactHandle {
    project_id: ProjectId,
    job_id: NonEmptyText,
    generation: u64,
    token: NonEmptyText,
}

impl ArtifactHandle {
    /// Creates a validated handle.
    ///
    /// `job_id` and `token` must be non-empty after trimming. Generation zero
    /// is not a valid generation.
    pub fn new(
        project_id: ProjectId,
        job_id: impl AsRef<str>,
        generation: u64,
        token: impl AsRef<str>,
    ) -> Result<Self, CoreError> {
        if generation == 0 {
            return Err(CoreError::InvalidValue {
                field: "artifactGeneration".to_owned(),
                violation: ArgumentViolation::MustBePositive,
            });
        }
        Ok(Self {
            project_id,
            job_id: required("artifactJobId", job_id)?,
            generation,
            token: required("artifactToken", token)?,
        })
    }

    /// Project that owns the job and candidate.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Opaque host job identifier.
    pub fn job_id(&self) -> &str {
        self.job_id.as_str()
    }

    /// Monotonic candidate generation within the job.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Opaque host capability token.
    pub fn token(&self) -> &str {
        self.token.as_str()
    }
}

impl fmt::Debug for ArtifactHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The token is a capability. Keep it out of logs and diagnostics.
        f.debug_struct("ArtifactHandle")
            .field("project_id", &self.project_id)
            .field("job_id", &self.job_id)
            .field("generation", &self.generation)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl Serialize for ArtifactHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("ArtifactHandle", 4)?;
        state.serialize_field("projectId", &self.project_id)?;
        state.serialize_field("jobId", self.job_id.as_str())?;
        state.serialize_field("generation", &self.generation)?;
        state.serialize_field("token", self.token.as_str())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ArtifactHandle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            project_id: ProjectId,
            job_id: String,
            generation: u64,
            token: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.project_id, wire.job_id, wire.generation, wire.token)
            .map_err(de::Error::custom)
    }
}

fn required(field: &str, value: impl AsRef<str>) -> Result<NonEmptyText, CoreError> {
    let value = value.as_ref();
    if value.trim().is_empty() {
        return Err(CoreError::InvalidValue {
            field: field.to_owned(),
            violation: ArgumentViolation::Empty,
        });
    }
    NonEmptyText::new(value)
}

/// One addressable artifact in a candidate authoring context.
///
/// Only [`ArtifactSlot::CandidateHtml`] and
/// [`ArtifactSlot::CandidateProvenance`] may be written or edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSlot {
    /// Immutable Markdown source snapshot for this generation.
    SourceMarkdown,
    /// Immutable current HTML companion snapshot, when one exists.
    ExistingHtml,
    /// Immutable shared CSS snapshot.
    SharedCss,
    /// The candidate HTML authored by the agent.
    CandidateHtml,
    /// The candidate provenance mapping authored by the agent.
    CandidateProvenance,
}

impl ArtifactSlot {
    /// Every slot in stable order.
    pub const ALL: [Self; 5] = [
        Self::SourceMarkdown,
        Self::ExistingHtml,
        Self::SharedCss,
        Self::CandidateHtml,
        Self::CandidateProvenance,
    ];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceMarkdown => "source_markdown",
            Self::ExistingHtml => "existing_html",
            Self::SharedCss => "shared_css",
            Self::CandidateHtml => "candidate_html",
            Self::CandidateProvenance => "candidate_provenance",
        }
    }

    /// Whether this slot is a candidate that write and edit may modify.
    pub const fn is_candidate(self) -> bool {
        matches!(self, Self::CandidateHtml | Self::CandidateProvenance)
    }
}

impl fmt::Display for ArtifactSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A versioned artifact body returned by the host artifact port.
///
/// `version` is the SHA-256 of `content`. The executor verifies it before and
/// after a write; the port does not get to silently truncate or rewrite bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactSnapshot {
    artifact: ArtifactSlot,
    version: FileVersion,
    content: String,
}

impl ArtifactSnapshot {
    /// Creates a snapshot from an artifact slot, version, and exact text.
    pub const fn new(artifact: ArtifactSlot, version: FileVersion, content: String) -> Self {
        Self {
            artifact,
            version,
            content,
        }
    }

    /// Slot this snapshot describes.
    pub const fn artifact(&self) -> ArtifactSlot {
        self.artifact
    }

    /// SHA-256 version of the exact bytes.
    pub const fn version(&self) -> &FileVersion {
        &self.version
    }

    /// Exact text content.
    pub fn content(&self) -> &str {
        &self.content
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::hash_bytes;

    fn handle() -> ArtifactHandle {
        ArtifactHandle::new(ProjectId::new(), "job-1", 2, "token-1").expect("handle")
    }

    #[test]
    fn handle_roundtrips_and_rejects_empty_or_zero_fields() {
        let handle = handle();
        let encoded = serde_json::to_value(&handle).expect("serialize");
        assert_eq!(encoded["jobId"], "job-1");
        assert_eq!(encoded["generation"], 2);
        assert_eq!(encoded["token"], "token-1");
        assert_eq!(
            serde_json::from_value::<ArtifactHandle>(encoded).expect("deserialize"),
            handle
        );

        let project = ProjectId::new();
        assert!(ArtifactHandle::new(project, "", 1, "token").is_err());
        assert!(ArtifactHandle::new(project, "job", 0, "token").is_err());
        assert!(ArtifactHandle::new(project, "job", 1, "  ").is_err());
    }

    #[test]
    fn only_candidate_slots_are_writable() {
        for slot in ArtifactSlot::ALL {
            assert_eq!(
                slot.is_candidate(),
                matches!(
                    slot,
                    ArtifactSlot::CandidateHtml | ArtifactSlot::CandidateProvenance
                )
            );
        }
        assert_eq!(ArtifactSlot::CandidateHtml.as_str(), "candidate_html");
    }

    #[test]
    fn snapshot_version_is_the_content_digest() {
        let content = "<html></html>".to_owned();
        let snapshot = ArtifactSnapshot::new(
            ArtifactSlot::CandidateHtml,
            hash_bytes(content.as_bytes()),
            content.clone(),
        );
        assert_eq!(snapshot.content(), content);
        assert_eq!(snapshot.version(), &hash_bytes(content.as_bytes()));
    }
}
