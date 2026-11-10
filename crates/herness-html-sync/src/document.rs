//! Document identity, monotonic source revisions, and dependency fingerprints.
//!
//! The document key is the project identifier plus the canonical
//! Target-relative Markdown path produced by the shared SDD resolver. H3 never
//! resolves a path on its own and never accepts an absolute or escaping path.
//!
//! The source revision is a monotonic observation counter, while the source
//! digest is the exact SHA-256 of the Markdown bytes. Returning to earlier bytes
//! changes the digest but never moves the revision backwards.

use herness_core::{ArgumentViolation, HostActivityId, ProjectId};
use herness_supervision::ContentDigest;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::H3Error;

/// Maximum UTF-8 bytes in one canonical Target-relative path.
pub const MAX_DOCUMENT_PATH_BYTES: usize = 4_096;

/// Project-scoped identity of one Target Markdown document.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DocumentKey {
    project_id: ProjectId,
    target_path: String,
    activity_id: HostActivityId,
}

impl DocumentKey {
    /// Validates a canonical Target-relative Markdown path.
    ///
    /// The path must be relative, use `/` separators, end in `.md`, contain no
    /// `.` or `..` component, no control characters, and stay within the byte
    /// limit.
    pub fn new(project_id: ProjectId, target_path: impl Into<String>) -> Result<Self, H3Error> {
        let target_path = target_path.into();
        if target_path.is_empty() {
            return Err(H3Error::empty("targetPath"));
        }
        if target_path.len() > MAX_DOCUMENT_PATH_BYTES {
            return Err(H3Error::InvalidValue {
                field: "targetPath".to_owned(),
                violation: ArgumentViolation::TooLongBytes {
                    actual: target_path.len(),
                    max: MAX_DOCUMENT_PATH_BYTES,
                },
            });
        }
        if target_path.contains('\0') || target_path.chars().any(char::is_control) {
            return Err(H3Error::invalid(
                "targetPath",
                "control characters are not allowed",
            ));
        }
        if target_path.starts_with('/') || target_path.contains('\\') {
            return Err(H3Error::invalid(
                "targetPath",
                "the Target path must be project-relative with '/' separators",
            ));
        }
        if !target_path.ends_with(".md") {
            return Err(H3Error::invalid(
                "targetPath",
                "the Target path must name a Markdown file",
            ));
        }
        for component in target_path.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(H3Error::invalid(
                    "targetPath",
                    "the Target path must not contain empty, '.' or '..' components",
                ));
            }
        }
        let activity_id = document_activity_id(project_id, &target_path);
        Ok(Self {
            project_id,
            target_path,
            activity_id,
        })
    }

    /// Project that owns the document.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Canonical Target-relative Markdown path.
    pub fn target_path(&self) -> &str {
        &self.target_path
    }

    /// Companion HTML path derived from the Target path.
    pub fn companion_path(&self) -> String {
        let stem = self
            .target_path
            .strip_suffix(".md")
            .expect("document paths always end in .md");
        format!("{stem}.html")
    }

    /// Stable host-activity identifier for this document.
    pub const fn activity_id(&self) -> HostActivityId {
        self.activity_id
    }

    /// Exact SHA-256 over the project and canonical path.
    pub fn digest(&self) -> ContentDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"h3-document\0");
        hasher.update(self.project_id.to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(self.target_path.as_bytes());
        ContentDigest::sha256(&hasher.finalize())
    }

    /// Rejects a key belonging to another project.
    pub fn validate_in(&self, project: ProjectId) -> Result<(), H3Error> {
        if self.project_id == project {
            Ok(())
        } else {
            Err(H3Error::CrossProject {
                id_kind: "document key".to_owned(),
                expected: project,
                found: self.project_id,
            })
        }
    }
}

fn document_activity_id(project_id: ProjectId, target_path: &str) -> HostActivityId {
    let mut hasher = Sha256::new();
    hasher.update(b"h3-document-activity\0");
    hasher.update(project_id.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(target_path.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize()[..16]);
    HostActivityId::from_parts(project_id, Uuid::from_bytes(bytes))
}

impl Serialize for DocumentKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire<'a> {
            project_id: ProjectId,
            target_path: &'a str,
        }
        Wire {
            project_id: self.project_id,
            target_path: &self.target_path,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DocumentKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            project_id: ProjectId,
            target_path: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.project_id, wire.target_path).map_err(de::Error::custom)
    }
}

/// A positive, monotonic observation revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SourceRevision(u64);

impl SourceRevision {
    /// Creates a positive revision.
    pub fn new(value: u64) -> Result<Self, H3Error> {
        if value == 0 {
            return Err(H3Error::must_be_positive("sourceRevision"));
        }
        Ok(Self(value))
    }

    /// Returns the numeric revision.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Exact source bytes and the monotonic revision that observed them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceSnapshot {
    revision: SourceRevision,
    digest: ContentDigest,
}

impl SourceSnapshot {
    /// Creates a snapshot from an explicit revision and exact digest.
    pub const fn new(revision: SourceRevision, digest: ContentDigest) -> Self {
        Self { revision, digest }
    }

    /// Records an observation without ever moving the revision backwards.
    ///
    /// The observed counter may be lower than the stored revision after a
    /// watcher restart. The stored revision is then kept. Returning to earlier
    /// bytes changes the digest and still advances or keeps the revision.
    pub fn observe(
        previous: Option<&Self>,
        observed: u64,
        digest: ContentDigest,
    ) -> Result<Self, H3Error> {
        if observed == 0 {
            return Err(H3Error::must_be_positive("sourceRevision"));
        }
        let revision = match previous {
            Some(previous) => SourceRevision::new(observed.max(previous.revision.get()))?,
            None => SourceRevision::new(observed)?,
        };
        Ok(Self { revision, digest })
    }

    /// Monotonic observation revision.
    pub const fn revision(&self) -> SourceRevision {
        self.revision
    }

    /// Exact Markdown bytes digest.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// Whether two snapshots carry exactly the same source bytes.
    pub fn same_bytes(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

/// Why current applicability was lost or retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintKind {
    /// Approved H3 settings.
    Settings,
    /// Common SDD policy and host-API version.
    Policy,
    /// Shared CSS.
    Css,
    /// Referenced local resources.
    Resources,
    /// Candidate HTML bytes.
    Candidate,
    /// Candidate provenance mapping.
    Provenance,
    /// Saved evaluation evidence.
    Evidence,
}

impl FingerprintKind {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Settings => "settings",
            Self::Policy => "policy",
            Self::Css => "css",
            Self::Resources => "resources",
            Self::Candidate => "candidate",
            Self::Provenance => "provenance",
            Self::Evidence => "evidence",
        }
    }
}

/// Separate fingerprints for every dependency that can invalidate a sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FingerprintSet {
    format_version: u32,
    settings: ContentDigest,
    policy: ContentDigest,
    css: ContentDigest,
    resources: ContentDigest,
    candidate: Option<ContentDigest>,
    provenance: Option<ContentDigest>,
    evidence: Option<ContentDigest>,
}

impl FingerprintSet {
    /// Creates a fingerprint set. Settings, policy, CSS, and resources are
    /// mandatory; candidate, provenance, and evidence exist after authoring.
    pub const fn new(
        settings: ContentDigest,
        policy: ContentDigest,
        css: ContentDigest,
        resources: ContentDigest,
        candidate: Option<ContentDigest>,
        provenance: Option<ContentDigest>,
        evidence: Option<ContentDigest>,
    ) -> Self {
        Self {
            format_version: crate::version::H3_FORMAT_VERSION,
            settings,
            policy,
            css,
            resources,
            candidate,
            provenance,
            evidence,
        }
    }

    /// Fingerprint for one dependency kind.
    pub const fn get(&self, kind: FingerprintKind) -> Option<&ContentDigest> {
        match kind {
            FingerprintKind::Settings => Some(&self.settings),
            FingerprintKind::Policy => Some(&self.policy),
            FingerprintKind::Css => Some(&self.css),
            FingerprintKind::Resources => Some(&self.resources),
            FingerprintKind::Candidate => self.candidate.as_ref(),
            FingerprintKind::Provenance => self.provenance.as_ref(),
            FingerprintKind::Evidence => self.evidence.as_ref(),
        }
    }

    /// Replaces the candidate fingerprint after authoring.
    pub fn with_candidate(mut self, candidate: ContentDigest) -> Self {
        self.candidate = Some(candidate);
        self
    }

    /// Replaces the provenance fingerprint after authoring.
    pub fn with_provenance(mut self, provenance: ContentDigest) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// Replaces the evidence fingerprint after assessment.
    pub fn with_evidence(mut self, evidence: ContentDigest) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// Compares every stored fingerprint with a later dependency snapshot.
    ///
    /// The first changed kind is returned. Candidate or evidence fingerprints
    /// that were absent before and are still absent do not count as changes.
    pub fn changed_since(&self, later: &Self) -> Option<FingerprintKind> {
        const KINDS: [FingerprintKind; 7] = [
            FingerprintKind::Settings,
            FingerprintKind::Policy,
            FingerprintKind::Css,
            FingerprintKind::Resources,
            FingerprintKind::Candidate,
            FingerprintKind::Provenance,
            FingerprintKind::Evidence,
        ];
        KINDS
            .into_iter()
            .find(|kind| self.get(*kind) != later.get(*kind))
    }
}

impl crate::version::H3Record for FingerprintSet {
    const RECORD: &'static str = "fingerprint set";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}
