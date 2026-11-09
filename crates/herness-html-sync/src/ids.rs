//! Project-scoped H3 identifiers.
//!
//! H3 job, cycle, generation, publication, request, and candidate identifiers
//! are distinct from H1 run/operation IDs and H2 supervision IDs. Their wire
//! form is `"<kind>:<project-uuid>:<local-uuid>"`, so a cross-project reference
//! is detectable before any state changes.

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use herness_core::ProjectId;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::H3Error;

/// Marker trait implemented by each H3 identifier kind.
pub trait H3KeyKind: Copy + 'static {
    /// Stable prefix used in the wire representation.
    const PREFIX: &'static str;
    /// Stable label used in structured errors.
    const LABEL: &'static str;
}

macro_rules! key_kind {
    ($name:ident, $prefix:literal, $label:literal) => {
        /// Marker type for one H3 identifier kind.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {}

        impl H3KeyKind for $name {
            const PREFIX: &'static str = $prefix;
            const LABEL: &'static str = $label;
        }
    };
}

key_kind!(JobKind, "h3_job", "html sync job");
key_kind!(CycleKind, "h3_cycle", "html sync cycle");
key_kind!(GenerationKind, "h3_generation", "html sync generation");
key_kind!(PublicationKind, "h3_publication", "html sync publication");
key_kind!(RequestKind, "h3_request", "html sync request");
key_kind!(CandidateKind, "h3_candidate", "html sync candidate");

/// A typed H3 identifier bound to exactly one project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct H3ScopedId<K: H3KeyKind> {
    project: ProjectId,
    local: Uuid,
    _kind: PhantomData<fn() -> K>,
}

impl<K: H3KeyKind> H3ScopedId<K> {
    /// Generates a new random identifier within `project`.
    pub fn new(project: ProjectId) -> Self {
        Self {
            project,
            local: Uuid::new_v4(),
            _kind: PhantomData,
        }
    }

    /// Reconstructs an identifier from its project and local UUID parts.
    pub const fn from_parts(project: ProjectId, local: Uuid) -> Self {
        Self {
            project,
            local,
            _kind: PhantomData,
        }
    }

    /// Project this identifier belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project
    }

    /// Project-local UUID part.
    pub const fn local_id(&self) -> Uuid {
        self.local
    }

    /// Rejects the identifier when it belongs to another project.
    pub fn validate_in(&self, project: ProjectId) -> Result<(), H3Error> {
        if self.project == project {
            Ok(())
        } else {
            Err(H3Error::CrossProject {
                id_kind: K::LABEL.to_owned(),
                expected: project,
                found: self.project,
            })
        }
    }
}

impl<K: H3KeyKind> fmt::Display for H3ScopedId<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", K::PREFIX, self.project, self.local)
    }
}

impl<K: H3KeyKind> FromStr for H3ScopedId<K> {
    type Err = H3Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || H3Error::invalid(K::LABEL, format!("invalid identifier {value:?}"));

        let mut parts = value.split(':');
        let prefix = parts.next().ok_or_else(invalid)?;
        let project = parts.next().ok_or_else(invalid)?;
        let local = parts.next().ok_or_else(invalid)?;
        if parts.next().is_some() || prefix != K::PREFIX {
            return Err(invalid());
        }
        let project = ProjectId::from_str(project).map_err(|_| invalid())?;
        let local = Uuid::parse_str(local).map_err(|_| invalid())?;
        Ok(Self::from_parts(project, local))
    }
}

impl<K: H3KeyKind> Serialize for H3ScopedId<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de, K: H3KeyKind> Deserialize<'de> for H3ScopedId<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// H3 sync job identifier.
pub type JobId = H3ScopedId<JobKind>;
/// H3 sync cycle identifier.
pub type CycleId = H3ScopedId<CycleKind>;
/// H3 document generation identifier.
pub type GenerationId = H3ScopedId<GenerationKind>;
/// H3 publication journal identifier.
pub type PublicationId = H3ScopedId<PublicationKind>;
/// H3 idempotent operation request identifier.
pub type H3RequestId = H3ScopedId<RequestKind>;
/// H3 candidate metadata identifier.
pub type CandidateId = H3ScopedId<CandidateKind>;
