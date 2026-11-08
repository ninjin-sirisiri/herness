//! Project-scoped identifiers used by supervision records.
//!
//! The IDs are stable within one project. Their wire form is
//! `"<kind>:<project-uuid>:<local-uuid>"`, mirroring H1 identifiers so a
//! cross-project reference is detectable before any state changes.

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use herness_core::contracts::{ProjectId, ScopedId, ScopedIdKind};
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SupervisionError;

/// Marker trait implemented by each supervision identifier kind.
pub trait SupervisionKeyKind: Copy + 'static {
    /// Stable prefix used in the wire representation.
    const PREFIX: &'static str;
    /// Stable label used in structured errors.
    const LABEL: &'static str;
}

macro_rules! key_kind {
    ($name:ident, $prefix:literal, $label:literal) => {
        /// Marker type for one supervision identifier kind.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {}

        impl SupervisionKeyKind for $name {
            const PREFIX: &'static str = $prefix;
            const LABEL: &'static str = $label;
        }
    };
}

key_kind!(SupervisionKind, "supervision", "supervision");
key_kind!(ConditionKind, "condition", "condition");
key_kind!(CheckKind, "check", "check");
key_kind!(EvidenceKind, "evidence", "evidence");
key_kind!(DecisionKind, "decision", "decision");
key_kind!(RunGroupKind, "run_group", "run group");
key_kind!(ConsentKind, "consent", "consent");
key_kind!(ProfileKind, "profile", "profile");
key_kind!(CommandKind, "command", "command");

/// A typed supervision identifier bound to exactly one project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SupervisionScopedId<K: SupervisionKeyKind> {
    project: ProjectId,
    local: Uuid,
    _kind: PhantomData<fn() -> K>,
}

impl<K: SupervisionKeyKind> SupervisionScopedId<K> {
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
    pub fn validate_in(&self, project: ProjectId) -> Result<(), SupervisionError> {
        if self.project == project {
            Ok(())
        } else {
            Err(SupervisionError::CrossProjectReference {
                id_kind: K::LABEL.to_owned(),
                expected: project,
                found: self.project,
            })
        }
    }
}

impl<K: SupervisionKeyKind> fmt::Display for SupervisionScopedId<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", K::PREFIX, self.project, self.local)
    }
}

impl<K: SupervisionKeyKind> FromStr for SupervisionScopedId<K> {
    type Err = SupervisionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || SupervisionError::InvalidId {
            id_kind: K::LABEL.to_owned(),
            value: value.to_owned(),
        };

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

impl<K: SupervisionKeyKind> Serialize for SupervisionScopedId<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de, K: SupervisionKeyKind> Deserialize<'de> for SupervisionScopedId<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// Supervision target identifier.
pub type SupervisionId = SupervisionScopedId<SupervisionKind>;
/// Completion-condition identifier.
pub type ConditionId = SupervisionScopedId<ConditionKind>;
/// Required verification-check identifier.
pub type CheckId = SupervisionScopedId<CheckKind>;
/// Verification-evidence identifier.
pub type EvidenceId = SupervisionScopedId<EvidenceKind>;
/// Assessment-decision identifier.
pub type DecisionId = SupervisionScopedId<DecisionKind>;
/// Run-group identifier.
pub type RunGroupId = SupervisionScopedId<RunGroupKind>;
/// Disclosure-consent identifier.
pub type ConsentId = SupervisionScopedId<ConsentKind>;
/// Assessment-profile identifier.
pub type ProfileId = SupervisionScopedId<ProfileKind>;
/// Host-owned idempotent command identifier.
pub type SupervisionRequestId = SupervisionScopedId<CommandKind>;

/// Verifies that a core project-scoped identifier belongs to `project`.
pub(crate) fn verify_core_id<K: ScopedIdKind>(
    id: &ScopedId<K>,
    project: ProjectId,
) -> Result<(), SupervisionError> {
    id.validate_in(&project)
        .map_err(|_| SupervisionError::CrossProjectReference {
            id_kind: K::KIND.as_str().to_owned(),
            expected: project,
            found: id.project_id(),
        })
}

/// Verifies that a supervision identifier belongs to `project`.
pub(crate) fn verify_scoped<K: SupervisionKeyKind>(
    id: &SupervisionScopedId<K>,
    project: ProjectId,
) -> Result<(), SupervisionError> {
    id.validate_in(project)
}
