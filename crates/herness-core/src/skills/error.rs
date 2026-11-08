//! Structured, non-secret skill and capability failures.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::skills::capability::{CapabilityUnavailableReason, HostCapability, SkillExecutionFlow};
use crate::skills::digest::SkillDigest;
use crate::skills::pack::SkillId;

/// Structured reason a skill operation failed.
///
/// Paths are recorded as supplied or resolved; pack contents, credentials, and
/// provider data are never included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum SkillFailure {
    /// The skill document or a required reference did not exist.
    NotFound {
        /// Missing path.
        path: String,
    },
    /// A referenced path existed but was not a regular file.
    NotAFile {
        /// Rejected path.
        path: String,
    },
    /// A resolved path escaped the configured pack root.
    OutsidePack {
        /// Rejected resolved path.
        path: String,
    },
    /// The skill or a reference was not valid UTF-8.
    InvalidUtf8 {
        /// Path whose bytes were rejected.
        path: String,
    },
    /// The filesystem rejected a read.
    Io {
        /// Path involved.
        path: String,
        /// Sanitized error kind.
        error_kind: String,
    },
    /// A relative reference could not be interpreted without escaping the
    /// pack.
    InvalidReference {
        /// Reference text as written in the skill.
        reference: String,
        /// Sanitized explanation.
        detail: String,
    },
    /// The skill or one of its included references changed after load.
    ChangedDuringRun {
        /// Fingerprint captured at load time.
        previous: SkillDigest,
        /// Fingerprint observed now.
        current: SkillDigest,
    },
    /// The skill's declared worker flow needs an unavailable host capability.
    CapabilityUnavailable {
        /// Requested worker flow.
        flow: SkillExecutionFlow,
        /// Capability the flow depends on.
        capability: HostCapability,
        /// Structured unavailability reason.
        reason: CapabilityUnavailableReason,
    },
    /// Documents from different pack roots were combined in one run context.
    MixedPackRoots {
        /// Pack root of the first document.
        expected: String,
        /// Pack root of the mismatched document.
        found: String,
    },
    /// The same skill was loaded twice into one run context.
    DuplicateSkill {
        /// Duplicated skill id.
        skill: SkillId,
    },
    /// An overlay or flow referred to a skill that is not in the context.
    UnknownSkill {
        /// Unknown skill id.
        skill: SkillId,
    },
    /// More than one overlay was supplied for the same skill.
    DuplicateOverlay {
        /// Skill with duplicate overlays.
        skill: SkillId,
    },
    /// More than one execution flow was supplied for the same skill.
    DuplicateFlow {
        /// Skill with duplicate flows.
        skill: SkillId,
    },
    /// The overlay's `removedText` did not occur in the pack text.
    OverlayRemovalNotFound {
        /// Skill the overlay belongs to.
        skill: SkillId,
    },
    /// The overlay's `removedText` occurred more than once in the pack text.
    OverlayRemovalNotUnique {
        /// Skill the overlay belongs to.
        skill: SkillId,
        /// Number of non-overlapping occurrences observed.
        occurrences: u64,
    },
}

impl fmt::Display for SkillFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { path } => write!(f, "path {path:?} does not exist"),
            Self::NotAFile { path } => write!(f, "path {path:?} is not a regular file"),
            Self::OutsidePack { path } => {
                write!(f, "path {path:?} is outside the configured pack root")
            }
            Self::InvalidUtf8 { path } => write!(f, "path {path:?} is not valid UTF-8"),
            Self::Io { path, error_kind } => {
                write!(f, "cannot read {path:?}: {error_kind}")
            }
            Self::InvalidReference { reference, detail } => {
                write!(f, "invalid skill reference {reference:?}: {detail}")
            }
            Self::ChangedDuringRun { previous, current } => write!(
                f,
                "skill changed during the run: fingerprint {previous} is now {current}"
            ),
            Self::CapabilityUnavailable {
                flow,
                capability,
                reason,
            } => write!(
                f,
                "skill flow {} requires unavailable capability {} ({reason:?})",
                flow.as_str(),
                capability.as_str()
            ),
            Self::MixedPackRoots { expected, found } => {
                write!(
                    f,
                    "skill pack roots differ: expected {expected:?}, found {found:?}"
                )
            }
            Self::DuplicateSkill { skill } => write!(f, "skill {skill} was loaded twice"),
            Self::UnknownSkill { skill } => {
                write!(f, "skill {skill} is not part of the run context")
            }
            Self::DuplicateOverlay { skill } => {
                write!(f, "skill {skill} has more than one host overlay")
            }
            Self::DuplicateFlow { skill } => {
                write!(f, "skill {skill} has more than one execution flow")
            }
            Self::OverlayRemovalNotFound { skill } => write!(
                f,
                "host overlay for skill {skill} removes text that is not present in the pack text"
            ),
            Self::OverlayRemovalNotUnique { skill, occurrences } => write!(
                f,
                "host overlay for skill {skill} removes text that occurs {occurrences} times; expected exactly one"
            ),
        }
    }
}
