//! Host-specific additions and removals applied on top of pack skill text.
//!
//! The pack remains canonical and is never rewritten. An overlay is an
//! explicit host artifact recorded with the run context next to the pack
//! source fingerprint, with `provenance: "host"` rather than `"pack"`.

use serde::{Deserialize, Serialize};

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::skills::error::SkillFailure;
use crate::skills::pack::SkillId;

/// Who produced the overlay text. H1 only accepts host overlays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlayProvenance {
    /// Text injected by the herness host, not the SDD pack.
    Host,
}

/// Host-added and optionally host-removed skill text.
///
/// `added_text` is appended to the pack text for the run context.
/// `removed_text`, when present, must occur exactly once in the pack text and
/// is removed before the addition is appended. Neither operation writes to the
/// pack; [`HostOverlay::apply`] returns a composed string only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostOverlay {
    skill_id: SkillId,
    provenance: OverlayProvenance,
    added_text: String,
    removed_text: Option<String>,
}

impl HostOverlay {
    /// Creates a host overlay. At least one of the two text fields must be
    /// non-empty after trimming.
    pub fn new(
        skill_id: SkillId,
        added_text: impl Into<String>,
        removed_text: Option<String>,
    ) -> Result<Self, CoreError> {
        let added_text = added_text.into();
        let removed_text = removed_text.filter(|text| !text.trim().is_empty());
        if added_text.trim().is_empty() && removed_text.is_none() {
            return Err(CoreError::InvalidValue {
                field: "hostOverlay".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: "an overlay must add or remove non-empty text".to_owned(),
                },
            });
        }
        Ok(Self {
            skill_id,
            provenance: OverlayProvenance::Host,
            added_text,
            removed_text,
        })
    }

    /// Skill the overlay applies to.
    pub fn skill_id(&self) -> &SkillId {
        &self.skill_id
    }

    /// Always [`OverlayProvenance::Host`] for this type.
    pub const fn provenance(&self) -> OverlayProvenance {
        self.provenance
    }

    /// Host text appended to the pack text.
    pub fn added_text(&self) -> &str {
        &self.added_text
    }

    /// Pack text removed before the host text is appended, if any.
    pub fn removed_text(&self) -> Option<&str> {
        self.removed_text.as_deref()
    }

    /// Composes pack text plus this overlay in memory.
    ///
    /// This does not write to the pack. A missing or non-unique removal target
    /// returns a structured failure instead of guessing.
    pub fn apply(&self, pack_text: &str) -> Result<String, CoreError> {
        let mut composed = pack_text.to_owned();
        if let Some(removed) = &self.removed_text {
            let occurrences = composed.matches(removed).count() as u64;
            if occurrences == 0 {
                return Err(self.error(SkillFailure::OverlayRemovalNotFound {
                    skill: self.skill_id.clone(),
                }));
            }
            if occurrences > 1 {
                return Err(self.error(SkillFailure::OverlayRemovalNotUnique {
                    skill: self.skill_id.clone(),
                    occurrences,
                }));
            }
            composed = composed.replacen(removed, "", 1);
        }
        if !self.added_text.is_empty() {
            if !composed.is_empty() && !composed.ends_with('\n') {
                composed.push('\n');
            }
            composed.push_str(&self.added_text);
            if !composed.ends_with('\n') {
                composed.push('\n');
            }
        }
        Ok(composed)
    }

    fn error(&self, failure: SkillFailure) -> CoreError {
        CoreError::SkillFailed {
            skill: self.skill_id.clone(),
            failure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_records_host_provenance() {
        let overlay = HostOverlay::new(
            SkillId::new("demo").expect("skill id"),
            "host instruction",
            None,
        )
        .expect("overlay");
        assert_eq!(overlay.provenance(), OverlayProvenance::Host);
        assert_eq!(
            serde_json::to_value(&overlay).expect("serialize")["provenance"],
            "host"
        );
    }

    #[test]
    fn overlay_rejects_empty_text() {
        let id = SkillId::new("demo").expect("skill id");
        assert!(HostOverlay::new(id.clone(), "", None).is_err());
        assert!(HostOverlay::new(id.clone(), "   ", Some(String::new())).is_err());
    }
}
