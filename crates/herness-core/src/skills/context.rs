//! Run-level skill context joining pack sources, host overlays, and capability
//! availability.
//!
//! Building a context never executes a skill flow. It records what the host
//! read and which worker flows are available, so later run orchestration can
//! attach the value without reinterpreting pack contents.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::contracts::errors::CoreError;
use crate::contracts::path::AbsolutePath;
use crate::skills::capability::{
    CapabilityStatus, CapabilityUnavailableReason, HostCapabilities, SkillExecutionFlow,
    SkillExecutionStatus,
};
use crate::skills::error::SkillFailure;
use crate::skills::overlay::HostOverlay;
use crate::skills::pack::{
    SkillDocument, SkillFingerprint, SkillId, SkillRevalidation, SkillSource,
};

/// One loaded skill in a run context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillContextEntry {
    document: SkillDocument,
    overlay: Option<HostOverlay>,
    execution: SkillExecutionStatus,
}

impl SkillContextEntry {
    /// Loaded document, including original text and load-time fingerprint.
    pub fn document(&self) -> &SkillDocument {
        &self.document
    }

    /// Source identity of the loaded document.
    pub fn source(&self) -> &SkillSource {
        self.document.source()
    }

    /// Skill id.
    pub fn skill_id(&self) -> &SkillId {
        &self.document.source().skill_id
    }

    /// Canonical pack path of `SKILL.md`.
    pub fn skill_path(&self) -> &AbsolutePath {
        &self.document.source().skill_path
    }

    /// Original pack text. Host overlay text is not merged here.
    pub fn text(&self) -> &str {
        self.document.text()
    }

    /// Fingerprint captured at load time.
    pub fn fingerprint(&self) -> &SkillFingerprint {
        self.document.fingerprint()
    }

    /// Host overlay recorded for this skill, if any.
    pub fn overlay(&self) -> Option<&HostOverlay> {
        self.overlay.as_ref()
    }

    /// Requested flow and its capability status.
    pub fn execution(&self) -> SkillExecutionStatus {
        self.execution
    }

    /// Pack text with the host overlay applied in memory.
    pub fn overlaid_text(&self) -> Result<String, CoreError> {
        match &self.overlay {
            Some(overlay) => overlay.apply(self.document.text()),
            None => Ok(self.document.text().to_owned()),
        }
    }
}

/// Skill context attached to one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillRunContext {
    pack_root: AbsolutePath,
    entries: Vec<SkillContextEntry>,
    capabilities: HostCapabilities,
}

impl SkillRunContext {
    /// Builds a context from loaded documents, host overlays, and requested
    /// execution flows.
    ///
    /// Reading a skill is separate from executing its worker flow. A context
    /// always keeps the original pack text and fingerprint; an unavailable
    /// worker flow is recorded as such rather than replaced by a parent-model
    /// dispatch.
    pub fn build(
        pack_root: &AbsolutePath,
        documents: Vec<SkillDocument>,
        overlays: &[HostOverlay],
        flows: &[(SkillId, SkillExecutionFlow)],
        capabilities: HostCapabilities,
    ) -> Result<Self, CoreError> {
        let mut documents_by_id: BTreeMap<SkillId, SkillDocument> = BTreeMap::new();
        for document in documents {
            let skill = document.source().skill_id.clone();
            if document.source().pack_root != *pack_root {
                return Err(CoreError::SkillFailed {
                    skill,
                    failure: SkillFailure::MixedPackRoots {
                        expected: pack_root.as_str().to_owned(),
                        found: document.source().pack_root.as_str().to_owned(),
                    },
                });
            }
            if documents_by_id.insert(skill.clone(), document).is_some() {
                return Err(CoreError::SkillFailed {
                    skill: skill.clone(),
                    failure: SkillFailure::DuplicateSkill { skill },
                });
            }
        }

        let mut overlays_by_id: BTreeMap<SkillId, HostOverlay> = BTreeMap::new();
        for overlay in overlays {
            let skill = overlay.skill_id().clone();
            if !documents_by_id.contains_key(&skill) {
                return Err(CoreError::SkillFailed {
                    skill: skill.clone(),
                    failure: SkillFailure::UnknownSkill { skill },
                });
            }
            if overlays_by_id
                .insert(skill.clone(), overlay.clone())
                .is_some()
            {
                return Err(CoreError::SkillFailed {
                    skill: skill.clone(),
                    failure: SkillFailure::DuplicateOverlay { skill },
                });
            }
        }

        let mut flows_by_id: BTreeMap<SkillId, SkillExecutionFlow> = BTreeMap::new();
        for (skill, flow) in flows {
            if !documents_by_id.contains_key(skill) {
                return Err(CoreError::SkillFailed {
                    skill: skill.clone(),
                    failure: SkillFailure::UnknownSkill {
                        skill: skill.clone(),
                    },
                });
            }
            if flows_by_id.insert(skill.clone(), *flow).is_some() {
                return Err(CoreError::SkillFailed {
                    skill: skill.clone(),
                    failure: SkillFailure::DuplicateFlow {
                        skill: skill.clone(),
                    },
                });
            }
        }

        let entries = documents_by_id
            .into_iter()
            .map(|(skill, document)| {
                let flow = flows_by_id
                    .get(&skill)
                    .copied()
                    .unwrap_or(SkillExecutionFlow::ReadOnly);
                SkillContextEntry {
                    document,
                    overlay: overlays_by_id.remove(&skill),
                    execution: SkillExecutionStatus::new(flow, capabilities),
                }
            })
            .collect();

        Ok(Self {
            pack_root: pack_root.clone(),
            entries,
            capabilities,
        })
    }

    /// Canonical pack root shared by every entry.
    pub fn pack_root(&self) -> &AbsolutePath {
        &self.pack_root
    }

    /// Entries ordered by skill id.
    pub fn entries(&self) -> &[SkillContextEntry] {
        &self.entries
    }

    /// Host capability report for this context.
    pub const fn capabilities(&self) -> HostCapabilities {
        self.capabilities
    }

    /// Finds one entry by skill id.
    pub fn entry(&self, skill: &SkillId) -> Option<&SkillContextEntry> {
        self.entries.iter().find(|entry| entry.skill_id() == skill)
    }

    /// Returns the requested flow when its capability is available, or a
    /// structured capability deficiency when it is not.
    ///
    /// A `ReadOnly` flow is always allowed here: loading text is not worker
    /// execution. For worker flows this method never substitutes another
    /// dispatch path.
    pub fn require_execution(&self, skill: &SkillId) -> Result<SkillExecutionStatus, CoreError> {
        let Some(entry) = self.entry(skill) else {
            return Err(CoreError::SkillFailed {
                skill: skill.clone(),
                failure: SkillFailure::UnknownSkill {
                    skill: skill.clone(),
                },
            });
        };
        let execution = entry.execution;
        if execution.status().is_available() {
            return Ok(execution);
        }
        let flow = execution.flow();
        let Some(capability) = flow.capability() else {
            return Ok(execution);
        };
        let reason = match execution.status() {
            CapabilityStatus::Unavailable { reason } => reason,
            CapabilityStatus::Available => CapabilityUnavailableReason::NotImplementedInH1,
        };
        Err(CoreError::SkillFailed {
            skill: skill.clone(),
            failure: SkillFailure::CapabilityUnavailable {
                flow,
                capability,
                reason,
            },
        })
    }

    /// Recomputes every entry's fingerprint without mutating the context.
    pub fn revalidate(&self) -> Result<SkillContextRevalidation, CoreError> {
        let mut skills = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            skills.push(entry.document.revalidate()?);
        }
        Ok(SkillContextRevalidation {
            changed: skills.iter().any(SkillRevalidation::changed),
            skills,
        })
    }

    /// Fails if any skill changed after this context was built.
    pub fn ensure_current(&self) -> Result<(), CoreError> {
        for entry in &self.entries {
            entry.document.ensure_current()?;
        }
        Ok(())
    }
}

/// Revalidation result for every skill in one run context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillContextRevalidation {
    /// Per-skill results ordered by skill id.
    pub skills: Vec<SkillRevalidation>,
    /// Whether any skill changed.
    pub changed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::capability::HostCapability;

    #[test]
    fn h1_reports_worker_capabilities_unavailable() {
        let capabilities = HostCapabilities::h1();
        assert!(
            capabilities
                .status(HostCapability::SkillRead)
                .is_available()
        );
        assert!(
            !capabilities
                .status(HostCapability::HtmlWorker)
                .is_available()
        );
        assert!(
            !capabilities
                .status(HostCapability::SddTaskController)
                .is_available()
        );
    }
}
