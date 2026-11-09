//! Approval bases for completion conditions.
//!
//! The host accepts either an explicit human confirmation or an approval
//! inherited from an already-approved H3 settings / H4 plan owner. A model is
//! never an approval actor. Approval is bound to the project, condition
//! version, and a digest of the exact condition content, so a changed set
//! invalidates the old decision.

use herness_core::contracts::{ProjectId, Timestamp};
use serde::{Deserialize, Serialize};

use crate::conditions::{ConditionDigest, ConditionVersion};
use crate::contract::OwnerRef;
use crate::error::{ApprovalRejection, SupervisionError};

/// Where an inherited condition approval came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerApprovalSource {
    /// H3 approved HTML settings.
    H3ApprovedSettings,
    /// H4 approved plan and Task constraints.
    H4ApprovedPlan,
}

/// Who is asking the host to accept a condition decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ApprovalActor {
    /// A human explicitly confirmed the action.
    Human,
    /// An already-approved H3/H4 owner supplies the decision.
    ApprovedOwner {
        /// Owner that issued the approval.
        owner: OwnerRef,
        /// Approval source owned by that phase.
        source: OwnerApprovalSource,
    },
    /// A model proposed or attempted the action. Never accepted.
    Model,
}

impl ApprovalActor {
    /// Whether this actor is a model.
    pub const fn is_model(&self) -> bool {
        matches!(self, Self::Model)
    }
}

/// Recorded basis of one condition approval.
///
/// Explicit human confirmation and inherited owner approval stay distinct.
/// The record contains no credential, prompt, or model text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ApprovalBasis {
    /// A human confirmed the condition set directly.
    ExplicitHuman {
        /// Time the human approved it.
        approved_at: Timestamp,
        /// Optional host-owned expiry.
        #[serde(default)]
        expires_at: Option<Timestamp>,
    },
    /// An already-approved H3/H4 owner supplies the approval.
    InheritedOwner {
        /// Owner that supplied the approval.
        owner: OwnerRef,
        /// Phase-specific approval source.
        source: OwnerApprovalSource,
        /// Time the owner approval was issued.
        approved_at: Timestamp,
        /// Optional host-owned expiry.
        #[serde(default)]
        expires_at: Option<Timestamp>,
    },
}

impl ApprovalBasis {
    /// Whether this basis is an explicit human confirmation.
    pub const fn is_human(&self) -> bool {
        matches!(self, Self::ExplicitHuman { .. })
    }

    /// Whether this basis is inherited from an approved H3/H4 owner.
    pub const fn is_inherited(&self) -> bool {
        matches!(self, Self::InheritedOwner { .. })
    }

    /// Optional expiry timestamp.
    pub const fn expires_at(&self) -> Option<Timestamp> {
        match self {
            Self::ExplicitHuman { expires_at, .. } | Self::InheritedOwner { expires_at, .. } => {
                *expires_at
            }
        }
    }
}

/// Approval of one exact completion-condition set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConditionApproval {
    project_id: ProjectId,
    basis: ApprovalBasis,
    condition_version: ConditionVersion,
    conditions_digest: ConditionDigest,
}

impl ConditionApproval {
    /// Records an approval bound to one project, version, and content digest.
    pub fn new(
        project_id: ProjectId,
        basis: ApprovalBasis,
        condition_version: ConditionVersion,
        conditions_digest: ConditionDigest,
    ) -> Result<Self, SupervisionError> {
        if let ApprovalBasis::InheritedOwner { owner, source, .. } = &basis {
            if !owner.is_approved_owner() {
                return Err(SupervisionError::ApprovalRejected {
                    reason: ApprovalRejection::OwnerNotApproved,
                });
            }
            let source_matches_owner = matches!(
                (owner.kind(), source),
                (
                    crate::contract::OwnerKind::H3HtmlJob,
                    OwnerApprovalSource::H3ApprovedSettings
                ) | (
                    crate::contract::OwnerKind::H4SddTask,
                    OwnerApprovalSource::H4ApprovedPlan
                )
            );
            if !source_matches_owner {
                return Err(SupervisionError::ApprovalRejected {
                    reason: ApprovalRejection::SourceOwnerMismatch,
                });
            }
        }
        Ok(Self {
            project_id,
            basis,
            condition_version,
            conditions_digest,
        })
    }

    /// Project the approval belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Recorded approval basis.
    pub fn basis(&self) -> &ApprovalBasis {
        &self.basis
    }

    /// Condition version this approval covers.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Exact condition content digest this approval covers.
    pub fn conditions_digest(&self) -> &ConditionDigest {
        &self.conditions_digest
    }

    /// Validates the approval against an actor, project, and exact condition
    /// version/content. Rejects fake, foreign, stale, and expired approvals.
    pub fn validate(
        &self,
        actor: ApprovalActor,
        project_id: ProjectId,
        condition_version: ConditionVersion,
        conditions_digest: &ConditionDigest,
        now: Timestamp,
    ) -> Result<(), SupervisionError> {
        if actor.is_model() {
            return Err(SupervisionError::ApprovalRejected {
                reason: ApprovalRejection::ModelOrigin,
            });
        }
        if self.project_id != project_id {
            return Err(SupervisionError::ApprovalRejected {
                reason: ApprovalRejection::ProjectMismatch,
            });
        }
        if self.condition_version != condition_version {
            return Err(SupervisionError::ApprovalRejected {
                reason: ApprovalRejection::StaleVersion {
                    approved: self.condition_version.get(),
                    found: condition_version.get(),
                },
            });
        }
        if &self.conditions_digest != conditions_digest {
            return Err(SupervisionError::ApprovalRejected {
                reason: ApprovalRejection::StaleDigest,
            });
        }
        if let ApprovalBasis::InheritedOwner { owner, source, .. } = &self.basis {
            if !owner.is_approved_owner() {
                return Err(SupervisionError::ApprovalRejected {
                    reason: ApprovalRejection::OwnerNotApproved,
                });
            }
            let source_matches_owner = matches!(
                (owner.kind(), source),
                (
                    crate::contract::OwnerKind::H3HtmlJob,
                    OwnerApprovalSource::H3ApprovedSettings
                ) | (
                    crate::contract::OwnerKind::H4SddTask,
                    OwnerApprovalSource::H4ApprovedPlan
                )
            );
            if !source_matches_owner {
                return Err(SupervisionError::ApprovalRejected {
                    reason: ApprovalRejection::SourceOwnerMismatch,
                });
            }
        }
        if let Some(expires_at) = self.basis.expires_at()
            && expires_at.as_unix_millis() <= now.as_unix_millis()
        {
            return Err(SupervisionError::ApprovalRejected {
                reason: ApprovalRejection::Expired {
                    expires_at: expires_at.as_unix_millis(),
                    now: now.as_unix_millis(),
                },
            });
        }
        match (&actor, &self.basis) {
            (ApprovalActor::Human, ApprovalBasis::ExplicitHuman { .. }) => Ok(()),
            (
                ApprovalActor::ApprovedOwner {
                    owner: actor_owner,
                    source: actor_source,
                },
                ApprovalBasis::InheritedOwner {
                    owner: basis_owner,
                    source: basis_source,
                    ..
                },
            ) => {
                if !actor_owner.is_approved_owner() {
                    return Err(SupervisionError::ApprovalRejected {
                        reason: ApprovalRejection::OwnerNotApproved,
                    });
                }
                if actor_owner != basis_owner || actor_source != basis_source {
                    return Err(SupervisionError::ApprovalRejected {
                        reason: ApprovalRejection::ActorMismatch,
                    });
                }
                Ok(())
            }
            _ => Err(SupervisionError::ApprovalRejected {
                reason: ApprovalRejection::ActorMismatch,
            }),
        }
    }
}
