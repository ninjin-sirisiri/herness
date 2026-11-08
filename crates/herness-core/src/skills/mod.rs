//! Read-only SDD pack access, skill fingerprints, host overlays, run context,
//! capability reporting, and external toolchain detection.
//!
//! The pack is external and canonical. A skill is loaded by identifier from
//! `<pack-root>/skills/<id>/SKILL.md`; an individual copied `SKILL.md` is
//! never treated as canonical. Nothing in this module writes to the pack.

pub mod capability;
pub mod context;
pub mod digest;
pub mod error;
pub mod overlay;
pub mod pack;
pub mod toolchain;

pub use capability::{
    CapabilityStatus, CapabilityUnavailableReason, HostCapabilities, HostCapability,
    SkillExecutionFlow, SkillExecutionStatus,
};
pub use context::{SkillContextEntry, SkillContextRevalidation, SkillRunContext};
pub use digest::SkillDigest;
pub use error::SkillFailure;
pub use overlay::{HostOverlay, OverlayProvenance};
pub use pack::{
    SkillChange, SkillDocument, SkillFingerprint, SkillId, SkillPack, SkillReference,
    SkillRevalidation, SkillSource,
};
pub use toolchain::{
    MINIMUM_PYTHON_VERSION, PythonVersion, ToolAvailability, ToolDetection, ToolRequirement,
    ToolchainConfig, ToolchainDeficiency, ToolchainDetector, ToolchainReport, ValidatorDetection,
    ValidatorProbe,
};
