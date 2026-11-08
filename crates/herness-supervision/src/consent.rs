//! Disclosure consent bound to provider origin, purpose, data kinds, and the
//! exact target-scope version.
//!
//! Consent is granted by a human for one exact bounded scope. The same scope
//! may continue to be used. Revocation, a different origin or purpose, a target
//! scope change, or adding an image requires re-confirmation before any unsent
//! request may leave the host. Consent records contain no credentials, prompt
//! text, or provider bodies.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use herness_core::contracts::{ContractVersion, ProjectId, Timestamp};
use serde::{Deserialize, Serialize};

use crate::approval::ApprovalActor;
use crate::error::SupervisionError;
use crate::evidence::TargetVersion;
use crate::ids::{ConsentId, verify_scoped};
use crate::profiles::ProfilePurpose;
use crate::version::current_contract_version;

/// Scheme of a provider origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginScheme {
    /// HTTPS.
    Https,
    /// HTTP, accepted only for loopback development endpoints.
    Http,
}

impl OriginScheme {
    /// Default port for the scheme.
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Https => 443,
            Self::Http => 80,
        }
    }

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
        }
    }
}

/// Exact provider origin: scheme, host, and port.
///
/// Paths, queries, fragments, userinfo, and credentials are rejected. The value
/// contains no secret and is safe to render in the UI.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderOrigin {
    scheme: OriginScheme,
    host: String,
    port: u16,
}

impl ProviderOrigin {
    /// Creates an origin from an explicit scheme, host, and port.
    pub fn new(
        scheme: OriginScheme,
        host: impl AsRef<str>,
        port: u16,
    ) -> Result<Self, SupervisionError> {
        let host = normalize_host(host.as_ref())?;
        if scheme == OriginScheme::Http && !is_loopback_host(&host) {
            return Err(SupervisionError::InvalidValue {
                field: "origin".to_owned(),
                detail: "non-loopback provider origins must use https".to_owned(),
            });
        }
        if port == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "origin.port".to_owned(),
                detail: "must be between 1 and 65535".to_owned(),
            });
        }
        Ok(Self { scheme, host, port })
    }

    /// Parses `scheme://host[:port]` exactly.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, SupervisionError> {
        let value = value.as_ref().trim();
        let (scheme, rest) =
            value
                .split_once("://")
                .ok_or_else(|| SupervisionError::InvalidValue {
                    field: "origin".to_owned(),
                    detail: "expected scheme://host[:port]".to_owned(),
                })?;
        let scheme = OriginScheme::from_str(scheme)?;
        if rest.contains('/') || rest.contains('?') || rest.contains('#') || rest.contains('@') {
            return Err(SupervisionError::InvalidValue {
                field: "origin".to_owned(),
                detail: "origin must not contain a path, query, fragment, or userinfo".to_owned(),
            });
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                let port = port
                    .parse::<u16>()
                    .map_err(|_| SupervisionError::InvalidValue {
                        field: "origin.port".to_owned(),
                        detail: "must be a number between 1 and 65535".to_owned(),
                    })?;
                (host, port)
            }
            _ => (rest, scheme.default_port()),
        };
        Self::new(scheme, host, port)
    }

    /// Scheme.
    pub const fn scheme(&self) -> OriginScheme {
        self.scheme
    }

    /// Normalized host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Effective port.
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl FromStr for OriginScheme {
    type Err = SupervisionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "https" => Ok(Self::Https),
            "http" => Ok(Self::Http),
            _ => Err(SupervisionError::InvalidValue {
                field: "origin.scheme".to_owned(),
                detail: "supported schemes are https and http".to_owned(),
            }),
        }
    }
}

impl<'de> Deserialize<'de> for ProviderOrigin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            scheme: OriginScheme,
            host: String,
            port: u16,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.scheme, wire.host, wire.port).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for ProviderOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let default = self.scheme.default_port();
        if self.port == default {
            write!(f, "{}://{}", self.scheme.as_str(), self.host)
        } else {
            write!(f, "{}://{}:{}", self.scheme.as_str(), self.host, self.port)
        }
    }
}

impl FromStr for ProviderOrigin {
    type Err = SupervisionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

fn normalize_host(host: &str) -> Result<String, SupervisionError> {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Err(SupervisionError::InvalidValue {
            field: "origin.host".to_owned(),
            detail: "must not be empty".to_owned(),
        });
    }
    if host.len() > 253
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(SupervisionError::InvalidValue {
            field: "origin.host".to_owned(),
            detail: "must be a DNS name, IPv4 address, or bracketed IPv6 address".to_owned(),
        });
    }
    Ok(host)
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// One class of data that may leave the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureDataKind {
    /// Prose text.
    Text,
    /// Source code.
    Code,
    /// Diffs.
    Diff,
    /// Logs.
    Log,
    /// Image bytes.
    Image,
}

impl DisclosureDataKind {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Code => "code",
            Self::Diff => "diff",
            Self::Log => "log",
            Self::Image => "image",
        }
    }
}

/// Exact data and target scope approved for one purpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisclosureScope {
    purpose: ProfilePurpose,
    data_kinds: BTreeSet<DisclosureDataKind>,
    targets: Vec<String>,
    target_scope_version: TargetVersion,
}

impl DisclosureScope {
    /// Creates a bounded scope.
    ///
    /// An empty kind set, empty target list, wildcard, or repository-root target
    /// is invalid. There is no "whole conversation" or "whole repository"
    /// default.
    pub fn new(
        purpose: ProfilePurpose,
        data_kinds: BTreeSet<DisclosureDataKind>,
        targets: Vec<String>,
        target_scope_version: TargetVersion,
    ) -> Result<Self, SupervisionError> {
        if data_kinds.is_empty() {
            return Err(SupervisionError::ConsentBlocked {
                reason: ConsentBlock::EmptyScope,
            });
        }
        if targets.is_empty() {
            return Err(SupervisionError::ConsentBlocked {
                reason: ConsentBlock::EmptyScope,
            });
        }
        for target in &targets {
            let trimmed = target.trim();
            if trimmed.is_empty()
                || trimmed == "*"
                || trimmed == "**"
                || trimmed == "."
                || trimmed == "/"
                || trimmed.split('/').any(|part| part == "..")
            {
                return Err(SupervisionError::ConsentBlocked {
                    reason: ConsentBlock::UnboundedScope,
                });
            }
        }
        Ok(Self {
            purpose,
            data_kinds,
            targets,
            target_scope_version,
        })
    }

    /// Purpose this scope was approved for.
    pub const fn purpose(&self) -> ProfilePurpose {
        self.purpose
    }

    /// Approved data kinds.
    pub fn data_kinds(&self) -> &BTreeSet<DisclosureDataKind> {
        &self.data_kinds
    }

    /// Approved target paths or sections.
    pub fn targets(&self) -> &[String] {
        &self.targets
    }

    /// Exact target-scope version this consent is bound to.
    pub const fn target_scope_version(&self) -> TargetVersion {
        self.target_scope_version
    }

    /// Revalidates a deserialized scope.
    pub fn validate(&self) -> Result<(), SupervisionError> {
        Self::new(
            self.purpose,
            self.data_kinds.clone(),
            self.targets.clone(),
            self.target_scope_version,
        )
        .map(|_| ())
    }
}

/// Current state of one consent record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ConsentState {
    /// A human approved the exact scope.
    Granted {
        /// Approval time.
        approved_at: Timestamp,
        /// Human that approved it.
        approved_by: ConsentApprover,
    },
    /// A human revoked the consent. Already sent content is not recalled.
    Revoked {
        /// Revocation time.
        revoked_at: Timestamp,
        /// Actor that revoked it.
        revoked_by: ConsentApprover,
    },
}

/// Who approved or revoked disclosure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentApprover {
    /// A human.
    Human,
}

/// One versioned disclosure-consent record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisclosureConsent {
    contract_version: ContractVersion,
    id: ConsentId,
    project_id: ProjectId,
    version: u64,
    origin: ProviderOrigin,
    scope: DisclosureScope,
    state: ConsentState,
}

impl DisclosureConsent {
    /// Grants consent for one exact scope after a human decision.
    ///
    /// A model or owner actor is rejected; the first disclosure decision is
    /// always a human one.
    pub fn grant(
        actor: ApprovalActor,
        id: ConsentId,
        origin: ProviderOrigin,
        scope: DisclosureScope,
        approved_at: Timestamp,
    ) -> Result<Self, SupervisionError> {
        match actor {
            ApprovalActor::Human => {}
            ApprovalActor::Model => {
                return Err(SupervisionError::ModelCannotApproveOrChange {
                    action: "grant disclosure consent".to_owned(),
                });
            }
            ApprovalActor::ApprovedOwner { .. } => {
                return Err(SupervisionError::ApprovalRejected {
                    reason: crate::error::ApprovalRejection::ActorMismatch,
                });
            }
        }
        let project_id = id.project_id();
        Ok(Self {
            contract_version: current_contract_version(),
            id,
            project_id,
            version: 1,
            origin,
            scope,
            state: ConsentState::Granted {
                approved_at,
                approved_by: ConsentApprover::Human,
            },
        })
    }

    /// Consent identifier.
    pub const fn id(&self) -> ConsentId {
        self.id
    }

    /// Project that owns the consent.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Consent record version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Provider origin.
    pub fn origin(&self) -> &ProviderOrigin {
        &self.origin
    }

    /// Approved scope.
    pub fn scope(&self) -> &DisclosureScope {
        &self.scope
    }

    /// Current consent state.
    pub fn state(&self) -> &ConsentState {
        &self.state
    }

    /// Purpose approved.
    pub const fn purpose(&self) -> ProfilePurpose {
        self.scope.purpose
    }

    /// Target-scope version approved.
    pub const fn target_scope_version(&self) -> TargetVersion {
        self.scope.target_scope_version
    }

    /// Fixed binding stored in a supervision contract.
    pub const fn binding(&self) -> ConsentBinding {
        ConsentBinding::new(
            self.id,
            self.version,
            self.scope.purpose,
            self.scope.target_scope_version,
        )
    }

    /// Revokes consent and advances the record version.
    ///
    /// The returned record blocks unsent requests. Content that was already
    /// sent is not recalled.
    pub fn revoke(
        &self,
        actor: ApprovalActor,
        revoked_at: Timestamp,
    ) -> Result<Self, SupervisionError> {
        if actor.is_model() {
            return Err(SupervisionError::ModelCannotApproveOrChange {
                action: "revoke disclosure consent".to_owned(),
            });
        }
        Ok(Self {
            state: ConsentState::Revoked {
                revoked_at,
                revoked_by: ConsentApprover::Human,
            },
            version: self.version.saturating_add(1),
            ..self.clone()
        })
    }

    /// Requires a granted consent record.
    pub fn require_granted(&self) -> Result<(), SupervisionError> {
        self.scope.validate()?;
        match self.state {
            ConsentState::Granted { .. } => Ok(()),
            ConsentState::Revoked { .. } => Err(SupervisionError::ConsentBlocked {
                reason: ConsentBlock::Revoked,
            }),
        }
    }

    /// Ensures the record belongs to `project`.
    pub fn ensure_project(&self, project: ProjectId) -> Result<(), SupervisionError> {
        verify_scoped(&self.id, project)?;
        if self.project_id == project {
            Ok(())
        } else {
            Err(SupervisionError::CrossProjectReference {
                id_kind: "consent".to_owned(),
                expected: project,
                found: self.project_id,
            })
        }
    }

    /// Authorizes one exact would-be request.
    pub fn authorize(&self, request: &DisclosureRequest) -> Result<(), ConsentBlock> {
        if self.scope.validate().is_err() {
            return Err(ConsentBlock::UnboundedScope);
        }
        if request.project_id != self.project_id {
            return Err(ConsentBlock::ProjectMismatch);
        }
        match self.state {
            ConsentState::Granted { .. } => {}
            ConsentState::Revoked { .. } => return Err(ConsentBlock::Revoked),
        }
        if request.data_kinds.is_empty() {
            return Err(ConsentBlock::EmptyScope);
        }
        if request.origin != self.origin {
            return Err(ConsentBlock::DifferentOrigin);
        }
        if request.purpose != self.scope.purpose {
            return Err(ConsentBlock::DifferentPurpose);
        }
        if request.target_scope_version != self.scope.target_scope_version {
            return Err(ConsentBlock::TargetScopeChanged);
        }
        let added = request
            .data_kinds
            .difference(&self.scope.data_kinds)
            .copied()
            .collect::<Vec<_>>();
        if !added.is_empty() {
            if added.contains(&DisclosureDataKind::Image) {
                return Err(ConsentBlock::ImageNotApproved);
            }
            return Err(ConsentBlock::ScopeExpanded { added });
        }
        Ok(())
    }
}

/// One exact request that would disclose data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisclosureRequest {
    project_id: ProjectId,
    origin: ProviderOrigin,
    purpose: ProfilePurpose,
    data_kinds: BTreeSet<DisclosureDataKind>,
    target_scope_version: TargetVersion,
}

impl DisclosureRequest {
    /// Creates a request with an explicit non-empty data-kind set.
    pub fn new(
        project_id: ProjectId,
        origin: ProviderOrigin,
        purpose: ProfilePurpose,
        data_kinds: BTreeSet<DisclosureDataKind>,
        target_scope_version: TargetVersion,
    ) -> Result<Self, SupervisionError> {
        if data_kinds.is_empty() {
            return Err(SupervisionError::ConsentBlocked {
                reason: ConsentBlock::EmptyScope,
            });
        }
        Ok(Self {
            project_id,
            origin,
            purpose,
            data_kinds,
            target_scope_version,
        })
    }

    /// Project that owns the request.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Requested provider origin.
    pub fn origin(&self) -> &ProviderOrigin {
        &self.origin
    }

    /// Requested purpose.
    pub const fn purpose(&self) -> ProfilePurpose {
        self.purpose
    }

    /// Requested data kinds.
    pub fn data_kinds(&self) -> &BTreeSet<DisclosureDataKind> {
        &self.data_kinds
    }

    /// Requested target-scope version.
    pub const fn target_scope_version(&self) -> TargetVersion {
        self.target_scope_version
    }
}

/// Exact consent identity fixed at supervision start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentBinding {
    consent_id: ConsentId,
    version: u64,
    purpose: ProfilePurpose,
    target_scope_version: TargetVersion,
}

impl ConsentBinding {
    /// Creates a consent binding fixed to one purpose and target version.
    pub const fn new(
        consent_id: ConsentId,
        version: u64,
        purpose: ProfilePurpose,
        target_scope_version: TargetVersion,
    ) -> Self {
        Self {
            consent_id,
            version,
            purpose,
            target_scope_version,
        }
    }

    /// Consent identifier.
    pub const fn consent_id(self) -> ConsentId {
        self.consent_id
    }

    /// Bound consent record version.
    pub const fn version(self) -> u64 {
        self.version
    }

    /// Bound disclosure purpose.
    pub const fn purpose(self) -> ProfilePurpose {
        self.purpose
    }

    /// Bound target-scope version.
    pub const fn target_scope_version(self) -> TargetVersion {
        self.target_scope_version
    }
}

/// Why a disclosure request is blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ConsentBlock {
    /// The consent was revoked.
    Revoked,
    /// The request belongs to another project.
    ProjectMismatch,
    /// A different provider scheme, host, or port was requested.
    DifferentOrigin,
    /// A different assessment purpose was requested.
    DifferentPurpose,
    /// The target-scope version changed.
    TargetScopeChanged,
    /// New data kinds were requested.
    ScopeExpanded {
        /// Newly requested kinds.
        added: Vec<DisclosureDataKind>,
    },
    /// Image bytes were not in the approved scope.
    ImageNotApproved,
    /// The request has no bounded data kinds.
    EmptyScope,
    /// The scope is a wildcard or repository root.
    UnboundedScope,
    /// The consent record version does not match the contract binding.
    VersionMismatch,
}

impl ConsentBlock {
    /// Whether a human must confirm a new exact scope before a send.
    pub fn requires_reconfirmation(self) -> bool {
        matches!(
            self,
            Self::Revoked
                | Self::DifferentOrigin
                | Self::DifferentPurpose
                | Self::TargetScopeChanged
                | Self::ScopeExpanded { .. }
                | Self::ImageNotApproved
                | Self::VersionMismatch
        )
    }

    /// Whether this block always prevents a send.
    pub fn blocks_send(self) -> bool {
        true
    }
}

impl fmt::Display for ConsentBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
