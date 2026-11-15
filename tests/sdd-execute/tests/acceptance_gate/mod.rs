//! Test-only acceptance gate and runner for a future real-connection run.
//!
//! This module is the executable form of the H4 acceptance rule:
//!
//! > 実providerでの実装・完了評価・HTML評価の一連の受入は、接続、fixtureと
//! > 送信bytes種別、有限要求数/retry、料金または枠を提示し、別途人間の許可を
//! > 得てから行う。
//!
//! Nothing here sends anything. It is a gate over a manifest plus a runner over
//! an injected [`AcceptanceTransport`], and the shipped target gives the runner
//! only a recording transport. The default result is a refusal, and a refusal
//! happens before the transport is touched, so the default external request
//! count is exactly zero.
//!
//! # Default deny
//!
//! A run is authorized only when all of the following hold:
//!
//! 1. `H4_ACCEPTANCE_OPT_IN` is the exact string `"1"`; a missing value, `"0"`,
//!    `"true"`, or `"yes"` is refused.
//! 2. The manifest path names a readable `h4-real-connection-acceptance-v1`
//!    manifest whose `status` is `approved`, whose `approvedBy` and `approvedAt`
//!    are non-empty, and whose `expiresAtMillis` is in the future.
//! 3. The manifest declares the connection identity, the fixtures, every one of
//!    the four required send-byte kinds, finite request and retry counts, and a
//!    money cap or a quota reference.
//! 4. The run requests exactly the approved fixtures and send-byte kinds, and
//!    stays within the approved counts.
//! 5. `credentialAccess` is `"none"` and the manifest carries no credential-like
//!    key. The approval is never widened into a login or credential discovery.
//! 6. The H3 image/residual capabilities are still declared `unconfirmed`, and
//!    every inherited H1/H2/H3/H4 item is present as `unconfirmed`. A manifest
//!    cannot turn an inherited unknown into a confirmation.

use std::collections::BTreeSet;
use std::fmt;

use serde_json::{Map, Value};

/// Environment variable that must be exactly `"1"` for any run.
pub const OPT_IN_ENV: &str = "H4_ACCEPTANCE_OPT_IN";

/// Environment variable naming the manifest the run would use.
pub const MANIFEST_ENV: &str = "H4_ACCEPTANCE_MANIFEST";

/// Manifest schema this gate implements.
pub const MANIFEST_SCHEMA: &str = "h4-real-connection-acceptance-v1";

/// The four send-byte kinds a real-connection acceptance must present.
///
/// Omitting one is a refusal: the H4 design names plan packets, Task reports,
/// assessment prompts, and H3 render evidence, and a partial list would hide
/// the cost and disclosure of the omitted kind.
pub const REQUIRED_SEND_BYTE_KINDS: [SendByteKind; 4] = [
    SendByteKind::PlanPacket,
    SendByteKind::TaskReport,
    SendByteKind::AssessmentPrompt,
    SendByteKind::H3RenderEvidence,
];

/// H3 capabilities that stay `unconfirmed` through this gate.
pub const UNCONFIRMED_H3_CAPABILITIES: [&str; 5] = [
    "image",
    "support",
    "usability",
    "render",
    "humanReadingObservation",
];

/// Items inherited as unconfirmed from H1, H2, H3 and this phase.
pub const INHERITED_UNCONFIRMED: [(&str, &str); 6] = [
    (
        "h1-acceptance",
        "H1 runtime acceptance is incomplete; its H4 integration additions are unconfirmed.",
    ),
    (
        "h2-acceptance",
        "H2 supervision acceptance is incomplete; its H4 integration additions are unconfirmed.",
    ),
    (
        "h3-image",
        "H3 image conditions were not run in the limited text-only acceptance.",
    ),
    (
        "h3-residual-conditions",
        "H3 support, usability and render conditions were not run in the limited text-only acceptance.",
    ),
    (
        "h3-human-reading-observation",
        "H3 human reading observation was not run.",
    ),
    (
        "h4-real-provider-acceptance",
        "No real provider implementation, completion, HTML assessment or render evidence has been accepted.",
    ),
];

/// Retry reasons the approval may name. Anything else is not approved.
pub const APPROVED_RETRY_REASONS: [&str; 4] = [
    "timeout",
    "connection-reset",
    "server-error",
    "rate-limited",
];

/// One kind of bytes a real-connection run would send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SendByteKind {
    /// The approved plan packet handed to a child.
    PlanPacket,
    /// One Task report handed back by a child.
    TaskReport,
    /// One condition-assessment prompt.
    AssessmentPrompt,
    /// One H3 render evidence payload.
    H3RenderEvidence,
}

impl SendByteKind {
    /// Stable manifest label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlanPacket => "plan_packet",
            Self::TaskReport => "task_report",
            Self::AssessmentPrompt => "assessment_prompt",
            Self::H3RenderEvidence => "h3_render_evidence",
        }
    }

    /// Parses a stable manifest label. An unknown label returns `None`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "plan_packet" => Some(Self::PlanPacket),
            "task_report" => Some(Self::TaskReport),
            "assessment_prompt" => Some(Self::AssessmentPrompt),
            "h3_render_evidence" => Some(Self::H3RenderEvidence),
            _ => None,
        }
    }
}

impl fmt::Display for SendByteKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The connection a run would use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionIdentity {
    /// Provider name, for example `openai`.
    pub provider: String,
    /// Host connection identifier.
    pub connection_id: String,
    /// Endpoint class the connection is bound to.
    pub endpoint_class: String,
    /// Exact model identifier.
    pub model: String,
}

impl ConnectionIdentity {
    /// Creates an identity from its four non-secret parts.
    pub fn new(
        provider: impl Into<String>,
        connection_id: impl Into<String>,
        endpoint_class: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            connection_id: connection_id.into(),
            endpoint_class: endpoint_class.into(),
            model: model.into(),
        }
    }

    fn field(&self, name: &'static str) -> &str {
        match name {
            "provider" => &self.provider,
            "connectionId" => &self.connection_id,
            "endpointClass" => &self.endpoint_class,
            "model" => &self.model,
            _ => unreachable!("the gate only asks for the four identity fields"),
        }
    }

    fn is_complete(&self) -> bool {
        [
            &self.provider,
            &self.connection_id,
            &self.endpoint_class,
            &self.model,
        ]
        .iter()
        .all(|value| !value.trim().is_empty())
    }
}

/// What a run plans to request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceRequest {
    /// Connection the run would use.
    pub connection: ConnectionIdentity,
    /// Fixtures the run would touch.
    pub fixtures: Vec<String>,
    /// Send-byte kinds the run would send.
    pub send_byte_kinds: Vec<SendByteKind>,
    /// Total requests the run plans.
    pub requests: u64,
    /// Requests the run plans for any one fixture.
    pub per_fixture_requests: u64,
    /// Retries the run plans in total.
    pub retries: u64,
}

/// One refusal. Every variant is decided before a transport call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateRefusal {
    /// `H4_ACCEPTANCE_OPT_IN` is unset.
    OptInMissing,
    /// `H4_ACCEPTANCE_OPT_IN` is set but not the exact string `"1"`.
    OptInNotExplicit {
        /// The observed value, already safe to display.
        value: String,
    },
    /// No manifest path was supplied.
    ManifestMissing,
    /// The manifest path cannot be read.
    ManifestUnreadable {
        /// Observed I/O error kind.
        kind: String,
    },
    /// The manifest is not one JSON object.
    ManifestNotObject,
    /// The manifest is not valid JSON.
    ManifestInvalidJson {
        /// Parser message.
        detail: String,
    },
    /// A required manifest field is absent or empty.
    ManifestFieldMissing {
        /// Field path.
        field: &'static str,
    },
    /// A manifest field carries a value this gate does not implement.
    ManifestFieldInvalid {
        /// Field path.
        field: &'static str,
        /// Non-secret detail.
        detail: String,
    },
    /// The manifest schema is not this gate's schema.
    UnsupportedManifestSchema {
        /// Observed schema.
        schema: String,
    },
    /// The manifest is not an approval.
    NotAuthorized {
        /// Observed status.
        status: String,
    },
    /// The approval has expired.
    Expired {
        /// Approved expiry.
        expires_at_millis: u64,
        /// Observation time.
        now_millis: u64,
    },
    /// The manifest widens the approval into credential access.
    CredentialAccessWidened {
        /// Observed value.
        value: String,
    },
    /// The manifest carries a credential-like key.
    CredentialMaterialPresent {
        /// Offending JSON key path.
        field: String,
    },
    /// The requested connection is not the approved connection.
    ConnectionMismatch {
        /// Identity field.
        field: &'static str,
    },
    /// The run requests no fixtures.
    FixtureListEmpty,
    /// A requested fixture is not approved.
    FixtureOutOfScope {
        /// Requested fixture.
        fixture: String,
    },
    /// A required send-byte kind is missing from the approval.
    RequiredSendByteKindMissing {
        /// Missing kind.
        kind: SendByteKind,
    },
    /// The approval names a send-byte kind this gate does not implement.
    UnknownSendByteKind {
        /// Observed label.
        kind: String,
    },
    /// The run's send-byte kinds are not exactly the approved kinds.
    SendByteKindsMismatch,
    /// A manifest claims an inherited H3 capability is confirmed.
    UnconfirmedCapabilityClaimed {
        /// Capability name.
        capability: &'static str,
        /// Observed value.
        value: String,
    },
    /// An inherited unconfirmed item is absent from the manifest.
    InheritedUnconfirmedMissing {
        /// Item id.
        id: &'static str,
    },
    /// A manifest turns an inherited unconfirmed item into a confirmation.
    InheritedUnconfirmedClaimed {
        /// Item id.
        id: String,
    },
    /// The request count is zero or not finite.
    RequestCountNotFinite,
    /// The run plans more requests than approved.
    RequestCountOverrun {
        /// Approved total.
        approved: u64,
        /// Planned total.
        requested: u64,
    },
    /// The run plans more requests for one fixture than approved.
    PerFixtureOverrun {
        /// Approved per fixture.
        approved: u64,
        /// Planned per fixture.
        requested: u64,
    },
    /// The retry count is zero or not finite.
    RetryCountNotFinite,
    /// The run plans more retries than approved.
    RetryOverrun {
        /// Approved retries.
        approved: u64,
        /// Planned retries.
        requested: u64,
    },
    /// The approval names a retry reason this gate does not implement.
    RetryReasonNotApproved {
        /// Observed reason.
        reason: String,
    },
    /// No money cap and no quota reference were approved.
    CostOrQuotaMissing,
    /// A priced request was approved without a money cap.
    PricedRequestWithoutMoneyCap,
    /// The money cap is not a finite number.
    CostNotFinite,
}

impl GateRefusal {
    /// One human-readable line, without secrets.
    pub fn message(&self) -> String {
        match self {
            Self::OptInMissing => {
                format!("{OPT_IN_ENV} is unset; a real-connection run is refused")
            }
            Self::OptInNotExplicit { value } => format!(
                "{OPT_IN_ENV}={value:?} is not the explicit opt-in \"1\"; a real-connection run is refused"
            ),
            Self::ManifestMissing => format!("{MANIFEST_ENV} must name an acceptance manifest"),
            Self::ManifestUnreadable { kind } => {
                format!("the acceptance manifest is unreadable ({kind})")
            }
            Self::ManifestNotObject => "the acceptance manifest must be one JSON object".to_owned(),
            Self::ManifestInvalidJson { detail } => {
                format!("the acceptance manifest is not valid JSON: {detail}")
            }
            Self::ManifestFieldMissing { field } => {
                format!("the acceptance manifest is missing {field}")
            }
            Self::ManifestFieldInvalid { field, detail } => {
                format!("the acceptance manifest field {field} is invalid: {detail}")
            }
            Self::UnsupportedManifestSchema { schema } => {
                format!("unsupported acceptance manifest schema {schema:?}")
            }
            Self::NotAuthorized { status } => {
                format!("the acceptance manifest status {status:?} is not \"approved\"")
            }
            Self::Expired {
                expires_at_millis,
                now_millis,
            } => format!(
                "the acceptance manifest expired at {expires_at_millis} (observed {now_millis})"
            ),
            Self::CredentialAccessWidened { value } => format!(
                "credentialAccess={value:?} widens the approval into a login or credential discovery"
            ),
            Self::CredentialMaterialPresent { field } => {
                format!("the acceptance manifest carries credential-like key {field}")
            }
            Self::ConnectionMismatch { field } => {
                format!("the requested connection {field} is not the approved one")
            }
            Self::FixtureListEmpty => {
                "the run must request at least one approved fixture".to_owned()
            }
            Self::FixtureOutOfScope { fixture } => {
                format!("fixture {fixture:?} is not in the approved fixture list")
            }
            Self::RequiredSendByteKindMissing { kind } => {
                format!("the approval omits the required send-byte kind {kind}")
            }
            Self::UnknownSendByteKind { kind } => {
                format!("send-byte kind {kind:?} is not part of this gate")
            }
            Self::SendByteKindsMismatch => {
                "the run's send-byte kinds are not exactly the approved kinds".to_owned()
            }
            Self::UnconfirmedCapabilityClaimed { capability, value } => format!(
                "H3 capability {capability} is {value:?}; an inherited unconfirmed condition cannot be claimed as confirmed"
            ),
            Self::InheritedUnconfirmedMissing { id } => {
                format!("the inherited unconfirmed item {id} is missing")
            }
            Self::InheritedUnconfirmedClaimed { id } => format!(
                "the inherited item {id} is claimed confirmed; H1/H2/H3 unknowns are inherited, never waived"
            ),
            Self::RequestCountNotFinite => {
                "requestBudget.maxRequests and perFixtureMax must be finite and positive".to_owned()
            }
            Self::RequestCountOverrun {
                approved,
                requested,
            } => {
                format!("the run plans {requested} requests; the approval allows {approved}")
            }
            Self::PerFixtureOverrun {
                approved,
                requested,
            } => {
                format!(
                    "the run plans {requested} requests per fixture; the approval allows {approved}"
                )
            }
            Self::RetryCountNotFinite => "retryPolicy.maxAttempts must be 1..=5".to_owned(),
            Self::RetryOverrun {
                approved,
                requested,
            } => {
                format!("the run plans {requested} retries; the approval allows {approved}")
            }
            Self::RetryReasonNotApproved { reason } => {
                format!("retry reason {reason:?} is not approved")
            }
            Self::CostOrQuotaMissing => {
                "a money cap or a confirmed quota reference is required before a priced request"
                    .to_owned()
            }
            Self::PricedRequestWithoutMoneyCap => {
                "the run is priced and has no money cap; a priced request is refused".to_owned()
            }
            Self::CostNotFinite => "the money cap must be a finite non-negative number".to_owned(),
        }
    }
}

impl fmt::Display for GateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

/// A validated approval. Holding one proves every manifest rule passed.
#[derive(Debug, Clone, PartialEq)]
pub struct AcceptanceGate {
    approved_by: String,
    approved_at: String,
    expires_at_millis: u64,
    connection: ConnectionIdentity,
    fixtures: BTreeSet<String>,
    send_byte_kinds: BTreeSet<SendByteKind>,
    max_requests: u64,
    per_fixture_max: u64,
    max_attempts: u64,
    retry_on: BTreeSet<String>,
    fee_cap_usd: Option<f64>,
    quota_label: Option<String>,
}

impl AcceptanceGate {
    /// Authorizes one run, or refuses it.
    ///
    /// `opt_in` is the observed `H4_ACCEPTANCE_OPT_IN` value; `manifest` is the
    /// manifest bytes read from the path named by `H4_ACCEPTANCE_MANIFEST`. Both
    /// are parameters instead of reads so the gate is deterministic in tests and
    /// so the environment is read in exactly one place
    /// ([`AcceptanceGate::from_environment`]).
    pub fn authorize(
        opt_in: Option<&str>,
        manifest: Option<&[u8]>,
        now_millis: u64,
        request: &AcceptanceRequest,
    ) -> Result<Self, GateRefusal> {
        match opt_in {
            None => return Err(GateRefusal::OptInMissing),
            Some("1") => {}
            Some(other) => {
                return Err(GateRefusal::OptInNotExplicit {
                    value: other.to_owned(),
                });
            }
        }
        let bytes = manifest.ok_or(GateRefusal::ManifestMissing)?;
        let value: Value =
            serde_json::from_slice(bytes).map_err(|error| GateRefusal::ManifestInvalidJson {
                detail: error.to_string(),
            })?;
        let object = value.as_object().ok_or(GateRefusal::ManifestNotObject)?;
        reject_credential_material(object, "")?;

        let gate = Self::from_manifest(object, now_millis)?;
        gate.authorize_request(request)?;
        Ok(gate)
    }

    /// Reads the opt-in and manifest from the environment, then authorizes.
    ///
    /// This is the only function that reads the environment. It is used by the
    /// explicit runner entry point and never by the fixture tests themselves.
    pub fn from_environment(
        now_millis: u64,
        request: &AcceptanceRequest,
    ) -> Result<Self, GateRefusal> {
        let opt_in = std::env::var(OPT_IN_ENV).ok();
        let manifest_path = std::env::var_os(MANIFEST_ENV).map(std::path::PathBuf::from);
        let manifest = match manifest_path {
            Some(path) => {
                Some(
                    std::fs::read(&path).map_err(|error| GateRefusal::ManifestUnreadable {
                        kind: format!("{:?}", error.kind()),
                    })?,
                )
            }
            None => None,
        };
        Self::authorize(opt_in.as_deref(), manifest.as_deref(), now_millis, request)
    }

    /// Human who approved the run.
    pub fn approved_by(&self) -> &str {
        &self.approved_by
    }

    /// When the human approved the run.
    pub fn approved_at(&self) -> &str {
        &self.approved_at
    }

    /// Approved expiry in Unix milliseconds.
    pub const fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }

    /// Approved connection identity.
    pub const fn connection(&self) -> &ConnectionIdentity {
        &self.connection
    }

    /// Approved fixtures.
    pub fn fixtures(&self) -> &BTreeSet<String> {
        &self.fixtures
    }

    /// Approved send-byte kinds.
    pub fn send_byte_kinds(&self) -> &BTreeSet<SendByteKind> {
        &self.send_byte_kinds
    }

    /// Approved total request count.
    pub const fn max_requests(&self) -> u64 {
        self.max_requests
    }

    /// Approved per-fixture request count.
    pub const fn per_fixture_max(&self) -> u64 {
        self.per_fixture_max
    }

    /// Approved retry count.
    pub const fn max_attempts(&self) -> u64 {
        self.max_attempts
    }

    /// Approved retry reasons.
    pub fn retry_on(&self) -> &BTreeSet<String> {
        &self.retry_on
    }

    /// Approved money cap, when the run is priced.
    pub const fn fee_cap_usd(&self) -> Option<f64> {
        self.fee_cap_usd
    }

    /// Approved quota label, when the run is unpriced.
    pub fn quota_label(&self) -> Option<&str> {
        self.quota_label.as_deref()
    }

    fn from_manifest(object: &Map<String, Value>, now_millis: u64) -> Result<Self, GateRefusal> {
        let schema = required_text(object, "schema")?;
        if schema != MANIFEST_SCHEMA {
            return Err(GateRefusal::UnsupportedManifestSchema {
                schema: schema.to_owned(),
            });
        }
        let status = required_text(object, "status")?;
        if status != "approved" {
            return Err(GateRefusal::NotAuthorized {
                status: status.to_owned(),
            });
        }
        let approved_by = required_text(object, "approvedBy")?.to_owned();
        let approved_at = required_text(object, "approvedAt")?.to_owned();
        let expires_at_millis = required_u64(object, "expiresAtMillis")?;
        if expires_at_millis <= now_millis {
            return Err(GateRefusal::Expired {
                expires_at_millis,
                now_millis,
            });
        }

        let credential_access = required_text(object, "credentialAccess")?;
        if credential_access != "none" {
            return Err(GateRefusal::CredentialAccessWidened {
                value: credential_access.to_owned(),
            });
        }

        let connection = object.get("connection").and_then(Value::as_object).ok_or(
            GateRefusal::ManifestFieldMissing {
                field: "connection",
            },
        )?;
        let connection = ConnectionIdentity::new(
            required_text(connection, "provider")?,
            required_text(connection, "connectionId")?,
            required_text(connection, "endpointClass")?,
            required_text(connection, "model")?,
        );
        let purpose = required_text(connection_object(object)?, "purpose")?;
        if purpose != "assessment" {
            return Err(GateRefusal::ManifestFieldInvalid {
                field: "connection.purpose",
                detail: format!("{purpose:?} is not the H4 assessment purpose"),
            });
        }
        if !connection.is_complete() {
            return Err(GateRefusal::ManifestFieldMissing {
                field: "connection",
            });
        }

        let fixtures = required_string_array(object, "fixtures")?;
        if fixtures.is_empty() {
            return Err(GateRefusal::FixtureListEmpty);
        }
        let mut approved_fixtures = BTreeSet::new();
        for fixture in &fixtures {
            approved_fixtures.insert(fixture.clone());
        }

        let kind_labels = required_string_array(object, "sendByteKinds")?;
        let mut kinds = BTreeSet::new();
        for label in &kind_labels {
            let kind =
                SendByteKind::parse(label).ok_or_else(|| GateRefusal::UnknownSendByteKind {
                    kind: label.clone(),
                })?;
            kinds.insert(kind);
        }
        for required in REQUIRED_SEND_BYTE_KINDS {
            if !kinds.contains(&required) {
                return Err(GateRefusal::RequiredSendByteKindMissing { kind: required });
            }
        }

        let capabilities = object
            .get("h3Capabilities")
            .and_then(Value::as_object)
            .ok_or(GateRefusal::ManifestFieldMissing {
                field: "h3Capabilities",
            })?;
        for capability in UNCONFIRMED_H3_CAPABILITIES {
            let value = required_text(capabilities, capability)?;
            if value != "unconfirmed" {
                return Err(GateRefusal::UnconfirmedCapabilityClaimed {
                    capability,
                    value: value.to_owned(),
                });
            }
        }

        let budget = object
            .get("requestBudget")
            .and_then(Value::as_object)
            .ok_or(GateRefusal::ManifestFieldMissing {
                field: "requestBudget",
            })?;
        let max_requests = required_u64(budget, "maxRequests")?;
        let per_fixture_max = required_u64(budget, "perFixtureMax")?;
        if max_requests == 0 || per_fixture_max == 0 {
            return Err(GateRefusal::RequestCountNotFinite);
        }
        if max_requests < approved_fixtures.len() as u64 {
            return Err(GateRefusal::RequestCountOverrun {
                approved: max_requests,
                requested: approved_fixtures.len() as u64,
            });
        }

        let retry = object.get("retryPolicy").and_then(Value::as_object).ok_or(
            GateRefusal::ManifestFieldMissing {
                field: "retryPolicy",
            },
        )?;
        let max_attempts = required_u64(retry, "maxAttempts")?;
        if !(1..=5).contains(&max_attempts) {
            return Err(GateRefusal::RetryCountNotFinite);
        }
        if retry.get("sameConnectionOnly").and_then(Value::as_bool) != Some(true) {
            return Err(GateRefusal::ManifestFieldInvalid {
                field: "retryPolicy.sameConnectionOnly",
                detail: "must be true".to_owned(),
            });
        }
        let retry_on = required_string_array(retry, "retryOn")?;
        if retry_on.is_empty() {
            return Err(GateRefusal::ManifestFieldMissing {
                field: "retryPolicy.retryOn",
            });
        }
        let mut approved_retry_on = BTreeSet::new();
        for reason in retry_on {
            if !APPROVED_RETRY_REASONS.contains(&reason.as_str()) {
                return Err(GateRefusal::RetryReasonNotApproved { reason });
            }
            approved_retry_on.insert(reason);
        }

        let cost = object
            .get("cost")
            .and_then(Value::as_object)
            .ok_or(GateRefusal::ManifestFieldMissing { field: "cost" })?;
        let priced = cost.get("priced").and_then(Value::as_bool).ok_or(
            GateRefusal::ManifestFieldMissing {
                field: "cost.priced",
            },
        )?;
        let fee_cap_usd = match cost.get("feeCapUsd") {
            Some(Value::Null) | None => None,
            Some(value) => {
                let cap = value.as_f64().ok_or(GateRefusal::CostNotFinite)?;
                if !cap.is_finite() || cap < 0.0 {
                    return Err(GateRefusal::CostNotFinite);
                }
                Some(cap)
            }
        };
        let quota_label = match cost.get("quotaLabel") {
            Some(Value::String(label)) if !label.trim().is_empty() => Some(label.clone()),
            _ => None,
        };
        let quota_confirmed = cost.get("quotaConfirmed").and_then(Value::as_bool) == Some(true);
        if priced && fee_cap_usd.is_none() {
            return Err(GateRefusal::PricedRequestWithoutMoneyCap);
        }
        if fee_cap_usd.is_none() && !(quota_confirmed && quota_label.is_some()) {
            return Err(GateRefusal::CostOrQuotaMissing);
        }

        let inherited = object
            .get("inheritedUnconfirmed")
            .and_then(Value::as_array)
            .ok_or(GateRefusal::ManifestFieldMissing {
                field: "inheritedUnconfirmed",
            })?;
        let mut seen = BTreeSet::new();
        for item in inherited {
            let item = item.as_object().ok_or(GateRefusal::ManifestFieldInvalid {
                field: "inheritedUnconfirmed",
                detail: "entries must be objects".to_owned(),
            })?;
            let id = required_text(item, "id")?;
            let status = required_text(item, "status")?;
            if status != "unconfirmed" {
                return Err(GateRefusal::InheritedUnconfirmedClaimed { id: id.to_owned() });
            }
            seen.insert(id.to_owned());
        }
        for (id, _) in INHERITED_UNCONFIRMED {
            if !seen.contains(id) {
                return Err(GateRefusal::InheritedUnconfirmedMissing { id });
            }
        }

        Ok(Self {
            approved_by,
            approved_at,
            expires_at_millis,
            connection,
            fixtures: approved_fixtures,
            send_byte_kinds: kinds,
            max_requests,
            per_fixture_max,
            max_attempts,
            retry_on: approved_retry_on,
            fee_cap_usd,
            quota_label,
        })
    }

    fn authorize_request(&self, request: &AcceptanceRequest) -> Result<(), GateRefusal> {
        for field in ["provider", "connectionId", "endpointClass", "model"] {
            if request.connection.field(field) != self.connection.field(field) {
                return Err(GateRefusal::ConnectionMismatch { field });
            }
        }
        if request.fixtures.is_empty() {
            return Err(GateRefusal::FixtureListEmpty);
        }
        let requested: BTreeSet<&String> = request.fixtures.iter().collect();
        if requested.len() != request.fixtures.len() {
            return Err(GateRefusal::ManifestFieldInvalid {
                field: "fixtures",
                detail: "the request lists a fixture more than once".to_owned(),
            });
        }
        for fixture in &request.fixtures {
            if !self.fixtures.contains(fixture) {
                return Err(GateRefusal::FixtureOutOfScope {
                    fixture: fixture.clone(),
                });
            }
        }
        let kinds: BTreeSet<SendByteKind> = request.send_byte_kinds.iter().copied().collect();
        if kinds.len() != request.send_byte_kinds.len() || kinds != self.send_byte_kinds {
            return Err(GateRefusal::SendByteKindsMismatch);
        }
        if request.requests == 0 {
            return Err(GateRefusal::RequestCountNotFinite);
        }
        if request.requests > self.max_requests {
            return Err(GateRefusal::RequestCountOverrun {
                approved: self.max_requests,
                requested: request.requests,
            });
        }
        if request.requests < request.fixtures.len() as u64 {
            return Err(GateRefusal::RequestCountOverrun {
                approved: request.requests,
                requested: request.fixtures.len() as u64,
            });
        }
        if request.per_fixture_requests == 0 {
            return Err(GateRefusal::PerFixtureOverrun {
                approved: self.per_fixture_max,
                requested: 0,
            });
        }
        if request.per_fixture_requests > self.per_fixture_max {
            return Err(GateRefusal::PerFixtureOverrun {
                approved: self.per_fixture_max,
                requested: request.per_fixture_requests,
            });
        }
        if request.retries > self.max_attempts {
            return Err(GateRefusal::RetryOverrun {
                approved: self.max_attempts,
                requested: request.retries,
            });
        }
        Ok(())
    }
}

/// One send the runner would perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledSend {
    /// Fixture the send belongs to.
    pub fixture: String,
    /// Bytes kind of the send.
    pub kind: SendByteKind,
}

/// A scripted transport failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFailure {
    /// Approved retry reason.
    pub reason: String,
}

impl TransportFailure {
    /// Creates a failure with an approved reason label.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Anything that can perform one send. The shipped tests only implement the
/// recording form, so no real provider branch is exercised.
pub trait AcceptanceTransport {
    /// Sends one payload. The runner never calls this before authorization.
    fn send(
        &mut self,
        connection: &ConnectionIdentity,
        send: &ScheduledSend,
    ) -> Result<(), TransportFailure>;
}

/// A refusal from the runner, including the pre-send gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunRefusal {
    /// The gate refused before any send.
    Gate(GateRefusal),
    /// The schedule does not match the authorized request count.
    ScheduleCountMismatch {
        /// Authorized requests.
        approved: u64,
        /// Scheduled sends.
        scheduled: u64,
    },
    /// A scheduled send uses a kind the run did not authorize.
    ScheduleKindUnapproved {
        /// Bytes kind.
        kind: SendByteKind,
    },
    /// A scheduled fixture is not part of the run.
    ScheduleFixtureUnapproved {
        /// Fixture name.
        fixture: String,
    },
    /// One fixture received more sends than the run authorized.
    PerFixtureOverrun {
        /// Authorized per fixture.
        approved: u64,
        /// Observed sends.
        observed: u64,
    },
    /// The total send count would exceed the authorization.
    RequestBudgetExceeded {
        /// Authorized total.
        approved: u64,
    },
    /// A retry used more than the approved retry count.
    RetryBudgetExceeded {
        /// Authorized retries.
        approved: u64,
    },
    /// A retry reason is not approved.
    RetryReasonNotApproved {
        /// Observed reason.
        reason: String,
    },
}

impl From<GateRefusal> for RunRefusal {
    fn from(value: GateRefusal) -> Self {
        Self::Gate(value)
    }
}

/// One simulated outcome the metrics fixture can record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptanceDefect {
    /// A Task was reported complete while its conditions were unmet.
    Completion,
    /// A commit was accepted while its evidence was stale.
    Commit,
    /// A Task was dispatched though the plan or approval no longer allowed it.
    Dispatch,
}

/// One hold state. Holds are counted apart from defects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptanceHold {
    /// The execution is pending a condition or a process.
    Pending,
    /// The execution is waiting for a human decision or permission.
    HumanWait,
}

/// The metrics output of the acceptance fixture.
///
/// Defects and holds are separate fields on purpose: a run that stops and waits
/// is not a wrong result, and the fixture must never merge the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceMetrics {
    wrong_completion: u64,
    wrong_commit: u64,
    wrong_dispatch: u64,
    held_pending: u64,
    held_human_wait: u64,
    external_requests: u64,
}

impl AcceptanceMetrics {
    /// No defect, no hold, no request.
    pub const fn zero() -> Self {
        Self {
            wrong_completion: 0,
            wrong_commit: 0,
            wrong_dispatch: 0,
            held_pending: 0,
            held_human_wait: 0,
            external_requests: 0,
        }
    }

    /// Records one simulated outcome.
    pub fn observe(&mut self, defect: AcceptanceDefect) {
        match defect {
            AcceptanceDefect::Completion => self.wrong_completion += 1,
            AcceptanceDefect::Commit => self.wrong_commit += 1,
            AcceptanceDefect::Dispatch => self.wrong_dispatch += 1,
        }
    }

    /// Records one hold.
    pub fn hold(&mut self, hold: AcceptanceHold) {
        match hold {
            AcceptanceHold::Pending => self.held_pending += 1,
            AcceptanceHold::HumanWait => self.held_human_wait += 1,
        }
    }

    /// Records one external request actually sent.
    pub fn record_external_request(&mut self) {
        self.external_requests += 1;
    }

    /// Wrong-completion count.
    pub const fn wrong_completion(&self) -> u64 {
        self.wrong_completion
    }

    /// Wrong-commit count.
    pub const fn wrong_commit(&self) -> u64 {
        self.wrong_commit
    }

    /// Wrong-dispatch count.
    pub const fn wrong_dispatch(&self) -> u64 {
        self.wrong_dispatch
    }

    /// Pending holds.
    pub const fn held_pending(&self) -> u64 {
        self.held_pending
    }

    /// Human-wait holds.
    pub const fn held_human_wait(&self) -> u64 {
        self.held_human_wait
    }

    /// External requests sent by this run.
    pub const fn external_requests(&self) -> u64 {
        self.external_requests
    }

    /// Machine-readable output with defects, holds and inherited items separate.
    pub fn to_json(&self, real_provider_confirmed: bool) -> Value {
        serde_json::json!({
            "schema": "h4-acceptance-metrics-v1",
            "status": if real_provider_confirmed { "run" } else { "not_run" },
            "externalRequests": self.external_requests,
            "realProvider": {
                "status": if real_provider_confirmed { "executed" } else { "not_executed" },
                "confirmed": real_provider_confirmed,
            },
            "counts": {
                "wrongCompletion": self.wrong_completion,
                "wrongCommit": self.wrong_commit,
                "wrongDispatch": self.wrong_dispatch,
            },
            "holds": {
                "pending": self.held_pending,
                "humanWait": self.held_human_wait,
            },
            "inheritedUnconfirmed": INHERITED_UNCONFIRMED
                .iter()
                .map(|(id, detail)| serde_json::json!({
                    "id": id,
                    "status": "unconfirmed",
                    "confirmed": false,
                    "detail": detail,
                }))
                .collect::<Vec<_>>(),
        })
    }
}

/// The result of one authorized run. The real provider is never executed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    /// Sends the transport accepted.
    pub sends: u64,
    /// Retries the transport needed.
    pub retries: u64,
    /// Metric output. The real-provider column stays unconfirmed.
    pub metrics: AcceptanceMetrics,
}

/// Runs the scheduled sends, or refuses before the first transport call.
///
/// The gate runs first. The runner then enforces the approved totals as it
/// sends, so a schedule that is larger than the authorization cannot overrun
/// it even when the caller mis-declares the request.
pub fn run_acceptance(
    opt_in: Option<&str>,
    manifest: Option<&[u8]>,
    now_millis: u64,
    request: &AcceptanceRequest,
    schedule: &[ScheduledSend],
    transport: &mut dyn AcceptanceTransport,
) -> Result<RunReport, RunRefusal> {
    let gate = AcceptanceGate::authorize(opt_in, manifest, now_millis, request)?;
    if schedule.len() as u64 != request.requests {
        return Err(RunRefusal::ScheduleCountMismatch {
            approved: request.requests,
            scheduled: schedule.len() as u64,
        });
    }
    let approved_kinds: BTreeSet<SendByteKind> = request.send_byte_kinds.iter().copied().collect();
    for send in schedule {
        if !approved_kinds.contains(&send.kind) {
            return Err(RunRefusal::ScheduleKindUnapproved { kind: send.kind });
        }
        if !request.fixtures.contains(&send.fixture) {
            return Err(RunRefusal::ScheduleFixtureUnapproved {
                fixture: send.fixture.clone(),
            });
        }
    }

    let mut metrics = AcceptanceMetrics::zero();
    let mut sends = 0_u64;
    let mut retries = 0_u64;
    let mut per_fixture = std::collections::BTreeMap::<String, u64>::new();
    for send in schedule {
        let observed = per_fixture.entry(send.fixture.clone()).or_insert(0);
        // The attempt and every retry are sends and count against both budgets.
        loop {
            if sends >= gate.max_requests {
                return Err(RunRefusal::RequestBudgetExceeded {
                    approved: gate.max_requests,
                });
            }
            if *observed >= gate.per_fixture_max {
                return Err(RunRefusal::PerFixtureOverrun {
                    approved: gate.per_fixture_max,
                    observed: *observed,
                });
            }
            sends += 1;
            *observed += 1;
            metrics.record_external_request();
            match transport.send(&gate.connection, send) {
                Ok(()) => break,
                Err(failure) => {
                    if !gate.retry_on.contains(&failure.reason) {
                        return Err(RunRefusal::RetryReasonNotApproved {
                            reason: failure.reason,
                        });
                    }
                    if retries >= gate.max_attempts {
                        return Err(RunRefusal::RetryBudgetExceeded {
                            approved: gate.max_attempts,
                        });
                    }
                    retries += 1;
                }
            }
        }
    }
    Ok(RunReport {
        sends,
        retries,
        metrics,
    })
}

// ---------------------------------------------------------------------------
// Manifest parsing helpers
// ---------------------------------------------------------------------------

fn connection_object(object: &Map<String, Value>) -> Result<&Map<String, Value>, GateRefusal> {
    object
        .get("connection")
        .and_then(Value::as_object)
        .ok_or(GateRefusal::ManifestFieldMissing {
            field: "connection",
        })
}

fn required_text<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, GateRefusal> {
    match object.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value),
        Some(Value::String(_)) | Some(Value::Null) | None => {
            Err(GateRefusal::ManifestFieldMissing { field })
        }
        Some(_) => Err(GateRefusal::ManifestFieldInvalid {
            field,
            detail: "must be a string".to_owned(),
        }),
    }
}

fn required_u64(object: &Map<String, Value>, field: &'static str) -> Result<u64, GateRefusal> {
    match object.get(field) {
        Some(Value::Number(number)) => number.as_u64().ok_or(GateRefusal::ManifestFieldInvalid {
            field,
            detail: "must be a non-negative integer".to_owned(),
        }),
        Some(_) => Err(GateRefusal::ManifestFieldInvalid {
            field,
            detail: "must be a non-negative integer".to_owned(),
        }),
        None => Err(GateRefusal::ManifestFieldMissing { field }),
    }
}

fn required_string_array(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Vec<String>, GateRefusal> {
    let values = match object.get(field) {
        Some(Value::Array(values)) => values,
        Some(_) => {
            return Err(GateRefusal::ManifestFieldInvalid {
                field,
                detail: "must be an array of strings".to_owned(),
            });
        }
        None => return Err(GateRefusal::ManifestFieldMissing { field }),
    };
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        match value {
            Value::String(text) if !text.trim().is_empty() => result.push(text.clone()),
            _ => {
                return Err(GateRefusal::ManifestFieldInvalid {
                    field,
                    detail: "must be an array of non-empty strings".to_owned(),
                });
            }
        }
    }
    Ok(result)
}

fn credential_like_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "apikey"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "authorization"
            | "password"
            | "secret"
            | "clientsecret"
            | "credential"
            | "credentials"
            | "privatekey"
            | "bearertoken"
    )
}

fn reject_credential_material(
    object: &Map<String, Value>,
    prefix: &str,
) -> Result<(), GateRefusal> {
    for (key, value) in object {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        if credential_like_key(key) {
            return Err(GateRefusal::CredentialMaterialPresent { field: path });
        }
        match value {
            Value::Object(nested) => reject_credential_material(nested, &path)?,
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    if let Value::Object(nested) = item {
                        reject_credential_material(nested, &format!("{path}.{index}"))?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}
