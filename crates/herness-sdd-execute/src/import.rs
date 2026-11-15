//! Pure plan import and side-effect-free preview.
//!
//! The pack owns the `sdd-plan-inspect` protocol and the plan parser. This
//! module is the host side of that protocol: it decodes the exact response
//! bytes into a validated [`PlanPreview`], and it verifies the spec and source
//! snapshots a preview binds. Nothing here performs I/O: the caller supplies
//! the response bytes and the exact file contents, so a test can exercise every
//! rule without a pack, a checkout, or a process.
//!
//! # What a preview proves, and what it does not
//!
//! A preview proves that the pack parsed the exact bytes the host sent, that
//! the returned digest and byte length describe those bytes, that every
//! returned byte range slices the exact input, and that the parsed structure is
//! internally consistent. It does not prove that the prose means what the plan
//! claims, that a human approved anything, or that a referenced document is the
//! currently approved revision of a spec. The approval and current-revision
//! checks are separate host decisions.
//!
//! # Failure mapping
//!
//! The H4 contract has ten refusal classes; a preview uses four of them:
//!
//! * `unsupported_plan_format` — the pack reported a document with no
//!   `sdd-execution-v1` block.
//! * `invalid_plan` — the pack reported a schema defect, or the host's own
//!   revalidation (byte ranges, cross references, spec references) refused the
//!   result.
//! * `unavailable` — the protocol exchange cannot be used: invalid JSON, an
//!   unknown field or operation, a non-zero exit, a timeout, oversize input, an
//!   unsupported protocol version, or a pack fingerprint that is not the
//!   approved one. The `feature` label names the sub-case so a caller can
//!   tell them apart.
//! * `unsupported_plan_schema_version` / `unsupported_inspector_protocol` —
//!   distinct typed errors for a version this build does not implement.
//!
//! There is no fallback: an unusable exchange never becomes a partial preview,
//! a `task-brief` scratch parse, or a heuristic Markdown guess.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::approval::{
    ApprovedCheck, ApprovedCondition, ApprovedDeliverable, CommitPolicy, ConditionMode,
    DeliverableKind,
};
use crate::error::{FailureDetails, SddExecutionError};
use crate::plan::{
    ExactPlanText, InspectRequest, InspectedPlan, InspectorCapabilities, InspectorProtocol,
    ParsedPlanSummary, ParsedPlanTask, PlanByteRange, PlanDiagnostic, PlanDiagnosticCode, PlanPath,
    base64_encode, validate_check_cwd, validate_project_path,
};
use crate::version::{
    MAX_PLAN_BYTES, PLAN_INSPECTOR_PROTOCOL, PLAN_INSPECTOR_PROTOCOL_VERSION, PackFingerprint,
    PlanDigest, Sha256Digest,
};

// ---------------------------------------------------------------------------
// Unavailable sub-case labels
// ---------------------------------------------------------------------------

/// An inspector response that is not one usable protocol object.
pub const RESPONSE_FEATURE: &str = "plan.inspector.response";

/// A response envelope whose protocol name or version this build does not
/// implement.
pub const PROTOCOL_FEATURE: &str = "plan.inspector.protocol";

/// A pack execution-contract fingerprint that is not the expected one.
pub const CONTRACT_FEATURE: &str = "plan.inspector.executionContract";

/// A pack execution-contract input whose bytes do not match its claim, or that
/// is missing from the pack root.
pub const CONTRACT_INPUT_FEATURE: &str = "plan.inspector.executionContractInput";

/// An inspector process that exited non-zero.
pub const EXIT_FEATURE: &str = "plan.inspector.exit";

/// An inspector process that exceeded the host timeout and was terminated.
pub const TIMEOUT_FEATURE: &str = "plan.inspector.timeout";

/// The pack root, toolchain, or inspector entry point is unusable.
pub const PACK_FEATURE: &str = "plan.inspector.pack";

/// An inspector response larger than the host capture limit.
pub const OVERSIZE_RESPONSE_FEATURE: &str = "plan.inspector.oversizeResponse";

/// A plan input larger than [`MAX_PLAN_BYTES`].
pub const OVERSIZE_PLAN_FEATURE: &str = "plan.import.oversizePlan";

/// A spec or source snapshot larger than the host read limit.
pub const OVERSIZE_SNAPSHOT_FEATURE: &str = "plan.import.oversizeSnapshot";

/// Maximum bytes read from one spec or source snapshot.
///
/// The packet (Task 14) must fit real sections into its own budget; this limit
/// only stops a multi-hundred-megabyte document from being read at all.
pub const MAX_SPEC_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Request and response protocol values
// ---------------------------------------------------------------------------

/// The two operations `sdd-plan-inspect` version 1 implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectorOperation {
    /// Report the schema version and the pack execution contract.
    Capabilities,
    /// Parse one plan from exact bytes.
    Inspect,
}

impl InspectorOperation {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities",
            Self::Inspect => "inspect",
        }
    }
}

/// Every stable error code `sdd-plan-inspect` version 1 can return.
///
/// The two plan codes come from the pack parser; the rest describe the request
/// or the exchange. An unknown code is not guessed into one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InspectorFailureCode {
    /// stdin was not one JSON object.
    InvalidJson,
    /// The request was JSON but not an object.
    RequestNotObject,
    /// A required request field was absent.
    MissingRequestField,
    /// A request field is not part of the operation.
    UnknownRequestField,
    /// A request field carries an invalid value.
    InvalidRequestValue,
    /// The protocol name is not `sdd-plan-inspect`.
    UnknownProtocol,
    /// The protocol version is not 1.
    UnsupportedProtocolVersion,
    /// The operation is not `capabilities` or `inspect`.
    UnknownOperation,
    /// `planPath` is not a canonical inspection path.
    InvalidPlanPath,
    /// `sourceBase64` is not canonical base64.
    InvalidSourceBase64,
    /// The plan exceeded 2 MiB.
    SourceTooLarge,
    /// A fingerprint input is missing from the pack root.
    FingerprintInputMissing,
    /// The inspector itself failed.
    InternalError,
    /// The document has no `sdd-execution-v1` block.
    UnsupportedPlanFormat,
    /// The document claims the format but violates its schema.
    InvalidPlan,
}

impl InspectorFailureCode {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid_json",
            Self::RequestNotObject => "request_not_object",
            Self::MissingRequestField => "missing_request_field",
            Self::UnknownRequestField => "unknown_request_field",
            Self::InvalidRequestValue => "invalid_request_value",
            Self::UnknownProtocol => "unknown_protocol",
            Self::UnsupportedProtocolVersion => "unsupported_protocol_version",
            Self::UnknownOperation => "unknown_operation",
            Self::InvalidPlanPath => "invalid_plan_path",
            Self::InvalidSourceBase64 => "invalid_source_base64",
            Self::SourceTooLarge => "source_too_large",
            Self::FingerprintInputMissing => "fingerprint_input_missing",
            Self::InternalError => "internal_error",
            Self::UnsupportedPlanFormat => "unsupported_plan_format",
            Self::InvalidPlan => "invalid_plan",
        }
    }

    /// Parses a stable wire label. An unknown label returns `None`.
    pub fn from_wire(value: &str) -> Option<Self> {
        const ALL: &[InspectorFailureCode] = &[
            InspectorFailureCode::InvalidJson,
            InspectorFailureCode::RequestNotObject,
            InspectorFailureCode::MissingRequestField,
            InspectorFailureCode::UnknownRequestField,
            InspectorFailureCode::InvalidRequestValue,
            InspectorFailureCode::UnknownProtocol,
            InspectorFailureCode::UnsupportedProtocolVersion,
            InspectorFailureCode::UnknownOperation,
            InspectorFailureCode::InvalidPlanPath,
            InspectorFailureCode::InvalidSourceBase64,
            InspectorFailureCode::SourceTooLarge,
            InspectorFailureCode::FingerprintInputMissing,
            InspectorFailureCode::InternalError,
            InspectorFailureCode::UnsupportedPlanFormat,
            InspectorFailureCode::InvalidPlan,
        ];
        ALL.iter().copied().find(|code| code.as_str() == value)
    }
}

/// The pack execution-contract input set this build requires.
///
/// The spec names the parser, the schema, the integration definition, and the
/// execute and implementer instructions. A pack may append further inputs to a
/// version 1 contract, so extra inputs are verified but not refused.
pub const REQUIRED_CONTRACT_INPUTS: &[&str] = &[
    "inspector",
    "plan-parser",
    "schema-document",
    "execute-instructions",
    "implementer-instructions",
    "herness-execution-definition",
    "herness-execution-module",
];

// ---------------------------------------------------------------------------
// Wire structures
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireResponse {
    protocol: String,
    version: u32,
    #[serde(default)]
    operation: Option<InspectorOperation>,
    ok: bool,
    #[serde(default)]
    error: Option<WireError>,
    #[serde(default)]
    result: Option<serde_json::Value>,
    #[serde(default)]
    diagnostics: Vec<WireDiagnostic>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireError {
    code: String,
    message: String,
    // Decoded so an unknown-shape error object is still refused; the pack's
    // free-form details are not used to build an H4 value.
    #[serde(default)]
    #[allow(dead_code)]
    details: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireDiagnostic {
    code: String,
    message: String,
    #[serde(default)]
    range: Option<PlanByteRange>,
    #[serde(default)]
    pointer: Option<String>,
    // See `WireError::details`.
    #[serde(default)]
    #[allow(dead_code)]
    details: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireCapabilitiesResult {
    schema_name: String,
    schema_version: u32,
    execution_block_info: String,
    max_plan_bytes: u64,
    plan_path_prefix: String,
    execution_contract: WireExecutionContract,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireExecutionContract {
    fingerprint: PackFingerprint,
    algorithm: String,
    inputs: Vec<WireContractInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireContractInput {
    id: String,
    path: String,
    digest: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireInspectResult {
    plan_path: PlanPath,
    digest: PlanDigest,
    byte_length: u64,
    schema_version: u32,
    header: WireHeader,
    global_constraints: WireConstraints,
    execution_block: WireBlock,
    spec_refs: Vec<WireSpecRef>,
    tasks: Vec<WireTask>,
    final_checks: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireHeader {
    range: PlanByteRange,
    goal: String,
    architecture: String,
    tech_stack: String,
    spec: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireConstraints {
    range: PlanByteRange,
    heading_range: PlanByteRange,
    body_range: PlanByteRange,
    text: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireBlock {
    info: String,
    range: PlanByteRange,
    content_range: PlanByteRange,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireSpecRef {
    source: String,
    path: String,
    sections: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireDeliverable {
    path: String,
    kind: DeliverableKind,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireCondition {
    id: String,
    title: String,
    rubric: String,
    mode: ConditionMode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireCheck {
    id: String,
    condition_id: String,
    description: String,
    command: String,
    cwd: String,
    timeout_seconds: f64,
    input_paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireTask {
    number: u32,
    title: String,
    depends_on: Vec<u32>,
    spec_refs: Vec<WireSpecRef>,
    read_paths: Vec<String>,
    write_paths: Vec<String>,
    allow_shell: bool,
    deliverables: Vec<WireDeliverable>,
    conditions: Vec<WireCondition>,
    checks: Vec<WireCheck>,
    html_targets: Vec<String>,
    commit_policy: CommitPolicy,
    heading_range: PlanByteRange,
    body_range: PlanByteRange,
    heading_text: String,
    body_text: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn unavailable(feature: &str, detail: impl AsRef<str>) -> SddExecutionError {
    SddExecutionError::Unavailable {
        feature: format!("{feature}: {}", detail.as_ref()),
        details: FailureDetails::none().boxed(),
    }
}

fn invalid(field: &str, detail: impl Into<String>) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.into(),
    }
}

fn invalid_plan(detail: impl Into<String>) -> SddExecutionError {
    let detail = detail.into();
    SddExecutionError::InvalidPlan {
        diagnostic: PlanDiagnostic::new(PlanDiagnosticCode::InvalidPlan, detail, None, None)
            .expect("a non-empty plan diagnostic message"),
        details: FailureDetails::none().boxed(),
    }
}

/// The `unavailable` label an inspector error code maps to.
///
/// The plan codes are not in this list: they are reported as
/// `unsupported_plan_format`/`invalid_plan` instead.
pub fn unavailable_feature_for(code: InspectorFailureCode) -> &'static str {
    match code {
        InspectorFailureCode::SourceTooLarge => OVERSIZE_PLAN_FEATURE,
        InspectorFailureCode::UnsupportedProtocolVersion
        | InspectorFailureCode::UnknownProtocol
        | InspectorFailureCode::UnknownOperation => PROTOCOL_FEATURE,
        InspectorFailureCode::FingerprintInputMissing => CONTRACT_INPUT_FEATURE,
        _ => RESPONSE_FEATURE,
    }
}

// ---------------------------------------------------------------------------
// Envelope decoding
// ---------------------------------------------------------------------------

fn protocol_identity(name: &str, version: u32) -> Result<InspectorProtocol, SddExecutionError> {
    if name != PLAN_INSPECTOR_PROTOCOL || version != PLAN_INSPECTOR_PROTOCOL_VERSION {
        return Err(SddExecutionError::UnsupportedInspectorProtocol {
            found: format!("{name}/{version}"),
            expected: format!("{PLAN_INSPECTOR_PROTOCOL}/{PLAN_INSPECTOR_PROTOCOL_VERSION}"),
        });
    }
    InspectorProtocol::new(name, version)
}

fn decode_envelope(
    raw: &[u8],
    expected: InspectorOperation,
) -> Result<WireResponse, SddExecutionError> {
    if raw.is_empty() {
        return Err(unavailable(RESPONSE_FEATURE, "the response is empty"));
    }
    let response: WireResponse = serde_json::from_slice(raw).map_err(|error| {
        unavailable(
            RESPONSE_FEATURE,
            format!("the response is not one JSON object with the known fields: {error}"),
        )
    })?;
    protocol_identity(&response.protocol, response.version)?;
    match response.operation {
        Some(operation) if operation == expected => {}
        Some(other) => {
            return Err(unavailable(
                RESPONSE_FEATURE,
                format!(
                    "the response reports operation {:?} but {:?} was requested",
                    other.as_str(),
                    expected.as_str()
                ),
            ));
        }
        None => {
            return Err(unavailable(
                RESPONSE_FEATURE,
                "the response does not report the operation it answers",
            ));
        }
    }
    if response.ok {
        if response.error.is_some() {
            return Err(unavailable(
                RESPONSE_FEATURE,
                "a successful response also carries an error object",
            ));
        }
        if !response.diagnostics.is_empty() {
            return Err(unavailable(
                RESPONSE_FEATURE,
                "a successful response also carries diagnostics",
            ));
        }
        if response.result.is_none() {
            return Err(unavailable(
                RESPONSE_FEATURE,
                "a successful response has no result",
            ));
        }
    } else {
        if response.result.is_some() {
            return Err(unavailable(
                RESPONSE_FEATURE,
                "a failed response also carries a result",
            ));
        }
        if response.error.is_none() {
            return Err(unavailable(
                RESPONSE_FEATURE,
                "a failed response has no error object",
            ));
        }
    }
    Ok(response)
}

fn decode_diagnostic(wire: &WireDiagnostic) -> Result<PlanDiagnostic, SddExecutionError> {
    let code = PlanDiagnosticCode::parse(&wire.code).ok_or_else(|| {
        unavailable(
            RESPONSE_FEATURE,
            format!("unknown diagnostic code {:?}", wire.code),
        )
    })?;
    PlanDiagnostic::new(code, wire.message.clone(), wire.pointer.clone(), wire.range)
}

/// One typed inspector failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectorFailure {
    code: InspectorFailureCode,
    message: String,
    diagnostics: Vec<PlanDiagnostic>,
}

impl InspectorFailure {
    /// Creates a typed failure.
    pub fn new(
        code: InspectorFailureCode,
        message: impl Into<String>,
        diagnostics: Vec<PlanDiagnostic>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            diagnostics,
        }
    }

    /// Typed failure code.
    pub const fn code(&self) -> InspectorFailureCode {
        self.code
    }

    /// Non-secret message produced by the pack.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Diagnostics with byte ranges, when the pack produced them.
    pub fn diagnostics(&self) -> &[PlanDiagnostic] {
        &self.diagnostics
    }
}

/// Maps one typed inspector failure onto the H4 error classes.
///
/// The two plan codes become `unsupported_plan_format`/`invalid_plan` with the
/// pack's first diagnostic, including its byte range. Every other code is
/// `unavailable` with a sub-case label, so an exchange failure is never
/// reported as a plan defect. An unknown wire code is not passed here at all:
/// [`PlanPreview::decode`] refuses it as an invalid response.
pub fn inspector_failure_error(failure: &InspectorFailure) -> SddExecutionError {
    match failure.code {
        InspectorFailureCode::UnsupportedPlanFormat => SddExecutionError::UnsupportedPlanFormat {
            diagnostic: failure.diagnostics.first().cloned().unwrap_or_else(|| {
                diagnostic_or(PlanDiagnosticCode::UnsupportedPlanFormat, &failure.message)
            }),
            details: FailureDetails::none().boxed(),
        },
        InspectorFailureCode::InvalidPlan => SddExecutionError::InvalidPlan {
            diagnostic: failure.diagnostics.first().cloned().unwrap_or_else(|| {
                diagnostic_or(PlanDiagnosticCode::InvalidPlan, &failure.message)
            }),
            details: FailureDetails::none().boxed(),
        },
        other => unavailable(
            unavailable_feature_for(other),
            format!("{}: {}", other.as_str(), failure.message),
        ),
    }
}

fn diagnostic_or(code: PlanDiagnosticCode, message: &str) -> PlanDiagnostic {
    PlanDiagnostic::new(code, message, None, None).expect("a non-empty plan diagnostic message")
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// One pack execution-contract input as claimed by `capabilities`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractInput {
    id: String,
    path: String,
    digest: Sha256Digest,
}

impl ContractInput {
    /// Input identifier, for example `plan-parser`.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Pack-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Claimed digest of the exact file bytes.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}

/// The decoded `capabilities` result.
///
/// The capability value is the H4 contract type; the input list is kept beside
/// it so the adapter can verify each claim against the pack root before it
/// binds the fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitiesReport {
    capabilities: InspectorCapabilities,
    algorithm: String,
    inputs: Vec<ContractInput>,
}

impl CapabilitiesReport {
    /// The validated capability value.
    pub fn capabilities(&self) -> &InspectorCapabilities {
        &self.capabilities
    }

    /// Claimed fingerprint algorithm; always `sha256`.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Claimed execution-contract inputs.
    pub fn inputs(&self) -> &[ContractInput] {
        &self.inputs
    }

    /// The pack execution-contract fingerprint.
    pub fn fingerprint(&self) -> &PackFingerprint {
        self.capabilities.execution_contract()
    }
}

/// Decodes one `capabilities` response.
pub fn decode_capabilities_response(raw: &[u8]) -> Result<CapabilitiesReport, SddExecutionError> {
    let response = decode_envelope(raw, InspectorOperation::Capabilities)?;
    let Some(result) = response.result else {
        return Err(unavailable(RESPONSE_FEATURE, "the result is missing"));
    };
    let wire: WireCapabilitiesResult = serde_json::from_value(result).map_err(|error| {
        unavailable(
            RESPONSE_FEATURE,
            format!("the capabilities result is not the known object: {error}"),
        )
    })?;
    if wire.execution_contract.algorithm != "sha256" {
        return Err(invalid(
            "inspector.executionContract.algorithm",
            format!(
                "expected sha256, found {:?}",
                wire.execution_contract.algorithm
            ),
        ));
    }
    if wire.execution_contract.inputs.is_empty() {
        return Err(invalid(
            "inspector.executionContract.inputs",
            "must not be empty",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut inputs = Vec::with_capacity(wire.execution_contract.inputs.len());
    for input in wire.execution_contract.inputs {
        if input.id.trim().is_empty() {
            return Err(invalid(
                "inspector.executionContract.inputs",
                "an id is empty",
            ));
        }
        if !ids.insert(input.id.clone()) {
            return Err(invalid(
                "inspector.executionContract.inputs",
                format!("duplicate input id {:?}", input.id),
            ));
        }
        validate_project_path("inspector.executionContract.inputs.path", &input.path)?;
        if !paths.insert(input.path.clone()) {
            return Err(invalid(
                "inspector.executionContract.inputs",
                format!("duplicate input path {:?}", input.path),
            ));
        }
        inputs.push(ContractInput {
            id: input.id,
            path: input.path,
            digest: input.digest,
        });
    }
    let capabilities = InspectorCapabilities::new(
        InspectorProtocol::expected(),
        wire.schema_name,
        wire.schema_version,
        wire.execution_block_info,
        wire.max_plan_bytes,
        wire.plan_path_prefix,
        wire.execution_contract.fingerprint,
    )?;
    Ok(CapabilitiesReport {
        capabilities,
        algorithm: wire.execution_contract.algorithm,
        inputs,
    })
}

// ---------------------------------------------------------------------------
// Preview values
// ---------------------------------------------------------------------------

/// The plan header returned by the inspector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanHeaderFacts {
    range: PlanByteRange,
    goal: String,
    architecture: String,
    tech_stack: String,
    spec: String,
}

impl PlanHeaderFacts {
    /// Byte range of the header block.
    pub const fn range(&self) -> PlanByteRange {
        self.range
    }

    /// Trimmed `Goal` value.
    pub fn goal(&self) -> &str {
        &self.goal
    }

    /// Trimmed `Architecture` value.
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    /// Trimmed `Tech Stack` value.
    pub fn tech_stack(&self) -> &str {
        &self.tech_stack
    }

    /// Trimmed `Spec` value, which is prose and not an execution reference.
    pub fn spec(&self) -> &str {
        &self.spec
    }
}

/// The one `sdd-execution-v1` fenced block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionBlockFacts {
    info: String,
    range: PlanByteRange,
    content_range: PlanByteRange,
}

impl ExecutionBlockFacts {
    /// Info string, always the capabilities `executionBlockInfo`.
    pub fn info(&self) -> &str {
        &self.info
    }

    /// Byte range of the whole fenced block, fences included.
    pub const fn range(&self) -> PlanByteRange {
        self.range
    }

    /// Byte range of the fenced content, fences excluded.
    pub const fn content_range(&self) -> PlanByteRange {
        self.content_range
    }
}

/// One spec reference exactly as the plan declares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewSpecRef {
    source: String,
    path: String,
    sections: Vec<String>,
}

impl PreviewSpecRef {
    /// Validates one declared reference.
    ///
    /// The alias shape mirrors the pack: `project`, or a registered read-only
    /// source alias. The path is a normalized project-relative (or
    /// alias-relative) path. The sections are non-empty headings.
    pub fn new(
        source: impl Into<String>,
        path: impl Into<String>,
        sections: Vec<String>,
    ) -> Result<Self, SddExecutionError> {
        let source = source.into();
        let path = path.into();
        validate_source_alias(&source)?;
        validate_project_path("specRef.path", &path)?;
        if sections.is_empty() {
            return Err(invalid("specRef.sections", "must not be empty"));
        }
        for section in &sections {
            if section.trim().is_empty() {
                return Err(invalid(
                    "specRef.sections",
                    "must not contain empty headings",
                ));
            }
        }
        Ok(Self {
            source,
            path,
            sections,
        })
    }

    /// `project` or a read-only source alias.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Project-relative, or alias-relative, path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Applied section headings.
    pub fn sections(&self) -> &[String] {
        &self.sections
    }

    /// Whether the reference resolves inside the project checkout.
    pub fn is_project(&self) -> bool {
        self.source == "project"
    }
}

/// One parsed Task with its approval-ready conditions, checks, and ranges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewTask {
    parsed: ParsedPlanTask,
    depends_on: Vec<u32>,
    spec_refs: Vec<PreviewSpecRef>,
    read_paths: Vec<String>,
    write_paths: Vec<String>,
    allow_shell: bool,
    deliverables: Vec<ApprovedDeliverable>,
    conditions: Vec<ApprovedCondition>,
    checks: Vec<ApprovedCheck>,
    html_targets: Vec<String>,
    commit_policy: CommitPolicy,
    heading_range: PlanByteRange,
    heading_text: String,
}

impl PreviewTask {
    /// Plan-assigned number, contiguous from one.
    pub const fn number(&self) -> u32 {
        self.parsed.number()
    }

    /// Heading title.
    pub fn title(&self) -> &str {
        self.parsed.title()
    }

    /// Exact Task body with its byte range.
    pub fn parsed(&self) -> &ParsedPlanTask {
        &self.parsed
    }

    /// Preceding Task numbers this Task depends on.
    pub fn depends_on(&self) -> &[u32] {
        &self.depends_on
    }

    /// Task spec references, a subset of the root references.
    pub fn spec_refs(&self) -> &[PreviewSpecRef] {
        &self.spec_refs
    }

    /// Read scope.
    pub fn read_paths(&self) -> &[String] {
        &self.read_paths
    }

    /// Write scope; empty for `no_change`.
    pub fn write_paths(&self) -> &[String] {
        &self.write_paths
    }

    /// Whether the Task may run an approved shell command.
    pub const fn allow_shell(&self) -> bool {
        self.allow_shell
    }

    /// Declared deliverables.
    pub fn deliverables(&self) -> &[ApprovedDeliverable] {
        &self.deliverables
    }

    /// Declared conditions.
    pub fn conditions(&self) -> &[ApprovedCondition] {
        &self.conditions
    }

    /// Declared checks; the command is a string, never executed here.
    pub fn checks(&self) -> &[ApprovedCheck] {
        &self.checks
    }

    /// Explicit HTML targets; change-detected targets are never narrowed.
    pub fn html_targets(&self) -> &[String] {
        &self.html_targets
    }

    /// Commit policy.
    pub const fn commit_policy(&self) -> CommitPolicy {
        self.commit_policy
    }

    /// Byte range of the `## Task N:` heading line.
    pub const fn heading_range(&self) -> PlanByteRange {
        self.heading_range
    }

    /// Exact heading text, including its line ending.
    pub fn heading_text(&self) -> &str {
        &self.heading_text
    }
}

/// A validated, side-effect-free preview of one execution plan.
///
/// Every byte range is inside the exact input the host sent, and the digest and
/// byte length describe that input. The value is the input to approval (Task
/// 13) and to the immutable Task packet (Task 14); producing it starts no
/// child, no model request, and no Git operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanPreview {
    plan_path: PlanPath,
    header: PlanHeaderFacts,
    global_constraints: ExactPlanText,
    global_constraints_heading: PlanByteRange,
    global_constraints_body: PlanByteRange,
    execution_block: ExecutionBlockFacts,
    spec_refs: Vec<PreviewSpecRef>,
    tasks: Vec<PreviewTask>,
    final_check_ids: Vec<String>,
    inspected: InspectedPlan,
}

impl PlanPreview {
    /// Decodes one `inspect` response against the exact request bytes.
    ///
    /// The capability value must be the one the same pack reported, so the
    /// schema version, execution block info, and byte limit are the pack's own.
    pub fn decode(
        capabilities: &InspectorCapabilities,
        request: &InspectRequest,
        raw: &[u8],
    ) -> Result<Self, SddExecutionError> {
        let response = decode_envelope(raw, InspectorOperation::Inspect)?;
        if !response.ok {
            let error = response
                .error
                .as_ref()
                .expect("a failed response carries an error");
            let Some(code) = InspectorFailureCode::from_wire(&error.code) else {
                return Err(unavailable(
                    RESPONSE_FEATURE,
                    format!("unknown inspector error code {:?}", error.code),
                ));
            };
            let diagnostics = response
                .diagnostics
                .iter()
                .map(decode_diagnostic)
                .collect::<Result<Vec<_>, _>>()?;
            return Err(inspector_failure_error(&InspectorFailure::new(
                code,
                error.message.clone(),
                diagnostics,
            )));
        }
        let Some(result) = response.result else {
            return Err(unavailable(RESPONSE_FEATURE, "the result is missing"));
        };
        let wire: WireInspectResult = serde_json::from_value(result).map_err(|error| {
            unavailable(
                RESPONSE_FEATURE,
                format!("the inspect result is not the known object: {error}"),
            )
        })?;
        Self::validate(capabilities, request, wire)
    }

    fn validate(
        capabilities: &InspectorCapabilities,
        request: &InspectRequest,
        wire: WireInspectResult,
    ) -> Result<Self, SddExecutionError> {
        let source = request.source();
        let length = source.len() as u64;
        if wire.schema_version != capabilities.schema_version() {
            return Err(SddExecutionError::UnsupportedPlanSchemaVersion {
                found: wire.schema_version,
                expected: capabilities.schema_version(),
            });
        }
        if wire.plan_path != *request.plan_path() {
            return Err(unavailable(
                RESPONSE_FEATURE,
                format!(
                    "the result reports plan {:?} but {:?} was inspected",
                    wire.plan_path.as_str(),
                    request.plan_path().as_str()
                ),
            ));
        }
        if wire.byte_length != length {
            return Err(invalid_plan(format!(
                "the inspector reports {length} input bytes, not the exact input length {}",
                wire.byte_length
            )));
        }
        if wire.digest != PlanDigest::sha256(source) {
            return Err(invalid_plan(
                "the inspector digest is not the digest of the exact input bytes",
            ));
        }
        if wire.execution_block.info != capabilities.execution_block_info() {
            return Err(invalid_plan(format!(
                "the execution block info is {:?}, not {:?}",
                wire.execution_block.info,
                capabilities.execution_block_info()
            )));
        }

        // Header: every range must slice the exact input, and the header text
        // must be present at its own range.
        let header_range = checked_range("header.range", wire.header.range, length)?;
        let header_slice = exact_slice(source, header_range)?;
        for (field, value) in [
            ("header.goal", &wire.header.goal),
            ("header.architecture", &wire.header.architecture),
            ("header.techStack", &wire.header.tech_stack),
            ("header.spec", &wire.header.spec),
        ] {
            if value.trim().is_empty() {
                return Err(invalid_plan(format!("{field} must not be empty")));
            }
            if !header_slice.contains(value.as_str()) {
                return Err(unavailable(
                    RESPONSE_FEATURE,
                    format!("{field} does not occur inside the reported header range"),
                ));
            }
        }

        // Global Constraints: the exact text must be the exact bytes of the
        // body range, and the whole range must contain the heading.
        let constraints_range = checked_range(
            "globalConstraints.range",
            wire.global_constraints.range,
            length,
        )?;
        let heading_range = checked_range(
            "globalConstraints.headingRange",
            wire.global_constraints.heading_range,
            length,
        )?;
        let body_range = checked_range(
            "globalConstraints.bodyRange",
            wire.global_constraints.body_range,
            length,
        )?;
        if heading_range.start() < constraints_range.start()
            || heading_range.end() > body_range.start()
            || body_range.end() > constraints_range.end()
        {
            return Err(unavailable(
                RESPONSE_FEATURE,
                "the Global Constraints ranges are not ordered heading, body, whole section",
            ));
        }
        let body_slice = exact_slice(source, body_range)?;
        if body_slice != wire.global_constraints.text {
            return Err(unavailable(
                RESPONSE_FEATURE,
                "the Global Constraints text is not the exact bytes of its range",
            ));
        }
        if wire.global_constraints.text.trim().is_empty() {
            return Err(invalid_plan(
                "the Global Constraints body must not be empty",
            ));
        }
        let heading_slice = exact_slice(source, heading_range)?;
        if !heading_slice.starts_with("##") {
            return Err(unavailable(
                RESPONSE_FEATURE,
                "the Global Constraints heading range does not start with '##'",
            ));
        }

        let block_range =
            checked_range("executionBlock.range", wire.execution_block.range, length)?;
        let content_range = checked_range(
            "executionBlock.contentRange",
            wire.execution_block.content_range,
            length,
        )?;
        if content_range.start() < block_range.start() || content_range.end() > block_range.end() {
            return Err(unavailable(
                RESPONSE_FEATURE,
                "the execution block content range is outside the block range",
            ));
        }

        let constraints_text =
            ExactPlanText::new(wire.global_constraints.text.clone(), body_range)?;

        let mut spec_refs = Vec::with_capacity(wire.spec_refs.len());
        for wire_ref in wire.spec_refs {
            spec_refs.push(PreviewSpecRef::new(
                wire_ref.source,
                wire_ref.path,
                wire_ref.sections,
            )?);
        }
        // The pack accepts a root list that repeats one document; merge the
        // sections instead of refusing a document it accepted, and keep first
        // declaration order. The root list may be empty in the format: H4's rule
        // that every Task declares a non-empty spec reference subset is enforced
        // per Task, so an empty root fails there with an accurate reason instead
        // of here with a reason the pack never produced.
        let spec_refs = merge_refs(spec_refs);

        if wire.tasks.is_empty() {
            return Err(invalid_plan("the plan declares no Task"));
        }
        let mut tasks = Vec::with_capacity(wire.tasks.len());
        for (index, wire_task) in wire.tasks.into_iter().enumerate() {
            let expected_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
            tasks.push(validate_task(
                source,
                expected_number,
                wire_task,
                &spec_refs,
            )?);
        }
        let final_check_ids = wire.final_checks;
        let last_task = tasks.last().expect("at least one Task");
        for id in &final_check_ids {
            if id.trim().is_empty() {
                return Err(invalid_plan("finalChecks must not contain empty ids"));
            }
            if !last_task.checks.iter().any(|check| check.id() == id) {
                return Err(invalid_plan(format!(
                    "finalChecks names {id:?}, which is not a check of the last Task"
                )));
            }
        }

        let parsed_tasks: Vec<ParsedPlanTask> =
            tasks.iter().map(|task| task.parsed().clone()).collect();
        let parsed = ParsedPlanSummary::new(
            wire.schema_version,
            constraints_text.clone(),
            parsed_tasks,
            final_check_ids.clone(),
        )?;
        let inspected = InspectedPlan::new(wire.digest, wire.byte_length, parsed, source)?;

        Ok(Self {
            plan_path: wire.plan_path,
            header: PlanHeaderFacts {
                range: header_range,
                goal: wire.header.goal,
                architecture: wire.header.architecture,
                tech_stack: wire.header.tech_stack,
                spec: wire.header.spec,
            },
            global_constraints: constraints_text,
            global_constraints_heading: heading_range,
            global_constraints_body: body_range,
            execution_block: ExecutionBlockFacts {
                info: wire.execution_block.info,
                range: block_range,
                content_range,
            },
            spec_refs,
            tasks,
            final_check_ids,
            inspected,
        })
    }

    /// Approved project-relative plan path.
    pub fn plan_path(&self) -> &PlanPath {
        &self.plan_path
    }

    /// Digest of the exact inspected bytes.
    pub fn digest(&self) -> &PlanDigest {
        self.inspected.digest()
    }

    /// Exact byte length.
    pub const fn byte_length(&self) -> u64 {
        self.inspected.byte_length()
    }

    /// Parsed header facts.
    pub fn header(&self) -> &PlanHeaderFacts {
        &self.header
    }

    /// Verbatim Global Constraints body with its exact byte range.
    pub fn global_constraints(&self) -> &ExactPlanText {
        &self.global_constraints
    }

    /// Byte range of the `## Global Constraints` heading line.
    pub const fn global_constraints_heading(&self) -> PlanByteRange {
        self.global_constraints_heading
    }

    /// Byte range of the Global Constraints body.
    pub const fn global_constraints_body(&self) -> PlanByteRange {
        self.global_constraints_body
    }

    /// The one execution block.
    pub fn execution_block(&self) -> &ExecutionBlockFacts {
        &self.execution_block
    }

    /// Root spec references.
    pub fn spec_refs(&self) -> &[PreviewSpecRef] {
        &self.spec_refs
    }

    /// Parsed Tasks in plan order.
    pub fn tasks(&self) -> &[PreviewTask] {
        &self.tasks
    }

    /// Final check identifiers of the last Task.
    pub fn final_check_ids(&self) -> &[String] {
        &self.final_check_ids
    }

    /// The parsed summary an approval binds.
    pub fn parsed(&self) -> &ParsedPlanSummary {
        self.inspected.parsed()
    }

    /// The inspector result an approval stores.
    pub fn inspected(&self) -> &InspectedPlan {
        &self.inspected
    }

    /// Consumes the preview into the inspector result an approval stores.
    pub fn into_inspected(self) -> InspectedPlan {
        self.inspected
    }
}

fn checked_range(
    field: &str,
    range: PlanByteRange,
    length: u64,
) -> Result<PlanByteRange, SddExecutionError> {
    // `PlanByteRange` is deserialized from the response, so the ordering
    // invariant `new` enforces is re-established here before any slicing.
    if range.end() < range.start() {
        return Err(unavailable(
            RESPONSE_FEATURE,
            format!("{field} ends before it starts"),
        ));
    }
    if range.end() > length {
        return Err(unavailable(
            RESPONSE_FEATURE,
            format!(
                "{field} ends at {} but the exact input is {length} bytes",
                range.end()
            ),
        ));
    }
    Ok(range)
}

fn exact_slice(source: &[u8], range: PlanByteRange) -> Result<&str, SddExecutionError> {
    let start = usize::try_from(range.start())
        .map_err(|_| unavailable(RESPONSE_FEATURE, "a byte range offset does not fit"))?;
    let end = usize::try_from(range.end())
        .map_err(|_| unavailable(RESPONSE_FEATURE, "a byte range offset does not fit"))?;
    std::str::from_utf8(&source[start..end]).map_err(|error| {
        unavailable(
            RESPONSE_FEATURE,
            format!("a reported byte range does not fall on UTF-8 boundaries: {error}"),
        )
    })
}

/// Merges repeated `(source, path)` declarations, keeping first-declaration
/// order and de-duplicating the sections.
fn merge_refs(refs: Vec<PreviewSpecRef>) -> Vec<PreviewSpecRef> {
    let mut merged: Vec<PreviewSpecRef> = Vec::with_capacity(refs.len());
    for spec_ref in refs {
        match merged
            .iter_mut()
            .find(|existing| existing.source == spec_ref.source && existing.path == spec_ref.path)
        {
            Some(existing) => {
                for section in spec_ref.sections {
                    if !existing.sections.contains(&section) {
                        existing.sections.push(section);
                    }
                }
            }
            None => merged.push(spec_ref),
        }
    }
    merged
}

fn validate_task(
    source: &[u8],
    expected_number: u32,
    wire: WireTask,
    root_refs: &[PreviewSpecRef],
) -> Result<PreviewTask, SddExecutionError> {
    let length = source.len() as u64;
    if wire.number != expected_number {
        return Err(invalid_plan(format!(
            "Task numbers must be contiguous from one; Task {expected_number} is numbered {}",
            wire.number
        )));
    }
    if wire.title.trim().is_empty() {
        return Err(invalid_plan(format!(
            "Task {} has an empty title",
            wire.number
        )));
    }
    let heading_range = checked_range("task.headingRange", wire.heading_range, length)?;
    let body_range = checked_range("task.bodyRange", wire.body_range, length)?;
    if heading_range.start() >= body_range.start() || heading_range.end() > body_range.start() {
        return Err(invalid_plan(format!(
            "Task {} has a heading range that does not precede its body",
            wire.number
        )));
    }
    let heading_slice = exact_slice(source, heading_range)?;
    if heading_slice != wire.heading_text {
        return Err(unavailable(
            RESPONSE_FEATURE,
            format!(
                "Task {} heading text is not the exact bytes of its range",
                wire.number
            ),
        ));
    }
    if !heading_slice.starts_with("## Task ") {
        return Err(unavailable(
            RESPONSE_FEATURE,
            format!(
                "Task {} heading range does not start with '## Task '",
                wire.number
            ),
        ));
    }
    let body_slice = exact_slice(source, body_range)?;
    if body_slice != wire.body_text {
        return Err(unavailable(
            RESPONSE_FEATURE,
            format!(
                "Task {} body text is not the exact bytes of its range",
                wire.number
            ),
        ));
    }
    if body_slice.trim().is_empty() {
        return Err(invalid_plan(format!(
            "Task {} has an empty body",
            wire.number
        )));
    }
    let parsed = ParsedPlanTask::new(
        wire.number,
        wire.title.clone(),
        ExactPlanText::new(wire.body_text.clone(), body_range)?,
    )?;

    let mut depends_on = Vec::with_capacity(wire.depends_on.len());
    let mut seen = BTreeSet::new();
    for number in wire.depends_on {
        if number == 0 || number >= wire.number {
            return Err(invalid_plan(format!(
                "Task {} depends on Task {number}, which is not an earlier Task",
                wire.number
            )));
        }
        if !seen.insert(number) {
            return Err(invalid_plan(format!(
                "Task {} repeats dependency {number}",
                wire.number
            )));
        }
        depends_on.push(number);
    }

    let mut spec_refs = Vec::with_capacity(wire.spec_refs.len());
    for wire_ref in wire.spec_refs {
        let spec_ref = PreviewSpecRef::new(wire_ref.source, wire_ref.path, wire_ref.sections)?;
        let root = root_refs
            .iter()
            .find(|root| root.source == spec_ref.source && root.path == spec_ref.path);
        let Some(root) = root else {
            return Err(invalid_plan(format!(
                "Task {} references spec {:?} {:?}, which the root does not declare",
                wire.number, spec_ref.source, spec_ref.path
            )));
        };
        for section in &spec_ref.sections {
            if !root.sections.contains(section) {
                return Err(invalid_plan(format!(
                    "Task {} applies section {:?} of {:?}, which the root declaration does not name",
                    wire.number, section, spec_ref.path
                )));
            }
        }
        spec_refs.push(spec_ref);
    }
    if spec_refs.is_empty() {
        return Err(invalid_plan(format!(
            "Task {} declares no spec reference",
            wire.number
        )));
    }
    let spec_refs = merge_refs(spec_refs);

    if wire.read_paths.is_empty() {
        return Err(invalid_plan(format!(
            "Task {} declares no read path",
            wire.number
        )));
    }
    for path in &wire.read_paths {
        validate_project_path("task.readPaths", path)?;
    }
    for path in &wire.write_paths {
        validate_project_path("task.writePaths", path)?;
    }
    for path in &wire.html_targets {
        validate_project_path("task.htmlTargets", path)?;
    }
    if wire.commit_policy == CommitPolicy::NoChange && !wire.write_paths.is_empty() {
        return Err(invalid_plan(format!(
            "Task {} is no_change but declares a write path",
            wire.number
        )));
    }

    let mut deliverables = Vec::with_capacity(wire.deliverables.len());
    for deliverable in wire.deliverables {
        deliverables.push(ApprovedDeliverable::new(
            deliverable.path,
            deliverable.kind,
        )?);
    }

    if wire.conditions.is_empty() {
        return Err(invalid_plan(format!(
            "Task {} declares no condition",
            wire.number
        )));
    }
    let mut condition_ids = BTreeSet::new();
    let mut conditions = Vec::with_capacity(wire.conditions.len());
    for condition in wire.conditions {
        if !condition_ids.insert(condition.id.clone()) {
            return Err(invalid_plan(format!(
                "Task {} repeats condition id {:?}",
                wire.number, condition.id
            )));
        }
        conditions.push(ApprovedCondition::new(
            condition.id,
            condition.title,
            condition.rubric,
            condition.mode,
        )?);
    }

    let mut check_ids = BTreeSet::new();
    let mut checks = Vec::with_capacity(wire.checks.len());
    for check in wire.checks {
        if !check_ids.insert(check.id.clone()) {
            return Err(invalid_plan(format!(
                "Task {} repeats check id {:?}",
                wire.number, check.id
            )));
        }
        let Some(condition) = conditions
            .iter()
            .find(|condition| condition.id() == check.condition_id)
        else {
            return Err(invalid_plan(format!(
                "Task {} check {:?} references unknown condition {:?}",
                wire.number, check.id, check.condition_id
            )));
        };
        if condition.mode() == ConditionMode::Assessment {
            return Err(invalid_plan(format!(
                "Task {} check {:?} names an assessment condition, so its command would be ignored",
                wire.number, check.id
            )));
        }
        if !check.timeout_seconds.is_finite() || check.timeout_seconds <= 0.0 {
            return Err(invalid_plan(format!(
                "Task {} check {:?} needs a positive finite timeout",
                wire.number, check.id
            )));
        }
        if check.cwd != "." {
            validate_check_cwd(&check.cwd)?;
        }
        // Round up: a fractional approved timeout is never shortened.
        let seconds = check.timeout_seconds.ceil();
        if seconds > u64::MAX as f64 {
            return Err(invalid_plan(format!(
                "Task {} check {:?} timeout is too large",
                wire.number, check.id
            )));
        }
        checks.push(ApprovedCheck::new(
            check.id,
            check.condition_id,
            check.description,
            check.command,
            check.cwd,
            seconds as u64,
            check.input_paths,
        )?);
    }
    for condition in &conditions {
        if condition.mode() == ConditionMode::Checks
            && !checks
                .iter()
                .any(|check| check.condition_id() == condition.id())
        {
            return Err(invalid_plan(format!(
                "Task {} condition {:?} is checks mode but has no check",
                wire.number,
                condition.id()
            )));
        }
    }

    Ok(PreviewTask {
        parsed,
        depends_on,
        spec_refs,
        read_paths: wire.read_paths,
        write_paths: wire.write_paths,
        allow_shell: wire.allow_shell,
        deliverables,
        conditions,
        checks,
        html_targets: wire.html_targets,
        commit_policy: wire.commit_policy,
        heading_range,
        heading_text: wire.heading_text,
    })
}

/// Validates a spec source: `project`, or a registered read-only alias.
pub fn validate_source_alias(source: &str) -> Result<(), SddExecutionError> {
    if source == "project" {
        return Ok(());
    }
    let bytes = source.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(invalid(
            "specRef.source",
            format!("{source:?} is neither project nor a valid read-only alias"),
        ))
    }
}

// ---------------------------------------------------------------------------
// Source layout and confinement
// ---------------------------------------------------------------------------

/// One human-approved read-only external source root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasRoot {
    alias: String,
    absolute_root: String,
    read_paths: Vec<String>,
}

impl AliasRoot {
    /// Creates an alias root. `absolute_root` must already be canonical.
    pub fn new(
        alias: impl Into<String>,
        absolute_root: impl Into<String>,
        read_paths: Vec<String>,
    ) -> Result<Self, SddExecutionError> {
        let alias = alias.into();
        validate_source_alias(&alias)?;
        if alias == "project" {
            return Err(invalid(
                "source.alias",
                "the reserved source name project is not an alias",
            ));
        }
        let absolute_root = absolute_root.into();
        if !std::path::Path::new(&absolute_root).is_absolute() {
            return Err(invalid("source.absoluteRoot", "must be an absolute path"));
        }
        if read_paths.is_empty() {
            return Err(invalid("source.readPaths", "must not be empty"));
        }
        for path in &read_paths {
            validate_read_grant("source.readPaths", path)?;
        }
        Ok(Self {
            alias,
            absolute_root: trim_trailing_slash(absolute_root),
            read_paths,
        })
    }

    /// Registered alias.
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// Approved canonical read-only root.
    pub fn absolute_root(&self) -> &str {
        &self.absolute_root
    }

    /// Bounded paths the alias may be read through.
    pub fn read_paths(&self) -> &[String] {
        &self.read_paths
    }

    fn grants(&self, path: &str) -> bool {
        self.read_paths
            .iter()
            .any(|granted| path_granted(granted, path))
    }
}

/// The project root plus every alias a human approved for read-only access.
///
/// Roots must be canonical absolute paths: this value performs no I/O, so the
/// caller canonicalizes once and this type compares strings. A relative or
/// non-canonical root would weaken [`SourceLayout::confine`], which is why
/// [`SourceLayout::new`] refuses a relative path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLayout {
    project_root: String,
    aliases: BTreeMap<String, AliasRoot>,
}

impl SourceLayout {
    /// Creates a layout for one canonical project root.
    pub fn new(project_root: impl Into<String>) -> Result<Self, SddExecutionError> {
        let project_root = project_root.into();
        if !std::path::Path::new(&project_root).is_absolute() {
            return Err(invalid("projectRoot", "must be an absolute path"));
        }
        Ok(Self {
            project_root: trim_trailing_slash(project_root),
            aliases: BTreeMap::new(),
        })
    }

    /// Builds a layout from the human-approved external sources of one approval.
    ///
    /// This is the only path Task 13 needs: an alias exists here exactly when a
    /// human approved it. The approval's `digest` is not consulted; the read
    /// rules are its alias, root, and read paths, and the current bytes are
    /// captured afresh as this preview's snapshot.
    pub fn from_approvals(
        project_root: impl Into<String>,
        sources: &[crate::approval::ExternalSourceApproval],
    ) -> Result<Self, SddExecutionError> {
        let mut layout = Self::new(project_root)?;
        for source in sources {
            layout = layout.with_alias(
                source.alias(),
                source.absolute_root(),
                source.read_paths().to_vec(),
            )?;
        }
        Ok(layout)
    }

    /// Adds one approved alias root.
    pub fn with_alias(
        mut self,
        alias: impl Into<String>,
        absolute_root: impl Into<String>,
        read_paths: Vec<String>,
    ) -> Result<Self, SddExecutionError> {
        let root = AliasRoot::new(alias, absolute_root, read_paths)?;
        if self.aliases.insert(root.alias.clone(), root).is_some() {
            return Err(invalid("source.alias", "aliases must be unique"));
        }
        Ok(self)
    }

    /// Canonical project root.
    pub fn project_root(&self) -> &str {
        &self.project_root
    }

    /// Approved aliases.
    pub fn aliases(&self) -> impl Iterator<Item = &AliasRoot> {
        self.aliases.values()
    }

    /// Looks up one alias.
    pub fn alias(&self, alias: &str) -> Option<&AliasRoot> {
        self.aliases.get(alias)
    }

    /// Resolves one declared reference to a lexical absolute path.
    ///
    /// Lexical only: absolute paths, `..`, and unknown aliases are refused
    /// here. A symlink escape is refused by [`Self::confine`] once the caller
    /// has canonicalized the file it read.
    pub fn resolve(&self, spec_ref: &PreviewSpecRef) -> Result<ResolvedSource, SddExecutionError> {
        self.resolve_key(&spec_ref.source, &spec_ref.path)
    }

    /// Resolves one `(source, path)` pair without a section list.
    pub fn resolve_key(
        &self,
        source: &str,
        path: &str,
    ) -> Result<ResolvedSource, SddExecutionError> {
        validate_source_alias(source)?;
        validate_project_path("specRef.path", path)?;
        let root = if source == "project" {
            self.project_root.clone()
        } else {
            let alias = self.aliases.get(source).ok_or_else(|| {
                invalid_plan(format!(
                    "spec reference source {source:?} is not a human-approved read-only alias"
                ))
            })?;
            if !alias.grants(path) {
                return Err(invalid_plan(format!(
                    "spec reference {source:?} {path:?} is outside the approved read paths of that alias"
                )));
            }
            alias.absolute_root.clone()
        };
        Ok(ResolvedSource {
            source: source.to_owned(),
            relative: path.to_owned(),
            root,
        })
    }

    /// Refuses a canonical path that is not inside the resolved root.
    ///
    /// This is the symlink-escape check: the caller canonicalizes the file it
    /// is about to read, and this method proves the real path stays under the
    /// approved root (the root itself, or a path below it).
    pub fn confine(
        &self,
        resolved: &ResolvedSource,
        canonical_path: &str,
    ) -> Result<(), SddExecutionError> {
        let root = resolved.root.as_str();
        let inside = canonical_path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/') && !rest.trim_end_matches('/').is_empty());
        if inside {
            Ok(())
        } else {
            Err(invalid_plan(format!(
                "spec reference {:?} {:?} resolves outside its approved root",
                resolved.source, resolved.relative
            )))
        }
    }
}

/// One resolved (lexical) spec reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSource {
    source: String,
    relative: String,
    root: String,
}

impl ResolvedSource {
    /// Declared source.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Reference path, relative to the root.
    pub fn relative(&self) -> &str {
        &self.relative
    }

    /// Canonical root the path must stay under.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Lexical absolute path the caller reads.
    pub fn absolute_path(&self) -> String {
        format!("{}/{}", self.root, self.relative)
    }
}

fn trim_trailing_slash(mut value: String) -> String {
    while value.len() > 1 && value.ends_with('/') {
        value.pop();
    }
    value
}

fn validate_read_grant(field: &str, value: &str) -> Result<(), SddExecutionError> {
    if value.trim().is_empty() {
        return Err(invalid(field, "must not be empty"));
    }
    if value == "." || value == "*" || value == "**" {
        return Err(invalid(field, "an unbounded grant is not allowed"));
    }
    // A grant may contain single-component `*` wildcards; every other rule is
    // the normalized project path rule.
    for component in value.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(invalid(
                field,
                "must not contain '.', '..', or empty components",
            ));
        }
        if component.contains('\\') || component.chars().any(char::is_control) {
            return Err(invalid(
                field,
                "must not contain control characters or backslashes",
            ));
        }
        if component.matches('*').count() > 0 && component.matches('*').count() < component.len() {
            return Err(invalid(
                field,
                "a wildcard must be one whole path component",
            ));
        }
        if component.matches("**").count() > 0 {
            return Err(invalid(field, "a '**' wildcard is not allowed"));
        }
    }
    Ok(())
}

/// Whether an approved read path covers one reference path.
///
/// Matching is exact component for component, and a `*` component matches
/// exactly one component. An approved grant therefore never covers more than a
/// human approved: `docs/spec.md` covers only itself, `docs/*` covers exactly
/// the files and directories directly below `docs`, and neither widens to a
/// deeper subtree. A wider send range needs a wider explicit grant.
fn path_granted(granted: &str, path: &str) -> bool {
    let grant_parts: Vec<&str> = granted.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
    grant_parts.len() == path_parts.len()
        && grant_parts
            .iter()
            .zip(path_parts.iter())
            .all(|(grant, actual)| *grant == "*" || grant == actual)
}

// ---------------------------------------------------------------------------
// Spec and source snapshots
// ---------------------------------------------------------------------------

/// Exact bytes read from one spec/source file, with the real path the reader
/// canonicalized.
///
/// The reader produces this; the verification below never reads a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSnapshot {
    source: String,
    path: String,
    canonical_path: String,
    bytes: Vec<u8>,
}

impl SourceSnapshot {
    /// Creates one read snapshot.
    pub fn new(
        source: impl Into<String>,
        path: impl Into<String>,
        canonical_path: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<Self, SddExecutionError> {
        let canonical_path = canonical_path.into();
        if !std::path::Path::new(&canonical_path).is_absolute() {
            return Err(invalid(
                "sourceSnapshot.canonicalPath",
                "must be the absolute path the reader opened",
            ));
        }
        if bytes.is_empty() {
            return Err(invalid("sourceSnapshot.bytes", "must not be empty"));
        }
        if bytes.len() as u64 > MAX_SPEC_SNAPSHOT_BYTES {
            return Err(unavailable(
                OVERSIZE_SNAPSHOT_FEATURE,
                format!(
                    "a source snapshot is {} bytes; the maximum is {MAX_SPEC_SNAPSHOT_BYTES}",
                    bytes.len()
                ),
            ));
        }
        Ok(Self {
            source: source.into(),
            path: path.into(),
            canonical_path,
            bytes,
        })
    }

    /// Declared source.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Declared path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Canonical path the reader opened.
    pub fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    /// Exact bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// One resolved Markdown section of a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionSnapshot {
    heading: String,
    level: u8,
    heading_range: PlanByteRange,
    body_range: PlanByteRange,
    text: String,
}

impl SectionSnapshot {
    /// Heading text without the `#` markers.
    pub fn heading(&self) -> &str {
        &self.heading
    }

    /// Heading level, 1-6.
    pub const fn level(&self) -> u8 {
        self.level
    }

    /// Byte range of the heading line.
    pub const fn heading_range(&self) -> PlanByteRange {
        self.heading_range
    }

    /// Byte range of the section body, below the heading.
    pub const fn body_range(&self) -> PlanByteRange {
        self.body_range
    }

    /// Exact body text.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// One verified spec/source snapshot: exact bytes, digest, and the applied
/// sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSpecSnapshot {
    source: String,
    path: String,
    canonical_path: String,
    digest: Sha256Digest,
    bytes: Vec<u8>,
    sections: Vec<SectionSnapshot>,
}

impl VerifiedSpecSnapshot {
    /// `project` or the approved alias.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Declared path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Canonical path the reader opened, proven to be inside its root.
    pub fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    /// Digest of the exact snapshot bytes.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// Exact snapshot bytes at the observed revision.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Applied sections in declaration order.
    pub fn sections(&self) -> &[SectionSnapshot] {
        &self.sections
    }

    /// Applied section headings, for an [`crate::approval::ApprovedSpecRef`].
    pub fn section_headings(&self) -> Vec<String> {
        self.sections
            .iter()
            .map(|section| section.heading.clone())
            .collect()
    }

    /// The approved spec reference this snapshot justifies.
    ///
    /// The digest is the snapshot's exact-byte digest, so the approval binds the
    /// revision the human saw instead of a later re-read.
    pub fn approved_spec_ref(&self) -> Result<crate::approval::ApprovedSpecRef, SddExecutionError> {
        crate::approval::ApprovedSpecRef::new(
            self.source.clone(),
            self.path.clone(),
            self.section_headings(),
            self.digest.clone(),
        )
    }
}

/// The verified snapshot set one preview binds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpecSnapshotSet {
    snapshots: Vec<VerifiedSpecSnapshot>,
}

impl SpecSnapshotSet {
    /// Verified snapshots in first-declaration order.
    pub fn snapshots(&self) -> &[VerifiedSpecSnapshot] {
        &self.snapshots
    }

    /// Finds one snapshot.
    pub fn find(&self, source: &str, path: &str) -> Option<&VerifiedSpecSnapshot> {
        self.snapshots
            .iter()
            .find(|snapshot| snapshot.source == source && snapshot.path == path)
    }

    /// Total exact bytes the snapshots carry.
    pub fn total_bytes(&self) -> u64 {
        self.snapshots
            .iter()
            .map(|snapshot| snapshot.bytes.len() as u64)
            .sum()
    }

    /// A deterministic digest for one approved external alias.
    ///
    /// Task 13 stores one `ExternalSourceApproval` per alias, and one alias may
    /// carry several files. This value binds the alias name and every verified
    /// `(path, file digest)` pair in sorted path order, so the approval is
    /// stable regardless of the order the plan declared them in and changes when
    /// any one file changes.
    pub fn alias_digest(&self, alias: &str) -> Option<Sha256Digest> {
        let mut entries: Vec<(&str, &Sha256Digest)> = self
            .snapshots
            .iter()
            .filter(|snapshot| snapshot.source == alias)
            .map(|snapshot| (snapshot.path.as_str(), &snapshot.digest))
            .collect();
        if entries.is_empty() {
            return None;
        }
        entries.sort_by(|left, right| left.0.cmp(right.0));
        let mut buffer = format!("herness.h4.spec-source\0{alias}\0").into_bytes();
        for (path, digest) in entries {
            buffer.extend_from_slice(path.as_bytes());
            buffer.push(0);
            buffer.extend_from_slice(digest.as_str().as_bytes());
            buffer.push(0);
        }
        Some(Sha256Digest::sha256(&buffer))
    }
}

/// Verifies every declared root spec reference against the supplied snapshots.
///
/// For each distinct `(source, path)` the caller must supply exactly one
/// snapshot. The rules are:
///
/// * the source is `project` or an alias present in the layout;
/// * for an alias, the path is inside that alias's approved read paths;
/// * the canonical path the reader opened stays under the resolved root, so a
///   symlink cannot escape;
/// * the bytes are valid UTF-8 Markdown;
/// * every declared section resolves to exactly one unique heading, so a
///   missing or ambiguous heading is refused instead of guessed;
/// * the exact bytes and their SHA-256 digest are captured for the packet.
pub fn verify_spec_snapshots(
    layout: &SourceLayout,
    refs: &[PreviewSpecRef],
    snapshots: &[SourceSnapshot],
) -> Result<SpecSnapshotSet, SddExecutionError> {
    // Merge the declared sections per document, in first-declaration order.
    let mut order: Vec<(String, String)> = Vec::new();
    let mut wanted: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for spec_ref in refs {
        let key = (spec_ref.source.clone(), spec_ref.path.clone());
        let entry = wanted.entry(key.clone()).or_insert_with(|| {
            order.push(key);
            Vec::new()
        });
        for section in &spec_ref.sections {
            if !entry.contains(section) {
                entry.push(section.clone());
            }
        }
    }

    let mut consumed = BTreeSet::new();
    let mut verified = Vec::with_capacity(order.len());
    for key in order {
        let resolved = layout.resolve_key(&key.0, &key.1)?;
        let position = snapshots
            .iter()
            .position(|snapshot| snapshot.source == key.0 && snapshot.path == key.1)
            .ok_or_else(|| {
                invalid_plan(format!(
                    "spec reference {:?} {:?} has no source snapshot",
                    key.0, key.1
                ))
            })?;
        if !consumed.insert(position) {
            return Err(invalid_plan(format!(
                "spec reference {:?} {:?} has more than one snapshot",
                key.0, key.1
            )));
        }
        let snapshot = &snapshots[position];
        layout.confine(&resolved, &snapshot.canonical_path)?;
        let text = std::str::from_utf8(&snapshot.bytes).map_err(|error| {
            invalid_plan(format!(
                "spec reference {:?} {:?} is not valid UTF-8: {error}",
                key.0, key.1
            ))
        })?;
        let headings = markdown_headings(text)?;
        let requested = wanted
            .get(&(key.0.clone(), key.1.clone()))
            .expect("a merged section list");
        let mut sections = Vec::with_capacity(requested.len());
        for name in requested {
            let matches: Vec<&RawHeading> = headings
                .iter()
                .filter(|heading| heading.text == name.as_str())
                .collect();
            match matches.as_slice() {
                [] => {
                    return Err(invalid_plan(format!(
                        "spec reference {:?} {:?} names section {:?}, which the snapshot does not contain",
                        key.0, key.1, name
                    )));
                }
                [heading] => sections.push(section_of(text, heading)?),
                _ => {
                    return Err(invalid_plan(format!(
                        "spec reference {:?} {:?} names section {:?}, which the snapshot contains more than once",
                        key.0, key.1, name
                    )));
                }
            }
        }
        verified.push(VerifiedSpecSnapshot {
            source: key.0,
            path: key.1,
            canonical_path: snapshot.canonical_path.clone(),
            digest: Sha256Digest::sha256(&snapshot.bytes),
            bytes: snapshot.bytes.clone(),
            sections,
        });
    }
    if consumed.len() != snapshots.len() {
        return Err(invalid_plan(
            "a source snapshot was supplied for a reference the plan does not declare",
        ));
    }
    Ok(SpecSnapshotSet {
        snapshots: verified,
    })
}

// ---------------------------------------------------------------------------
// Markdown headings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawHeading {
    level: u8,
    text: String,
    line_start: usize,
    line_end: usize,
    body_end: usize,
}

fn section_of(text: &str, heading: &RawHeading) -> Result<SectionSnapshot, SddExecutionError> {
    let body_start = heading.line_end;
    let body_end = heading.body_end;
    let body = text
        .get(body_start..body_end)
        .ok_or_else(|| invalid_plan("a heading range does not fall on UTF-8 boundaries"))?;
    Ok(SectionSnapshot {
        heading: heading.text.clone(),
        level: heading.level,
        heading_range: PlanByteRange::new(heading.line_start as u64, heading.line_end as u64)?,
        body_range: PlanByteRange::new(body_start as u64, body_end as u64)?,
        text: body.to_owned(),
    })
}

/// Scans ATX headings outside fenced code blocks.
///
/// A heading is one to six `#` characters after at most three spaces, followed
/// by whitespace or the end of the line. Fenced blocks (` ``` ` or `~~~`) are
/// skipped. Each heading's body runs to the next heading of the same or a
/// higher level, or the end of the document.
fn markdown_headings(text: &str) -> Result<Vec<RawHeading>, SddExecutionError> {
    let bytes = text.as_bytes();
    let mut headings: Vec<RawHeading> = Vec::new();
    let mut fence: Option<(u8, usize)> = None;
    let mut offset = 0usize;
    while offset <= bytes.len() {
        let line_end = bytes[offset..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| offset + index)
            .unwrap_or(bytes.len());
        let mut content_end = line_end;
        if content_end > offset && bytes[content_end - 1] == b'\r' {
            content_end -= 1;
        }
        let line = &text[offset..content_end];
        if let Some((marker, count)) = fence {
            let trimmed = line.trim_start_matches(' ');
            let leading = line.len() - trimmed.len();
            if leading <= 3 {
                let run = trimmed.bytes().take_while(|byte| *byte == marker).count();
                if run >= count && trimmed[run..].trim().is_empty() {
                    fence = None;
                }
            }
        } else if let Some((marker, count)) = fence_open(line) {
            fence = Some((marker, count));
        } else if let Some((level, heading_text)) = parse_atx(line) {
            headings.push(RawHeading {
                level,
                text: heading_text,
                line_start: offset,
                line_end: content_end,
                body_end: 0,
            });
        }
        if line_end == bytes.len() {
            break;
        }
        offset = line_end + 1;
    }
    for index in 0..headings.len() {
        let level = headings[index].level;
        let body_end = headings[index + 1..]
            .iter()
            .find(|heading| heading.level <= level)
            .map(|heading| heading.line_start)
            .unwrap_or(bytes.len());
        if body_end < headings[index].line_end {
            return Err(invalid_plan("a heading body ends before its heading"));
        }
        headings[index].body_end = body_end;
    }
    Ok(headings)
}

fn fence_open(line: &str) -> Option<(u8, usize)> {
    let trimmed = line.trim_start_matches(' ');
    let leading = line.len() - trimmed.len();
    if leading > 3 {
        return None;
    }
    let marker = *trimmed.as_bytes().first()?;
    if marker != b'`' && marker != b'~' {
        return None;
    }
    let run = trimmed.bytes().take_while(|byte| *byte == marker).count();
    (run >= 3).then_some((marker, run))
}

fn parse_atx(line: &str) -> Option<(u8, String)> {
    let trimmed = line.trim_start_matches(' ');
    let leading = line.len() - trimmed.len();
    if leading > 3 {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let level = bytes.iter().take_while(|byte| **byte == b'#').count();
    if !(1..=6).contains(&level) || bytes.len() < level {
        return None;
    }
    if bytes
        .get(level)
        .is_some_and(|byte| *byte != b' ' && *byte != b'\t')
    {
        return None;
    }
    let rest = trimmed[level..].trim();
    // A Markdown closing sequence is a run of `#` preceded by whitespace (or the
    // whole rest); a `#` inside the heading text, as in `C#`, is not one.
    let mut text = rest;
    let closing = text.trim_end_matches('#');
    if closing.is_empty() {
        text = "";
    } else if closing.len() != text.len() && closing.ends_with([' ', '\t']) {
        text = closing.trim_end();
    }
    (!text.is_empty()).then(|| (level as u8, text.to_owned()))
}

// ---------------------------------------------------------------------------
// Exact plan bytes helper
// ---------------------------------------------------------------------------

/// Builds the exact `inspect` request bytes for one request.
///
/// The envelope is one JSON object with the protocol identity, the operation,
/// the validated plan path, and canonical base64 of the exact plan bytes. The
/// inspector rejects anything else: no whitespace in the base64, no extra
/// field, no default.
pub fn inspect_request_envelope(request: &InspectRequest) -> Result<Vec<u8>, SddExecutionError> {
    if request.source().len() as u64 > MAX_PLAN_BYTES {
        return Err(unavailable(
            OVERSIZE_PLAN_FEATURE,
            format!(
                "the plan is {} bytes; the maximum is {MAX_PLAN_BYTES}",
                request.source().len()
            ),
        ));
    }
    serde_json::to_vec(&serde_json::json!({
        "protocol": PLAN_INSPECTOR_PROTOCOL,
        "version": PLAN_INSPECTOR_PROTOCOL_VERSION,
        "operation": InspectorOperation::Inspect.as_str(),
        "planPath": request.plan_path().as_str(),
        "sourceBase64": base64_encode(request.source()),
    }))
    .map_err(|error| {
        unavailable(
            RESPONSE_FEATURE,
            format!("cannot encode the request: {error}"),
        )
    })
}
