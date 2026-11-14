//! Plan identity, inspector protocol values, and plan diagnostics.
//!
//! The pack owns the plan parser and the `sdd-plan-inspect` protocol. H4 only
//! carries the resulting identity, the exact Global Constraints text, the byte
//! ranges, and the stable diagnostics so a plan defect is never confused with
//! an unavailable inspector or an H4 contract version.

use std::fmt;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::error::SddExecutionError;
use crate::version::{
    MAX_PLAN_BYTES, PLAN_EXECUTION_BLOCK_INFO, PLAN_INSPECTOR_PROTOCOL,
    PLAN_INSPECTOR_PROTOCOL_VERSION, PLAN_PATH_PREFIX, PLAN_SCHEMA_NAME, PLAN_SCHEMA_VERSION,
    PackFingerprint, PlanDigest,
};

/// A canonical project-relative plan path under `docs/sdd/plans/`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanPath(String);

impl PlanPath {
    /// Validates a plan path.
    ///
    /// The path must start with `docs/sdd/plans/`, name one Markdown file
    /// directly below it, use `/` separators, and contain no `.` or `..`
    /// component.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, SddExecutionError> {
        let value = value.as_ref().trim();
        let invalid = |detail: &str| SddExecutionError::InvalidValue {
            field: "planPath".to_owned(),
            detail: detail.to_owned(),
        };
        if value.is_empty() {
            return Err(invalid("must not be empty"));
        }
        if value.starts_with('/') || value.contains('\\') {
            return Err(invalid("must be project-relative with '/' separators"));
        }
        if value.contains('\0') || value.chars().any(char::is_control) {
            return Err(invalid("must not contain control characters"));
        }
        let rest = value
            .strip_prefix(PLAN_PATH_PREFIX)
            .ok_or_else(|| invalid("must be below docs/sdd/plans/"))?;
        if rest.is_empty() || rest.contains('/') {
            return Err(invalid(
                "must name one Markdown file directly below docs/sdd/plans/",
            ));
        }
        if !rest.ends_with(".md") || rest == ".md" {
            return Err(invalid("must end with '.md'"));
        }
        for component in value.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(invalid("must not contain '.', '..', or empty components"));
            }
        }
        Ok(Self(value.to_owned()))
    }

    /// The validated project-relative path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PlanPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A half-open `[start, end)` byte range over the exact plan input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanByteRange {
    start: u64,
    end: u64,
}

impl PlanByteRange {
    /// Creates a range. `end` must not precede `start`.
    pub fn new(start: u64, end: u64) -> Result<Self, SddExecutionError> {
        if end < start {
            return Err(SddExecutionError::InvalidValue {
                field: "planByteRange".to_owned(),
                detail: "end must not precede start".to_owned(),
            });
        }
        Ok(Self { start, end })
    }

    /// Inclusive start offset.
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Exclusive end offset.
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Length in bytes.
    pub const fn len(self) -> u64 {
        self.end - self.start
    }

    /// Whether the range is empty.
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// Stable plan diagnostic code returned by the pack parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanDiagnosticCode {
    /// The document does not use the `sdd-execution-v1` format.
    UnsupportedPlanFormat,
    /// The document claims the format but violates its schema.
    InvalidPlan,
}

impl PlanDiagnosticCode {
    /// Stable wire code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlanFormat => "unsupported_plan_format",
            Self::InvalidPlan => "invalid_plan",
        }
    }

    /// Parses a stable wire code. An unknown code returns `None`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unsupported_plan_format" => Some(Self::UnsupportedPlanFormat),
            "invalid_plan" => Some(Self::InvalidPlan),
            _ => None,
        }
    }
}

/// One deterministic plan diagnostic with a byte range into the exact input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanDiagnostic {
    code: PlanDiagnosticCode,
    message: String,
    #[serde(default)]
    pointer: Option<String>,
    #[serde(default)]
    byte_range: Option<PlanByteRange>,
}

impl PlanDiagnostic {
    /// Creates a diagnostic.
    pub fn new(
        code: PlanDiagnosticCode,
        message: impl Into<String>,
        pointer: Option<String>,
        byte_range: Option<PlanByteRange>,
    ) -> Result<Self, SddExecutionError> {
        let message = message.into();
        if message.trim().is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "planDiagnostic.message".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        Ok(Self {
            code,
            message,
            pointer,
            byte_range,
        })
    }

    /// Diagnostic code.
    pub const fn code(&self) -> PlanDiagnosticCode {
        self.code
    }

    /// Non-secret explanation produced by the pack.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// JSON pointer of the offending field, when known.
    pub fn pointer(&self) -> Option<&str> {
        self.pointer.as_deref()
    }

    /// Byte range of the Markdown region that contains the defect.
    pub const fn byte_range(&self) -> Option<PlanByteRange> {
        self.byte_range
    }
}

/// The `sdd-plan-inspect` protocol identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectorProtocol {
    name: String,
    version: u32,
}

impl InspectorProtocol {
    /// Creates a protocol identity.
    pub fn new(name: impl Into<String>, version: u32) -> Result<Self, SddExecutionError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "inspector.protocol".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        if version == 0 {
            return Err(SddExecutionError::InvalidValue {
                field: "inspector.version".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        Ok(Self { name, version })
    }

    /// The protocol this build implements.
    pub fn expected() -> Self {
        Self {
            name: PLAN_INSPECTOR_PROTOCOL.to_owned(),
            version: PLAN_INSPECTOR_PROTOCOL_VERSION,
        }
    }

    /// Protocol name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Protocol version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Rejects a protocol this build does not implement.
    pub fn ensure_current(&self) -> Result<(), SddExecutionError> {
        if self.name == PLAN_INSPECTOR_PROTOCOL && self.version == PLAN_INSPECTOR_PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(SddExecutionError::UnsupportedInspectorProtocol {
                found: format!("{}/{}", self.name, self.version),
                expected: format!("{PLAN_INSPECTOR_PROTOCOL}/{PLAN_INSPECTOR_PROTOCOL_VERSION}"),
            })
        }
    }
}

impl Default for InspectorProtocol {
    fn default() -> Self {
        Self::expected()
    }
}

/// The inspector `capabilities` result H4 binds before importing a plan.
///
/// A capability value with any other schema or protocol version is rejected.
/// The fingerprint is the pack's execution-contract identity, not the H3 HTML
/// policy fingerprint and not an approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectorCapabilities {
    protocol: InspectorProtocol,
    schema_name: String,
    schema_version: u32,
    execution_block_info: String,
    max_plan_bytes: u64,
    plan_path_prefix: String,
    execution_contract: PackFingerprint,
}

impl InspectorCapabilities {
    /// Creates a capability value and rejects an unknown plan version.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: InspectorProtocol,
        schema_name: impl Into<String>,
        schema_version: u32,
        execution_block_info: impl Into<String>,
        max_plan_bytes: u64,
        plan_path_prefix: impl Into<String>,
        execution_contract: PackFingerprint,
    ) -> Result<Self, SddExecutionError> {
        protocol.ensure_current()?;
        if schema_version != PLAN_SCHEMA_VERSION {
            return Err(SddExecutionError::UnsupportedPlanSchemaVersion {
                found: schema_version,
                expected: PLAN_SCHEMA_VERSION,
            });
        }
        let schema_name = schema_name.into();
        if schema_name != PLAN_SCHEMA_NAME {
            return Err(SddExecutionError::InvalidValue {
                field: "inspector.schemaName".to_owned(),
                detail: format!("expected {PLAN_SCHEMA_NAME}"),
            });
        }
        let execution_block_info = execution_block_info.into();
        if execution_block_info != PLAN_EXECUTION_BLOCK_INFO {
            return Err(SddExecutionError::InvalidValue {
                field: "inspector.executionBlockInfo".to_owned(),
                detail: format!("expected {PLAN_EXECUTION_BLOCK_INFO}"),
            });
        }
        if max_plan_bytes != MAX_PLAN_BYTES {
            return Err(SddExecutionError::InvalidValue {
                field: "inspector.maxPlanBytes".to_owned(),
                detail: format!("expected {MAX_PLAN_BYTES}"),
            });
        }
        let plan_path_prefix = plan_path_prefix.into();
        if plan_path_prefix != PLAN_PATH_PREFIX {
            return Err(SddExecutionError::InvalidValue {
                field: "inspector.planPathPrefix".to_owned(),
                detail: format!("expected {PLAN_PATH_PREFIX}"),
            });
        }
        Ok(Self {
            protocol,
            schema_name,
            schema_version,
            execution_block_info,
            max_plan_bytes,
            plan_path_prefix,
            execution_contract,
        })
    }

    /// Protocol identity.
    pub fn protocol(&self) -> &InspectorProtocol {
        &self.protocol
    }

    /// Plan schema name.
    pub fn schema_name(&self) -> &str {
        &self.schema_name
    }

    /// Plan schema version.
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Fenced block info string.
    pub fn execution_block_info(&self) -> &str {
        &self.execution_block_info
    }

    /// Accepted plan byte limit.
    pub const fn max_plan_bytes(&self) -> u64 {
        self.max_plan_bytes
    }

    /// Accepted plan path prefix.
    pub fn plan_path_prefix(&self) -> &str {
        &self.plan_path_prefix
    }

    /// Pack execution-contract fingerprint.
    pub fn execution_contract(&self) -> &PackFingerprint {
        &self.execution_contract
    }
}

/// Exact text plus the byte range it occupied in the plan input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactPlanText {
    text: String,
    byte_range: PlanByteRange,
}

impl ExactPlanText {
    /// Creates exact text. The text must not be empty.
    pub fn new(
        text: impl Into<String>,
        byte_range: PlanByteRange,
    ) -> Result<Self, SddExecutionError> {
        let text = text.into();
        if text.trim().is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "planText.text".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        Ok(Self { text, byte_range })
    }

    /// Verbatim text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Byte range in the exact input.
    pub const fn byte_range(&self) -> PlanByteRange {
        self.byte_range
    }
}

/// One parsed Task summary carried by the approved plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParsedPlanTask {
    number: u32,
    title: String,
    body: ExactPlanText,
}

impl ParsedPlanTask {
    /// Creates a parsed Task summary.
    pub fn new(
        number: u32,
        title: impl Into<String>,
        body: ExactPlanText,
    ) -> Result<Self, SddExecutionError> {
        if number == 0 {
            return Err(SddExecutionError::InvalidValue {
                field: "parsedPlanTask.number".to_owned(),
                detail: "Task numbers start at one".to_owned(),
            });
        }
        let title = title.into();
        if title.trim().is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "parsedPlanTask.title".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        Ok(Self {
            number,
            title,
            body,
        })
    }

    /// Plan-assigned number.
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// Task title from the heading.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Exact Task body.
    pub fn body(&self) -> &ExactPlanText {
        &self.body
    }
}

/// The parsed result the approved plan revision binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParsedPlanSummary {
    schema_version: u32,
    global_constraints: ExactPlanText,
    tasks: Vec<ParsedPlanTask>,
    final_check_ids: Vec<String>,
}

impl ParsedPlanSummary {
    /// Creates a parsed summary and checks contiguous one-based Task numbers.
    pub fn new(
        schema_version: u32,
        global_constraints: ExactPlanText,
        tasks: Vec<ParsedPlanTask>,
        final_check_ids: Vec<String>,
    ) -> Result<Self, SddExecutionError> {
        if schema_version != PLAN_SCHEMA_VERSION {
            return Err(SddExecutionError::UnsupportedPlanSchemaVersion {
                found: schema_version,
                expected: PLAN_SCHEMA_VERSION,
            });
        }
        if tasks.is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "parsedPlan.tasks".to_owned(),
                detail: "must contain at least one Task".to_owned(),
            });
        }
        for (index, task) in tasks.iter().enumerate() {
            let expected = u32::try_from(index + 1).unwrap_or(u32::MAX);
            if task.number != expected {
                return Err(SddExecutionError::InvalidValue {
                    field: "parsedPlan.tasks".to_owned(),
                    detail: "Task numbers must be contiguous from one".to_owned(),
                });
            }
        }
        if final_check_ids.is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "parsedPlan.finalCheckIds".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        for value in &final_check_ids {
            if value.trim().is_empty() {
                return Err(SddExecutionError::InvalidValue {
                    field: "parsedPlan.finalCheckIds".to_owned(),
                    detail: "check identifiers must not be empty".to_owned(),
                });
            }
        }
        Ok(Self {
            schema_version,
            global_constraints,
            tasks,
            final_check_ids,
        })
    }

    /// Parsed schema version.
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Verbatim Global Constraints section.
    pub fn global_constraints(&self) -> &ExactPlanText {
        &self.global_constraints
    }

    /// Parsed Tasks in plan order.
    pub fn tasks(&self) -> &[ParsedPlanTask] {
        &self.tasks
    }

    /// Final check identifiers.
    pub fn final_check_ids(&self) -> &[String] {
        &self.final_check_ids
    }
}

/// One inspector request over the exact plan bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectRequest {
    plan_path: PlanPath,
    source: Vec<u8>,
}

impl InspectRequest {
    /// Creates a request. The exact bytes must be non-empty and at most
    /// [`MAX_PLAN_BYTES`]; a larger input is refused, never truncated.
    pub fn new(plan_path: PlanPath, source: Vec<u8>) -> Result<Self, SddExecutionError> {
        if source.is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "inspect.source".to_owned(),
                detail: "must contain the exact plan bytes".to_owned(),
            });
        }
        if source.len() as u64 > MAX_PLAN_BYTES {
            return Err(SddExecutionError::InvalidValue {
                field: "inspect.source".to_owned(),
                detail: format!(
                    "plan is {} bytes; the maximum is {MAX_PLAN_BYTES}",
                    source.len()
                ),
            });
        }
        Ok(Self { plan_path, source })
    }

    /// Requested plan path.
    pub fn plan_path(&self) -> &PlanPath {
        &self.plan_path
    }

    /// Exact plan bytes.
    pub fn source(&self) -> &[u8] {
        &self.source
    }
}

/// A successful inspector result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectedPlan {
    digest: PlanDigest,
    byte_length: u64,
    parsed: ParsedPlanSummary,
}

impl InspectedPlan {
    /// Creates a result. The digest and byte length must match the exact input.
    pub fn new(
        digest: PlanDigest,
        byte_length: u64,
        parsed: ParsedPlanSummary,
        source: &[u8],
    ) -> Result<Self, SddExecutionError> {
        if byte_length != source.len() as u64 {
            return Err(SddExecutionError::InvalidValue {
                field: "inspectedPlan.byteLength".to_owned(),
                detail: "must equal the exact input length".to_owned(),
            });
        }
        if digest != PlanDigest::sha256(source) {
            return Err(SddExecutionError::InvalidValue {
                field: "inspectedPlan.digest".to_owned(),
                detail: "must be the digest of the exact input".to_owned(),
            });
        }
        Ok(Self {
            digest,
            byte_length,
            parsed,
        })
    }

    /// Exact input digest.
    pub fn digest(&self) -> &PlanDigest {
        &self.digest
    }

    /// Exact input length.
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Parsed result.
    pub fn parsed(&self) -> &ParsedPlanSummary {
        &self.parsed
    }
}

/// Exact plan bytes approved by one human decision.
///
/// The value keeps the bytes the human approved, not a re-read of the file. Its
/// wire form is canonical base64, mirroring the inspector's `sourceBase64`, so
/// a stored approval round-trips byte for byte. Larger input than
/// [`crate::version::MAX_PLAN_BYTES`] is refused, never truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactPlanBytes {
    source: Vec<u8>,
    digest: PlanDigest,
}

impl ExactPlanBytes {
    /// Wraps the exact bytes and computes their digest.
    pub fn new(source: Vec<u8>) -> Result<Self, SddExecutionError> {
        if source.is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "plan.source".to_owned(),
                detail: "must contain the exact plan bytes".to_owned(),
            });
        }
        if source.len() as u64 > MAX_PLAN_BYTES {
            return Err(SddExecutionError::InvalidValue {
                field: "plan.source".to_owned(),
                detail: format!(
                    "plan is {} bytes; the maximum is {MAX_PLAN_BYTES}",
                    source.len()
                ),
            });
        }
        let digest = PlanDigest::sha256(&source);
        Ok(Self { source, digest })
    }

    /// Reconstructs the value from bytes plus a claimed digest, refusing a
    /// mismatch instead of trusting the claim.
    pub fn verify(source: Vec<u8>, digest: PlanDigest) -> Result<Self, SddExecutionError> {
        let value = Self::new(source)?;
        if value.digest != digest {
            return Err(SddExecutionError::InvalidValue {
                field: "plan.digest".to_owned(),
                detail: "must be the digest of the exact plan bytes".to_owned(),
            });
        }
        Ok(value)
    }

    /// Exact bytes.
    pub fn source(&self) -> &[u8] {
        &self.source
    }

    /// Byte length.
    pub fn byte_length(&self) -> u64 {
        self.source.len() as u64
    }

    /// Digest of the exact bytes.
    pub fn digest(&self) -> &PlanDigest {
        &self.digest
    }
}

impl Serialize for ExactPlanBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64_encode(&self.source))
    }
}

impl<'de> Deserialize<'de> for ExactPlanBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let source = base64_decode(&value).map_err(de::Error::custom)?;
        Self::new(source).map_err(de::Error::custom)
    }
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Canonical base64 of exact bytes, as the inspector's `sourceBase64`.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map(u32::from);
        let b2 = chunk.get(2).copied().map(u32::from);
        let triple = (b0 << 16) | (b1.unwrap_or(0) << 8) | b2.unwrap_or(0);
        out.push(BASE64_ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(BASE64_ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        out.push(if b1.is_some() {
            BASE64_ALPHABET[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if b2.is_some() {
            BASE64_ALPHABET[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Decodes canonical base64, refusing padding and character defects.
pub fn base64_decode(value: &str) -> Result<Vec<u8>, String> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 length must be a multiple of four".to_owned());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let last = index + 1 == bytes.len() / 4;
        let mut quad = [0u8; 4];
        let mut padding = 0usize;
        for (slot, byte) in chunk.iter().enumerate() {
            if *byte == b'=' {
                if !last || slot < 2 {
                    return Err("unexpected base64 padding".to_owned());
                }
                padding += 1;
                quad[slot] = 0;
                continue;
            }
            if padding > 0 {
                return Err("base64 padding must be at the end".to_owned());
            }
            quad[slot] = BASE64_ALPHABET
                .iter()
                .position(|candidate| candidate == byte)
                .ok_or_else(|| "base64 contains an invalid character".to_owned())?
                as u8;
        }
        let triple = (u32::from(quad[0]) << 18)
            | (u32::from(quad[1]) << 12)
            | (u32::from(quad[2]) << 6)
            | u32::from(quad[3]);
        out.push((triple >> 16) as u8);
        if padding < 2 {
            out.push((triple >> 8) as u8);
        }
        if padding < 1 {
            out.push(triple as u8);
        }
    }
    Ok(out)
}

/// Validates a normalized project-relative path.
///
/// Absolute paths, `..`, `.`, empty components, and the unbounded `.`/`*`
/// scopes are rejected. The check is lexical; the pack and H2 own any stronger
/// resolution.
pub fn validate_project_path(field: &str, path: &str) -> Result<(), SddExecutionError> {
    let invalid = |detail: &str| SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.to_owned(),
    };
    if path.trim().is_empty() {
        return Err(invalid("must not be empty"));
    }
    if path == "." || path == "*" || path == "/" || path == "./" {
        return Err(invalid("an unbounded or root path is not allowed"));
    }
    if path.starts_with('/') || path.contains('\\') {
        return Err(invalid("must be project-relative with '/' separators"));
    }
    if path.contains('\0') || path.chars().any(char::is_control) {
        return Err(invalid("must not contain control characters"));
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(invalid("must not contain '.', '..', or empty components"));
        }
    }
    Ok(())
}

/// Validates a check `cwd`: `.` or a normalized project-relative directory.
pub fn validate_check_cwd(path: &str) -> Result<(), SddExecutionError> {
    if path == "." {
        Ok(())
    } else {
        validate_project_path("check.cwd", path)
    }
}
