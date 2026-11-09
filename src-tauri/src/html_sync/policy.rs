//! Explicit Common SDD policy bridge for H3.
//!
//! The bridge discovers the pack with [`herness_core::SkillPack`] and Python with
//! the existing [`herness_core::ToolchainDetector`]. It then invokes
//! `scripts/html-docs host-api` as an argv array with one JSON request on
//! stdin, in the project-root working directory. There is no shell string, no
//! file write, no HTML creation, no model call, and no external network path in
//! this module.
//!
//! The bridge is type-separated:
//!
//! * [`HtmlPolicyBridge`] is only discovery metadata (pack, Python, validator).
//!   It cannot call an operation.
//! * [`HtmlPolicyBridge::connect`] verifies the pack fingerprint, integration
//!   version, policy fingerprint, and host-API version against an approved
//!   [`H3PackBinding`], then invokes `capabilities` once and caches it.
//! * [`ConnectedPolicyBridge`] is the only type with `discover`, `source-units`,
//!   and `candidate-check` methods.
//!
//! An old or unknown pack, invalid metadata/JSON, timeout, process failure, or
//! missing capability is an explicit [`PolicyBridgeError`] unavailable result.
//! It is never reported as "missing approval" and never silently bootstraps a
//! companion.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use herness_core::{SkillPack, ToolchainConfig, ToolchainDetector};
use herness_html_sync::config::{
    H3PackBinding, HOST_API_PROTOCOL, HOST_API_VERSION, PACK_INTEGRATION_HOST,
    PACK_INTEGRATION_SCHEMA, PACK_POLICY_VERSION,
};
use herness_supervision::ContentDigest;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

/// Required host-API operations.
pub const REQUIRED_OPERATIONS: [&str; 4] = [
    "capabilities",
    "discover",
    "source-units",
    "candidate-check",
];

/// Policy modules covered by the pack policy fingerprint.
pub const POLICY_FILES: [&str; 5] = [
    "html_units.py",
    "html_semantic.py",
    "html_svg.py",
    "html_policy.py",
    "html_host_api.py",
];

/// Default host-API request budget in milliseconds.
pub const DEFAULT_HOST_API_TIMEOUT_MS: u64 = 30_000;

/// Maximum time to wait for a killed process to be reaped.
const KILL_GRACE: Duration = Duration::from_millis(1_000);
/// Poll interval for process termination.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

const PACK_FINGERPRINT_DOMAIN: &[u8] = b"herness.sdd.pack.v1\0";

/// One structured policy-bridge unavailability.
///
/// Every variant is an explicit unavailable result. None is mapped to
/// "missing approval" or to an automatic bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyBridgeError {
    /// Python or the validator was not detected by the existing resolver.
    ToolchainUnavailable {
        /// Requirement label.
        tool: &'static str,
        /// Sanitized status.
        status: String,
    },
    /// The pack root could not be opened or read.
    PackUnavailable {
        /// Sanitized detail.
        detail: String,
    },
    /// The integration definition is absent, invalid, or disables the bridge.
    IntegrationInvalid {
        /// Sanitized detail.
        detail: String,
    },
    /// The pack definition does not match the approved definition identity.
    IntegrationMismatch {
        /// Field that differs.
        field: &'static str,
        /// Approved value.
        approved: String,
        /// Found value.
        found: String,
    },
    /// The policy version is not the approved version.
    PolicyVersionMismatch {
        /// Approved version.
        approved: String,
        /// Found version.
        found: String,
    },
    /// The policy fingerprint is not the approved fingerprint.
    PolicyFingerprintMismatch {
        /// Approved fingerprint.
        approved: String,
        /// Found fingerprint.
        found: String,
    },
    /// The combined pack fingerprint is not the approved fingerprint.
    PackFingerprintMismatch {
        /// Approved fingerprint.
        approved: String,
        /// Found fingerprint.
        found: String,
    },
    /// The host API protocol or version is not the approved one.
    HostApiMismatch {
        /// Approved identity.
        approved: String,
        /// Found identity.
        found: String,
    },
    /// The pack does not advertise one required operation or capability.
    MissingCapability {
        /// Missing operation or capability.
        operation: String,
    },
    /// The host API response is structurally invalid metadata.
    InvalidMetadata {
        /// Sanitized detail.
        detail: String,
    },
    /// The host API did not return valid JSON.
    InvalidJson {
        /// Sanitized detail.
        detail: String,
        /// Process exit code, when it exited.
        exit_code: Option<i32>,
    },
    /// The host API exceeded the request budget.
    Timeout {
        /// Requested budget in milliseconds.
        timeout_ms: u64,
    },
    /// The process could not be started or did not exit normally.
    ProcessFailed {
        /// Sanitized detail.
        detail: String,
        /// Process exit code, when it exited.
        exit_code: Option<i32>,
    },
    /// The host API returned a protocol error envelope.
    Protocol {
        /// Stable error code.
        code: String,
        /// Sanitized message.
        message: String,
    },
    /// The host API resolved a different document root than the project root.
    RootMismatch {
        /// Canonical project root.
        expected: String,
        /// Root reported by the host API.
        observed: String,
    },
    /// A supplied input exceeds the approved pack limit before any call.
    LimitExceeded {
        /// Input path or category.
        field: String,
        /// Approved limit.
        limit: u64,
        /// Supplied size.
        actual: u64,
    },
    /// A local filesystem read failed.
    Io {
        /// Sanitized detail.
        detail: String,
    },
}

impl fmt::Display for PolicyBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ToolchainUnavailable { tool, status } => {
                write!(f, "policy bridge unavailable: {tool} is {status}")
            }
            Self::PackUnavailable { detail } => {
                write!(f, "policy bridge unavailable: pack cannot be read: {detail}")
            }
            Self::IntegrationInvalid { detail } => {
                write!(f, "policy bridge unavailable: invalid pack integration metadata: {detail}")
            }
            Self::IntegrationMismatch {
                field,
                approved,
                found,
            } => write!(
                f,
                "policy bridge unavailable: integration {field} is {found}, approved {approved}"
            ),
            Self::PolicyVersionMismatch { approved, found } => write!(
                f,
                "policy bridge unavailable: policy version {found}, approved {approved}"
            ),
            Self::PolicyFingerprintMismatch { approved, found } => write!(
                f,
                "policy bridge unavailable: policy fingerprint {found}, approved {approved}"
            ),
            Self::PackFingerprintMismatch { approved, found } => write!(
                f,
                "policy bridge unavailable: pack fingerprint {found}, approved {approved}"
            ),
            Self::HostApiMismatch { approved, found } => write!(
                f,
                "policy bridge unavailable: host API {found}, approved {approved}"
            ),
            Self::MissingCapability { operation } => {
                write!(f, "policy bridge unavailable: missing capability {operation}")
            }
            Self::InvalidMetadata { detail } => {
                write!(f, "policy bridge unavailable: invalid host API metadata: {detail}")
            }
            Self::InvalidJson { detail, exit_code } => write!(
                f,
                "policy bridge unavailable: invalid JSON (exit {exit_code:?}): {detail}"
            ),
            Self::Timeout { timeout_ms } => {
                write!(f, "policy bridge unavailable: host API timed out after {timeout_ms} ms")
            }
            Self::ProcessFailed { detail, exit_code } => write!(
                f,
                "policy bridge unavailable: process failed (exit {exit_code:?}): {detail}"
            ),
            Self::Protocol { code, message } => {
                write!(f, "policy bridge unavailable: host API {code}: {message}")
            }
            Self::RootMismatch { expected, observed } => write!(
                f,
                "policy bridge unavailable: host API root {observed}, project root {expected}"
            ),
            Self::LimitExceeded {
                field,
                limit,
                actual,
            } => write!(
                f,
                "policy bridge unavailable: {field} is {actual} bytes, approved limit {limit}"
            ),
            Self::Io { detail } => {
                write!(f, "policy bridge unavailable: local read failed: {detail}")
            }
        }
    }
}

impl std::error::Error for PolicyBridgeError {}

/// Local pack metadata discovered before approval verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackProbe {
    integration_schema: String,
    integration_version: u32,
    integration_revision: u32,
    definition_digest: ContentDigest,
    policy_version: String,
    policy_fingerprint: ContentDigest,
    host_api_protocol: String,
    host_api_version: u32,
    pack_fingerprint: ContentDigest,
}

impl PackProbe {
    /// Integration definition schema.
    pub fn integration_schema(&self) -> &str {
        &self.integration_schema
    }

    /// Integration definition version.
    pub const fn integration_version(&self) -> u32 {
        self.integration_version
    }

    /// Integration definition revision.
    pub const fn integration_revision(&self) -> u32 {
        self.integration_revision
    }

    /// SHA-256 of the exact integration definition bytes.
    pub const fn definition_digest(&self) -> &ContentDigest {
        &self.definition_digest
    }

    /// Pack policy version.
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// Pack policy fingerprint computed from the exact policy module bytes.
    pub const fn policy_fingerprint(&self) -> &ContentDigest {
        &self.policy_fingerprint
    }

    /// Host API protocol name.
    pub fn host_api_protocol(&self) -> &str {
        &self.host_api_protocol
    }

    /// Host API version.
    pub const fn host_api_version(&self) -> u32 {
        self.host_api_version
    }

    /// Combined pack fingerprint.
    pub const fn pack_fingerprint(&self) -> &ContentDigest {
        &self.pack_fingerprint
    }

    /// Candidate approval binding for the trusted UI.
    ///
    /// This is not approval; it is the exact value a human approves.
    pub fn approval_binding(&self) -> Result<H3PackBinding, PolicyBridgeError> {
        H3PackBinding::new(
            self.integration_schema.clone(),
            self.integration_version,
            self.integration_revision,
            self.policy_version.clone(),
            self.policy_fingerprint.clone(),
            self.pack_fingerprint.clone(),
            self.host_api_protocol.clone(),
            self.host_api_version,
        )
        .map_err(|error| PolicyBridgeError::IntegrationInvalid {
            detail: error.to_string(),
        })
    }
}

/// Unapproved pack discovery. This type has no operation methods.
#[derive(Debug)]
pub struct HtmlPolicyBridge {
    project_root: PathBuf,
    pack_root: PathBuf,
    definition: IntegrationDefinition,
    probe: PackProbe,
    python: PathBuf,
    script: PathBuf,
    timeout_ms: u64,
    invocations: Arc<AtomicUsize>,
}

impl Clone for HtmlPolicyBridge {
    fn clone(&self) -> Self {
        Self {
            project_root: self.project_root.clone(),
            pack_root: self.pack_root.clone(),
            definition: self.definition.clone(),
            probe: self.probe.clone(),
            python: self.python.clone(),
            script: self.script.clone(),
            timeout_ms: self.timeout_ms,
            invocations: Arc::clone(&self.invocations),
        }
    }
}

impl HtmlPolicyBridge {
    /// Discovers the pack and Python without invoking the host API.
    ///
    /// The project root is canonicalized first, so a symlinked project uses the
    /// real directory as `cwd`. The pack is opened through `SkillPack`, which
    /// canonicalizes and confines every read to the pack.
    pub fn detect(
        project_root: impl AsRef<Path>,
        pack_root: impl AsRef<Path>,
        toolchain: ToolchainConfig,
    ) -> Result<Self, PolicyBridgeError> {
        let project_root =
            fs::canonicalize(project_root.as_ref()).map_err(|error| PolicyBridgeError::Io {
                detail: format!("cannot canonicalize project root: {:?}", error.kind()),
            })?;
        if !project_root.is_dir() {
            return Err(PolicyBridgeError::Io {
                detail: "the project root is not a directory".to_owned(),
            });
        }
        let pack = SkillPack::open(pack_root.as_ref()).map_err(|error| {
            PolicyBridgeError::PackUnavailable {
                detail: error.to_string(),
            }
        })?;
        let definition_bytes = fs::read(pack.root().join("adapters/herness/integration.json"))
            .map_err(|error| PolicyBridgeError::PackUnavailable {
                detail: format!(
                    "cannot read adapters/herness/integration.json: {:?}",
                    error.kind()
                ),
            })?;
        let definition: IntegrationDefinition = serde_json::from_slice(&definition_bytes)
            .map_err(|error| PolicyBridgeError::IntegrationInvalid {
                detail: error.to_string(),
            })?;
        definition
            .validate()
            .map_err(|detail| PolicyBridgeError::IntegrationInvalid { detail })?;
        let definition_digest = ContentDigest::sha256(&definition_bytes);
        let policy_fingerprint = policy_fingerprint(pack.root())?;
        let pack_fingerprint = pack_fingerprint(
            &definition,
            &definition_digest,
            &policy_fingerprint,
        )?;
        let probe = PackProbe {
            integration_schema: definition.schema.clone(),
            integration_version: definition.version,
            integration_revision: definition.revision,
            definition_digest: definition_digest.clone(),
            policy_version: definition.pack.policy.clone(),
            policy_fingerprint,
            host_api_protocol: definition.capability.requires.policy_bridge.protocol.clone(),
            host_api_version: definition.capability.requires.policy_bridge.version,
            pack_fingerprint,
        };

        let report = ToolchainDetector::new(toolchain).detect();
        if !report.python.is_available() {
            return Err(PolicyBridgeError::ToolchainUnavailable {
                tool: "python",
                status: format!("{:?}", report.python.status),
            });
        }
        if !report.html_docs.is_available() {
            return Err(PolicyBridgeError::ToolchainUnavailable {
                tool: "html_docs_validator",
                status: format!("{:?}", report.html_docs.status),
            });
        }
        let Some(python) = report.python.executable_path.as_ref() else {
            return Err(PolicyBridgeError::ToolchainUnavailable {
                tool: "python",
                status: "interpreter-path-missing".to_owned(),
            });
        };
        let Some(script) = report.html_docs.script_path.as_ref() else {
            return Err(PolicyBridgeError::ToolchainUnavailable {
                tool: "html_docs_validator",
                status: "script-path-missing".to_owned(),
            });
        };
        Ok(Self {
            project_root,
            pack_root: pack.root().to_path_buf(),
            definition,
            probe,
            python: python.as_path().to_path_buf(),
            script: script.as_path().to_path_buf(),
            timeout_ms: DEFAULT_HOST_API_TIMEOUT_MS,
            invocations: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Replaces the host-API request budget. This does not change any approved
    /// limit; it only bounds one local process call.
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Result<Self, PolicyBridgeError> {
        if timeout_ms == 0 {
            return Err(PolicyBridgeError::InvalidMetadata {
                detail: "the host API timeout must be positive".to_owned(),
            });
        }
        self.timeout_ms = timeout_ms;
        Ok(self)
    }

    /// Canonical project root used as `cwd`.
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    /// Canonical pack root.
    pub fn pack_root(&self) -> &Path {
        &self.pack_root
    }

    /// Local pack metadata. Not an approval.
    pub const fn probe(&self) -> &PackProbe {
        &self.probe
    }

    /// Number of local host-API processes started by this bridge.
    pub fn invocations(&self) -> usize {
        self.invocations.load(Ordering::SeqCst)
    }

    /// Verifies the approved pack identity and connects the operations.
    ///
    /// The verification is entirely local before `capabilities` is invoked:
    /// the exact integration definition, policy module bytes, and combined
    /// fingerprint must match the approved binding. A mismatch is unavailable
    /// before any process starts.
    pub fn connect(self, approved: &H3PackBinding) -> Result<ConnectedPolicyBridge, PolicyBridgeError> {
        self.verify_approved(approved)?;
        let (envelope, capabilities) = self.call("capabilities", json!({}))?;
        let operations = validate_capabilities(&capabilities, &self.probe)?;
        let observed_root = envelope
            .get("root")
            .and_then(Value::as_str)
            .ok_or_else(|| PolicyBridgeError::InvalidMetadata {
                detail: "the capabilities envelope has no root".to_owned(),
            })?;
        if observed_root != self.project_root.to_string_lossy().as_ref() {
            return Err(PolicyBridgeError::RootMismatch {
                expected: self.project_root.to_string_lossy().into_owned(),
                observed: observed_root.to_owned(),
            });
        }
        let pack = self.probe.approval_binding()?;
        Ok(ConnectedPolicyBridge {
            inner: self,
            bootstrap: PolicyBootstrap {
                capabilities,
                pack,
                operations,
            },
        })
    }

    fn verify_approved(&self, approved: &H3PackBinding) -> Result<(), PolicyBridgeError> {
        if approved.integration_schema() != self.definition.schema {
            return Err(PolicyBridgeError::IntegrationMismatch {
                field: "schema",
                approved: approved.integration_schema().to_owned(),
                found: self.definition.schema.clone(),
            });
        }
        if approved.integration_version() != self.definition.version {
            return Err(PolicyBridgeError::IntegrationMismatch {
                field: "version",
                approved: approved.integration_version().to_string(),
                found: self.definition.version.to_string(),
            });
        }
        if approved.integration_revision() != self.definition.revision {
            return Err(PolicyBridgeError::IntegrationMismatch {
                field: "revision",
                approved: approved.integration_revision().to_string(),
                found: self.definition.revision.to_string(),
            });
        }
        if approved.policy_version() != self.probe.policy_version {
            return Err(PolicyBridgeError::PolicyVersionMismatch {
                approved: approved.policy_version().to_owned(),
                found: self.probe.policy_version.clone(),
            });
        }
        if approved.policy_fingerprint() != &self.probe.policy_fingerprint {
            return Err(PolicyBridgeError::PolicyFingerprintMismatch {
                approved: approved.policy_fingerprint().as_str().to_owned(),
                found: self.probe.policy_fingerprint.as_str().to_owned(),
            });
        }
        if approved.pack_fingerprint() != &self.probe.pack_fingerprint {
            return Err(PolicyBridgeError::PackFingerprintMismatch {
                approved: approved.pack_fingerprint().as_str().to_owned(),
                found: self.probe.pack_fingerprint.as_str().to_owned(),
            });
        }
        if approved.host_api_protocol() != self.probe.host_api_protocol
            || approved.host_api_version() != self.probe.host_api_version
        {
            return Err(PolicyBridgeError::HostApiMismatch {
                approved: format!(
                    "{}:{}",
                    approved.host_api_protocol(),
                    approved.host_api_version()
                ),
                found: format!(
                    "{}:{}",
                    self.probe.host_api_protocol, self.probe.host_api_version
                ),
            });
        }
        Ok(())
    }

    fn call(
        &self,
        operation: &str,
        extra: Value,
    ) -> Result<(Value, Value), PolicyBridgeError> {
        let mut request = Map::new();
        request.insert("version".to_owned(), json!(1));
        request.insert("operation".to_owned(), json!(operation));
        request.insert("timeout_ms".to_owned(), json!(self.timeout_ms));
        if let Value::Object(extra) = extra {
            for (key, value) in extra {
                request.insert(key, value);
            }
        }
        let body = serde_json::to_vec(&Value::Object(request)).map_err(|error| {
            PolicyBridgeError::InvalidMetadata {
                detail: error.to_string(),
            }
        })?;
        let stdout = self.run_process(&body)?;
        let text = String::from_utf8(stdout).map_err(|_| PolicyBridgeError::InvalidJson {
            detail: "the host API wrote non-UTF-8 output".to_owned(),
            exit_code: None,
        })?;
        let envelope: Value = serde_json::from_str(&text).map_err(|error| {
            PolicyBridgeError::InvalidJson {
                detail: error.to_string(),
                exit_code: None,
            }
        })?;
        let ok = envelope.get("ok").and_then(Value::as_bool).ok_or_else(|| {
            PolicyBridgeError::InvalidMetadata {
                detail: "the host API envelope has no boolean ok".to_owned(),
            }
        })?;
        if !ok {
            let code = envelope
                .pointer("/error/code")
                .and_then(Value::as_str)
                .unwrap_or("protocol-error")
                .to_owned();
            let message = envelope
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("the host API rejected the request")
                .to_owned();
            return Err(PolicyBridgeError::Protocol { code, message });
        }
        if envelope.get("version").and_then(Value::as_u64) != Some(1)
            || envelope.get("operation").and_then(Value::as_str) != Some(operation)
        {
            return Err(PolicyBridgeError::InvalidMetadata {
                detail: "the host API envelope version or operation does not match".to_owned(),
            });
        }
        let result = envelope.get("result").cloned().ok_or_else(|| {
            PolicyBridgeError::InvalidMetadata {
                detail: "the host API envelope has no result".to_owned(),
            }
        })?;
        Ok((envelope, result))
    }

    fn run_process(&self, body: &[u8]) -> Result<Vec<u8>, PolicyBridgeError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let mut child = Command::new(&self.python)
            .arg("-B")
            .arg(&self.script)
            .arg("host-api")
            .current_dir(&self.project_root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| PolicyBridgeError::ProcessFailed {
                detail: format!("cannot start the host API: {:?}", error.kind()),
                exit_code: None,
            })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| PolicyBridgeError::ProcessFailed {
                detail: "the host API stdin pipe is unavailable".to_owned(),
                exit_code: None,
            })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PolicyBridgeError::ProcessFailed {
                detail: "the host API stdout pipe is unavailable".to_owned(),
                exit_code: None,
            })?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| PolicyBridgeError::ProcessFailed {
                detail: "the host API stderr pipe is unavailable".to_owned(),
                exit_code: None,
            })?;
        let body = body.to_vec();
        let writer = thread::spawn(move || {
            let mut stdin = stdin;
            let _ = stdin.write_all(&body);
        });
        let out_reader = thread::spawn(move || read_all(stdout));
        let err_reader = thread::spawn(move || read_all(stderr));

        let timeout = Duration::from_millis(self.timeout_ms);
        let deadline = Instant::now() + timeout;
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        let _ = child.kill();
                        let kill_deadline = Instant::now() + KILL_GRACE;
                        loop {
                            match child.try_wait() {
                                Ok(Some(_)) => break,
                                Ok(None) if Instant::now() < kill_deadline => {
                                    thread::sleep(POLL_INTERVAL);
                                }
                                Ok(None) | Err(_) => break,
                            }
                        }
                        let _ = child.wait();
                        break None;
                    }
                    thread::sleep(POLL_INTERVAL);
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(PolicyBridgeError::ProcessFailed {
                        detail: format!("cannot poll the host API: {:?}", error.kind()),
                        exit_code: None,
                    });
                }
            }
        };
        let _ = writer.join();
        let stdout = out_reader
            .join()
            .map_err(|_| PolicyBridgeError::ProcessFailed {
                detail: "the host API stdout reader failed".to_owned(),
                exit_code: status.and_then(|status| status.code()),
            })?
            .map_err(|error| PolicyBridgeError::ProcessFailed {
                detail: format!("cannot read host API stdout: {:?}", error.kind()),
                exit_code: status.and_then(|status| status.code()),
            })?;
        let stderr = err_reader
            .join()
            .map_err(|_| PolicyBridgeError::ProcessFailed {
                detail: "the host API stderr reader failed".to_owned(),
                exit_code: status.and_then(|status| status.code()),
            })?
            .map_err(|error| PolicyBridgeError::ProcessFailed {
                detail: format!("cannot read host API stderr: {:?}", error.kind()),
                exit_code: status.and_then(|status| status.code()),
            })?;
        if timed_out {
            return Err(PolicyBridgeError::Timeout {
                timeout_ms: self.timeout_ms,
            });
        }
        let Some(status) = status else {
            return Err(PolicyBridgeError::ProcessFailed {
                detail: "the host API process disappeared".to_owned(),
                exit_code: None,
            });
        };
        if stdout.is_empty() && !stderr.is_empty() {
            let detail = String::from_utf8_lossy(&stderr);
            let detail = detail.lines().next().unwrap_or("").trim().to_owned();
            return Err(PolicyBridgeError::ProcessFailed {
                detail: if detail.is_empty() {
                    "the host API exited without output".to_owned()
                } else {
                    truncate(&detail, 512)
                },
                exit_code: status.code(),
            });
        }
        // A protocol failure (exit 2) still carries a JSON error envelope. The
        // caller parses it into a structured `Protocol` error. A static
        // candidate denial (exit 1) carries a valid `ok:true` result.
        Ok(stdout)
    }
}

/// Cached, verified bootstrap result.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyBootstrap {
    capabilities: Value,
    pack: H3PackBinding,
    operations: BTreeSet<String>,
}

impl PolicyBootstrap {
    /// Saved `capabilities` result.
    pub const fn capabilities(&self) -> &Value {
        &self.capabilities
    }

    /// Verified pack binding.
    pub const fn pack(&self) -> &H3PackBinding {
        &self.pack
    }

    /// Verified operation set.
    pub fn operations(&self) -> &BTreeSet<String> {
        &self.operations
    }
}

/// Verified connection. This is the only type that can call host-API
/// operations.
#[derive(Debug)]
pub struct ConnectedPolicyBridge {
    inner: HtmlPolicyBridge,
    bootstrap: PolicyBootstrap,
}

impl ConnectedPolicyBridge {
    /// Saved bootstrap result. Reused; `capabilities` is not called again.
    pub const fn bootstrap(&self) -> &PolicyBootstrap {
        &self.bootstrap
    }

    /// Canonical project root used as `cwd`.
    pub fn project_root(&self) -> &Path {
        self.inner.project_root()
    }

    /// Number of local host-API processes started by this connection.
    pub fn invocations(&self) -> usize {
        self.inner.invocations()
    }

    /// Calls `discover` with repository-relative paths.
    pub fn discover(&self, paths: &[String]) -> Result<Value, PolicyBridgeError> {
        if paths.is_empty() {
            return Err(PolicyBridgeError::InvalidMetadata {
                detail: "discover requires at least one path".to_owned(),
            });
        }
        let (_, result) = self
            .inner
            .call("discover", json!({ "paths": paths }))?;
        Ok(result)
    }

    /// Calls `source-units` with the exact Markdown bytes supplied in memory.
    pub fn source_units(
        &self,
        path: &str,
        inputs: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Value, PolicyBridgeError> {
        self.check_inputs(inputs)?;
        let (_, result) = self.inner.call(
            "source-units",
            json!({
                "path": path,
                "inputs": encode_inputs(inputs),
            }),
        )?;
        Ok(result)
    }

    /// Calls `candidate-check` with exact source and candidate bytes supplied
    /// in memory. The bridge never reads or writes the official files.
    pub fn candidate_check(
        &self,
        path: &str,
        stage: CandidateStage,
        receipt: Option<&str>,
        inputs: &BTreeMap<String, Vec<u8>>,
    ) -> Result<CandidateCheck, PolicyBridgeError> {
        self.check_inputs(inputs)?;
        let mut extra = Map::new();
        extra.insert("path".to_owned(), json!(path));
        extra.insert("stage".to_owned(), json!(stage.as_str()));
        if let Some(receipt) = receipt {
            extra.insert("receipt".to_owned(), json!(receipt));
        }
        extra.insert("inputs".to_owned(), encode_inputs(inputs));
        let (_, result) = self
            .inner
            .call("candidate-check", Value::Object(extra))?;
        CandidateCheck::from_value(result)
    }

    fn check_inputs(&self, inputs: &BTreeMap<String, Vec<u8>>) -> Result<(), PolicyBridgeError> {
        let mut total: u64 = 0;
        for bytes in inputs.values() {
            let size = bytes.len() as u64;
            total = total.checked_add(size).ok_or_else(|| {
                PolicyBridgeError::LimitExceeded {
                    field: "inputs.total".to_owned(),
                    limit: 64 * 1024 * 1024,
                    actual: u64::MAX,
                }
            })?;
        }
        if total > 64 * 1024 * 1024 {
            return Err(PolicyBridgeError::LimitExceeded {
                field: "inputs.total".to_owned(),
                limit: 64 * 1024 * 1024,
                actual: total,
            });
        }
        Ok(())
    }
}

/// Candidate check stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateStage {
    /// Static checks only; never a final pass.
    Structural,
    /// Static checks plus receipt and input digest binding.
    Final,
}

impl CandidateStage {
    /// Stable host API label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Structural => "structural",
            Self::Final => "final",
        }
    }
}

/// Candidate decision from the Common SDD policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateDecision {
    /// The candidate satisfies the supplied stage.
    Allow,
    /// The candidate violates the supplied stage.
    Deny,
}

/// One policy finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFinding {
    code: String,
    message: String,
}

impl PolicyFinding {
    /// Stable finding code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Sanitized finding message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Structured `candidate-check` result.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateCheck {
    decision: CandidateDecision,
    stage: String,
    final_pass: bool,
    final_binding: bool,
    contract: String,
    digests: Value,
    input_digests: Value,
    violations: Vec<PolicyFinding>,
    warnings: Vec<PolicyFinding>,
    message: String,
}

impl CandidateCheck {
    fn from_value(value: Value) -> Result<Self, PolicyBridgeError> {
        let decision = match value.get("decision").and_then(Value::as_str) {
            Some("allow") => CandidateDecision::Allow,
            Some("deny") => CandidateDecision::Deny,
            _ => {
                return Err(PolicyBridgeError::InvalidMetadata {
                    detail: "candidate-check has no allow/deny decision".to_owned(),
                });
            }
        };
        let stage = value
            .get("stage")
            .and_then(Value::as_str)
            .ok_or_else(|| PolicyBridgeError::InvalidMetadata {
                detail: "candidate-check has no stage".to_owned(),
            })?
            .to_owned();
        let final_pass = value
            .get("final")
            .and_then(Value::as_bool)
            .ok_or_else(|| PolicyBridgeError::InvalidMetadata {
                detail: "candidate-check has no final flag".to_owned(),
            })?;
        let final_binding = value
            .get("final_binding")
            .and_then(Value::as_bool)
            .ok_or_else(|| PolicyBridgeError::InvalidMetadata {
                detail: "candidate-check has no final_binding flag".to_owned(),
            })?;
        let contract = value
            .get("contract")
            .and_then(Value::as_str)
            .ok_or_else(|| PolicyBridgeError::InvalidMetadata {
                detail: "candidate-check has no contract".to_owned(),
            })?
            .to_owned();
        let digests = value.get("digests").cloned().ok_or_else(|| {
            PolicyBridgeError::InvalidMetadata {
                detail: "candidate-check has no digests".to_owned(),
            }
        })?;
        let input_digests = value.get("input_digests").cloned().ok_or_else(|| {
            PolicyBridgeError::InvalidMetadata {
                detail: "candidate-check has no input_digests".to_owned(),
            }
        })?;
        let violations = findings(value.get("violations"))?;
        let warnings = findings(value.get("warnings"))?;
        let message = value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Ok(Self {
            decision,
            stage,
            final_pass,
            final_binding,
            contract,
            digests,
            input_digests,
            violations,
            warnings,
            message,
        })
    }

    /// Policy decision.
    pub const fn decision(&self) -> CandidateDecision {
        self.decision
    }

    /// Supplied stage.
    pub fn stage(&self) -> &str {
        &self.stage
    }

    /// Whether this is a final pass. Structural is always false.
    pub const fn final_pass(&self) -> bool {
        self.final_pass
    }

    /// Whether final receipt/input binding was checked.
    pub const fn final_binding(&self) -> bool {
        self.final_binding
    }

    /// Declared HTML contract.
    pub fn contract(&self) -> &str {
        &self.contract
    }

    /// Source/candidate/receipt digests.
    pub const fn digests(&self) -> &Value {
        &self.digests
    }

    /// Per-input digests.
    pub const fn input_digests(&self) -> &Value {
        &self.input_digests
    }

    /// Violations.
    pub fn violations(&self) -> &[PolicyFinding] {
        &self.violations
    }

    /// Warnings.
    pub fn warnings(&self) -> &[PolicyFinding] {
        &self.warnings
    }

    /// Policy message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

fn findings(value: Option<&Value>) -> Result<Vec<PolicyFinding>, PolicyBridgeError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = value.as_array().ok_or_else(|| {
        PolicyBridgeError::InvalidMetadata {
            detail: "candidate-check findings must be an array".to_owned(),
        }
    })?;
    items
        .iter()
        .map(|item| {
            let code = item
                .get("code")
                .and_then(Value::as_str)
                .ok_or_else(|| PolicyBridgeError::InvalidMetadata {
                    detail: "a candidate-check finding has no code".to_owned(),
                })?;
            let message = item
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default();
            Ok(PolicyFinding {
                code: code.to_owned(),
                message: message.to_owned(),
            })
        })
        .collect()
}

fn validate_capabilities(
    result: &Value,
    probe: &PackProbe,
) -> Result<BTreeSet<String>, PolicyBridgeError> {
    let protocol = result
        .pointer("/protocol/name")
        .and_then(Value::as_str)
        .ok_or_else(invalid_capabilities)?;
    let version = result
        .pointer("/protocol/version")
        .and_then(Value::as_u64)
        .ok_or_else(invalid_capabilities)?;
    if protocol != probe.host_api_protocol || version != u64::from(probe.host_api_version) {
        return Err(PolicyBridgeError::HostApiMismatch {
            approved: format!("{}:{}", probe.host_api_protocol, probe.host_api_version),
            found: format!("{protocol}:{version}"),
        });
    }
    let operations: BTreeSet<String> = result
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(invalid_capabilities)?
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    for required in REQUIRED_OPERATIONS {
        if !operations.contains(required) {
            return Err(PolicyBridgeError::MissingCapability {
                operation: required.to_owned(),
            });
        }
    }
    let contracts: BTreeSet<String> = result
        .get("contracts")
        .and_then(Value::as_array)
        .ok_or_else(invalid_capabilities)?
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    for required in ["strict", "semantic-v1"] {
        if !contracts.contains(required) {
            return Err(PolicyBridgeError::MissingCapability {
                operation: required.to_owned(),
            });
        }
    }
    let policy_version = result
        .pointer("/policy/version")
        .and_then(Value::as_str)
        .ok_or_else(invalid_capabilities)?;
    if policy_version != probe.policy_version {
        return Err(PolicyBridgeError::PolicyVersionMismatch {
            approved: probe.policy_version.clone(),
            found: policy_version.to_owned(),
        });
    }
    let policy_digest = parse_prefixed_digest(
        result
            .pointer("/policy/digest")
            .and_then(Value::as_str)
            .ok_or_else(invalid_capabilities)?,
    )?;
    if &policy_digest != &probe.policy_fingerprint {
        return Err(PolicyBridgeError::PolicyFingerprintMismatch {
            approved: probe.policy_fingerprint.as_str().to_owned(),
            found: policy_digest.as_str().to_owned(),
        });
    }
    let writes_files = result
        .pointer("/writes/files")
        .and_then(Value::as_bool)
        .ok_or_else(invalid_capabilities)?;
    let writes_html = result
        .pointer("/writes/html")
        .and_then(Value::as_bool)
        .ok_or_else(invalid_capabilities)?;
    if writes_files || writes_html {
        return Err(PolicyBridgeError::InvalidMetadata {
            detail: "the host API claims file or HTML writes, which this bridge does not permit"
                .to_owned(),
        });
    }
    let implicit_bootstrap = result
        .pointer("/bootstrap/implicit")
        .and_then(Value::as_bool)
        .ok_or_else(invalid_capabilities)?;
    if implicit_bootstrap {
        return Err(PolicyBridgeError::InvalidMetadata {
            detail: "the host API claims implicit bootstrap; H3 requires explicit bootstrap"
                .to_owned(),
        });
    }
    let structural_final = result
        .pointer("/stages/structural/final")
        .and_then(Value::as_bool)
        .ok_or_else(invalid_capabilities)?;
    let final_binding = result
        .pointer("/stages/final/final_binding")
        .and_then(Value::as_bool)
        .ok_or_else(invalid_capabilities)?;
    if structural_final || !final_binding {
        return Err(PolicyBridgeError::InvalidMetadata {
            detail: "the host API stage semantics do not match version 1".to_owned(),
        });
    }
    Ok(operations)
}

fn invalid_capabilities() -> PolicyBridgeError {
    PolicyBridgeError::InvalidMetadata {
        detail: "the host API capabilities result is incomplete".to_owned(),
    }
}

fn parse_prefixed_digest(value: &str) -> Result<ContentDigest, PolicyBridgeError> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    ContentDigest::parse(value).map_err(|_| PolicyBridgeError::InvalidMetadata {
        detail: "the host API policy digest is not a SHA-256 value".to_owned(),
    })
}

fn read_all(mut stream: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn truncate(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn encode_inputs(inputs: &BTreeMap<String, Vec<u8>>) -> Value {
    let mut map = Map::new();
    for (path, bytes) in inputs {
        map.insert(path.clone(), Value::String(base64_encode(bytes)));
    }
    Value::Object(map)
}

/// Standard base64 without padding ambiguity. Kept local so the policy bridge
/// adds no dependency and has no encoder hidden behind a feature.
pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied();
        let third = chunk.get(2).copied();
        encoded.push(ALPHABET[(first >> 2) as usize] as char);
        encoded.push(
            ALPHABET[(((first & 0b0000_0011) << 4) | (second.unwrap_or(0) >> 4)) as usize] as char,
        );
        match second {
            Some(second) => {
                encoded.push(
                    ALPHABET[(((second & 0b0000_1111) << 2) | (third.unwrap_or(0) >> 6)) as usize]
                        as char,
                );
            }
            None => encoded.push('='),
        }
        match third {
            Some(third) => encoded.push(ALPHABET[(third & 0b0011_1111) as usize] as char),
            None => encoded.push('='),
        }
    }
    encoded
}

fn policy_fingerprint(pack_root: &Path) -> Result<ContentDigest, PolicyBridgeError> {
    let directory = pack_root.join("scripts/sddlib");
    let mut hasher = Sha256::new();
    for name in POLICY_FILES {
        let bytes = fs::read(directory.join(name)).map_err(|error| {
            PolicyBridgeError::PackUnavailable {
                detail: format!("cannot read policy module {name}: {:?}", error.kind()),
            }
        })?;
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(bytes.len().to_string().as_bytes());
        hasher.update([0]);
        hasher.update(&bytes);
    }
    Ok(finish_digest(hasher))
}

fn pack_fingerprint(
    definition: &IntegrationDefinition,
    definition_digest: &ContentDigest,
    policy_fingerprint: &ContentDigest,
) -> Result<ContentDigest, PolicyBridgeError> {
    let mut hasher = Sha256::new();
    hasher.update(PACK_FINGERPRINT_DOMAIN);
    let mut component = |value: &str| {
        hasher.update(value.as_bytes());
        hasher.update([0]);
    };
    component(&definition.schema);
    component(&definition.version.to_string());
    component(&definition.revision.to_string());
    component(definition_digest.as_str());
    component(&definition.pack.policy);
    component(policy_fingerprint.as_str());
    component(&definition.capability.requires.policy_bridge.protocol);
    component(&definition.capability.requires.policy_bridge.version.to_string());
    drop(component);
    Ok(finish_digest(hasher))
}

fn finish_digest(hasher: Sha256) -> ContentDigest {
    ContentDigest::parse(format!("{:x}", hasher.finalize()))
        .expect("a SHA-256 hex value is a valid content digest")
}

#[derive(Debug, Clone, Deserialize)]
struct IntegrationDefinition {
    schema: String,
    version: u32,
    revision: u32,
    host: String,
    capability: IntegrationCapability,
    pack: IntegrationPack,
}

impl IntegrationDefinition {
    fn validate(&self) -> Result<(), String> {
        if self.schema != PACK_INTEGRATION_SCHEMA {
            return Err(format!(
                "integration schema {:?} is not {PACK_INTEGRATION_SCHEMA:?}",
                self.schema
            ));
        }
        if self.host != PACK_INTEGRATION_HOST {
            return Err(format!("integration host {:?} is not herness", self.host));
        }
        if self.version == 0 || self.revision == 0 {
            return Err("integration version and revision must be positive".to_owned());
        }
        if self.pack.policy != PACK_POLICY_VERSION {
            return Err(format!(
                "integration policy {:?} is not {PACK_POLICY_VERSION:?}",
                self.pack.policy
            ));
        }
        let bridge = &self.capability.requires.policy_bridge;
        if bridge.protocol != HOST_API_PROTOCOL || bridge.version != HOST_API_VERSION {
            return Err(format!(
                "integration requires host API {}:{}, not {HOST_API_PROTOCOL}:{HOST_API_VERSION}",
                bridge.protocol, bridge.version
            ));
        }
        if self.capability.worker.enabled_by_definition {
            return Err(
                "the integration definition must not enable the HtmlWorker by itself".to_owned(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
struct IntegrationCapability {
    requires: IntegrationRequires,
    worker: IntegrationWorker,
}

#[derive(Debug, Clone, Deserialize)]
struct IntegrationRequires {
    policy_bridge: IntegrationBridge,
}

#[derive(Debug, Clone, Deserialize)]
struct IntegrationBridge {
    protocol: String,
    version: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct IntegrationWorker {
    enabled_by_definition: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct IntegrationPack {
    policy: String,
}
