//! The real `sdd-plan-inspect` bridge and the side-effect-free import preview.
//!
//! This module is the only place that starts the pack inspector. It runs
//! `python3 <pack>/scripts/plan-inspect` as one fixed argv through
//! `herness_core`'s [`ArgvLauncher`] under a [`ProcessSupervisor`], with the
//! project root as cwd, the exact request bytes on stdin, a bounded output
//! capture, and a 30 second timeout (or the caller's shorter remaining Task
//! budget). No `sh -c` string, no `PATH` lookup for the program, no shell, and
//! no model request is involved.
//!
//! # What is verified before bytes are sent
//!
//! 1. The pack root is canonical and carries an executable `scripts/plan-inspect`.
//! 2. `python3` is executable and reports at least Python 3.11 (the H1
//!    requirement for the SDD validator), probed through the same supervised
//!    argv path.
//! 3. `capabilities` returns protocol 1, schema 1, the expected execution block
//!    info, the 2 MiB limit, and the `docs/sdd/plans/` prefix.
//! 4. Every claimed execution-contract input file is read from the pack root and
//!    its digest is compared with the claim; the required input set is present,
//!    so a fingerprint cannot silently omit the parser, schema, integration
//!    definition, or instructions.
//! 5. The resulting [`PackBinding`] names the exact pack root and fingerprint.
//!    A plan is only imported when the caller's expected binding equals it, so a
//!    stale or different pack is `unavailable`, never a partial preview.
//!
//! # What it never does
//!
//! * No fallback parser: a non-zero exit, invalid JSON, timeout, oversize input
//!   or output, unsupported version, or fingerprint mismatch is an explicit
//!   `unavailable`. There is no `task-brief` scratch output and no Rust guess.
//! * No H2 child, no model request, no Git command, and no write. The only
//!   process is the inspector, and `PYTHONDONTWRITEBYTECODE=1` keeps Python from
//!   creating a `__pycache__` beside the pack.

use std::time::Duration;

use herness_core::contracts::{HostActivityId, ProjectId};
use herness_core::skills::PythonVersion;
use herness_core::tools::process::{
    ArgvLauncher, ArgvRequest, CaptureHandle, DEFAULT_CAPTURE_TIMEOUT, DEFAULT_CONFIRM_TIMEOUT,
    DEFAULT_OUTPUT_LIMIT, DEFAULT_TIMEOUT_GRACE, ManagedChild, ManagedOwner, ProcessSupervisor,
    SystemArgvLauncher, supervise,
};
use herness_core::{AbsolutePath, ShellStopStatus};
use herness_sdd_execute::import::{
    CONTRACT_FEATURE, CONTRACT_INPUT_FEATURE, CapabilitiesReport, EXIT_FEATURE,
    OVERSIZE_PLAN_FEATURE, OVERSIZE_RESPONSE_FEATURE, PACK_FEATURE, REQUIRED_CONTRACT_INPUTS,
    RESPONSE_FEATURE, TIMEOUT_FEATURE,
};
use herness_sdd_execute::{
    ExactPlanBytes, FailureDetails, INSPECTOR_TIMEOUT_SECONDS, InspectRequest, InspectedPlan,
    InspectorCapabilities, InspectorProtocol, MAX_PLAN_BYTES, PackFingerprint, PlanInspectorPort,
    PlanPreview, PlanSourcePort, RecoveryReason, SddExecutionError, SourceLayout, SpecSnapshotSet,
    inspect_request_envelope,
};
use sha2::Digest as _;
use uuid::Uuid;

use crate::sdd_execute::source::{ConfinedReader, PlanFileSource, read_and_verify_specs};

/// Host-enforced inspector budget: 30 seconds unless the caller supplies less.
pub const INSPECTOR_TIMEOUT: Duration = Duration::from_secs(INSPECTOR_TIMEOUT_SECONDS);

/// Retained bytes per captured stream. One 2 MiB plan with full Task text
/// produces a larger response than the plan itself, so the ceiling is well above
/// the plan limit; a larger response is refused rather than truncated.
pub const INSPECTOR_OUTPUT_LIMIT: usize = 32 * 1024 * 1024;

/// Minimum Python for the SDD pack, inherited from H1.
pub const MINIMUM_PYTHON: PythonVersion = PythonVersion::new(3, 11, 0);

/// Domain separator of the pack execution-contract fingerprint algorithm.
///
/// The pack documents `sha256(domain || NUL || id || NUL || path || NUL ||
/// file-sha256-hex)` for every input in order. Recomputing it here proves that
/// the reported fingerprint is the digest of the exact files this bridge read
/// from this pack root, instead of an opaque string copied from the response.
pub const EXECUTION_CONTRACT_DOMAIN: &str = "sdd-execution-contract-v1";

/// Maximum bytes read from one claimed execution-contract input.
///
/// The inputs are pack files (the inspector, parser, schema document,
/// instructions, and the integration definition). A larger file is refused
/// rather than hashed from a truncated read.
pub const MAX_CONTRACT_INPUT_BYTES: u64 = 16 * 1024 * 1024;

/// Pack-relative inspector entry point.
pub const INSPECTOR_SCRIPT: &str = "scripts/plan-inspect";

/// Fixed environment for the inspector child.
///
/// `PYTHONDONTWRITEBYTECODE` keeps Python from creating `__pycache__` files in
/// the pack, which is the one write a Python invocation would otherwise cause.
/// `PYTHONIOENCODING` and `PYTHONUTF8` make the protocol's byte stream explicit
/// instead of locale-dependent.
const INSPECTOR_ENVIRONMENT: &[(&str, &str)] = &[
    ("PYTHONDONTWRITEBYTECODE", "1"),
    ("PYTHONIOENCODING", "utf-8"),
    ("PYTHONUTF8", "1"),
    // A pack module must never reach the network for the inspector, and an
    // ambient proxy setting must not change the result.
    ("NO_PROXY", "*"),
];

// ---------------------------------------------------------------------------
// Pack root and binding
// ---------------------------------------------------------------------------

/// A verified pack root, its Python interpreter, and its execution contract.
///
/// The binding is what Task 13 stores in an approval, so a later start compares
/// the same pack root and fingerprint before it trusts a parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackBinding {
    root: String,
    protocol: InspectorProtocol,
    schema_version: u32,
    fingerprint: PackFingerprint,
    inputs: Vec<(String, String, String)>,
}

impl PackBinding {
    /// Canonical pack root.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Inspector protocol that produced the capability.
    pub fn protocol(&self) -> &InspectorProtocol {
        &self.protocol
    }

    /// Plan schema version that produced the parse.
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Pack execution-contract fingerprint.
    pub fn fingerprint(&self) -> &PackFingerprint {
        &self.fingerprint
    }

    /// Verified `(id, path, digest)` inputs in claimed order.
    pub fn inputs(&self) -> &[(String, String, String)] {
        &self.inputs
    }
}

/// One `sdd-plan-inspect` process bridge over a fixed pack root.
pub struct PackInspector<L = SystemArgvLauncher> {
    root: String,
    python: AbsolutePath,
    script: AbsolutePath,
    launcher: L,
    supervisor: ProcessSupervisor,
    activity: HostActivityId,
    /// Canonical project root the protocol requires as the process cwd.
    project_root: Option<String>,
    timeout: Duration,
    output_limit: usize,
}

impl<L> PackInspector<L> {
    /// Creates a bridge for one pack root.
    ///
    /// The root and the inspector script must exist; nothing is created. The
    /// interpreter is only probed when the first request runs, so constructing a
    /// bridge is cheap and side-effect free.
    pub fn new(
        pack_root: impl AsRef<std::path::Path>,
        python: AbsolutePath,
        launcher: L,
        supervisor: ProcessSupervisor,
        project_id: ProjectId,
    ) -> Result<Self, SddExecutionError> {
        let root = std::fs::canonicalize(pack_root.as_ref()).map_err(|error| {
            unavailable(
                PACK_FEATURE,
                format!("cannot canonicalize the pack root: {}", error.kind()),
            )
        })?;
        let root_text = root
            .to_str()
            .ok_or_else(|| unavailable(PACK_FEATURE, "the pack root is not valid UTF-8"))?
            .to_owned();
        let script = root.join(INSPECTOR_SCRIPT);
        let metadata = std::fs::metadata(&script).map_err(|error| {
            unavailable(
                PACK_FEATURE,
                format!("{INSPECTOR_SCRIPT} is missing: {}", error.kind()),
            )
        })?;
        if !metadata.is_file() {
            return Err(unavailable(
                PACK_FEATURE,
                format!("{INSPECTOR_SCRIPT} is not a file"),
            ));
        }
        let script = AbsolutePath::new(script.to_string_lossy().into_owned())
            .map_err(|error| unavailable(PACK_FEATURE, error.to_string()))?;
        if !python.as_path().is_absolute() {
            return Err(unavailable(
                PACK_FEATURE,
                "the interpreter path is not absolute",
            ));
        }
        Ok(Self {
            root: root_text,
            python,
            script,
            launcher,
            supervisor,
            activity: inspector_activity(project_id),
            project_root: None,
            timeout: INSPECTOR_TIMEOUT,
            output_limit: INSPECTOR_OUTPUT_LIMIT,
        })
    }

    /// Replaces the per-request timeout with a shorter remaining Task budget.
    ///
    /// A zero or sub-second budget still runs one bounded attempt: refusing to
    /// inspect would leave the caller unable to report why. The value is never
    /// raised above [`INSPECTOR_TIMEOUT`].
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = if timeout.is_zero() {
            Duration::from_millis(1)
        } else {
            timeout.min(INSPECTOR_TIMEOUT)
        };
        self
    }

    /// Effective per-request timeout.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Replaces the retained per-stream capture size.
    ///
    /// The inspector writes one JSON object, and a plan at the 2 MiB limit
    /// produces a response of the same order. A larger response is refused as
    /// oversize, never parsed from a truncated capture.
    #[must_use]
    pub fn with_output_limit(mut self, limit: usize) -> Self {
        self.output_limit = limit;
        self
    }

    /// Retained per-stream capture size.
    pub const fn output_limit(&self) -> usize {
        self.output_limit
    }

    /// Binds the project root the protocol requires as the process cwd.
    #[must_use]
    pub fn with_project_root(mut self, project_root: impl Into<String>) -> Self {
        self.project_root = Some(project_root.into());
        self
    }

    /// Project root used as the process cwd, when bound.
    pub fn project_root(&self) -> Option<&str> {
        self.project_root.as_deref()
    }

    /// The bound project root, or an explicit refusal.
    fn required_project_root(&self) -> Result<&str, SddExecutionError> {
        self.project_root.as_deref().ok_or_else(|| {
            unavailable(
                PACK_FEATURE,
                "no project root is bound, so the inspector cannot run with the required cwd",
            )
        })
    }

    /// Canonical pack root.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Inspector entry point.
    pub fn script(&self) -> &AbsolutePath {
        &self.script
    }

    /// Interpreter used for the inspector.
    pub fn python(&self) -> &AbsolutePath {
        &self.python
    }

    /// Host activity that owns every inspector group of this bridge.
    pub const fn activity_id(&self) -> HostActivityId {
        self.activity
    }
}

impl<L: ArgvLauncher> PackInspector<L> {
    /// Probes the interpreter version through the supervised argv path.
    ///
    /// The program is the interpreter with exactly `--version` and no script, so
    /// the probe cannot be confused with an inspector invocation.
    pub fn probe_python(&mut self, cwd: &str) -> Result<PythonVersion, SddExecutionError> {
        let output = self.run_with_script(cwd, false, Some("--version"), None)?;
        if !output.succeeded() {
            return Err(unavailable(
                PACK_FEATURE,
                format!("python --version failed: {}", output.detail()),
            ));
        }
        let banner = if output.stdout().trim().is_empty() {
            output.stderr()
        } else {
            output.stdout()
        };
        let version = PythonVersion::from_banner(banner).ok_or_else(|| {
            unavailable(PACK_FEATURE, "python --version did not report a version")
        })?;
        if version < MINIMUM_PYTHON {
            return Err(unavailable(
                PACK_FEATURE,
                format!("python {version} is older than {MINIMUM_PYTHON}"),
            ));
        }
        Ok(version)
    }

    /// Asks the pack for its capability and execution-contract identity.
    pub fn capabilities(&mut self, cwd: &str) -> Result<CapabilitiesReport, SddExecutionError> {
        let request = capabilities_envelope();
        let output = self.run(cwd, &[], Some(request))?;
        self.checked_output(&output)?;
        herness_sdd_execute::decode_capabilities_response(output.stdout.as_bytes())
    }

    /// Verifies the claimed execution contract against the pack root.
    ///
    /// Every claimed input is re-read from the pack root and its digest compared
    /// with the claim. The required input set must be present, so a fingerprint
    /// that omits the parser, schema, integration definition, or instructions is
    /// refused instead of accepted as an opaque string.
    pub fn verify_binding(
        &self,
        capabilities: &CapabilitiesReport,
        required_fingerprint: Option<&PackFingerprint>,
    ) -> Result<PackBinding, SddExecutionError> {
        if let Some(required) = required_fingerprint
            && required != capabilities.fingerprint()
        {
            return Err(unavailable(
                CONTRACT_FEATURE,
                format!(
                    "the pack reports {}, but this approval binds {}",
                    capabilities.fingerprint(),
                    required
                ),
            ));
        }
        for required in REQUIRED_CONTRACT_INPUTS {
            if !capabilities
                .inputs()
                .iter()
                .any(|input| input.id() == *required)
            {
                return Err(unavailable(
                    CONTRACT_INPUT_FEATURE,
                    format!("the execution contract does not bind the required input {required:?}"),
                ));
            }
        }
        let reader = ConfinedReader::new(&self.root, MAX_CONTRACT_INPUT_BYTES)?;
        let mut inputs = Vec::with_capacity(capabilities.inputs().len());
        for input in capabilities.inputs() {
            let read = reader.read(input.path()).map_err(|error| {
                unavailable(
                    CONTRACT_INPUT_FEATURE,
                    format!(
                        "the execution contract input {:?} is unreadable: {error}",
                        input.id()
                    ),
                )
            })?;
            let digest = format!("sha256:{:x}", sha2::Sha256::digest(read.bytes()));
            if digest != input.digest().as_str() {
                return Err(unavailable(
                    CONTRACT_INPUT_FEATURE,
                    format!(
                        "the execution contract input {:?} does not match its claimed digest; the pack changed after capabilities",
                        input.id()
                    ),
                ));
            }
            inputs.push((input.id().to_owned(), input.path().to_owned(), digest));
        }
        let recomputed = execution_contract_fingerprint(&inputs)?;
        if &recomputed != capabilities.fingerprint() {
            return Err(unavailable(
                CONTRACT_FEATURE,
                format!(
                    "the reported fingerprint is {}, but the exact pack files hash to {recomputed}",
                    capabilities.fingerprint()
                ),
            ));
        }
        Ok(PackBinding {
            root: self.root.clone(),
            protocol: capabilities.capabilities().protocol().clone(),
            schema_version: capabilities.capabilities().schema_version(),
            fingerprint: recomputed,
            inputs,
        })
    }

    /// Sends one exact `inspect` request and decodes the preview.
    pub fn preview(
        &mut self,
        project_root: &str,
        capabilities: &InspectorCapabilities,
        request: &InspectRequest,
    ) -> Result<PlanPreview, SddExecutionError> {
        if request.source().len() as u64 > MAX_PLAN_BYTES {
            return Err(unavailable(
                OVERSIZE_PLAN_FEATURE,
                format!(
                    "the plan is {} bytes; the maximum is {MAX_PLAN_BYTES}",
                    request.source().len()
                ),
            ));
        }
        let envelope = inspect_request_envelope(request)?;
        let output = self.run(project_root, &[], Some(envelope))?;
        self.checked_output(&output)?;
        PlanPreview::decode(capabilities, request, output.stdout.as_bytes())
    }

    fn checked_output(&self, output: &InspectorOutput) -> Result<(), SddExecutionError> {
        match output.status {
            ShellStopStatus::Completed => {}
            ShellStopStatus::Timeout => {
                return Err(unavailable(
                    TIMEOUT_FEATURE,
                    format!(
                        "the inspector exceeded {} ms and was terminated",
                        self.timeout.as_millis()
                    ),
                ));
            }
            ShellStopStatus::ExitedNonZero | ShellStopStatus::Killed => {
                return Err(unavailable(
                    EXIT_FEATURE,
                    format!(
                        "the inspector exited with {:?}: {}",
                        output.exit_code,
                        output.detail()
                    ),
                ));
            }
            ShellStopStatus::StopRequested => {
                return Err(SddExecutionError::RecoveryRequired {
                    reason: RecoveryReason::StopUnconfirmed,
                    details: FailureDetails::none().boxed(),
                });
            }
            ShellStopStatus::Unconfirmed => {
                return Err(SddExecutionError::RecoveryRequired {
                    reason: RecoveryReason::StopUnconfirmed,
                    details: FailureDetails::none().boxed(),
                });
            }
        }
        if self.output_limit > 0 && output.stdout_truncated {
            return Err(unavailable(
                OVERSIZE_RESPONSE_FEATURE,
                format!(
                    "the inspector response was truncated at {} bytes",
                    self.output_limit
                ),
            ));
        }
        if output.stdout.is_empty() {
            return Err(unavailable(
                RESPONSE_FEATURE,
                "the inspector wrote no response",
            ));
        }
        Ok(())
    }

    fn run(
        &mut self,
        cwd: &str,
        extra_args: &[String],
        stdin: Option<Vec<u8>>,
    ) -> Result<InspectorOutput, SddExecutionError> {
        self.run_with_script(cwd, true, extra_args.first().map(String::as_str), stdin)
    }

    fn run_with_script(
        &mut self,
        cwd: &str,
        with_script: bool,
        argument: Option<&str>,
        stdin: Option<Vec<u8>>,
    ) -> Result<InspectorOutput, SddExecutionError> {
        let cwd =
            AbsolutePath::new(cwd).map_err(|error| unavailable(PACK_FEATURE, error.to_string()))?;
        let mut args = Vec::with_capacity(2);
        if with_script {
            args.push(self.script.as_str().to_owned());
        }
        if let Some(argument) = argument {
            args.push(argument.to_owned());
        }
        let mut request = ArgvRequest::new(self.python.as_str(), args, cwd)
            .map_err(|error| unavailable(PACK_FEATURE, error.to_string()))?;
        for (key, value) in INSPECTOR_ENVIRONMENT {
            request = request
                .with_env(*key, *value)
                .map_err(|error| unavailable(PACK_FEATURE, error.to_string()))?;
        }
        if let Some(bytes) = stdin {
            request = request.with_stdin(bytes);
        }

        let Some(gate) = self.supervisor.begin_spawn() else {
            return Err(SddExecutionError::RecoveryRequired {
                reason: RecoveryReason::StopUnconfirmed,
                details: FailureDetails::none().boxed(),
            });
        };
        let mut child = match self.launcher.spawn_argv(&request) {
            Ok(child) => child,
            Err(error) => {
                drop(gate);
                return Err(unavailable(
                    PACK_FEATURE,
                    format!("cannot start the inspector: {}", error.kind()),
                ));
            }
        };
        let pid = child.pid();
        let pgid = pid;
        let lease = self
            .supervisor
            .register(ManagedOwner::HostActivity(self.activity), pid, pgid);
        drop(gate);
        let _lease = lease;

        let stdout = CaptureHandle::start(child.take_stdout(), self.output_limit);
        let stderr = CaptureHandle::start(child.take_stderr(), DEFAULT_OUTPUT_LIMIT);
        let completion = supervise(
            &mut child,
            pgid,
            &self.supervisor,
            Some(self.timeout),
            DEFAULT_TIMEOUT_GRACE,
            DEFAULT_CONFIRM_TIMEOUT,
        );
        let stdout = stdout.wait(DEFAULT_CAPTURE_TIMEOUT);
        let stderr = stderr.wait(DEFAULT_CAPTURE_TIMEOUT);

        Ok(InspectorOutput {
            status: completion.stop_status(),
            exit_code: completion.exit_code(),
            stdout: stdout.text().to_owned(),
            stdout_truncated: stdout.truncated(),
            stderr: stderr.text().to_owned(),
        })
    }
}

impl PlanInspectorPort for PackInspector<SystemArgvLauncher> {
    fn capabilities(&mut self) -> Result<InspectorCapabilities, SddExecutionError> {
        // The protocol is spoken with the project root as cwd. A bridge without
        // one refuses instead of substituting the pack root, because the cwd is
        // part of the agreed protocol and a different one would be a silent
        // deviation.
        let cwd = self.required_project_root()?.to_owned();
        let capabilities = PackInspector::capabilities(self, &cwd)?;
        Ok(capabilities.capabilities().clone())
    }

    fn inspect(&mut self, request: &InspectRequest) -> Result<InspectedPlan, SddExecutionError> {
        let cwd = self.required_project_root()?.to_owned();
        let capabilities = PackInspector::capabilities(self, &cwd)?
            .capabilities()
            .clone();
        let preview = PackInspector::preview(self, &cwd, &capabilities, request)?;
        Ok(preview.into_inspected())
    }
}

#[derive(Debug, Clone)]
struct InspectorOutput {
    status: ShellStopStatus,
    exit_code: Option<i32>,
    stdout: String,
    stdout_truncated: bool,
    stderr: String,
}

impl InspectorOutput {
    fn succeeded(&self) -> bool {
        self.status == ShellStopStatus::Completed && self.exit_code == Some(0)
    }

    fn stdout(&self) -> &str {
        &self.stdout
    }

    fn stderr(&self) -> &str {
        &self.stderr
    }

    fn detail(&self) -> String {
        let source = if self.stderr.trim().is_empty() {
            &self.stdout
        } else {
            &self.stderr
        };
        let mut text = String::new();
        for character in source.chars() {
            if character.is_control() {
                if character == '\n' || character == '\t' {
                    text.push(' ');
                }
                continue;
            }
            text.push(character);
            if text.len() >= 300 {
                break;
            }
        }
        let trimmed = text.trim();
        if trimmed.is_empty() {
            format!("exit {:?}", self.exit_code)
        } else {
            trimmed.to_owned()
        }
    }
}

fn capabilities_envelope() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "protocol": herness_sdd_execute::PLAN_INSPECTOR_PROTOCOL,
        "version": herness_sdd_execute::PLAN_INSPECTOR_PROTOCOL_VERSION,
        "operation": "capabilities",
    }))
    .expect("the capability envelope is a constant object")
}

/// Recomputes the pack execution-contract fingerprint from verified inputs.
///
/// `inputs` are `(id, path, digest)` triples in the pack's claimed order, each
/// digest already checked against the exact bytes read from the pack root.
fn execution_contract_fingerprint(
    inputs: &[(String, String, String)],
) -> Result<PackFingerprint, SddExecutionError> {
    if inputs.is_empty() {
        return Err(unavailable(
            CONTRACT_INPUT_FEATURE,
            "the execution contract has no input to bind",
        ));
    }
    let mut hasher = sha2::Sha256::new();
    hasher.update(EXECUTION_CONTRACT_DOMAIN.as_bytes());
    for (id, path, digest) in inputs {
        let hex = digest.strip_prefix("sha256:").ok_or_else(|| {
            unavailable(
                CONTRACT_INPUT_FEATURE,
                format!("the input {id:?} digest is not sha256-prefixed"),
            )
        })?;
        hasher.update([0u8]);
        hasher.update(id.as_bytes());
        hasher.update([0u8]);
        hasher.update(path.as_bytes());
        hasher.update([0u8]);
        hasher.update(hex.as_bytes());
    }
    PackFingerprint::parse(format!("sha256:{:x}", hasher.finalize()))
}

fn inspector_activity(project_id: ProjectId) -> HostActivityId {
    let digest = sha2::Sha256::digest(format!("herness.h4.inspector\0{project_id}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    HostActivityId::from_parts(project_id, Uuid::from_bytes(bytes))
}

fn unavailable(feature: &str, detail: impl std::fmt::Display) -> SddExecutionError {
    SddExecutionError::Unavailable {
        feature: format!("{feature}: {detail}"),
        details: FailureDetails::none().boxed(),
    }
}

// ---------------------------------------------------------------------------
// Import preview
// ---------------------------------------------------------------------------

/// One read-only import: exact plan bytes in, verified preview plus spec
/// snapshots out.
#[derive(Debug, Clone)]
pub struct ImportPreview {
    project_root: String,
    source: ExactPlanBytes,
    preview: PlanPreview,
    specs: SpecSnapshotSet,
    binding: PackBinding,
}

impl ImportPreview {
    /// Canonical project root the plan and spec snapshots were read from.
    pub fn project_root(&self) -> &str {
        &self.project_root
    }

    /// The exact plan bytes the human would approve.
    pub fn source(&self) -> &ExactPlanBytes {
        &self.source
    }

    /// The validated preview.
    pub fn preview(&self) -> &PlanPreview {
        &self.preview
    }

    /// Verified spec/source snapshots the preview binds.
    pub fn specs(&self) -> &SpecSnapshotSet {
        &self.specs
    }

    /// Pack root and fingerprint the parse came from.
    pub fn binding(&self) -> &PackBinding {
        &self.binding
    }

    /// Consumes the import into its exact bytes and parts.
    pub fn into_parts(self) -> (ExactPlanBytes, PlanPreview, SpecSnapshotSet, PackBinding) {
        (self.source, self.preview, self.specs, self.binding)
    }
}

/// Ties one pack bridge, one project plan source, and the approved alias roots
/// into a read-only import.
///
/// A caller that supplies an expected [`PackFingerprint`] only imports when the
/// pack still reports it. The importer holds no H2, model, H3, store, or Git
/// port: the type system makes those side effects unreachable from a preview.
pub struct PlanImporter<L, S> {
    inspector: PackInspector<L>,
    source: S,
    layout: SourceLayout,
    expected: Option<PackFingerprint>,
}

impl<L: ArgvLauncher, S: RootedPlanSource> PlanImporter<L, S> {
    /// Creates an importer over a verified bridge and a plan source.
    pub fn new(
        inspector: PackInspector<L>,
        source: S,
        layout: SourceLayout,
        expected: Option<PackFingerprint>,
    ) -> Self {
        Self {
            inspector,
            source,
            layout,
            expected,
        }
    }

    /// Replaces the per-request timeout with the remaining Task budget.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.inspector = self.inspector.with_timeout(timeout);
        self
    }

    /// The approved alias roots this importer may read.
    pub const fn layout(&self) -> &SourceLayout {
        &self.layout
    }

    /// Runs one side-effect-free import.
    ///
    /// Order: read the exact plan bytes (so an absent or oversize plan starts
    /// nothing), probe Python, ask for capabilities, verify the execution
    /// contract against the pack root, send the exact bytes to `inspect`, decode
    /// and revalidate the preview, then read and verify one snapshot per
    /// declared spec/source. Nothing is written and no other process starts.
    pub fn import(
        &mut self,
        plan_path: &herness_sdd_execute::PlanPath,
    ) -> Result<ImportPreview, SddExecutionError> {
        let project_root = self
            .source
            .project_root()
            .ok_or_else(|| unavailable(PACK_FEATURE, "the plan source has no project root"))?
            .to_owned();
        if let Some(bound) = self.inspector.project_root()
            && bound != project_root
        {
            return Err(unavailable(
                PACK_FEATURE,
                format!(
                    "the bridge is bound to project root {bound}, but the plan source root is {project_root}"
                ),
            ));
        }
        if self.layout.project_root() != project_root {
            return Err(unavailable(
                PACK_FEATURE,
                format!(
                    "the source layout root {} is not the plan source root {project_root}",
                    self.layout.project_root()
                ),
            ));
        }
        let project_id = self.source.project_id();
        let plan = self.source.read_plan(project_id, plan_path)?;
        let exact = ExactPlanBytes::verify(plan.source().to_vec(), plan.digest().clone())?;
        let request = InspectRequest::new(plan_path.clone(), exact.source().to_vec())?;
        let _ = self.inspector.probe_python(&project_root)?;
        let capabilities = self.inspector.capabilities(&project_root)?;
        let binding = self
            .inspector
            .verify_binding(&capabilities, self.expected.as_ref())?;
        let preview =
            self.inspector
                .preview(&project_root, capabilities.capabilities(), &request)?;
        if preview.digest() != plan.digest() {
            return Err(SddExecutionError::PlanChanged {
                reason: herness_sdd_execute::PlanChangeReason::UnstableObservation,
                details: FailureDetails::none().boxed(),
            });
        }
        let specs = read_and_verify_specs(&self.layout, preview.spec_refs())?;
        Ok(ImportPreview {
            project_root,
            source: exact,
            preview,
            specs,
            binding,
        })
    }
}

/// A plan source that also exposes its project root, so an importer can pass the
/// protocol's cwd without guessing it.
pub trait RootedPlanSource: PlanSourcePort {
    /// Canonical project root.
    fn project_root(&self) -> Option<&str>;
    /// Project this source belongs to.
    fn project_id(&self) -> ProjectId;
}

impl RootedPlanSource for PlanFileSource {
    fn project_root(&self) -> Option<&str> {
        Some(PlanFileSource::project_root(self))
    }

    fn project_id(&self) -> ProjectId {
        PlanFileSource::project_id(self)
    }
}
