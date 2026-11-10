//! H3 candidate render evidence.
//!
//! The renderer presents one already-authored candidate to a separate,
//! non-privileged WebKit view and records what the platform actually laid out.
//! The candidate is served from memory through a job-scoped custom protocol;
//! the renderer never reads the project or writes a candidate file. Evidence is
//! written only by the caller to the requested evidence directory.
//!
//! The pure model in this module owns the protocol routing rules, the fixed
//! viewport matrix, the 30-second/remaining-cycle budget, cancellation, and the
//! versioned manifest. The macOS bridge in `render_macos.rs` owns the WKWebView
//! lifecycle and is the only module that needs `unsafe`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use herness_html_sync::{
    DependencyKind, MAX_APPROVED_RENDER_TIMEOUT_MS, MAX_CANDIDATE_BYTES, dependency_fingerprint,
};
use herness_supervision::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

/// Version of the evidence manifest written by this module.
pub const RENDER_MANIFEST_VERSION: &str = "h3-render-manifest-v1";

/// Scheme used by the job-scoped in-memory candidate protocol.
pub const RENDER_SCHEME: &str = "h3render";

/// Document served at the root of a render job.
pub const RENDER_DOCUMENT_PATH: &str = "index.html";

/// Stylesheet name reserved for the candidate's shared CSS.
pub const RENDER_STYLESHEET_PATH: &str = "candidate.css";

/// Fixed hard ceiling for one candidate render.
pub const RENDER_HARD_TIMEOUT: Duration = Duration::from_millis(MAX_APPROVED_RENDER_TIMEOUT_MS);

/// Upper bound on CSS bytes presented to one render.
pub const MAX_RENDER_CSS_BYTES: usize = MAX_CANDIDATE_BYTES;

/// Upper bound on declared resource bytes presented to one render.
pub const MAX_RENDER_RESOURCE_BYTES: usize = MAX_CANDIDATE_BYTES;

/// Upper bound on the number of declared resources in one render.
pub const MAX_RENDER_RESOURCES: usize = 256;

/// One CSS-pixel viewport in the fixed render matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderViewport {
    /// Width in CSS pixels.
    pub width: u32,
    /// Height in CSS pixels.
    pub height: u32,
}

impl RenderViewport {
    /// Creates a non-empty viewport.
    pub fn new(width: u32, height: u32) -> Result<Self, RenderError> {
        if width == 0 || height == 0 || width > 8_192 || height > 8_192 {
            return Err(RenderError::InvalidJob {
                detail: format!("viewport {width}x{height} is outside the accepted range"),
            });
        }
        Ok(Self { width, height })
    }
}

/// Colour scheme requested from the render view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderAppearance {
    /// Light appearance (`NSAppearanceNameAqua`).
    Light,
    /// Dark appearance (`NSAppearanceNameDarkAqua`).
    Dark,
}

impl RenderAppearance {
    /// Stable manifest label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

/// One configuration in the fixed render matrix.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RenderConfiguration {
    /// Stable configuration identifier used for the PNG file name.
    pub id: &'static str,
    /// Window size in CSS pixels.
    pub viewport: RenderViewport,
    /// Requested appearance.
    pub appearance: RenderAppearance,
    /// Page zoom applied to the WebKit view.
    pub page_zoom: f64,
}

const fn configuration(
    id: &'static str,
    width: u32,
    height: u32,
    appearance: RenderAppearance,
    page_zoom: f64,
) -> RenderConfiguration {
    RenderConfiguration {
        id,
        viewport: RenderViewport { width, height },
        appearance,
        page_zoom,
    }
}

/// Required render matrix: two viewports, light/dark, and 200% page zoom.
pub const RENDER_CONFIGURATIONS: [RenderConfiguration; 8] = [
    configuration("desktop-light", 1_280, 800, RenderAppearance::Light, 1.0),
    configuration("desktop-dark", 1_280, 800, RenderAppearance::Dark, 1.0),
    configuration("desktop-zoom-200", 1_280, 800, RenderAppearance::Light, 2.0),
    configuration(
        "desktop-zoom-200-dark",
        1_280,
        800,
        RenderAppearance::Dark,
        2.0,
    ),
    configuration("mobile-light", 390, 844, RenderAppearance::Light, 1.0),
    configuration("mobile-dark", 390, 844, RenderAppearance::Dark, 1.0),
    configuration("mobile-zoom-200", 390, 844, RenderAppearance::Light, 2.0),
    configuration(
        "mobile-zoom-200-dark",
        390,
        844,
        RenderAppearance::Dark,
        2.0,
    ),
];

/// One declared resource served to the render view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderResource {
    path: String,
    content_type: String,
    bytes: Vec<u8>,
}

impl RenderResource {
    /// Creates a resource after validating its relative path and content type.
    pub fn new(
        path: impl Into<String>,
        content_type: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<Self, RenderError> {
        let path = path.into();
        validate_relative_path(&path, "resource")?;
        if path == RENDER_DOCUMENT_PATH || path == RENDER_STYLESHEET_PATH {
            return Err(RenderError::InvalidJob {
                detail: format!("resource path `{path}` collides with a reserved render path"),
            });
        }
        let content_type = content_type.into();
        if !is_allowed_resource_content_type(&content_type) {
            return Err(RenderError::InvalidJob {
                detail: format!("resource `{path}` has unsupported content type `{content_type}`"),
            });
        }
        Ok(Self {
            path,
            content_type,
            bytes,
        })
    }

    /// Relative resource path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Response content type.
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// Exact bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.bytes)
    }
}

/// Exact candidate inputs for one render job.
#[derive(Debug, Clone)]
pub struct RenderJob {
    job_id: String,
    html: Vec<u8>,
    css: Vec<u8>,
    resources: Vec<RenderResource>,
    fingerprints: RenderFingerprints,
}

/// Digests that bind render evidence to the exact candidate bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderFingerprints {
    /// Candidate HTML digest.
    pub html: ContentDigest,
    /// Shared CSS digest.
    pub css: ContentDigest,
    /// Aggregate resource-set digest using the observer's recipe.
    pub resources: ContentDigest,
    /// Aggregate candidate digest covering HTML, CSS, and resources.
    pub candidate: ContentDigest,
}

impl RenderJob {
    /// Builds a render job from exact candidate bytes.
    ///
    /// `job_id` is an opaque lowercase host-issued identifier. It scopes the
    /// custom protocol origin and must not contain user data.
    pub fn new(
        job_id: impl Into<String>,
        html: Vec<u8>,
        css: Vec<u8>,
        resources: Vec<RenderResource>,
    ) -> Result<Self, RenderError> {
        let job_id = job_id.into();
        if job_id.len() < 8
            || job_id.len() > 64
            || !job_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || job_id.starts_with('-')
            || job_id.ends_with('-')
        {
            return Err(RenderError::InvalidJob {
                detail: "job id must be 8-64 lowercase ASCII letters, digits, or interior hyphens"
                    .to_owned(),
            });
        }
        if html.is_empty() {
            return Err(RenderError::InvalidJob {
                detail: "candidate HTML is empty".to_owned(),
            });
        }
        if html.len() > MAX_CANDIDATE_BYTES {
            return Err(RenderError::InvalidJob {
                detail: format!(
                    "candidate HTML is {} bytes; the limit is {MAX_CANDIDATE_BYTES}",
                    html.len()
                ),
            });
        }
        if css.len() > MAX_RENDER_CSS_BYTES {
            return Err(RenderError::InvalidJob {
                detail: format!(
                    "candidate CSS is {} bytes; the limit is {MAX_RENDER_CSS_BYTES}",
                    css.len()
                ),
            });
        }
        if resources.len() > MAX_RENDER_RESOURCES {
            return Err(RenderError::InvalidJob {
                detail: format!(
                    "candidate declares {} resources; the limit is {MAX_RENDER_RESOURCES}",
                    resources.len()
                ),
            });
        }
        let mut paths = BTreeSet::new();
        let mut resource_bytes = 0usize;
        for resource in &resources {
            if !paths.insert(resource.path.clone()) {
                return Err(RenderError::InvalidJob {
                    detail: format!("duplicate resource path `{}`", resource.path),
                });
            }
            resource_bytes = resource_bytes
                .checked_add(resource.bytes.len())
                .ok_or_else(|| RenderError::InvalidJob {
                    detail: "resource byte count overflowed".to_owned(),
                })?;
        }
        if resource_bytes > MAX_RENDER_RESOURCE_BYTES {
            return Err(RenderError::InvalidJob {
                detail: format!(
                    "candidate resources total {resource_bytes} bytes; the limit is \
                     {MAX_RENDER_RESOURCE_BYTES}"
                ),
            });
        }

        let html_digest = ContentDigest::sha256(&html);
        let css_digest = ContentDigest::sha256(&css);
        let resource_digest = dependency_fingerprint(
            DependencyKind::Resource,
            resources
                .iter()
                .map(|resource| (resource.path.as_str(), resource.digest())),
        );
        let candidate_digest = candidate_digest(
            html_digest.clone(),
            css_digest.clone(),
            resource_digest.clone(),
        );

        Ok(Self {
            job_id,
            html,
            css,
            resources,
            fingerprints: RenderFingerprints {
                html: html_digest,
                css: css_digest,
                resources: resource_digest,
                candidate: candidate_digest,
            },
        })
    }

    /// Host-issued job identifier.
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Exact candidate HTML.
    pub fn html(&self) -> &[u8] {
        &self.html
    }

    /// Exact shared CSS.
    pub fn css(&self) -> &[u8] {
        &self.css
    }

    /// Declared resources.
    pub fn resources(&self) -> &[RenderResource] {
        &self.resources
    }

    /// Fingerprints bound into the manifest.
    pub fn fingerprints(&self) -> &RenderFingerprints {
        &self.fingerprints
    }

    /// Canonical entry URL for this job.
    pub fn entry_url(&self) -> String {
        format!("{RENDER_SCHEME}://{}/{RENDER_DOCUMENT_PATH}", self.job_id)
    }

    pub(crate) fn payload(&self) -> Arc<RenderPayload> {
        let mut entries = BTreeMap::new();
        entries.insert(
            RENDER_DOCUMENT_PATH.to_owned(),
            ServedFile {
                content_type: "text/html; charset=utf-8".to_owned(),
                bytes: self.html.clone(),
            },
        );
        entries.insert(
            RENDER_STYLESHEET_PATH.to_owned(),
            ServedFile {
                content_type: "text/css; charset=utf-8".to_owned(),
                bytes: self.css.clone(),
            },
        );
        for resource in &self.resources {
            entries.insert(
                resource.path.clone(),
                ServedFile {
                    content_type: resource.content_type.clone(),
                    bytes: resource.bytes.clone(),
                },
            );
        }
        Arc::new(RenderPayload {
            job_id: self.job_id.clone(),
            entries,
            log: Mutex::new(Vec::new()),
        })
    }

    fn candidate_evidence(&self) -> CandidateEvidence {
        CandidateEvidence {
            html_sha256: self.fingerprints.html.clone(),
            css_sha256: self.fingerprints.css.clone(),
            resources_sha256: self.fingerprints.resources.clone(),
            candidate_sha256: self.fingerprints.candidate.clone(),
            html_bytes: self.html.len() as u64,
            css_bytes: self.css.len() as u64,
            resource_count: self.resources.len() as u32,
            resource_bytes: self
                .resources
                .iter()
                .map(|resource| resource.bytes.len() as u64)
                .sum(),
            resources: self
                .resources
                .iter()
                .map(|resource| ResourceFingerprint {
                    path: resource.path.clone(),
                    content_type: resource.content_type.clone(),
                    sha256: resource.digest(),
                    bytes: resource.bytes.len() as u64,
                })
                .collect(),
        }
    }
}

/// One in-memory file in the job protocol.
#[derive(Debug)]
struct ServedFile {
    content_type: String,
    bytes: Vec<u8>,
}

/// Response returned by the in-memory protocol router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProtocolResponse {
    pub(crate) status: u16,
    pub(crate) reason: &'static str,
    pub(crate) content_type: String,
    pub(crate) body: Vec<u8>,
}

impl ProtocolResponse {
    fn text(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            content_type: "text/plain; charset=utf-8".to_owned(),
            body: format!("{status} {reason}\n").into_bytes(),
        }
    }
}

/// The job-scoped, in-memory protocol payload shared with the native bridge.
#[derive(Debug)]
pub(crate) struct RenderPayload {
    job_id: String,
    entries: BTreeMap<String, ServedFile>,
    log: Mutex<Vec<ProtocolRequestRecord>>,
}

impl RenderPayload {
    /// Resolves one absolute protocol URL.
    ///
    /// Only the exact job host and an exact declared path are served. Unknown
    /// jobs are forbidden, escapes and encodings are rejected, and undeclared
    /// files (including files that happen to exist on disk) are not found.
    pub(crate) fn resolve(&self, raw_url: &str) -> ProtocolResponse {
        let response = self.route(raw_url);
        self.record(raw_url, &response);
        response
    }

    fn route(&self, raw_url: &str) -> ProtocolResponse {
        if raw_url
            .chars()
            .any(|character| character == '\\' || character == '\0')
            || raw_url.contains('?')
            || raw_url.contains('#')
            || raw_url.contains('%')
            || raw_url.contains("..")
            || raw_url.contains("./")
        {
            return ProtocolResponse::text(400, "path_escape");
        }
        let Ok(parsed) = Url::parse(raw_url) else {
            return ProtocolResponse::text(400, "invalid_url");
        };
        if parsed.scheme() != RENDER_SCHEME
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.port().is_some()
        {
            return ProtocolResponse::text(400, "invalid_url");
        }
        let host = parsed.host_str().unwrap_or_default();
        if host != self.job_id {
            return ProtocolResponse::text(403, "unknown_job");
        }
        let path = parsed.path();
        if path.contains("//") {
            return ProtocolResponse::text(400, "path_escape");
        }
        let Some(relative) = path.strip_prefix('/') else {
            return ProtocolResponse::text(400, "path_escape");
        };
        if relative.is_empty()
            || relative.split('/').any(|segment| {
                segment.is_empty() || segment == "." || segment == ".." || segment.contains('\\')
            })
        {
            return ProtocolResponse::text(400, "path_escape");
        }
        match self.entries.get(relative) {
            Some(file) => ProtocolResponse {
                status: 200,
                reason: "served",
                content_type: file.content_type.clone(),
                body: file.bytes.clone(),
            },
            None => ProtocolResponse::text(404, "missing_resource"),
        }
    }

    fn record(&self, raw_url: &str, response: &ProtocolResponse) {
        if let Ok(mut log) = self.log.lock() {
            log.push(ProtocolRequestRecord {
                url: raw_url.to_owned(),
                path: Url::parse(raw_url)
                    .map(|url| url.path().to_owned())
                    .unwrap_or_else(|_| raw_url.to_owned()),
                status: response.status,
                reason: response.reason.to_owned(),
            });
        }
    }

    /// Snapshot of every request handled by the job protocol.
    pub(crate) fn protocol_log(&self) -> Vec<ProtocolRequestRecord> {
        self.log.lock().map(|log| log.clone()).unwrap_or_default()
    }

    /// Deterministic in-memory router boundary probe.
    ///
    /// This is a pure self-check of the serving policy, not a network capture.
    /// It is recorded separately from requests observed by the native handler.
    pub(crate) fn router_self_probe(&self) -> RouterSelfProbe {
        let other = if self.job_id == "0".repeat(32) {
            "f".repeat(32)
        } else {
            "0".repeat(32)
        };
        let base = format!("{RENDER_SCHEME}://{}", self.job_id);
        RouterSelfProbe {
            probe_source: "in-memory-router".to_owned(),
            unknown_job_status: self
                .route(&format!("{RENDER_SCHEME}://{other}/index.html"))
                .status,
            path_escape_status: self.route(&format!("{base}/../secret.txt")).status,
            missing_resource_status: self.route(&format!("{base}/missing.png")).status,
            non_candidate_status: self.route(&format!("{base}/secret.txt")).status,
        }
    }
}

/// One request observed by the job-scoped protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolRequestRecord {
    /// Exact URL handed to the protocol handler.
    pub url: String,
    /// Parsed path (or the original string if parsing failed).
    pub path: String,
    /// HTTP status returned to WebKit.
    pub status: u16,
    /// Stable rejection reason or `served`.
    pub reason: String,
}

/// One render timeout input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderBudget {
    requested: Duration,
    remaining_cycle: Option<Duration>,
}

impl RenderBudget {
    /// Creates a budget from the requested per-candidate timeout and the
    /// remaining cycle time, if the host knows it.
    pub fn new(
        requested: Duration,
        remaining_cycle: Option<Duration>,
    ) -> Result<Self, RenderError> {
        if requested.is_zero() {
            return Err(RenderError::InvalidBudget {
                detail: "render timeout must be greater than zero".to_owned(),
            });
        }
        Ok(Self {
            requested,
            remaining_cycle,
        })
    }

    /// Effective timeout: the shorter of the request, the hard 30-second
    /// ceiling, and the remaining cycle budget.
    pub fn effective_timeout(self) -> Duration {
        let requested = self.requested.min(RENDER_HARD_TIMEOUT);
        match self.remaining_cycle {
            Some(remaining) => requested.min(remaining),
            None => requested,
        }
    }

    /// Absolute deadline for this render.
    pub fn deadline(self, now: Instant) -> Instant {
        now + self.effective_timeout()
    }
}

/// Cooperative cancellation shared between the caller and the render bridge.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    state: Arc<CancelState>,
}

#[derive(Debug, Default)]
struct CancelState {
    cancelled: AtomicBool,
    reason: Mutex<Option<String>>,
}

impl CancellationToken {
    /// Creates a token that has not been cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. The first reason wins.
    pub fn cancel(&self, reason: impl Into<String>) {
        if let Ok(mut stored) = self.state.reason.lock()
            && stored.is_none()
        {
            *stored = Some(reason.into());
        }
        self.state.cancelled.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::SeqCst)
    }

    /// The first cancellation reason, if any.
    pub fn reason(&self) -> Option<String> {
        self.state
            .reason
            .lock()
            .ok()
            .and_then(|reason| reason.clone())
    }
}

/// Render failure with the partially captured evidence.
#[derive(Debug)]
pub struct RenderFailure {
    error: RenderError,
    manifest: RenderManifest,
    pngs: Vec<RenderPng>,
}

impl RenderFailure {
    /// Primary failure.
    pub fn error(&self) -> &RenderError {
        &self.error
    }

    /// Manifest marked `incomplete`.
    pub fn manifest(&self) -> &RenderManifest {
        &self.manifest
    }

    /// PNGs captured before the failure.
    pub fn pngs(&self) -> &[RenderPng] {
        &self.pngs
    }

    /// Writes the incomplete manifest and any captured PNGs.
    pub fn write_to(&self, directory: &Path) -> Result<(), RenderError> {
        write_evidence(directory, &self.manifest, &self.pngs)
    }
}

/// Complete render evidence.
#[derive(Debug)]
pub struct RenderEvidence {
    pub(crate) manifest: RenderManifest,
    pub(crate) pngs: Vec<RenderPng>,
}

impl RenderEvidence {
    /// Versioned manifest.
    pub fn manifest(&self) -> &RenderManifest {
        &self.manifest
    }

    /// PNG snapshots.
    pub fn pngs(&self) -> &[RenderPng] {
        &self.pngs
    }

    /// Verifies that every required configuration produced a real PNG and
    /// that the manifest is complete. A partial capture is never accepted.
    pub fn validate(&self) -> Result<(), RenderError> {
        if self.manifest.status != RenderStatus::Complete {
            return Err(RenderError::IncompleteCapture {
                detail: "manifest is not complete".to_owned(),
            });
        }
        if self.manifest.manifest_version != RENDER_MANIFEST_VERSION
            || self.manifest.evidence_source != "wkwebview-native"
        {
            return Err(RenderError::IncompleteCapture {
                detail: "manifest version or native evidence source is not recognised".to_owned(),
            });
        }
        if self.manifest.configurations.len() != RENDER_CONFIGURATIONS.len() {
            return Err(RenderError::IncompleteCapture {
                detail: format!(
                    "expected {} configurations, found {}",
                    RENDER_CONFIGURATIONS.len(),
                    self.manifest.configurations.len()
                ),
            });
        }
        for (expected, actual) in RENDER_CONFIGURATIONS
            .iter()
            .zip(self.manifest.configurations.iter())
        {
            if expected.id != actual.id {
                return Err(RenderError::IncompleteCapture {
                    detail: format!(
                        "configuration order mismatch: expected `{}`, found `{}`",
                        expected.id, actual.id
                    ),
                });
            }
            let png = self
                .pngs
                .iter()
                .find(|png| png.path == actual.png.path)
                .ok_or_else(|| RenderError::IncompleteCapture {
                    detail: format!("PNG `{}` is missing", actual.png.path),
                })?;
            if png.bytes.len() < 8 || !png.bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                return Err(RenderError::IncompleteCapture {
                    detail: format!("PNG `{}` is not a PNG file", actual.png.path),
                });
            }
            if png.pixel_width == 0 || png.pixel_height == 0 {
                return Err(RenderError::IncompleteCapture {
                    detail: format!("PNG `{}` has no pixels", actual.png.path),
                });
            }
            if ContentDigest::sha256(&png.bytes) != actual.png.sha256 {
                return Err(RenderError::IncompleteCapture {
                    detail: format!("PNG `{}` digest does not match", actual.png.path),
                });
            }
            if actual.dom.is_null() || actual.accessibility.is_null() {
                return Err(RenderError::IncompleteCapture {
                    detail: format!(
                        "configuration `{}` is missing DOM or AX evidence",
                        actual.id
                    ),
                });
            }
        }
        if self.manifest.browser.tauri_ipc_injected {
            return Err(RenderError::IncompleteCapture {
                detail: "render webview reports an injected Tauri IPC bridge".to_owned(),
            });
        }
        if self.manifest.hidden_window.visible_to_user
            || !self.manifest.hidden_window.capture_succeeded_while_hidden
        {
            return Err(RenderError::IncompleteCapture {
                detail: "hidden-window capture was not proven".to_owned(),
            });
        }
        if !self.manifest.isolation.is_isolated() {
            return Err(RenderError::IncompleteCapture {
                detail: "website data store isolation was not proven".to_owned(),
            });
        }
        Ok(())
    }

    /// Writes the manifest and PNGs to an evidence directory.
    pub fn write_to(&self, directory: &Path) -> Result<(), RenderError> {
        self.validate()?;
        write_evidence(directory, &self.manifest, &self.pngs)
    }

    /// Reads complete evidence written by the hidden render child.
    ///
    /// Every PNG is read from the canonical evidence directory only; a missing
    /// file, digest mismatch, or unsafe file name is an explicit error. The
    /// returned evidence still has to pass [`Self::validate`] before use.
    pub fn read_from(directory: &Path) -> Result<Self, RenderError> {
        let manifest_path = directory.join("manifest.json");
        let manifest_bytes = std::fs::read(&manifest_path).map_err(|error| RenderError::Io {
            detail: format!("read {}: {error}", manifest_path.display()),
        })?;
        let manifest: RenderManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|error| RenderError::Io {
                detail: format!("parse manifest: {error}"),
            })?;
        let mut pngs = Vec::with_capacity(manifest.configurations.len());
        for configuration in &manifest.configurations {
            let name = &configuration.png.path;
            if name.is_empty()
                || name.contains('/')
                || name.contains('\\')
                || name.contains("..")
                || Path::new(name).is_absolute()
            {
                return Err(RenderError::IncompleteCapture {
                    detail: format!("unsafe PNG file name `{name}`"),
                });
            }
            let bytes = std::fs::read(directory.join(name)).map_err(|error| RenderError::Io {
                detail: format!("read PNG {name}: {error}"),
            })?;
            pngs.push(RenderPng::new(
                name.clone(),
                bytes,
                configuration.png.pixel_width,
                configuration.png.pixel_height,
            ));
        }
        let evidence = Self { manifest, pngs };
        evidence.validate()?;
        Ok(evidence)
    }
}

/// One captured PNG snapshot.
#[derive(Debug, Clone)]
pub struct RenderPng {
    path: String,
    bytes: Vec<u8>,
    pixel_width: u32,
    pixel_height: u32,
}

impl RenderPng {
    pub(crate) fn new(path: String, bytes: Vec<u8>, pixel_width: u32, pixel_height: u32) -> Self {
        Self {
            path,
            bytes,
            pixel_width,
            pixel_height,
        }
    }

    /// Relative file name inside the evidence directory.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Exact PNG bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// PNG width in device pixels.
    pub fn pixel_width(&self) -> u32 {
        self.pixel_width
    }

    /// PNG height in device pixels.
    pub fn pixel_height(&self) -> u32 {
        self.pixel_height
    }
}

/// Final status of one render.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderStatus {
    /// Every required capture completed.
    Complete,
    /// One or more required captures did not complete.
    Incomplete,
}

/// Versioned render evidence manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderManifest {
    /// Manifest format version.
    pub manifest_version: String,
    /// Evidence producer. Always `wkwebview-native` for this bridge.
    pub evidence_source: String,
    /// Job identifier.
    pub job_id: String,
    /// Final status.
    pub status: RenderStatus,
    /// Why the render is incomplete, if it is.
    pub incomplete_reason: Option<String>,
    /// Wall-clock start in Unix milliseconds.
    pub started_at_unix_ms: u64,
    /// Total elapsed time.
    pub duration_ms: u64,
    /// Exact candidate bytes and fingerprints.
    pub candidate: CandidateEvidence,
    /// Browser and policy identity.
    pub browser: BrowserEvidence,
    /// Hidden-window proof.
    pub hidden_window: HiddenWindowEvidence,
    /// Non-persistent store isolation proof.
    pub isolation: IsolationEvidence,
    /// One entry per required configuration.
    pub configurations: Vec<ConfigurationEvidence>,
}

impl RenderManifest {
    pub(crate) fn start(job: &RenderJob) -> Self {
        Self {
            manifest_version: RENDER_MANIFEST_VERSION.to_owned(),
            evidence_source: "wkwebview-native".to_owned(),
            job_id: job.job_id.clone(),
            status: RenderStatus::Incomplete,
            incomplete_reason: Some("render did not finish".to_owned()),
            started_at_unix_ms: unix_millis(),
            duration_ms: 0,
            candidate: job.candidate_evidence(),
            browser: BrowserEvidence::pending(),
            hidden_window: HiddenWindowEvidence::pending(),
            isolation: IsolationEvidence::pending(),
            configurations: Vec::new(),
        }
    }

    /// Whether the manifest represents a complete capture.
    pub fn is_complete(&self) -> bool {
        self.status == RenderStatus::Complete
    }

    pub(crate) fn push(&mut self, configuration: ConfigurationEvidence) {
        self.configurations.push(configuration);
    }

    pub(crate) fn finish(&mut self, started: Instant) {
        self.status = RenderStatus::Complete;
        self.incomplete_reason = None;
        self.duration_ms = elapsed_millis(started);
    }

    pub(crate) fn fail(&mut self, started: Instant, reason: String) {
        self.status = RenderStatus::Incomplete;
        self.incomplete_reason = Some(reason);
        self.duration_ms = elapsed_millis(started);
    }
}

/// Exact candidate digest cover.
///
/// The recipe is `sha256("h3-render-candidate\0" + html + "\0" + css + "\0" +
/// resources)`. It is intentionally separate from the H3 candidate digest so a
/// render receipt can name both the exact HTML digest and the CSS/resource set.
fn candidate_digest(
    html: ContentDigest,
    css: ContentDigest,
    resources: ContentDigest,
) -> ContentDigest {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"h3-render-candidate\0");
    hasher.update(html.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(css.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(resources.as_str().as_bytes());
    ContentDigest::sha256(&hasher.finalize())
}

/// Exact candidate evidence stored in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateEvidence {
    /// HTML digest.
    pub html_sha256: ContentDigest,
    /// CSS digest.
    pub css_sha256: ContentDigest,
    /// Aggregate resource digest.
    pub resources_sha256: ContentDigest,
    /// Aggregate candidate digest.
    pub candidate_sha256: ContentDigest,
    /// HTML byte length.
    pub html_bytes: u64,
    /// CSS byte length.
    pub css_bytes: u64,
    /// Number of declared resources.
    pub resource_count: u32,
    /// Total declared resource bytes.
    pub resource_bytes: u64,
    /// Per-resource digests.
    pub resources: Vec<ResourceFingerprint>,
}

/// One resource fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceFingerprint {
    /// Relative path.
    pub path: String,
    /// Declared content type.
    pub content_type: String,
    /// Exact SHA-256 digest.
    pub sha256: ContentDigest,
    /// Byte length.
    pub bytes: u64,
}

/// Browser and policy identity observed in the render view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserEvidence {
    /// Full user agent.
    pub user_agent: String,
    /// `navigator.appVersion`.
    pub app_version: String,
    /// `navigator.platform`.
    pub platform: String,
    /// `AppleWebKit/...` version parsed from the user agent, when present.
    pub webkit_version: Option<String>,
    /// `navigator.language`.
    pub language: String,
    /// `window.devicePixelRatio` from the render view.
    pub device_pixel_ratio: f64,
    /// JavaScript was enabled for evidence observation.
    pub java_script_enabled: bool,
    /// JavaScript may not open new windows; the native UI delegate also denies.
    pub java_script_can_open_windows: bool,
    /// Native content-rule list identifier.
    pub content_rule_list_identifier: String,
    /// Whether the list compiled successfully.
    pub content_rule_list_compiled: bool,
    /// Number of native content rules.
    pub content_rule_list_rule_count: u32,
    /// The exact encoded rule list installed on the render view.
    pub content_rule_list: Vec<Value>,
    /// Scripts installed by the render bridge itself.
    pub injected_user_script_count: u32,
    /// The render bridge injects no Tauri IPC bootstrap.
    pub tauri_ipc_injected: bool,
}

impl BrowserEvidence {
    pub(crate) fn pending() -> Self {
        Self {
            user_agent: String::new(),
            app_version: String::new(),
            platform: String::new(),
            webkit_version: None,
            language: String::new(),
            device_pixel_ratio: 0.0,
            java_script_enabled: true,
            java_script_can_open_windows: false,
            content_rule_list_identifier: String::new(),
            content_rule_list_compiled: false,
            content_rule_list_rule_count: 0,
            content_rule_list: Vec::new(),
            injected_user_script_count: 0,
            tauri_ipc_injected: false,
        }
    }
}

/// Hidden-window proof.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenWindowEvidence {
    /// Never true for the render window.
    pub visible_to_user: bool,
    /// The window is positioned outside every screen.
    pub offscreen: bool,
    /// Window origin X in screen points.
    pub origin_x: f64,
    /// Window origin Y in screen points.
    pub origin_y: f64,
    /// Window alpha (never used to hide the window).
    pub alpha: f64,
    /// The window was ordered in without activating the application.
    pub ordered_front: bool,
    /// The window was ordered out after capture.
    pub ordered_out: bool,
    /// At least one snapshot succeeded while the window was hidden.
    pub capture_succeeded_while_hidden: bool,
    /// The renderer did not use the main trusted UI webview.
    pub main_ui_webview_used: bool,
}

impl HiddenWindowEvidence {
    pub(crate) fn pending() -> Self {
        Self {
            visible_to_user: false,
            offscreen: true,
            origin_x: f64::NAN,
            origin_y: f64::NAN,
            alpha: 1.0,
            ordered_front: false,
            ordered_out: false,
            capture_succeeded_while_hidden: false,
            main_ui_webview_used: false,
        }
    }
}

/// Cookie and local-storage isolation proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IsolationEvidence {
    /// The render view's website data store is non-persistent.
    pub render_store_persistent: bool,
    /// The render view's data store is the default store.
    pub render_store_is_default_store: bool,
    /// The control view's website data store is persistent.
    pub control_store_persistent: bool,
    /// The default store really received its own probe cookie.
    pub main_store_sees_its_cookie: bool,
    /// The render store really received its own probe cookie.
    pub render_store_sees_its_cookie: bool,
    /// The default store really received its own local-storage canary.
    pub main_store_sees_its_local_storage: bool,
    /// The render store really received its own local-storage canary.
    pub render_store_sees_its_local_storage: bool,
    /// A cookie written to the default store is invisible to the render store.
    pub main_cookie_visible_in_render: bool,
    /// A cookie written to the render store is invisible to the default store.
    pub render_cookie_visible_in_main: bool,
    /// Local storage written in the default store is invisible to the render store.
    pub main_local_storage_visible_in_render: bool,
    /// Local storage written in the render store is invisible to the control view.
    pub render_local_storage_visible_in_main: bool,
    /// Value the render store observed for the main-store canary.
    pub main_local_storage_value_observed_by_render: Option<String>,
    /// Value the control view observed for the render-store canary.
    pub render_local_storage_value_observed_by_control: Option<String>,
    /// Extra non-secret observations.
    pub notes: Vec<String>,
}

impl IsolationEvidence {
    pub(crate) fn pending() -> Self {
        Self {
            render_store_persistent: true,
            render_store_is_default_store: true,
            control_store_persistent: false,
            main_store_sees_its_cookie: false,
            render_store_sees_its_cookie: false,
            main_store_sees_its_local_storage: false,
            render_store_sees_its_local_storage: false,
            main_cookie_visible_in_render: true,
            render_cookie_visible_in_main: true,
            main_local_storage_visible_in_render: true,
            render_local_storage_visible_in_main: true,
            main_local_storage_value_observed_by_render: None,
            render_local_storage_value_observed_by_control: None,
            notes: vec!["isolation was not observed".to_owned()],
        }
    }

    pub(crate) fn is_isolated(&self) -> bool {
        !self.render_store_persistent
            && !self.render_store_is_default_store
            && self.control_store_persistent
            && self.main_store_sees_its_cookie
            && self.render_store_sees_its_cookie
            && self.main_store_sees_its_local_storage
            && self.render_store_sees_its_local_storage
            && !self.main_cookie_visible_in_render
            && !self.render_cookie_visible_in_main
            && !self.main_local_storage_visible_in_render
            && !self.render_local_storage_visible_in_main
    }
}

/// Evidence for one required configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationEvidence {
    /// Stable configuration id.
    pub id: String,
    /// Window viewport in CSS pixels.
    pub viewport: RenderViewport,
    /// Requested appearance.
    pub appearance: RenderAppearance,
    /// Requested page zoom.
    pub page_zoom: f64,
    /// Actual layout viewport reported by the page.
    pub css_viewport: CssViewport,
    /// PNG snapshot.
    pub png: PngEvidence,
    /// Full DOM/layout metrics object.
    pub dom: Value,
    /// Accessibility projection.
    pub accessibility: Value,
    /// Derived overflow/overlap/readability signals.
    pub signals: RenderSignals,
    /// Job protocol requests and JS-visible outcomes.
    pub protocol: ProtocolEvidence,
    /// Time spent on this configuration.
    pub timing_ms: u64,
}

/// CSS viewport as observed by the page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CssViewport {
    /// `window.innerWidth`.
    pub inner_width: u32,
    /// `window.innerHeight`.
    pub inner_height: u32,
    /// `window.devicePixelRatio`.
    pub device_pixel_ratio: f64,
    /// `document.documentElement.scrollWidth`.
    pub scroll_width: u32,
    /// `document.documentElement.scrollHeight`.
    pub scroll_height: u32,
}

/// PNG metadata stored next to the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PngEvidence {
    /// Relative PNG file name.
    pub path: String,
    /// PNG width in device pixels.
    pub pixel_width: u32,
    /// PNG height in device pixels.
    pub pixel_height: u32,
    /// PNG byte length.
    pub bytes: u64,
    /// PNG SHA-256 digest.
    pub sha256: ContentDigest,
}

/// Derived render signals used by later assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderSignals {
    /// The document is wider than the viewport.
    pub page_horizontal_overflow: bool,
    /// Number of elements whose content overflows their box.
    pub overflowing_elements: u32,
    /// Number of overlapping block pairs.
    pub overlapping_blocks: u32,
    /// Aggregate readability failures.
    pub readability_failures: u32,
    /// Smallest rendered font size in CSS pixels.
    pub min_font_size_px: f64,
    /// Smallest rendered line-height ratio.
    pub min_line_height_ratio: f64,
    /// Number of elements below the 12 CSS-pixel comfort floor.
    pub small_text_elements: u32,
    /// Number of text elements below the WCAG AA contrast heuristic.
    pub contrast_failures: u32,
    /// Number of images that failed to decode or load.
    pub failed_images: u32,
    /// Number of inline SVG elements.
    pub svg_elements: u32,
    /// Number of nodes in the accessibility projection.
    pub aria_nodes: u32,
    /// Number of headings in the accessibility projection.
    pub headings: u32,
}

impl RenderSignals {
    /// Derives typed signals from the measured objects.
    pub fn from_evidence(dom: &Value, accessibility: &Value) -> Result<Self, RenderError> {
        let overflow = dom.get("overflow").ok_or_else(|| missing("overflow"))?;
        let overlap = dom.get("overlap").ok_or_else(|| missing("overlap"))?;
        let readability = dom
            .get("readability")
            .ok_or_else(|| missing("readability"))?;
        let document = dom.get("document").ok_or_else(|| missing("document"))?;
        let aria_nodes = accessibility
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or_else(|| missing("accessibility.nodes"))?
            .len() as u32;
        let headings = accessibility
            .get("counts")
            .and_then(|counts| counts.get("heading"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        Ok(Self {
            page_horizontal_overflow: overflow
                .get("pageHorizontal")
                .and_then(Value::as_bool)
                .ok_or_else(|| missing("overflow.pageHorizontal"))?,
            overflowing_elements: array_len(overflow.get("elements"), "overflow.elements")?,
            overlapping_blocks: overlap
                .get("count")
                .and_then(Value::as_u64)
                .ok_or_else(|| missing("overlap.count"))? as u32,
            readability_failures: readability
                .get("failures")
                .and_then(Value::as_u64)
                .ok_or_else(|| missing("readability.failures"))?
                as u32,
            min_font_size_px: readability
                .get("minFontSizePx")
                .and_then(Value::as_f64)
                .ok_or_else(|| missing("readability.minFontSizePx"))?,
            min_line_height_ratio: readability
                .get("minLineHeightRatio")
                .and_then(Value::as_f64)
                .ok_or_else(|| missing("readability.minLineHeightRatio"))?,
            small_text_elements: readability
                .get("smallTextCount")
                .and_then(Value::as_u64)
                .ok_or_else(|| missing("readability.smallTextCount"))?
                as u32,
            contrast_failures: readability
                .get("contrastFailures")
                .and_then(Value::as_u64)
                .ok_or_else(|| missing("readability.contrastFailures"))?
                as u32,
            failed_images: document
                .get("failedImages")
                .and_then(Value::as_u64)
                .ok_or_else(|| missing("document.failedImages"))? as u32,
            svg_elements: document
                .get("svgElements")
                .and_then(Value::as_u64)
                .ok_or_else(|| missing("document.svgElements"))? as u32,
            aria_nodes,
            headings,
        })
    }
}

/// Protocol requests and page-visible outcomes for one configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolEvidence {
    /// Every request observed by the native protocol handler.
    pub requests: Vec<ProtocolRequestRecord>,
    /// An unknown job host was rejected.
    pub unknown_job_rejected: bool,
    /// A path escape or encoded path was rejected.
    pub path_escape_rejected: bool,
    /// An undeclared resource was not found.
    pub missing_resource_rejected: bool,
    /// A non-candidate file on disk was not served.
    pub non_candidate_rejected: bool,
    /// Native new-window requests denied by `WKUIDelegate`.
    pub new_windows_blocked: u32,
    /// Native download decisions denied by the navigation delegates.
    pub downloads_blocked: u32,
    /// Native navigation actions denied by `WKNavigationDelegate`.
    pub navigations_blocked: u32,
    /// Native navigation responses denied by `WKNavigationDelegate`.
    pub responses_blocked: u32,
    /// Page-visible protocol and IPC probe results.
    pub page_probe: Value,
    /// Deterministic in-memory router boundary self-check.
    pub router_self_probe: RouterSelfProbe,
}

/// Router boundary self-check. Explicitly not a network capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterSelfProbe {
    /// Always `in-memory-router` so this is not confused with webview traffic.
    pub probe_source: String,
    /// Status for a URL naming a different job.
    pub unknown_job_status: u16,
    /// Status for a `..` path escape.
    pub path_escape_status: u16,
    /// Status for an undeclared resource.
    pub missing_resource_status: u16,
    /// Status for a non-candidate file name.
    pub non_candidate_status: u16,
}

/// Render errors. No error is converted into a passing capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// The job or one of its inputs is not renderable.
    InvalidJob {
        /// What failed.
        detail: String,
    },
    /// The requested timeout is not usable.
    InvalidBudget {
        /// What failed.
        detail: String,
    },
    /// This build has no native render bridge.
    UnsupportedPlatform {
        /// Host platform.
        platform: String,
    },
    /// A render step exceeded its deadline.
    Timeout {
        /// Step name.
        phase: String,
        /// Effective budget in milliseconds.
        after_ms: u64,
    },
    /// A caller cancelled the render.
    Cancelled {
        /// Cancellation reason.
        reason: String,
    },
    /// The native bridge failed.
    Native {
        /// Step name.
        phase: String,
        /// Non-secret detail.
        detail: String,
    },
    /// A required capture is absent or invalid.
    IncompleteCapture {
        /// What is missing.
        detail: String,
    },
    /// Evidence could not be written.
    Io {
        /// Path or operation.
        detail: String,
    },
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJob { detail } => write!(f, "invalid render job: {detail}"),
            Self::InvalidBudget { detail } => write!(f, "invalid render budget: {detail}"),
            Self::UnsupportedPlatform { platform } => {
                write!(f, "native render is unavailable on {platform}")
            }
            Self::Timeout { phase, after_ms } => {
                write!(f, "render timed out during {phase} after {after_ms} ms")
            }
            Self::Cancelled { reason } => write!(f, "render cancelled: {reason}"),
            Self::Native { phase, detail } => {
                write!(f, "native render failed in {phase}: {detail}")
            }
            Self::IncompleteCapture { detail } => {
                write!(f, "render capture is incomplete: {detail}")
            }
            Self::Io { detail } => write!(f, "render evidence I/O failed: {detail}"),
        }
    }
}

impl std::error::Error for RenderError {}

impl RenderError {
    /// Stable, non-secret failure label for manifests and logs.
    pub fn label(&self) -> String {
        match self {
            Self::InvalidJob { .. } => "invalid_job".to_owned(),
            Self::InvalidBudget { .. } => "invalid_budget".to_owned(),
            Self::UnsupportedPlatform { .. } => "unsupported_platform".to_owned(),
            Self::Timeout { phase, after_ms } => format!("timeout:{phase}:{after_ms}ms"),
            Self::Cancelled { reason } => format!("cancelled:{reason}"),
            Self::Native { phase, detail } => format!("native:{phase}:{detail}"),
            Self::IncompleteCapture { detail } => format!("incomplete:{detail}"),
            Self::Io { detail } => format!("io:{detail}"),
        }
    }
}

/// Renders one candidate using the real, non-privileged WebKit view.
///
/// This call blocks the calling thread while WebKit callbacks run on the
/// AppKit main thread. Call it from a background thread, never from the
/// AppKit main thread.
#[cfg(target_os = "macos")]
#[allow(clippy::result_large_err)]
pub fn render_candidate(
    app: &tauri::AppHandle,
    job: &RenderJob,
    budget: RenderBudget,
    cancellation: &CancellationToken,
) -> Result<RenderEvidence, RenderFailure> {
    super::render_macos::render(app, job, budget, cancellation)
}

/// Non-macOS builds never claim render evidence.
#[cfg(not(target_os = "macos"))]
pub fn render_candidate(
    _app: &tauri::AppHandle,
    job: &RenderJob,
    _budget: RenderBudget,
    _cancellation: &CancellationToken,
) -> Result<RenderEvidence, RenderFailure> {
    let started = Instant::now();
    Err(incomplete_failure(
        started,
        RenderError::UnsupportedPlatform {
            platform: std::env::consts::OS.to_owned(),
        },
        RenderManifest::start(job),
        Vec::new(),
    ))
}

pub(crate) fn incomplete_failure(
    started: Instant,
    error: RenderError,
    mut manifest: RenderManifest,
    pngs: Vec<RenderPng>,
) -> RenderFailure {
    manifest.fail(started, error.label());
    RenderFailure {
        error,
        manifest,
        pngs,
    }
}

fn missing(field: &str) -> RenderError {
    RenderError::IncompleteCapture {
        detail: format!("evidence field `{field}` is missing"),
    }
}

fn array_len(value: Option<&Value>, field: &str) -> Result<u32, RenderError> {
    value
        .and_then(Value::as_array)
        .map(|items| items.len() as u32)
        .ok_or_else(|| missing(field))
}

fn validate_relative_path(path: &str, label: &str) -> Result<(), RenderError> {
    if path.is_empty() || path.len() > 512 {
        return Err(RenderError::InvalidJob {
            detail: format!("{label} path length is outside 1-512 bytes"),
        });
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(RenderError::InvalidJob {
            detail: format!("{label} path `{path}` must be relative"),
        });
    }
    if path
        .chars()
        .any(|character| character == '\\' || character == '\0' || character == '%')
        || path.contains('?')
        || path.contains('#')
    {
        return Err(RenderError::InvalidJob {
            detail: format!("{label} path `{path}` contains a forbidden character"),
        });
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(RenderError::InvalidJob {
            detail: format!("{label} path `{path}` contains an empty or escaping segment"),
        });
    }
    Ok(())
}

fn is_allowed_resource_content_type(content_type: &str) -> bool {
    matches!(
        content_type,
        "image/svg+xml"
            | "image/png"
            | "image/jpeg"
            | "image/gif"
            | "image/webp"
            | "font/woff"
            | "font/woff2"
            | "text/css; charset=utf-8"
            | "text/plain; charset=utf-8"
    )
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

fn write_evidence(
    directory: &Path,
    manifest: &RenderManifest,
    pngs: &[RenderPng],
) -> Result<(), RenderError> {
    std::fs::create_dir_all(directory).map_err(|error| RenderError::Io {
        detail: format!("create {}: {error}", directory.display()),
    })?;
    for png in pngs {
        if png.path.contains('/') || png.path.contains('\\') || png.path.contains("..") {
            return Err(RenderError::Io {
                detail: format!("unsafe PNG file name `{}`", png.path),
            });
        }
        std::fs::write(directory.join(&png.path), &png.bytes).map_err(|error| RenderError::Io {
            detail: format!("write {}: {error}", png.path),
        })?;
    }
    let json = serde_json::to_vec_pretty(manifest).map_err(|error| RenderError::Io {
        detail: format!("serialize manifest: {error}"),
    })?;
    let temporary = directory.join("manifest.json.tmp");
    std::fs::write(&temporary, json).map_err(|error| RenderError::Io {
        detail: format!("write manifest: {error}"),
    })?;
    std::fs::rename(&temporary, directory.join("manifest.json")).map_err(|error| {
        RenderError::Io {
            detail: format!("commit manifest: {error}"),
        }
    })?;
    Ok(())
}

// Shared assertions for the manifest helpers below.
#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> RenderJob {
        RenderJob::new(
            "0123456789abcdef0123456789abcdef",
            b"<!doctype html><html><body><h1>fixture</h1></body></html>".to_vec(),
            b"body { color: black; }".to_vec(),
            vec![
                RenderResource::new(
                    "assets/diagram.svg",
                    "image/svg+xml",
                    b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>".to_vec(),
                )
                .expect("resource"),
            ],
        )
        .expect("job")
    }

    #[test]
    fn protocol_serves_only_declared_job_paths() {
        let payload = job().payload();
        assert_eq!(payload.resolve(&job().entry_url()).status, 200);
        assert_eq!(
            payload
                .resolve("h3render://0123456789abcdef0123456789abcdef/candidate.css")
                .status,
            200
        );
        assert_eq!(
            payload
                .resolve("h3render://0123456789abcdef0123456789abcdef/assets/diagram.svg")
                .status,
            200
        );
        assert_eq!(
            payload
                .resolve("h3render://ffffffffffffffffffffffffffffffff/index.html")
                .status,
            403
        );
        assert_eq!(
            payload
                .resolve("h3render://0123456789abcdef0123456789abcdef/secret.txt")
                .status,
            404
        );
        assert_eq!(
            payload
                .resolve("h3render://0123456789abcdef0123456789abcdef/../secret.txt")
                .status,
            400
        );
        assert_eq!(
            payload
                .resolve("h3render://0123456789abcdef0123456789abcdef/%2e%2e/secret.txt")
                .status,
            400
        );
        assert_eq!(
            payload
                .resolve("h3render://0123456789abcdef0123456789abcdef/index.html?x=1")
                .status,
            400
        );
        let log = payload.protocol_log();
        assert!(log.iter().any(|record| record.reason == "unknown_job"));
        assert!(log.iter().any(|record| record.reason == "path_escape"));
        assert!(log.iter().any(|record| record.reason == "missing_resource"));

        let probe = payload.router_self_probe();
        assert_eq!(probe.probe_source, "in-memory-router");
        assert_eq!(probe.unknown_job_status, 403);
        assert_eq!(probe.path_escape_status, 400);
        assert_eq!(probe.missing_resource_status, 404);
        assert_eq!(probe.non_candidate_status, 404);
    }

    #[test]
    fn budget_uses_the_shorter_of_the_candidate_and_cycle_limits() {
        let budget = RenderBudget::new(Duration::from_secs(30), Some(Duration::from_secs(5)))
            .expect("budget");
        assert_eq!(budget.effective_timeout(), Duration::from_secs(5));
        let budget = RenderBudget::new(Duration::from_secs(120), None).expect("budget");
        assert_eq!(budget.effective_timeout(), RENDER_HARD_TIMEOUT);
        let budget =
            RenderBudget::new(Duration::from_secs(10), Some(Duration::ZERO)).expect("budget");
        assert_eq!(budget.effective_timeout(), Duration::ZERO);
        let budget = RenderBudget::new(Duration::from_secs(10), Some(Duration::from_secs(60)))
            .expect("budget");
        assert_eq!(budget.effective_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn cancellation_is_first_reason_wins_and_visible_to_every_clone() {
        let token = CancellationToken::new();
        let clone = token.clone();
        clone.cancel("timeout");
        token.cancel("human");
        assert!(token.is_cancelled());
        assert_eq!(token.reason().as_deref(), Some("timeout"));
    }

    #[test]
    fn invalid_jobs_and_resources_are_rejected() {
        assert!(
            RenderJob::new("short", b"x".to_vec(), b"y".to_vec(), Vec::new()).is_err(),
            "short job ids are rejected"
        );
        assert!(
            RenderResource::new("../secret.txt", "text/plain; charset=utf-8", Vec::new()).is_err()
        );
        assert!(
            RenderResource::new("assets/a.exe", "application/octet-stream", Vec::new()).is_err()
        );
        assert!(
            RenderResource::new(RENDER_DOCUMENT_PATH, "text/html; charset=utf-8", Vec::new())
                .is_err()
        );
        assert!(
            RenderJob::new(
                "0123456789abcdef",
                b"x".to_vec(),
                b"y".to_vec(),
                vec![
                    RenderResource::new("a.svg", "image/svg+xml", Vec::new()).expect("first"),
                    RenderResource::new("a.svg", "image/svg+xml", Vec::new()).expect("second"),
                ],
            )
            .is_err(),
            "duplicate resource paths are rejected"
        );
    }

    #[test]
    fn signals_require_every_measured_field() {
        let dom = serde_json::json!({
            "overflow": {"pageHorizontal": false, "elements": []},
            "overlap": {"count": 1},
            "readability": {
                "failures": 2,
                "minFontSizePx": 11.0,
                "minLineHeightRatio": 1.1,
                "smallTextCount": 1,
                "contrastFailures": 1,
            },
            "document": {"failedImages": 0, "svgElements": 3},
        });
        let ax = serde_json::json!({"nodes": [{"role": "heading"}], "counts": {"heading": 1}});
        let signals = RenderSignals::from_evidence(&dom, &ax).expect("signals");
        assert!(!signals.page_horizontal_overflow);
        assert_eq!(signals.overlapping_blocks, 1);
        assert_eq!(signals.aria_nodes, 1);
        assert_eq!(signals.headings, 1);
        let broken = serde_json::json!({"overflow": {}});
        assert!(RenderSignals::from_evidence(&broken, &ax).is_err());
    }

    #[test]
    fn the_manifest_covers_the_fixed_render_matrix() {
        assert_eq!(RENDER_CONFIGURATIONS.len(), 8);
        let ids = RENDER_CONFIGURATIONS
            .iter()
            .map(|configuration| configuration.id)
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "desktop-light",
                "desktop-dark",
                "desktop-zoom-200",
                "desktop-zoom-200-dark",
                "mobile-light",
                "mobile-dark",
                "mobile-zoom-200",
                "mobile-zoom-200-dark"
            ]
        );
        assert!(RENDER_CONFIGURATIONS.iter().any(|configuration| {
            configuration.viewport.width == 1_280 && configuration.viewport.height == 800
        }));
        assert!(RENDER_CONFIGURATIONS.iter().any(|configuration| {
            configuration.viewport.width == 390 && configuration.viewport.height == 844
        }));
        assert!(
            RENDER_CONFIGURATIONS
                .iter()
                .any(|configuration| { configuration.appearance == RenderAppearance::Dark })
        );
        assert!(
            RENDER_CONFIGURATIONS
                .iter()
                .any(|configuration| { configuration.page_zoom == 2.0 })
        );
    }
}
