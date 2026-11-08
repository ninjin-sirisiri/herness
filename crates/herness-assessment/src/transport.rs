//! Tool-less assessment HTTP transport.
//!
//! The transport owns only the parts that must be identical for every
//! assessment provider:
//!
//! * it never sends `tools` or `tool_choice` and rejects a payload that declares
//!   them,
//! * it resolves the credential through the existing H1
//!   [`CredentialPort`](herness_core::CredentialPort) at send time,
//! * it attaches the credential only to the exact configured origin and never
//!   follows redirects,
//! * it enforces a timeout of at most 60 seconds (or the shorter remaining run
//!   deadline), cooperative cancellation, and a same-connection retry budget,
//! * it validates required text/image modalities against the registered
//!   connection capabilities before sending,
//! * it accepts image bytes only and never fetches an image URL,
//! * it does not reserve money, record cost, or persist any request or
//!   response. Those belong to the upper H2 request gate and budget ledger.
//!
//! Wire schemas for individual providers are deliberately not implemented
//! here. A caller supplies the tool-less JSON body and parses the returned
//! bytes with its provider-specific adapter.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use herness_core::{
    AuthMethod, ConnectionCapabilities, ConnectionDirectory, ConnectionError, ConnectionId,
    CredentialKind, CredentialPort, Endpoint, EndpointClass, InputModality, Origin, Provider,
    RedirectAuthDecision, redirect_auth_decision,
};
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, LOCATION, RETRY_AFTER,
};
use serde_json::Value;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::error::{AssessmentError, AssessmentErrorKind};

/// Hard upper bound for one assessment request, including retries.
pub const MAX_ASSESSMENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of additional attempts on the same connection.
pub const MAX_ADDITIONAL_RETRIES: u8 = 2;

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_IMAGE_BYTES: usize = 20 * 1024 * 1024;
const MAX_MODEL_CHARS: usize = 256;
const BASE_RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(2)];
const DEFAULT_JITTER_MAX: Duration = Duration::from_millis(250);
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Cooperative cancellation handle shared with one assessment request.
///
/// The handle can be cloned into a stop controller. Cancelling it stops an
/// in-flight request and its retry wait; it never turns into a retry.
#[derive(Debug, Clone)]
pub struct CancelToken {
    sender: watch::Sender<bool>,
    receiver: watch::Receiver<bool>,
}

impl CancelToken {
    /// Creates an uncancelled token.
    pub fn new() -> Self {
        let (sender, receiver) = watch::channel(false);
        Self { sender, receiver }
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        let _ = self.sender.send(true);
    }

    /// Whether cancellation has already been requested.
    pub fn is_cancelled(&self) -> bool {
        *self.receiver.borrow()
    }

    async fn cancelled(&self) {
        let mut receiver = self.receiver.clone();
        if *receiver.borrow() {
            return;
        }
        let _ = receiver.changed().await;
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Timeout and cancellation inputs for one assessment request.
#[derive(Debug, Clone)]
pub struct TransportControl {
    remaining: Option<Duration>,
    cancel: CancelToken,
}

impl TransportControl {
    /// Creates a control without a run deadline.
    pub fn new(cancel: CancelToken) -> Self {
        Self {
            remaining: None,
            cancel,
        }
    }

    /// Sets the remaining run deadline. The request timeout is the shorter of
    /// this value and [`MAX_ASSESSMENT_TIMEOUT`].
    pub fn with_remaining(mut self, remaining: Duration) -> Self {
        self.remaining = Some(remaining);
        self
    }

    /// Remaining run deadline supplied by the caller, if any.
    pub const fn remaining(&self) -> Option<Duration> {
        self.remaining
    }

    /// Cancellation handle for this request.
    pub const fn cancel_token(&self) -> &CancelToken {
        &self.cancel
    }

    /// Effective request timeout.
    pub fn timeout(&self) -> Duration {
        self.remaining.map_or(MAX_ASSESSMENT_TIMEOUT, |remaining| {
            remaining.min(MAX_ASSESSMENT_TIMEOUT)
        })
    }
}

impl Default for TransportControl {
    fn default() -> Self {
        Self::new(CancelToken::new())
    }
}

/// Limited same-connection retry policy.
///
/// The H2 default waits one second after the first retryable failure and two
/// seconds after the second, plus up to 250 ms of jitter. A provider
/// `Retry-After` value replaces the base wait only when it fits inside the
/// remaining deadline. There is no provider, model, or connection fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    base_delays: [Duration; 2],
    jitter_max: Duration,
}

impl RetryPolicy {
    /// H2 default: two additional attempts, 1 s/2 s base waits, and jitter.
    pub const fn h2_default() -> Self {
        Self {
            base_delays: BASE_RETRY_DELAYS,
            jitter_max: DEFAULT_JITTER_MAX,
        }
    }

    /// Deterministic 1 s/2 s policy without jitter. Intended for tests.
    pub const fn without_jitter() -> Self {
        Self {
            base_delays: BASE_RETRY_DELAYS,
            jitter_max: Duration::ZERO,
        }
    }

    /// Deterministic policy with explicit base waits and no jitter.
    pub const fn with_base_delays(base_delays: [Duration; 2]) -> Self {
        Self {
            base_delays,
            jitter_max: Duration::ZERO,
        }
    }

    /// Base wait values.
    pub const fn base_delays(self) -> [Duration; 2] {
        self.base_delays
    }

    /// Maximum additional jitter.
    pub const fn jitter_max(self) -> Duration {
        self.jitter_max
    }

    /// Maximum number of additional attempts.
    pub const fn max_additional_retries(self) -> u8 {
        MAX_ADDITIONAL_RETRIES
    }

    fn delay(self, retry_index: usize) -> Duration {
        let base = self
            .base_delays
            .get(retry_index)
            .copied()
            .unwrap_or(self.base_delays[1]);
        base + self.jitter()
    }

    fn jitter(self) -> Duration {
        if self.jitter_max.is_zero() {
            return Duration::ZERO;
        }
        let max_millis = u64::try_from(self.jitter_max.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| {
                u64::from(duration.subsec_nanos())
                    ^ duration.as_secs().rotate_left(17)
                    ^ (duration.subsec_millis() as u64)
            })
            .unwrap_or(0);
        Duration::from_millis(seed % max_millis)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::h2_default()
    }
}

/// An assessment payload with no tool declarations.
///
/// Construction rejects a top-level `tools` or `tool_choice` field instead of
/// silently stripping it. The transport never adds either field.
#[derive(Clone, PartialEq)]
pub struct ToolLessPayload(Value);

impl ToolLessPayload {
    /// Wraps a JSON object that must not declare tools.
    ///
    /// An external image reference (`image_url`, `imageUrl`, or `image_uri`) is
    /// rejected because assessment images must be caller-provided bytes.
    pub fn new(value: Value) -> Result<Self, AssessmentError> {
        let object = value
            .as_object()
            .ok_or_else(|| AssessmentError::new(AssessmentErrorKind::InvalidRequest))?;
        if object.contains_key("tools") || object.contains_key("tool_choice") {
            return Err(AssessmentError::new(AssessmentErrorKind::ToolUseNotAllowed));
        }
        if contains_external_image_reference(&value) {
            return Err(AssessmentError::new(AssessmentErrorKind::ExternalImageUrl));
        }
        Ok(Self(value))
    }

    fn value(&self) -> &Value {
        &self.0
    }
}

impl fmt::Debug for ToolLessPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ToolLessPayload([REDACTED])")
    }
}

fn contains_external_image_reference(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            if matches!(
                key.as_str(),
                "image_url" | "imageurl" | "image_uri" | "imageuri"
            ) {
                return image_reference_is_external(value);
            }
            if key == "type"
                && value
                    .as_str()
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("image_url"))
            {
                // The URL itself is checked where it appears.
                return false;
            }
            contains_external_image_reference(value)
        }),
        Value::Array(items) => items.iter().any(contains_external_image_reference),
        _ => false,
    }
}

/// Only an inline `data:image/...;base64,` value represents caller-provided
/// bytes. Any other image reference would make the provider fetch content the
/// caller did not supply.
fn image_reference_is_external(value: &Value) -> bool {
    let url = match value {
        Value::String(url) => Some(url.as_str()),
        Value::Object(object) => object.get("url").and_then(Value::as_str),
        _ => None,
    };
    !url.is_some_and(inline_image_data_url)
}

fn inline_image_data_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("data:") else {
        return false;
    };
    let Some((metadata, payload)) = rest.split_once(',') else {
        return false;
    };
    let Some(media_type) = metadata
        .trim()
        .to_ascii_lowercase()
        .strip_suffix(";base64")
        .map(str::to_owned)
    else {
        return false;
    };
    matches!(
        media_type.as_str(),
        "image/png" | "image/jpeg" | "image/webp" | "image/gif"
    ) && !payload.is_empty()
}

/// One caller-provided image.
///
/// The bytes are held in memory and are never fetched from a URL. Debug output
/// reports only the media type and byte length.
#[derive(Clone, PartialEq, Eq)]
pub struct ImageInput {
    media_type: String,
    bytes: Vec<u8>,
}

impl ImageInput {
    /// Creates a validated image from caller-provided bytes.
    pub fn new(
        media_type: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, AssessmentError> {
        let media_type = media_type.into().trim().to_ascii_lowercase();
        if !matches!(
            media_type.as_str(),
            "image/png" | "image/jpeg" | "image/webp" | "image/gif"
        ) {
            return Err(AssessmentError::new(AssessmentErrorKind::InvalidRequest));
        }
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
            return Err(AssessmentError::new(AssessmentErrorKind::InvalidRequest));
        }
        Ok(Self { media_type, bytes })
    }

    /// Normalized media type.
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Caller-provided bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ImageInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageInput")
            .field("media_type", &self.media_type)
            .field(
                "bytes",
                &format_args!("[REDACTED; {} bytes]", self.bytes.len()),
            )
            .finish()
    }
}

/// An image source supplied by a caller.
#[derive(Clone, PartialEq, Eq)]
pub enum ImageSource {
    /// Caller-provided bytes.
    Bytes(ImageInput),
    /// An external URL. Assessment rejects it and never fetches it.
    Url(String),
}

impl fmt::Debug for ImageSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(image) => f.debug_tuple("Bytes").field(image).finish(),
            Self::Url(_) => f.write_str("Url([REDACTED])"),
        }
    }
}

/// One tool-less assessment request.
///
/// The caller owns the provider wire body. The transport validates that it is
/// an object with no tools, checks required modalities, and sends it unchanged.
#[derive(Clone, PartialEq)]
pub struct AssessmentRequest {
    connection: ConnectionId,
    model: String,
    body: ToolLessPayload,
    images: Vec<ImageInput>,
    require_image: bool,
}

impl AssessmentRequest {
    /// Creates a request with text as the default required modality.
    pub fn new(
        connection: ConnectionId,
        model: impl Into<String>,
        body: Value,
    ) -> Result<Self, AssessmentError> {
        let model = model.into();
        let trimmed = model.trim();
        if trimmed.is_empty()
            || trimmed.chars().count() > MAX_MODEL_CHARS
            || trimmed.chars().any(char::is_control)
        {
            return Err(AssessmentError::new(AssessmentErrorKind::InvalidRequest));
        }
        Ok(Self {
            connection,
            model: trimmed.to_owned(),
            body: ToolLessPayload::new(body)?,
            images: Vec::new(),
            require_image: false,
        })
    }

    /// Adds caller-provided image bytes and requires image support.
    pub fn with_image(mut self, image: ImageInput) -> Self {
        self.images.push(image);
        self.require_image = true;
        self
    }

    /// Adds image sources. Any URL is rejected before a request is sent.
    pub fn with_image_sources<I>(mut self, sources: I) -> Result<Self, AssessmentError>
    where
        I: IntoIterator<Item = ImageSource>,
    {
        for source in sources {
            match source {
                ImageSource::Bytes(image) => {
                    self.images.push(image);
                    self.require_image = true;
                }
                ImageSource::Url(_) => {
                    return Err(AssessmentError::new(AssessmentErrorKind::ExternalImageUrl));
                }
            }
        }
        Ok(self)
    }

    /// Requires image support without attaching an image to the wire body.
    pub fn require_image(mut self) -> Self {
        self.require_image = true;
        self
    }

    /// Selected connection.
    pub const fn connection(&self) -> ConnectionId {
        self.connection
    }

    /// Declared request model.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Caller-provided images.
    pub fn images(&self) -> &[ImageInput] {
        &self.images
    }

    /// Modalities that must be checked before send.
    pub fn required_modalities(&self) -> Vec<InputModality> {
        let mut modalities = vec![InputModality::Text];
        if self.require_image || !self.images.is_empty() {
            modalities.push(InputModality::Image);
        }
        modalities
    }
}

impl fmt::Debug for AssessmentRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssessmentRequest")
            .field("connection", &self.connection)
            .field("model", &self.model)
            .field("body", &"[REDACTED]")
            .field("images", &self.images.len())
            .field("require_image", &self.require_image)
            .finish()
    }
}

/// Successful assessment HTTP response.
///
/// The raw body is available to the provider-specific adapter but is hidden
/// from Debug output and is never serializable.
#[derive(Clone, PartialEq, Eq)]
pub struct AssessmentResponse {
    status: u16,
    attempts: u8,
    body: Vec<u8>,
}

impl AssessmentResponse {
    /// HTTP status.
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Number of HTTP attempts that produced this response.
    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    /// Raw response bytes for the provider-specific adapter.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Parses the body as JSON without echoing the body on failure.
    pub fn json(&self) -> Result<Value, AssessmentError> {
        serde_json::from_slice(&self.body).map_err(|_| {
            AssessmentError::new(AssessmentErrorKind::InvalidResponse)
                .with_status(self.status)
                .with_attempts(self.attempts)
        })
    }

    /// Top-level provider-reported model, when present and safe to display.
    pub fn reported_model(&self) -> Option<String> {
        let value: Value = serde_json::from_slice(&self.body).ok()?;
        let model = value.get("model")?.as_str()?.trim();
        if model.is_empty()
            || model.chars().count() > MAX_MODEL_CHARS
            || model.chars().any(char::is_control)
        {
            return None;
        }
        Some(model.to_owned())
    }
}

impl fmt::Debug for AssessmentResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssessmentResponse")
            .field("status", &self.status)
            .field("attempts", &self.attempts)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Provider bases used by the assessment transport.
///
/// Production hosts use [`Self::official`]. Tests and local integration runs
/// use [`Self::for_loopback`], which rejects any non-loopback host so a
/// credential cannot be redirected to an arbitrary origin by configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentEndpoints {
    typesafe_base: Endpoint,
    openai_base: Endpoint,
    anthropic_base: Endpoint,
}

impl AssessmentEndpoints {
    /// Official Jev System One, OpenAI, and Anthropic bases.
    pub fn official() -> Self {
        Self {
            typesafe_base: Endpoint::parse("https://api.typesafe.ai")
                .expect("static TypeSafe endpoint is valid"),
            openai_base: Endpoint::parse("https://api.openai.com/v1")
                .expect("static OpenAI endpoint is valid"),
            anthropic_base: Endpoint::parse("https://api.anthropic.com")
                .expect("static Anthropic endpoint is valid"),
        }
    }

    /// Loopback bases for transport tests. Every value must resolve to a
    /// loopback host.
    pub fn for_loopback(
        typesafe_base: impl AsRef<str>,
        openai_base: impl AsRef<str>,
        anthropic_base: impl AsRef<str>,
    ) -> Result<Self, AssessmentError> {
        Ok(Self {
            typesafe_base: loopback_endpoint(typesafe_base.as_ref())?,
            openai_base: loopback_endpoint(openai_base.as_ref())?,
            anthropic_base: loopback_endpoint(anthropic_base.as_ref())?,
        })
    }

    /// Resolves the request URL for an endpoint class. Assessment-only classes
    /// use fixed bases; only OpenAI-compatible connections use their configured
    /// endpoint.
    fn url_for(
        &self,
        endpoint_class: EndpointClass,
        settings: &herness_core::ConnectionSettings,
    ) -> Result<(String, Endpoint), AssessmentError> {
        let (base, path) = match endpoint_class {
            EndpointClass::TypeSafeSystemOne => (&self.typesafe_base, "v1/systemone"),
            EndpointClass::OpenAiDecisions => (&self.openai_base, "decisions"),
            EndpointClass::OpenAiResponses => (&self.openai_base, "responses"),
            EndpointClass::AnthropicMessages => (&self.anthropic_base, "v1/messages"),
            EndpointClass::OpenAiCompletions => {
                let base = settings
                    .endpoint()
                    .ok_or_else(|| AssessmentError::new(AssessmentErrorKind::CapabilityMismatch))?;
                (base, "chat/completions")
            }
        };
        let url = join_url(&base.as_url(), path);
        let endpoint = Endpoint::parse(&url)
            .map_err(|_| AssessmentError::new(AssessmentErrorKind::CapabilityMismatch))?;
        Ok((endpoint.as_url(), endpoint))
    }
}

fn loopback_endpoint(value: &str) -> Result<Endpoint, AssessmentError> {
    let endpoint = Endpoint::parse(value).map_err(|_| AssessmentError::invalid_configuration())?;
    if !endpoint.is_loopback() {
        return Err(AssessmentError::invalid_configuration());
    }
    Ok(endpoint)
}

fn join_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthHeader {
    Bearer,
    AnthropicApiKey,
}

impl AuthHeader {
    fn for_capabilities(capabilities: &ConnectionCapabilities) -> Self {
        match capabilities.provider() {
            Provider::Anthropic => Self::AnthropicApiKey,
            Provider::OpenAi | Provider::OpenAiCompatible | Provider::TypeSafe => Self::Bearer,
        }
    }

    fn apply(
        self,
        builder: reqwest::RequestBuilder,
        secret: &str,
    ) -> Result<reqwest::RequestBuilder, AssessmentError> {
        let value = match self {
            Self::Bearer => format!("Bearer {secret}"),
            Self::AnthropicApiKey => secret.to_owned(),
        };
        let value = HeaderValue::from_str(&value)
            .map_err(|_| AssessmentError::new(AssessmentErrorKind::CredentialUnavailable))?;
        Ok(match self {
            Self::Bearer => builder.header(AUTHORIZATION, value),
            Self::AnthropicApiKey => builder
                .header("x-api-key", value)
                .header("anthropic-version", ANTHROPIC_VERSION),
        })
    }
}

struct TransportInner {
    client: reqwest::Client,
    credentials: Arc<dyn CredentialPort + Send + Sync>,
    directory: ConnectionDirectory,
    endpoints: AssessmentEndpoints,
}

/// Tool-less assessment HTTP transport.
///
/// The value owns a small internal runtime so its synchronous `send` method can
/// be used from the existing synchronous host adapters. It has no store,
/// billing, cost, or persistence dependency.
pub struct AssessmentTransport {
    runtime: tokio::runtime::Runtime,
    inner: Arc<TransportInner>,
    retry: RetryPolicy,
}

impl AssessmentTransport {
    /// Creates a transport over the H1 credential port and connection
    /// directory.
    pub fn new(
        credentials: Arc<dyn CredentialPort + Send + Sync>,
        directory: ConnectionDirectory,
        endpoints: AssessmentEndpoints,
    ) -> Result<Self, AssessmentError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // Assessment traffic is low volume. Avoiding idle pooled sockets
            // keeps a retry from racing a provider's `Connection: close` and
            // makes pre-send connection failures unambiguous.
            .pool_max_idle_per_host(0)
            .no_proxy()
            .build()
            .map_err(|_| AssessmentError::new(AssessmentErrorKind::Internal))?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("herness-assessment")
            .build()
            .map_err(|_| AssessmentError::new(AssessmentErrorKind::Internal))?;
        Ok(Self {
            runtime,
            inner: Arc::new(TransportInner {
                client,
                credentials,
                directory,
                endpoints,
            }),
            retry: RetryPolicy::h2_default(),
        })
    }

    /// Replaces the default retry policy.
    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Reads the registered capabilities for one connection without sending.
    ///
    /// Assessment adapters use this to prove that the connection/profile they
    /// were given is the exact registered connection, not a stale or
    /// re-pointed value.
    pub fn capabilities(
        &self,
        connection: ConnectionId,
    ) -> Result<ConnectionCapabilities, AssessmentError> {
        self.inner
            .directory
            .capabilities(connection)
            .map_err(|error| match error {
                ConnectionError::UnknownConnection { .. } => {
                    AssessmentError::new(AssessmentErrorKind::UnknownConnection)
                }
                _ => AssessmentError::new(AssessmentErrorKind::CapabilityMismatch),
            })
    }

    /// Sends one assessment request.
    ///
    /// The credential is resolved for every attempt, but only the selected
    /// connection is ever used. No redirect is followed and no provider,
    /// model, or connection fallback exists.
    pub fn send(
        &self,
        request: AssessmentRequest,
        control: TransportControl,
    ) -> Result<AssessmentResponse, AssessmentError> {
        let inner = Arc::clone(&self.inner);
        let retry = self.retry;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        self.runtime.spawn(async move {
            let _ = sender.send(inner.send(request, control, retry).await);
        });
        receiver
            .recv()
            .map_err(|_| AssessmentError::new(AssessmentErrorKind::Internal))?
    }
}

impl TransportInner {
    async fn send(
        &self,
        request: AssessmentRequest,
        control: TransportControl,
        retry: RetryPolicy,
    ) -> Result<AssessmentResponse, AssessmentError> {
        let timeout = control.timeout();
        if timeout.is_zero() {
            return Err(AssessmentError::new(AssessmentErrorKind::DeadlineReached));
        }
        let settings = self
            .directory
            .get(request.connection())
            .map_err(|_| AssessmentError::new(AssessmentErrorKind::UnknownConnection))?;
        if settings.model() != request.model() {
            return Err(AssessmentError::new(AssessmentErrorKind::ModelMismatch));
        }
        let capabilities = settings
            .capabilities()
            .map_err(|_| AssessmentError::new(AssessmentErrorKind::CapabilityMismatch))?;
        if !capabilities.allows_assessment() {
            return Err(AssessmentError::new(
                AssessmentErrorKind::CapabilityMismatch,
            ));
        }
        if capabilities.endpoint_class() == EndpointClass::OpenAiDecisions
            && capabilities.auth_method() != AuthMethod::ApiKey
        {
            return Err(AssessmentError::new(
                AssessmentErrorKind::CapabilityMismatch,
            ));
        }
        if capabilities.provider() == Provider::TypeSafe
            && capabilities.auth_method() != AuthMethod::ApiKey
        {
            return Err(AssessmentError::new(
                AssessmentErrorKind::CapabilityMismatch,
            ));
        }
        if matches!(
            capabilities.endpoint_class(),
            EndpointClass::TypeSafeSystemOne | EndpointClass::OpenAiDecisions
        ) && settings.endpoint().is_some()
        {
            // Assessment-only classes use fixed provider origins. A custom
            // endpoint is a registration error, never a routing option.
            return Err(AssessmentError::new(
                AssessmentErrorKind::CapabilityMismatch,
            ));
        }
        for modality in request.required_modalities() {
            if !capabilities.input().supports(modality) {
                return Err(AssessmentError::new(
                    AssessmentErrorKind::UnsupportedModality,
                ));
            }
        }
        let (url, endpoint) = self
            .endpoints
            .url_for(capabilities.endpoint_class(), &settings)?;
        let origin = Origin::from_endpoint(&endpoint);
        let auth = AuthHeader::for_capabilities(&capabilities);
        let expected_kind = match capabilities.auth_method() {
            AuthMethod::ApiKey => CredentialKind::ApiKey,
            AuthMethod::ChatGptLogin => CredentialKind::OAuthToken,
        };
        let deadline = Instant::now() + timeout;
        let mut attempts = 0_u8;

        loop {
            if control.cancel_token().is_cancelled() {
                return Err(
                    AssessmentError::new(AssessmentErrorKind::Cancelled).with_attempts(attempts)
                );
            }
            if Instant::now() >= deadline {
                return Err(AssessmentError::new(AssessmentErrorKind::DeadlineReached)
                    .with_attempts(attempts));
            }
            let credentials = Arc::clone(&self.credentials);
            let connection = request.connection();
            let resolving = tokio::task::spawn_blocking(move || credentials.resolve(&connection));
            let credential = tokio::select! {
                biased;
                _ = control.cancel_token().cancelled() => {
                    return Err(
                        AssessmentError::new(AssessmentErrorKind::Cancelled)
                            .with_attempts(attempts),
                    );
                }
                result = tokio::time::timeout_at(deadline, resolving) => {
                    match result {
                        Ok(Ok(Ok(credential))) => credential,
                        Ok(Ok(Err(_))) => {
                            return Err(
                                AssessmentError::new(AssessmentErrorKind::CredentialUnavailable)
                                    .with_attempts(attempts),
                            );
                        }
                        Ok(Err(_)) => {
                            return Err(
                                AssessmentError::new(AssessmentErrorKind::Internal)
                                    .with_attempts(attempts),
                            );
                        }
                        Err(_) => {
                            return Err(
                                AssessmentError::new(AssessmentErrorKind::DeadlineReached)
                                    .with_attempts(attempts),
                            );
                        }
                    }
                }
            };
            if credential.kind() != expected_kind {
                return Err(
                    AssessmentError::new(AssessmentErrorKind::CredentialUnavailable)
                        .with_attempts(attempts),
                );
            }
            if control.cancel_token().is_cancelled() {
                return Err(
                    AssessmentError::new(AssessmentErrorKind::Cancelled).with_attempts(attempts)
                );
            }
            if Instant::now() >= deadline {
                return Err(AssessmentError::new(AssessmentErrorKind::DeadlineReached)
                    .with_attempts(attempts));
            }

            attempts += 1;
            let result = self
                .attempt_once(
                    &request,
                    &url,
                    &origin,
                    auth,
                    credential.expose_secret(),
                    control.cancel_token(),
                    deadline,
                )
                .await;
            match result {
                Ok(mut response) => {
                    response.attempts = attempts;
                    return Ok(response);
                }
                Err(error) => {
                    let error = error.with_attempts(attempts);
                    if !error.is_retryable() || attempts > MAX_ADDITIONAL_RETRIES {
                        return Err(if error.is_retryable() {
                            error.exhausted()
                        } else {
                            error
                        });
                    }
                    let wait = match error.retry_after() {
                        Some(retry_after) => {
                            if retry_after > remaining(deadline) {
                                return Err(AssessmentError::new(
                                    AssessmentErrorKind::RetryAfterBeyondDeadline,
                                )
                                .with_attempts(attempts));
                            }
                            retry_after
                        }
                        None => {
                            let wait = retry.delay(usize::from(attempts - 1));
                            if wait > remaining(deadline) {
                                return Err(AssessmentError::new(
                                    AssessmentErrorKind::DeadlineReached,
                                )
                                .with_attempts(attempts));
                            }
                            wait
                        }
                    };
                    match wait_for_retry(wait, deadline, control.cancel_token()).await {
                        WaitOutcome::Waited => {}
                        WaitOutcome::Cancelled => {
                            return Err(AssessmentError::new(AssessmentErrorKind::Cancelled)
                                .with_attempts(attempts));
                        }
                        WaitOutcome::DeadlineReached => {
                            return Err(AssessmentError::new(AssessmentErrorKind::DeadlineReached)
                                .with_attempts(attempts));
                        }
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn attempt_once(
        &self,
        request: &AssessmentRequest,
        url: &str,
        origin: &Origin,
        auth: AuthHeader,
        secret: &str,
        cancel: &CancelToken,
        deadline: Instant,
    ) -> Result<AssessmentResponse, AssessmentError> {
        let body = serde_json::to_vec(request.body.value())
            .map_err(|_| AssessmentError::new(AssessmentErrorKind::InvalidRequest))?;
        let builder = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .body(body);
        let builder = auth.apply(builder, secret)?;

        let attempt =
            async {
                let response = builder.send().await.map_err(classify_send_error)?;
                let status = response.status().as_u16();
                if (300..400).contains(&status) {
                    let target = response
                        .headers()
                        .get(LOCATION)
                        .and_then(|value| value.to_str().ok());
                    let cross_origin = target
                        .map(|target| redirect_leaves_origin(origin, target))
                        .unwrap_or(true);
                    return Err(if cross_origin {
                        AssessmentError::new(AssessmentErrorKind::CrossOriginRedirect)
                    } else {
                        AssessmentError::new(AssessmentErrorKind::NoRedirectFollowing)
                    }
                    .with_status(status));
                }
                if status == 429 {
                    return Err(AssessmentError::new(AssessmentErrorKind::RateLimited)
                        .with_status(status)
                        .with_retry_after(response_retry_after(response.headers())));
                }
                if matches!(status, 500 | 502 | 503 | 504) {
                    return Err(AssessmentError::new(AssessmentErrorKind::ServerFailure)
                        .with_status(status)
                        .with_retry_after(response_retry_after(response.headers())));
                }
                if matches!(status, 401 | 403) {
                    return Err(
                        AssessmentError::new(AssessmentErrorKind::AuthenticationFailed)
                            .with_status(status),
                    );
                }
                if !(200..300).contains(&status) {
                    return Err(AssessmentError::new(AssessmentErrorKind::RequestRejected)
                        .with_status(status));
                }
                let body = read_body(response).await?;
                if body.is_empty() {
                    return Err(AssessmentError::new(AssessmentErrorKind::InvalidResponse)
                        .with_status(status));
                }
                Ok(AssessmentResponse {
                    status,
                    attempts: 0,
                    body,
                })
            };

        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                Err(AssessmentError::new(AssessmentErrorKind::Cancelled))
            }
            result = tokio::time::timeout_at(deadline, attempt) => {
                match result {
                    Ok(result) => result,
                    // A timeout after the send may have transmitted the request.
                    Err(_) => Err(AssessmentError::new(AssessmentErrorKind::SendResultUnknown)),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitOutcome {
    Waited,
    Cancelled,
    DeadlineReached,
}

async fn wait_for_retry(wait: Duration, deadline: Instant, cancel: &CancelToken) -> WaitOutcome {
    let wake = (Instant::now() + wait).min(deadline);
    tokio::select! {
        biased;
        _ = cancel.cancelled() => WaitOutcome::Cancelled,
        _ = tokio::time::sleep_until(wake) => {
            if Instant::now() >= deadline {
                WaitOutcome::DeadlineReached
            } else {
                WaitOutcome::Waited
            }
        }
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Whether a redirect target leaves the request origin.
///
/// A relative reference stays on the same origin. A protocol-relative target is
/// resolved with the request scheme. An unparseable absolute target is treated
/// as leaving the origin because it must not receive the credential.
fn redirect_leaves_origin(origin: &Origin, target: &str) -> bool {
    let target = target.trim();
    if let Some(rest) = target.strip_prefix("//") {
        let absolute = format!("{}://{rest}", origin.scheme());
        return matches!(
            redirect_auth_decision(origin, &absolute),
            RedirectAuthDecision::DropAuthorization { .. }
        );
    }
    if !target.contains("://") {
        return false;
    }
    matches!(
        redirect_auth_decision(origin, target),
        RedirectAuthDecision::DropAuthorization { .. }
    )
}

fn classify_send_error(error: reqwest::Error) -> AssessmentError {
    if error.is_timeout() {
        return AssessmentError::new(AssessmentErrorKind::SendResultUnknown);
    }
    if error.is_connect() {
        return AssessmentError::new(AssessmentErrorKind::ConnectionFailed);
    }
    if error.is_request() {
        return AssessmentError::new(AssessmentErrorKind::InvalidRequest);
    }
    // Errors after a connection or partial send are ambiguous. They are never
    // retried because the provider may have received the request.
    AssessmentError::new(AssessmentErrorKind::SendResultUnknown)
}

fn response_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    let seconds = value.parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds))
}

async fn read_body(mut response: reqwest::Response) -> Result<Vec<u8>, AssessmentError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AssessmentError::new(AssessmentErrorKind::InvalidResponse))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(AssessmentError::new(AssessmentErrorKind::ResponseTooLarge));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_is_capped_at_sixty_seconds_and_by_the_remaining_deadline() {
        let control = TransportControl::default();
        assert_eq!(control.timeout(), Duration::from_secs(60));
        let control = control.with_remaining(Duration::from_secs(3_600));
        assert_eq!(control.timeout(), Duration::from_secs(60));
        let control = control.with_remaining(Duration::from_secs(12));
        assert_eq!(control.timeout(), Duration::from_secs(12));
    }

    #[test]
    fn retry_policy_defaults_match_the_h2_values() {
        let policy = RetryPolicy::h2_default();
        assert_eq!(policy.max_additional_retries(), 2);
        assert_eq!(
            policy.base_delays(),
            [Duration::from_secs(1), Duration::from_secs(2)]
        );
        assert!(policy.jitter_max() > Duration::ZERO);
        assert_eq!(policy.jitter_max(), Duration::from_millis(250));
        let deterministic = RetryPolicy::without_jitter();
        assert_eq!(deterministic.jitter(), Duration::ZERO);
        assert_eq!(deterministic.delay(0), Duration::from_secs(1));
        assert_eq!(deterministic.delay(1), Duration::from_secs(2));
    }

    #[test]
    fn tool_declarations_are_rejected_instead_of_stripped() {
        let error = ToolLessPayload::new(serde_json::json!({
            "input": "hello",
            "tools": [{"name": "bash"}]
        }))
        .unwrap_err();
        assert_eq!(error.kind(), AssessmentErrorKind::ToolUseNotAllowed);
        let error = ToolLessPayload::new(serde_json::json!({
            "input": "hello",
            "tool_choice": "auto"
        }))
        .unwrap_err();
        assert_eq!(error.kind(), AssessmentErrorKind::ToolUseNotAllowed);
        assert!(ToolLessPayload::new(serde_json::json!(["not", "an", "object"])).is_err());
        let error = ToolLessPayload::new(serde_json::json!({
            "input": "hello",
            "content": [{"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}]
        }))
        .unwrap_err();
        assert_eq!(error.kind(), AssessmentErrorKind::ExternalImageUrl);
        for body in [
            serde_json::json!({
                "content": [{"type": "image_url", "image_url": {"url": "data:image/png;base64,AA=="}}]
            }),
            serde_json::json!({
                "content": [{"type": "input_image", "image_url": "data:image/png;base64,AA=="}]
            }),
        ] {
            assert!(
                ToolLessPayload::new(body).is_ok(),
                "inline caller bytes must be accepted"
            );
        }
        for body in [
            serde_json::json!({"content": [{"image_url": "data:text/plain;base64,AA=="}]}),
            serde_json::json!({"content": [{"image_url": "https://example.com/a.png"}]}),
            serde_json::json!({"content": [{"image_url": {"url": "https://example.com/a.png"}}]}),
            serde_json::json!({"content": [{"image_url": {"file_id": "file-1"}}]}),
        ] {
            assert_eq!(
                ToolLessPayload::new(body).unwrap_err().kind(),
                AssessmentErrorKind::ExternalImageUrl
            );
        }
    }

    #[test]
    fn image_urls_are_rejected_and_image_bytes_are_redacted() {
        let image = ImageInput::new("image/png", vec![1_u8, 2, 3]).unwrap();
        let debug = format!("{image:?}");
        assert!(debug.contains("image/png"));
        assert!(!debug.contains("1, 2, 3"));
        let request = AssessmentRequest::new(
            ConnectionId::new(),
            "model",
            serde_json::json!({"input": "x"}),
        )
        .unwrap()
        .with_image(image);
        assert!(
            request
                .required_modalities()
                .contains(&InputModality::Image)
        );
        let error = request
            .clone()
            .with_image_sources([ImageSource::Url(
                "https://user:pass@example.com/image.png".to_owned(),
            )])
            .unwrap_err();
        assert_eq!(error.kind(), AssessmentErrorKind::ExternalImageUrl);
        assert!(!format!("{error:?}").contains("pass"));
        let debug = format!("{request:?}");
        assert!(!debug.contains("input"));
        assert!(!debug.contains("x"));
        let response = AssessmentResponse {
            status: 200,
            attempts: 1,
            body: br#"{"text":"canary"}"#.to_vec(),
        };
        assert!(!format!("{response:?}").contains("canary"));
        assert_eq!(response.json().unwrap()["text"].as_str(), Some("canary"));
    }

    #[test]
    fn redirect_classification_keeps_relative_targets_same_origin() {
        let origin = Origin::parse("https://api.example.com/v1").unwrap();
        for target in ["/next", "next", "../other", "?next=1", "#section"] {
            assert!(!redirect_leaves_origin(&origin, target), "{target}");
        }
        for target in [
            "http://api.example.com/v1",
            "https://other.example.com/v1",
            "https://api.example.com:8443/v1",
            "//other.example.com/v1",
            "ftp://api.example.com/v1",
            "https://",
        ] {
            assert!(redirect_leaves_origin(&origin, target), "{target}");
        }
    }

    #[test]
    fn loopback_endpoints_reject_remote_hosts() {
        assert!(
            AssessmentEndpoints::for_loopback(
                "https://api.typesafe.ai",
                "http://127.0.0.1:1234/v1",
                "http://127.0.0.1:1235",
            )
            .is_err()
        );
        let endpoints = AssessmentEndpoints::for_loopback(
            "http://127.0.0.1:1234",
            "http://127.0.0.1:1235/v1",
            "http://127.0.0.1:1236",
        )
        .unwrap();
        assert_eq!(endpoints.openai_base.as_url(), "http://127.0.0.1:1235/v1");
        assert!(
            AssessmentEndpoints::for_loopback(
                "http://user:pass@127.0.0.1:1234",
                "http://127.0.0.1:1235/v1",
                "http://127.0.0.1:1236",
            )
            .is_err(),
            "credential-bearing URL must be rejected"
        );
    }
}
