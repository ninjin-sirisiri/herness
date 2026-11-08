//! Real HTTPS token transport and OpenID discovery for the ChatGPT flow.
//!
//! This module is the opt-in production wiring for Task 13. It is constructed
//! by the trusted desktop host but is not exercised by normal workspace tests:
//! unit tests use a loopback plain-HTTP server through
//! [`AuthHttpConfig::for_loopback`]. Real requests only happen after the human
//! approves them in the Phase B runbook.
//!
//! The transport uses `reqwest` 0.12 with its blocking client, `rustls-tls`
//! (webpki roots from the tracked `Cargo.lock`). Redirects are disabled: a
//! token request never forwards its form body to another origin, and a
//! discovery/JWKS redirect is a failure rather than a silent follow. No request
//! or response body, code, verifier, token, or ID token is logged.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use herness_core::{Endpoint, HttpScheme};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE};
use reqwest::redirect::Policy;
use serde::Deserialize;

use super::error::{JwksError, TokenTransportError};
use super::jwk::JwkSet;
use super::transport::{
    RefreshRequest, RevokeRequest, TokenExchangeRequest, TokenResponse, TokenTransport,
};
use super::types::{ISSUER, TOKEN_ENDPOINT};

/// Discovery document URL confirmed by the Task 8 research record.
pub const DISCOVERY_URL: &str = "https://auth.openai.com/.well-known/openid-configuration";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);
const MAX_CACHE_TTL: Duration = Duration::from_secs(3_600);

/// Endpoints and policy for the real ChatGPT transport.
///
/// Production uses [`Self::official`]. The loopback constructor is test-only
/// and requires both URLs to resolve to `127.0.0.1`/`localhost`; a remote plain
/// HTTP endpoint is never accepted.
#[derive(Clone)]
pub struct AuthHttpConfig {
    token_endpoint: String,
    discovery_url: String,
    expected_issuer: String,
    allow_loopback_http: bool,
    timeout: Duration,
    default_cache_ttl: Duration,
}

impl AuthHttpConfig {
    /// Official OpenAI endpoints.
    pub fn official() -> Self {
        Self {
            token_endpoint: TOKEN_ENDPOINT.to_owned(),
            discovery_url: DISCOVERY_URL.to_owned(),
            expected_issuer: ISSUER.to_owned(),
            allow_loopback_http: false,
            timeout: DEFAULT_TIMEOUT,
            default_cache_ttl: DEFAULT_CACHE_TTL,
        }
    }

    /// Loopback plain-HTTP configuration for tests.
    ///
    /// Returns `None` if either URL is not a loopback HTTP endpoint or the
    /// issuer is empty.
    pub fn for_loopback(
        token_endpoint: impl Into<String>,
        discovery_url: impl Into<String>,
        expected_issuer: impl Into<String>,
    ) -> Option<Self> {
        let token_endpoint = token_endpoint.into();
        let discovery_url = discovery_url.into();
        let expected_issuer = expected_issuer.into();
        if expected_issuer.trim().is_empty() {
            return None;
        }
        if !is_loopback_http(&token_endpoint) || !is_loopback_http(&discovery_url) {
            return None;
        }
        Some(Self {
            token_endpoint,
            discovery_url,
            expected_issuer,
            allow_loopback_http: true,
            timeout: Duration::from_secs(5),
            default_cache_ttl: DEFAULT_CACHE_TTL,
        })
    }

    /// Overrides the request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl fmt::Debug for AuthHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthHttpConfig")
            .field("token_endpoint_origin", &origin_only(&self.token_endpoint))
            .field("discovery_origin", &origin_only(&self.discovery_url))
            .field("expected_issuer", &self.expected_issuer)
            .field("allow_loopback_http", &self.allow_loopback_http)
            .finish_non_exhaustive()
    }
}

/// Shared discovery/JWKS cache and HTTP client.
///
/// The token transport and JWKS source share one instance so discovery is
/// fetched once per cache window.
pub struct AuthHttp {
    config: AuthHttpConfig,
    client: Client,
    discovery: Mutex<Option<Cached<DiscoveryDocument>>>,
    jwks: Mutex<Option<Cached<JwkSet>>>,
}

impl AuthHttp {
    /// Builds the HTTP client and validates the configured URLs.
    pub fn new(config: AuthHttpConfig) -> Result<Arc<Self>, TokenTransportError> {
        validate_url(&config.token_endpoint, config.allow_loopback_http)?;
        validate_url(&config.discovery_url, config.allow_loopback_http)?;
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .https_only(!config.allow_loopback_http)
            .timeout(config.timeout)
            .build()
            .map_err(|_| TokenTransportError::Unavailable)?;
        Ok(Arc::new(Self {
            config,
            client,
            discovery: Mutex::new(None),
            jwks: Mutex::new(None),
        }))
    }

    fn discovery(&self) -> Result<DiscoveryDocument, JwksError> {
        if let Some(document) = self.read_cache(&self.discovery) {
            return Ok(document);
        }
        let (status, body, ttl) = self
            .get(&self.config.discovery_url)
            .map_err(|_| JwksError::Unavailable)?;
        if !(200..300).contains(&status) {
            return Err(JwksError::Unavailable);
        }
        let document: DiscoveryDocument =
            serde_json::from_str(&body).map_err(|_| JwksError::Malformed)?;
        if document.issuer != self.config.expected_issuer {
            return Err(JwksError::Unavailable);
        }
        validate_url(&document.jwks_uri, self.config.allow_loopback_http)
            .map_err(|_| JwksError::Unavailable)?;
        if let Some(revocation) = document.revocation_endpoint.as_deref() {
            validate_url(revocation, self.config.allow_loopback_http)
                .map_err(|_| JwksError::Unavailable)?;
        }
        self.write_cache(&self.discovery, document.clone(), ttl);
        Ok(document)
    }

    fn read_cache<T: Clone>(&self, cache: &Mutex<Option<Cached<T>>>) -> Option<T> {
        let guard = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .as_ref()
            .filter(|cached| cached.expires_at > Instant::now())
            .map(|cached| cached.value.clone())
    }

    fn write_cache<T>(&self, cache: &Mutex<Option<Cached<T>>>, value: T, ttl: Duration) {
        if ttl.is_zero() {
            return;
        }
        let mut guard = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(Cached {
            value,
            expires_at: Instant::now() + ttl,
        });
    }

    fn get(&self, url: &str) -> Result<(u16, String, Duration), TokenTransportError> {
        let response = self
            .client
            .get(url)
            .header(ACCEPT, "application/json")
            .send()
            .map_err(|_| TokenTransportError::Network)?;
        let status = response.status().as_u16();
        let ttl = cache_ttl(response.headers(), self.config.default_cache_ttl);
        let body = response.text().map_err(|_| TokenTransportError::Network)?;
        Ok((status, body, ttl))
    }

    fn post_form(&self, url: &str, form: &str) -> Result<(u16, String), TokenTransportError> {
        let response = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .body(form.to_owned())
            .send()
            .map_err(|_| TokenTransportError::Network)?;
        let status = response.status().as_u16();
        let body = response.text().map_err(|_| TokenTransportError::Network)?;
        Ok((status, body))
    }
}

/// Real HTTPS token transport.
pub struct HttpsTokenTransport {
    http: Arc<AuthHttp>,
}

impl HttpsTokenTransport {
    /// Wraps a shared HTTP/discovery instance.
    pub fn new(http: Arc<AuthHttp>) -> Self {
        Self { http }
    }
}

impl TokenTransport for HttpsTokenTransport {
    fn exchange(
        &self,
        request: &TokenExchangeRequest,
    ) -> Result<TokenResponse, TokenTransportError> {
        let form = form_encode(&[
            ("grant_type", "authorization_code"),
            ("client_id", request.client_id()),
            ("code", request.code()),
            ("code_verifier", request.code_verifier()),
            ("redirect_uri", request.redirect_uri()),
            ("resource", request.resource()),
        ]);
        let (status, body) = self
            .http
            .post_form(&self.http.config.token_endpoint, &form)?;
        parse_token_response(status, &body)
    }

    fn refresh(&self, request: &RefreshRequest) -> Result<TokenResponse, TokenTransportError> {
        // `scope` is deliberately omitted so the provider keeps the granted
        // plan scopes across a refresh.
        let form = form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", request.client_id()),
            ("refresh_token", request.refresh_token()),
            ("resource", request.resource()),
        ]);
        let (status, body) = self
            .http
            .post_form(&self.http.config.token_endpoint, &form)?;
        parse_token_response(status, &body)
    }

    fn revoke(&self, request: &RevokeRequest) -> Result<(), TokenTransportError> {
        self.revoke_confirmed(request).map(|_| ())
    }

    fn revoke_confirmed(&self, request: &RevokeRequest) -> Result<bool, TokenTransportError> {
        let document = self
            .http
            .discovery()
            .map_err(|_| TokenTransportError::RevocationUnconfirmed)?;
        let Some(endpoint) = document.revocation_endpoint.as_deref() else {
            return Err(TokenTransportError::RevocationUnconfirmed);
        };
        let form = form_encode(&[
            ("token", request.refresh_token()),
            ("token_type_hint", "refresh_token"),
            ("client_id", request.client_id()),
        ]);
        let (status, body) = self.http.post_form(endpoint, &form)?;
        match status {
            // Confirmed only for the documented empty HTTP 200.
            200 => Ok(body.is_empty()),
            // Any other 2xx is an accepted request with no confirmation.
            201..=299 => Ok(false),
            _ => Err(TokenTransportError::Rejected),
        }
    }
}

/// Real OIDC discovery-backed JWKS source.
pub struct DiscoveryJwksSource {
    http: Arc<AuthHttp>,
}

impl DiscoveryJwksSource {
    /// Wraps a shared HTTP/discovery instance.
    pub fn new(http: Arc<AuthHttp>) -> Self {
        Self { http }
    }
}

impl super::jwk::JwksSource for DiscoveryJwksSource {
    fn jwks(&self) -> Result<JwkSet, JwksError> {
        if let Some(keys) = self.http.read_cache(&self.http.jwks) {
            return Ok(keys);
        }
        let document = self.http.discovery()?;
        let (status, body, ttl) = self
            .http
            .get(&document.jwks_uri)
            .map_err(|_| JwksError::Unavailable)?;
        if !(200..300).contains(&status) {
            return Err(JwksError::Unavailable);
        }
        let keys = JwkSet::parse(body.as_bytes())?;
        self.http.write_cache(&self.http.jwks, keys.clone(), ttl);
        Ok(keys)
    }
}

/// Builds the official real transport and JWKS source over one shared cache.
pub fn official_auth_components()
-> Result<(HttpsTokenTransport, DiscoveryJwksSource), TokenTransportError> {
    let http = AuthHttp::new(AuthHttpConfig::official())?;
    Ok((
        HttpsTokenTransport::new(Arc::clone(&http)),
        DiscoveryJwksSource::new(http),
    ))
}

#[derive(Clone, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
}

struct Cached<T> {
    value: T,
    expires_at: Instant,
}

#[derive(Deserialize)]
struct TokenBody {
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    expires_in: Option<ExpiresIn>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ExpiresIn {
    Number(u64),
    Text(String),
}

impl ExpiresIn {
    fn value(&self) -> Option<u64> {
        match self {
            Self::Number(value) => Some(*value),
            Self::Text(value) => value.trim().parse().ok(),
        }
    }
}

fn parse_token_response(status: u16, body: &str) -> Result<TokenResponse, TokenTransportError> {
    if status == 400 {
        return Err(if is_invalid_grant(body) {
            TokenTransportError::InvalidGrant
        } else {
            TokenTransportError::Rejected
        });
    }
    if !(200..300).contains(&status) {
        return Err(if status >= 500 {
            TokenTransportError::Network
        } else {
            TokenTransportError::Rejected
        });
    }
    let parsed: TokenBody =
        serde_json::from_str(body).map_err(|_| TokenTransportError::InvalidResponse)?;
    let access_token = parsed
        .access_token
        .as_deref()
        .ok_or(TokenTransportError::InvalidResponse)?;
    let expires_in = parsed
        .expires_in
        .as_ref()
        .and_then(ExpiresIn::value)
        .ok_or(TokenTransportError::InvalidResponse)?;
    TokenResponse::new(
        access_token,
        parsed.refresh_token.as_deref(),
        parsed.id_token.as_deref(),
        expires_in,
        parsed.scope.as_deref(),
    )
}

fn is_invalid_grant(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    value.get("error").is_some_and(|error| {
        error.as_str() == Some("invalid_grant")
            || error.get("code").and_then(|code| code.as_str()) == Some("invalid_grant")
    }) || value.get("code").and_then(|code| code.as_str()) == Some("invalid_grant")
}

fn validate_url(raw: &str, allow_loopback_http: bool) -> Result<String, TokenTransportError> {
    let endpoint = Endpoint::parse(raw).map_err(|_| TokenTransportError::Unavailable)?;
    if endpoint.scheme() == HttpScheme::Http && !(allow_loopback_http && endpoint.is_loopback()) {
        return Err(TokenTransportError::Unavailable);
    }
    Ok(endpoint.as_url())
}

fn is_loopback_http(raw: &str) -> bool {
    Endpoint::parse(raw)
        .map(|endpoint| endpoint.scheme() == HttpScheme::Http && endpoint.is_loopback())
        .unwrap_or(false)
}

fn cache_ttl(headers: &reqwest::header::HeaderMap, default: Duration) -> Duration {
    let Some(value) = headers
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
    else {
        return default;
    };
    let mut ttl = default;
    for directive in value.split(',') {
        let directive = directive.trim();
        if directive.eq_ignore_ascii_case("no-store") {
            return Duration::ZERO;
        }
        if let Some(raw) = directive.strip_prefix("max-age=")
            && let Ok(seconds) = raw.trim().parse::<u64>()
        {
            ttl = Duration::from_secs(seconds).min(MAX_CACHE_TTL);
        }
    }
    ttl
}

fn origin_only(raw: &str) -> String {
    Endpoint::parse(raw)
        .map(|endpoint| {
            let port = endpoint
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default();
            format!("{}://{}{port}", endpoint.scheme(), endpoint.host())
        })
        .unwrap_or_else(|_| "[invalid]".to_owned())
}

fn form_encode(fields: &[(&str, &str)]) -> String {
    let mut output = String::new();
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            output.push('&');
        }
        encode_component(key, &mut output);
        output.push('=');
        encode_component(value, &mut output);
    }
    output
}

fn encode_component(value: &str, output: &mut String) {
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push_str(&format!("{byte:02X}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::JoinHandle;

    use super::super::jwk::JwksSource;
    use super::*;

    struct TestRequest {
        line: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl TestRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }

        fn form(&self) -> Vec<(String, String)> {
            self.body
                .split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| {
                    let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                    (percent_decode(key), percent_decode(value))
                })
                .collect()
        }
    }

    struct TestResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl TestResponse {
        fn json(body: impl Into<String>) -> Self {
            Self {
                status: 200,
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                body: body.into(),
            }
        }

        fn empty(status: u16) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: String::new(),
            }
        }

        fn with_body(mut self, body: &str) -> Self {
            self.body = body.to_owned();
            self
        }

        fn with_header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_owned(), value.to_owned()));
            self
        }
    }

    struct TestServer {
        base: String,
        requests: Arc<Mutex<Vec<TestRequest>>>,
        handle: Option<JoinHandle<()>>,
    }

    impl TestServer {
        fn start(build: impl FnOnce(&str) -> Vec<TestResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
            let base = format!("http://{}", listener.local_addr().expect("address"));
            let responses = build(&base);
            let requests = Arc::new(Mutex::new(Vec::new()));
            let captured = Arc::clone(&requests);
            let handle = std::thread::spawn(move || {
                for response in responses {
                    let Ok((stream, _)) = listener.accept() else {
                        return;
                    };
                    let request = read_request(stream.try_clone().expect("clone stream"));
                    captured
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(request);
                    write_response(stream, response);
                }
            });
            Self {
                base,
                requests,
                handle: Some(handle),
            }
        }

        fn url(&self, path: &str) -> String {
            format!("{}{path}", self.base)
        }

        fn requests(&self) -> Vec<TestRequest> {
            let requests = self
                .requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            requests
                .iter()
                .map(|request| TestRequest {
                    line: request.line.clone(),
                    headers: request.headers.clone(),
                    body: request.body.clone(),
                })
                .collect()
        }

        fn finish(mut self) {
            if let Some(handle) = self.handle.take() {
                handle.join().expect("test server thread");
            }
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            // Wake a server that is still waiting for an unexpected request so
            // the thread does not outlive the test.
            if let Some(handle) = self.handle.take() {
                let _ = TcpStream::connect(self.base.trim_start_matches("http://"));
                let _ = handle.join();
            }
        }
    }

    fn read_request(stream: TcpStream) -> TestRequest {
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("request line");
        let mut headers = Vec::new();
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).expect("header line");
            if header == "\r\n" || header == "\n" || header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.trim_end().split_once(':') {
                headers.push((name.trim().to_owned(), value.trim().to_owned()));
            }
        }
        let length = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0_u8; length];
        reader.read_exact(&mut body).expect("request body");
        TestRequest {
            line: line.trim_end().to_owned(),
            headers,
            body: String::from_utf8(body).expect("utf-8 request body"),
        }
    }

    fn write_response(mut stream: TcpStream, response: TestResponse) {
        let mut raw = format!("HTTP/1.1 {} Test\r\n", response.status);
        for (name, value) in &response.headers {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        raw.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            response.body.len(),
            response.body
        ));
        stream.write_all(raw.as_bytes()).expect("write response");
        stream.flush().expect("flush response");
    }

    fn percent_decode(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut output = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' && index + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    output.push(byte);
                    index += 3;
                    continue;
                }
            }
            output.push(bytes[index]);
            index += 1;
        }
        String::from_utf8(output).unwrap_or_default()
    }

    fn config(server: &TestServer, discovery_path: &str) -> AuthHttpConfig {
        AuthHttpConfig::for_loopback(
            server.url("/token"),
            server.url(discovery_path),
            "https://issuer.test",
        )
        .expect("loopback config")
    }

    #[test]
    fn exchange_posts_the_authorization_code_grant_without_a_client_secret() {
        let server = TestServer::start(|_| {
            vec![TestResponse::json(
                r#"{"access_token":"access-value","refresh_token":"refresh-value","id_token":"id-value","expires_in":3600,"scope":"openid chatgpt.tokens.use.direct"}"#,
            )]
        });
        let http = AuthHttp::new(config(&server, "/discovery")).expect("http");
        let transport = HttpsTokenTransport::new(http);
        let request = TokenExchangeRequest::new(
            "oaiapp_client",
            "code-value",
            "verifier-value",
            "http://127.0.0.1:7777/auth/callback",
            "https://api.openai.com/v1",
        );
        let response = transport.exchange(&request).expect("exchange");
        assert_eq!(response.access_token().expose_secret(), "access-value");
        assert_eq!(
            response.refresh_token().map(|token| token.expose_secret()),
            Some("refresh-value")
        );
        assert_eq!(response.expires_in(), 3600);
        assert_eq!(
            response.scopes(),
            vec!["openid", "chatgpt.tokens.use.direct"]
        );

        let captured = server.requests();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].line, "POST /token HTTP/1.1");
        assert_eq!(
            captured[0].header("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(captured[0].header("authorization"), None);
        let form = captured[0].form();
        let value = |name: &str| {
            form.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(value("grant_type"), Some("authorization_code"));
        assert_eq!(value("client_id"), Some("oaiapp_client"));
        assert_eq!(value("code"), Some("code-value"));
        assert_eq!(value("code_verifier"), Some("verifier-value"));
        assert_eq!(
            value("redirect_uri"),
            Some("http://127.0.0.1:7777/auth/callback")
        );
        assert_eq!(value("resource"), Some("https://api.openai.com/v1"));
        assert_eq!(value("client_secret"), None);
        server.finish();
    }

    #[test]
    fn refresh_omits_scope_and_uses_the_refresh_token_grant() {
        let server = TestServer::start(|_| {
            vec![TestResponse::json(
                r#"{"access_token":"new-access","expires_in":"120"}"#,
            )]
        });
        let http = AuthHttp::new(config(&server, "/discovery")).expect("http");
        let transport = HttpsTokenTransport::new(http);
        let request = RefreshRequest::new(
            "oaiapp_client",
            "refresh-value",
            "https://api.openai.com/v1",
        );
        let response = transport.refresh(&request).expect("refresh");
        assert_eq!(response.access_token().expose_secret(), "new-access");
        assert_eq!(response.expires_in(), 120);
        let captured = server.requests();
        let form = captured[0].form();
        let value = |name: &str| {
            form.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(value("grant_type"), Some("refresh_token"));
        assert_eq!(value("refresh_token"), Some("refresh-value"));
        assert_eq!(value("scope"), None);
        server.finish();
    }

    #[test]
    fn a_token_redirect_is_rejected_without_following_it() {
        let server = TestServer::start(|_| {
            vec![TestResponse {
                status: 302,
                headers: vec![(
                    "Location".to_owned(),
                    "http://127.0.0.1:1/other-origin".to_owned(),
                )],
                body: String::new(),
            }]
        });
        let http = AuthHttp::new(config(&server, "/discovery")).expect("http");
        let transport = HttpsTokenTransport::new(http);
        let request = TokenExchangeRequest::new(
            "oaiapp_client",
            "code-value",
            "verifier-value",
            "http://127.0.0.1:7777/auth/callback",
            "https://api.openai.com/v1",
        );
        assert_eq!(
            transport.exchange(&request).expect_err("must reject"),
            TokenTransportError::Rejected
        );
        assert_eq!(server.requests().len(), 1);
        server.finish();
    }

    #[test]
    fn invalid_grant_is_distinguished_without_exposing_the_body() {
        let server = TestServer::start(|_| {
            vec![TestResponse {
                status: 400,
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                body: r#"{"error":"invalid_grant","error_description":"provider detail must not leak"}"#
                    .to_owned(),
            }]
        });
        let http = AuthHttp::new(config(&server, "/discovery")).expect("http");
        let transport = HttpsTokenTransport::new(http);
        let request = TokenExchangeRequest::new(
            "oaiapp_client",
            "code-value",
            "verifier-value",
            "http://127.0.0.1:7777/auth/callback",
            "https://api.openai.com/v1",
        );
        assert_eq!(
            transport.exchange(&request).expect_err("must reject"),
            TokenTransportError::InvalidGrant
        );
        assert!(!format!("{:?}", TokenTransportError::InvalidGrant).contains("provider detail"));
        server.finish();
    }

    #[test]
    fn discovery_and_jwks_are_cached() {
        let server = TestServer::start(|base| {
            vec![
                TestResponse::json(format!(
                    r#"{{"issuer":"https://issuer.test","jwks_uri":"{base}/jwks","revocation_endpoint":"{base}/revoke"}}"#
                ))
                .with_header("Cache-Control", "max-age=300"),
                TestResponse::json(
                    r#"{"keys":[{"kty":"RSA","kid":"key-1","alg":"RS256","n":"AQ","e":"AQAB"}]}"#,
                )
                .with_header("Cache-Control", "max-age=300"),
            ]
        });
        let config = AuthHttpConfig::for_loopback(
            server.url("/token"),
            server.url("/discovery"),
            "https://issuer.test",
        )
        .expect("loopback config");
        let http = AuthHttp::new(config).expect("http");
        let jwks = DiscoveryJwksSource::new(Arc::clone(&http));
        let first = jwks.jwks().expect("first jwks");
        let second = jwks.jwks().expect("cached jwks");
        assert_eq!(first.keys.len(), 1);
        assert_eq!(second.keys.len(), 1);
        assert_eq!(server.requests().len(), 2);
        server.finish();
    }

    #[test]
    fn revoke_is_confirmed_only_for_an_empty_http_200() {
        for (body, expected) in [("", true), ("accepted", false)] {
            let server = TestServer::start(|base| {
                vec![
                    TestResponse::json(format!(
                        r#"{{"issuer":"https://issuer.test","jwks_uri":"{base}/jwks","revocation_endpoint":"{base}/revoke"}}"#
                    ))
                    .with_header("Cache-Control", "max-age=300"),
                    TestResponse::empty(200).with_body(body),
                ]
            });
            let config = AuthHttpConfig::for_loopback(
                server.url("/token"),
                server.url("/discovery"),
                "https://issuer.test",
            )
            .expect("loopback config");
            let http = AuthHttp::new(config).expect("http");
            let transport = HttpsTokenTransport::new(http);
            let request = RevokeRequest::new("oaiapp_client", "refresh-value");
            assert_eq!(
                transport.revoke_confirmed(&request).expect("revoke"),
                expected
            );
            let captured = server.requests();
            assert_eq!(captured.len(), 2);
            assert_eq!(captured[1].line, "POST /revoke HTTP/1.1");
            let form = captured[1].form();
            let value = |name: &str| {
                form.iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value("token"), Some("refresh-value"));
            assert_eq!(value("token_type_hint"), Some("refresh_token"));
            assert_eq!(value("client_id"), Some("oaiapp_client"));
            server.finish();
        }
    }

    #[test]
    fn discovery_rejects_an_untrusted_issuer() {
        let server = TestServer::start(|_| {
            vec![TestResponse::json(
                r#"{"issuer":"https://attacker.test","jwks_uri":"https://attacker.test/jwks"}"#,
            )]
        });
        let http = AuthHttp::new(config(&server, "/discovery")).expect("http");
        let source = DiscoveryJwksSource::new(http);
        assert_eq!(
            source.jwks().expect_err("must reject"),
            JwksError::Unavailable
        );
        assert_eq!(server.requests().len(), 1);
        server.finish();
    }

    #[test]
    fn a_response_without_an_access_token_is_invalid() {
        let server = TestServer::start(|_| vec![TestResponse::json(r#"{"expires_in":60}"#)]);
        let http = AuthHttp::new(config(&server, "/discovery")).expect("http");
        let transport = HttpsTokenTransport::new(http);
        let request = TokenExchangeRequest::new(
            "oaiapp_client",
            "code-value",
            "verifier-value",
            "http://127.0.0.1:7777/auth/callback",
            "https://api.openai.com/v1",
        );
        assert_eq!(
            transport.exchange(&request).expect_err("must reject"),
            TokenTransportError::InvalidResponse
        );
        server.finish();
    }
}
