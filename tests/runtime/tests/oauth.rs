//! Black-box tests for the official ChatGPT OAuth flow and terms gate.
//!
//! Every test is mock-only. Token exchange and JWKS retrieval are scripted;
//! the authorization callback uses a real `127.0.0.1` loopback listener. The
//! ID tokens are signed with an embedded synthetic RSA key. No real credential,
//! Keychain item, OpenAI host, or network service is touched.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use herness_core::*;
use herness_engine_pi::auth::*;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use serde_json::{Value, json};

const TEST_KEY_PKCS8_B64: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDNekM0C3NdYmsQdY/PN8gbL4w27YQXlt87BVFy6CGfYc5gI3d3vp5FKwQGa9QID9p7okpWXkG5kd9Sj5jyfYmp8FJuBb408rD60Vau6JHdnjjSrRMS3zaoPN7sg25mYpWRhGgFmHU3CAdhfb9w0SDyq2QS5XvUmDtfA7yURt/+GKZAueVszhUrEI/6y2VcRmz5pB6wJ4MogwEYllNLWJukc4OeeAET3XRoUwoXGkC4yCe860zG2tGDsItgLYCwFxaGMiWbH+EKedFknUgdi6rIEvh6p8uhIp9DlzWZKBuj/CCGGKj1eHcaB9/wA4CJqYvM3WAAhOSpnPMFCZ0F0MwNAgMBAAECggEAEW+chqzdRafCU6U5ZmlI9U81lyIHuxC1/jlXTgIQrrukwL4bUL5ZVwYHBpx2/TAkzagmpemQ3jRYpPx2ca1H1aaekaN/HnMYClCVPUZfvYfD/p/QWVU21O14mGbjiWCenIVSmZb0UcHzdMkwFsMVCEKVVvbBaUR5u6uCs+DHxRuFvdSc0MDoTjZrpJaZUESbKN251lETy0Y8xo1BSKnnWsflUuO/IroguvVdjb/x6tJcVWvWPF8FLslHklZqP53XmJXIqAMlpoizTvPJyndSWTll/6UXbu2P6Gm19fOBzWsB6zgw+Q+qY5uy38rKe1GWnuI8zfUHhJDMwJzL0rKp6QKBgQD2Hg7Uvx8I+YWmiKqemcrHXrO/668DsPmCzn7nignE0OV4p7ibEuswpNwsyqehWUOELmKWxXAoKZ36/2SWC04BgSqSO7N3MWxhbl6jLp3SXjFtJ4ZiyEdL4q+5/ozrgEQv66l42kVJd8TTSYY1SFAA1uSFvEMzK69eDrH7as2otwKBgQDVunN7hex/0HPm5SnEQJ4kltQvEzgVR5sYGJ0SeQlPSpzlxQmoeOfxAEK2fMAe+pBL62cfW1g2qhNNbTItQvOUU/DQn+8uiPBCcRpaspe+f9dhCV81zfcqOdlJknk+ym6X6hXNClKGSlpR7Rn1xpXLPQIEs0cq9vGqCSUHqCfFWwKBgGg/8yhKjGrQxrvzx9HGcw5gHuN8gXWe0RGHRlntLpYfphOld5y4Nsc0Dc8rSDYgCWlD/J7AovFgL3rSE1k7EJ+yhsXKZApo9O+QQKX+aPtiyqzhwRq2mvyZ2LWADVDz0+44dGCslAy6nrSgwChxqPGyFLpRNGXIa0/8CYflhZehAoGAfqHANpm87GXnphB1VLAsguVSxqmOex04CWjb98v69h3xJDpAZK9uTV6oKFN1yWUQBctuCCgo9gqC8UcXibW3eFTbw+Be6KV+JP+6a66RNe+s/vN8k/Z60WwBEBRW/hsWt6+cRyYsiyCWrx/aV8LXkdmNzpciPZSezu4oIIdDOS0CgYBBC5CWZq13DnDFP25tEMuZBub/HrZ0NlxxJZP2EPW803gqnaZFWHT/yo5Am+nig8vILYzkfTGYI72OySOrYPS+0eCL3ULi7w1iP9/55OGnzBD/8ep6gMzWtnePVBRmk2FKOcjrwfPjG90zxqJAv/9OekY4HWVEkpzXUv/H+jbDUA==";
const TEST_KEY_JWK_N: &str = "zXpDNAtzXWJrEHWPzzfIGy-MNu2EF5bfOwVRcughn2HOYCN3d76eRSsEBmvUCA_ae6JKVl5BuZHfUo-Y8n2JqfBSbgW-NPKw-tFWruiR3Z440q0TEt82qDze7INuZmKVkYRoBZh1NwgHYX2_cNEg8qtkEuV71Jg7XwO8lEbf_himQLnlbM4VKxCP-stlXEZs-aQesCeDKIMBGJZTS1ibpHODnngBE910aFMKFxpAuMgnvOtMxtrRg7CLYC2AsBcWhjIlmx_hCnnRZJ1IHYuqyBL4eqfLoSKfQ5c1mSgbo_wghhio9Xh3Ggff8AOAiamLzN1gAITkqZzzBQmdBdDMDQ";
const OTHER_KEY_PKCS8_B64: &str = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCqgtLdXYHe0hg1uqC+QdWrmmgXB2cR0JcTCL8OrCteIO85fjE3GpLBegA5HQ5J+jx1tTPVugOrMnfV5JuuKEkDGbx6vRTbXaD6b/5WDU4qAK/B2/p2tCS8Yp7qLpZE7gHguw1SSl9WrUibighub9Jnjo18vqewl1Z9XKwuL/N1pEfAqflk8XGrirQXMvT4hZm8O3A8blcnJHxY2i3ugF4oU7569wTotJi176V4jk7kESHegq3mRrORmat0u7NGSPpEVTOsrfJVtXUDzNhJjWox/ciVlxVc4SFTl20ipO1ORm+LIRjVwyhcj0aLc2QAjgqd/FRj9mr/MqzWG8o9K9bLAgMBAAECggEAOWWyb7vjVMtqROPe6kylDY/7jAz84B1UTZ77GYhRTO1POg5FqOP0FNbprlAemD55DbKCkWZ9h6qEdmbvFPAQq8+FB9gQZkudPdBnUDZIYpE6mMphBIZde2DDV9d41Bk+XpT4xgOtFjNcpqcPcYWI0T1GWYCgWCyJe8evWhjgHnAx1ygxGDD28H3/6wrhYu8POzKBSkfMtLiGpAMiD3+URPXaFyYPnAouKKTbyR9QYKJSK68Hv/JjzllPyEs3pBsUWZ+AHxgpid4a5u6L87XsQKYjs7WwRBb4RoHvr8RNZ1lNzx9CeavdFosHRT7BiiWCig3jbfUAyp8e6kjIwbnXCQKBgQDr9s4MqKLJthIVcRdy7Zw08T2VGG4sGKKDEu6uq4emDmUHiRDFyZ8UecFI/RNzmv6TyaN3oM9ZYQc8PFhmMHgtSUtcEQxRoLp6Ose9LB/8ANqO+sJmMKbXYI32rDhmDoYnKnyUC+nA1ny2xghJu7BDOK14U3NpOc3LgguR6hiUxwKBgQC4/UDvsLDWbagNibnXl0JZedLJhyhLrn3xYEOYY5JoX8++EePwrQpfzMrTwBsdwTzC/x+TTWnZD7UkHGYKW32MBhlWNt5wHq/kP91l0dnQYURor0vKOYX6j0AF/JSAtVQAkNt1JZaIQSFzsoy1+aLDfXx4VwOGtoe1sSHngcxh3QKBgQCJAyglxY2wnl3lwWMiQsIfI6zkc+kVBcDnZwjct5DuZRFYzMfGcQpD82a+IOU4jVkhK0YV4nRDq8ltuoSB4ccGVLbDYMrMYw2kh5kPSR3RUBWYTBaxC7L1AIWuI9YjvG89MrhfpoM2i9SitF5/odH5VmGzqpErGntancpmEY3wZQKBgA0PfE0v6VxKQ6opBiDtgfa1PieSTksBl8y54ivZI9YQpacitjggz3GyEMPgdUmlgfe2cXFB7u4vSLey9ZVXnkaLi7BlkVDTKdHwnF368ejfZSgK8EvnwcjN4lRJ3+YyZyrfD093Bui5yHXVrk+Ov2oT6vzID+yr6GrwhZdFt7tVAoGBAOELgBGY1w4ExVQU4c38cvriolvH+BZ5A6fY0lVXzHLckwnbvdmv+C7EOCuw25Tz9sEeq7/YQfpsBgydYAgXkNgoGAXVsFRtDo3sHjFk80W9WQvY0n4clX9MhaZBbqMTu3My1UZZ0ZldQAcUp2H4d5MGB85KzXdvAn7IWcG7TN/E";
const EC_KEY_PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+ZAMuQhcbA2167PKrkzLrnGSAEOUMaIIeKZMlKsjqX2hRANCAARndIdtYh416HWqIQkT3wSrLstdSyqarkPvriMheqU1mGsZr+W1xDLo8y+t3c1ijDWlwOkgGG98SZwbsq/ANJ8s";
const EC_JWK_X: &str = "Z3SHbWIeNeh1qiEJE98Eqy7LXUsqmq5D764jIXqlNZg";
const EC_JWK_Y: &str = "axmv5bXEMujzL63dzWKMNaXA6SAYb3xJnBuyr8A0nyw";

const NOW_MILLIS: u64 = 1_800_000_000_000;
const CANARY_CODE: &str = "code-canary-28f0";
const CANARY_ACCESS: &str = "access-canary-51bd";
const CANARY_REFRESH: &str = "refresh-canary-e42a";
const CANARY_ID: &str = "id-token-canary-9c31";
const PLAN_SCOPE: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";

#[derive(Default)]
struct VaultState {
    items: BTreeMap<String, Vec<u8>>,
    write_failure: Option<VaultFailure>,
    delete_failure: Option<VaultFailure>,
    writes: usize,
}

#[derive(Clone, Default)]
struct FakeVault {
    state: Arc<Mutex<VaultState>>,
}

impl FakeVault {
    fn raw(&self, account: &str) -> Option<Vec<u8>> {
        self.state.lock().unwrap().items.get(account).cloned()
    }

    fn fail_next_write(&self, failure: VaultFailure) {
        self.state.lock().unwrap().write_failure = Some(failure);
    }

    fn fail_next_delete(&self, failure: VaultFailure) {
        self.state.lock().unwrap().delete_failure = Some(failure);
    }

    fn write_count(&self) -> usize {
        self.state.lock().unwrap().writes
    }
}

impl CredentialVault for FakeVault {
    fn set(&self, account: &VaultAccount, data: &[u8]) -> Result<(), VaultFailure> {
        let mut state = self.state.lock().unwrap();
        state.writes += 1;
        if let Some(failure) = state.write_failure.take() {
            return Err(failure);
        }
        state
            .items
            .insert(account.as_str().to_owned(), data.to_vec());
        Ok(())
    }

    fn get(&self, account: &VaultAccount) -> Result<Option<Vec<u8>>, VaultFailure> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .items
            .get(account.as_str())
            .cloned())
    }

    fn delete(&self, account: &VaultAccount) -> Result<(), VaultFailure> {
        let mut state = self.state.lock().unwrap();
        if let Some(failure) = state.delete_failure.take() {
            return Err(failure);
        }
        match state.items.remove(account.as_str()) {
            Some(_) => Ok(()),
            None => Err(VaultFailure::MissingItem),
        }
    }
}

#[derive(Default)]
struct TransportState {
    exchange: VecDeque<Result<TokenResponse, TokenTransportError>>,
    refresh: VecDeque<Result<TokenResponse, TokenTransportError>>,
    revoke: VecDeque<Result<(), TokenTransportError>>,
    exchange_calls: usize,
    refresh_calls: usize,
    revoke_calls: usize,
    exchange_capture: Option<ExchangeCapture>,
    refresh_capture: Option<RefreshCapture>,
    refresh_delay: Duration,
}

#[derive(Clone)]
struct ExchangeCapture {
    client_id: String,
    code: String,
    verifier: String,
    redirect_uri: String,
    resource: String,
}

#[derive(Clone)]
struct RefreshCapture {
    client_id: String,
    refresh_token: String,
    resource: String,
}

#[derive(Default)]
struct TransportMock {
    state: Arc<Mutex<TransportState>>,
}

impl TransportMock {
    fn push_exchange(&self, response: Result<TokenResponse, TokenTransportError>) {
        self.state.lock().unwrap().exchange.push_back(response);
    }

    fn push_refresh(&self, response: Result<TokenResponse, TokenTransportError>) {
        self.state.lock().unwrap().refresh.push_back(response);
    }

    fn push_revoke(&self, response: Result<(), TokenTransportError>) {
        self.state.lock().unwrap().revoke.push_back(response);
    }

    fn exchange_calls(&self) -> usize {
        self.state.lock().unwrap().exchange_calls
    }

    fn refresh_calls(&self) -> usize {
        self.state.lock().unwrap().refresh_calls
    }

    fn revoke_calls(&self) -> usize {
        self.state.lock().unwrap().revoke_calls
    }

    fn exchange_capture(&self) -> ExchangeCapture {
        self.state
            .lock()
            .unwrap()
            .exchange_capture
            .clone()
            .expect("exchange was called")
    }

    fn refresh_capture(&self) -> RefreshCapture {
        self.state
            .lock()
            .unwrap()
            .refresh_capture
            .clone()
            .expect("refresh was called")
    }

    fn set_refresh_delay(&self, delay: Duration) {
        self.state.lock().unwrap().refresh_delay = delay;
    }
}

impl TokenTransport for TransportMock {
    fn exchange(
        &self,
        request: &TokenExchangeRequest,
    ) -> Result<TokenResponse, TokenTransportError> {
        let mut state = self.state.lock().unwrap();
        state.exchange_calls += 1;
        state.exchange_capture = Some(ExchangeCapture {
            client_id: request.client_id().to_owned(),
            code: request.code().to_owned(),
            verifier: request.code_verifier().to_owned(),
            redirect_uri: request.redirect_uri().to_owned(),
            resource: request.resource().to_owned(),
        });
        state
            .exchange
            .pop_front()
            .unwrap_or(Err(TokenTransportError::Unavailable))
    }

    fn refresh(&self, request: &RefreshRequest) -> Result<TokenResponse, TokenTransportError> {
        let delay = {
            let mut state = self.state.lock().unwrap();
            state.refresh_calls += 1;
            state.refresh_capture = Some(RefreshCapture {
                client_id: request.client_id().to_owned(),
                refresh_token: request.refresh_token().to_owned(),
                resource: request.resource().to_owned(),
            });
            state.refresh_delay
        };
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        self.state
            .lock()
            .unwrap()
            .refresh
            .pop_front()
            .unwrap_or(Err(TokenTransportError::Unavailable))
    }

    fn revoke(&self, _request: &RevokeRequest) -> Result<(), TokenTransportError> {
        let mut state = self.state.lock().unwrap();
        state.revoke_calls += 1;
        state.revoke.pop_front().unwrap_or(Ok(()))
    }
}

#[derive(Clone, Default)]
struct RecordingBrowser {
    urls: Arc<Mutex<Vec<String>>>,
}

impl BrowserOpener for RecordingBrowser {
    fn open(&self, authorization_url: &str) -> Result<(), AuthError> {
        self.urls.lock().unwrap().push(authorization_url.to_owned());
        Ok(())
    }
}

fn ec_jwks() -> Arc<StaticJwks> {
    let json = format!(
        r#"{{"keys":[{{"kty":"EC","kid":"ec-key","alg":"ES256","crv":"P-256","x":"{EC_JWK_X}","y":"{EC_JWK_Y}"}}]}}"#
    );
    Arc::new(StaticJwks::new(JwkSet::parse(json.as_bytes()).unwrap()))
}

fn test_jwks() -> Arc<StaticJwks> {
    let json = format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"test-key","alg":"RS256","n":"{TEST_KEY_JWK_N}","e":"AQAB"}}]}}"#
    );
    Arc::new(StaticJwks::new(JwkSet::parse(json.as_bytes()).unwrap()))
}

struct Harness {
    auth: ChatGptAuth<FakeVault>,
    admin: ConnectionAdmin,
    vault: FakeVault,
    transport: Arc<TransportMock>,
    browser: RecordingBrowser,
    accounts: Arc<InMemoryAccountDirectory>,
    clock: Arc<FixedClock>,
    connection: ConnectionId,
}

impl Harness {
    fn new() -> Self {
        Self::with_config(
            test_jwks(),
            ChatGptAuthConfig::new("herness-test")
                .with_terms(TermsConfirmation::local_unpublished()),
        )
    }

    fn with_config(jwks: Arc<dyn JwksSource>, config: ChatGptAuthConfig) -> Self {
        let admin = ConnectionAdmin::new();
        let settings = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-5",
            AuthMethod::ChatGptLogin,
            None,
            None,
        )
        .unwrap();
        let connection = settings.connection_id();
        admin.add(settings).unwrap();
        let vault = FakeVault::default();
        let transport = Arc::new(TransportMock::default());
        let browser = RecordingBrowser::default();
        let accounts = Arc::new(InMemoryAccountDirectory::new());
        let clock = Arc::new(FixedClock::new(Timestamp::from_unix_millis(NOW_MILLIS)));
        let host_store = Arc::new(MemoryHostIdStore::new());
        let auth = ChatGptAuth::new(
            admin.clone(),
            vault.clone(),
            accounts.clone(),
            host_store,
            transport.clone(),
            jwks,
            clock.clone(),
            Arc::new(browser.clone()),
            config,
        )
        .unwrap();
        Self {
            auth,
            admin,
            vault,
            transport,
            browser,
            accounts,
            clock,
            connection,
        }
    }

    fn begin_new(&self) -> Arc<PendingAuthorization> {
        self.auth
            .begin_sign_in(&SignInRequest::new_account(self.connection))
            .unwrap()
    }

    fn begin_reauth(&self, account: &ChatGptAccount) -> Arc<PendingAuthorization> {
        self.auth
            .begin_sign_in(&SignInRequest::reauthorize(
                self.connection,
                account.reference(),
            ))
            .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_in(
        &self,
        client_id: &str,
        sub: &str,
        access: &str,
        refresh: &str,
        scopes: &str,
        claims: Option<Value>,
        signer: &str,
    ) -> Result<SignInOutcome, AuthError> {
        let pending = self.begin_new();
        let url = pending.authorization_url().to_owned();
        let state = query_param(&url, "state");
        let nonce = query_param(&url, "nonce");
        let claims = claims.unwrap_or_else(|| {
            id_claims(
                client_id,
                &nonce,
                sub,
                "user@example.com",
                NOW_MILLIS / 1000,
            )
        });
        let id_token = sign_jwt(&claims, "test-key", signer);
        self.transport.push_exchange(Ok(TokenResponse::new(
            access,
            Some(refresh),
            Some(&id_token),
            3600,
            Some(scopes),
        )
        .unwrap()));
        send_callback(
            &pending,
            &[
                ("code", CANARY_CODE),
                ("state", &state),
                ("client_id", client_id),
                ("scope", scopes),
            ],
        );
        pending
            .wait_for_callback(Duration::from_secs(2))
            .expect("loopback callback");
        self.auth.complete_sign_in(&pending)
    }

    fn sign_out(&self, account: &ChatGptAccount) -> Result<SignOutOutcome, AuthError> {
        self.auth.sign_out(self.connection, &account.reference())
    }
}

fn id_claims(
    client_id: &str,
    nonce: &str,
    subject: &str,
    email: &str,
    issued_at_seconds: u64,
) -> Value {
    json!({
        "iss": "https://auth.openai.com",
        "aud": [client_id],
        "sub": subject,
        "exp": issued_at_seconds + 3600,
        "iat": issued_at_seconds,
        "nonce": nonce,
        "email": email,
    })
}

fn sign_jwt_es256(claims: &Value, kid: &str) -> String {
    let header = json!({"alg": "ES256", "kid": kid, "typ": "JWT"});
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header}.{claims}");
    let key_der = base64::engine::general_purpose::STANDARD
        .decode(EC_KEY_PKCS8_B64)
        .unwrap();
    let rng = SystemRandom::new();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &key_der, &rng)
        .expect("valid EC test key");
    let signature = key.sign(&rng, signing_input.as_bytes()).unwrap();
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    )
}

fn sign_jwt(claims: &Value, kid: &str, key_b64: &str) -> String {
    let header = json!({"alg": "RS256", "kid": kid, "typ": "JWT"});
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header}.{claims}");
    let key_der = URL_SAFE_NO_PAD
        .decode(key_b64.trim())
        .or_else(|_| {
            use base64::engine::general_purpose::STANDARD;
            STANDARD.decode(key_b64.trim())
        })
        .expect("embedded test key");
    let key = RsaKeyPair::from_pkcs8(&key_der).expect("valid test key");
    let mut signature = vec![0_u8; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signing_input.as_bytes(),
        &mut signature,
    )
    .expect("sign synthetic ID token");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn send_callback(pending: &PendingAuthorization, params: &[(&str, &str)]) {
    let uri = pending.redirect_uri();
    let authority = uri
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap();
    let query = params
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let mut stream = TcpStream::connect(authority).expect("connect loopback listener");
    write!(
        stream,
        "GET /auth/callback?{query} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    // The listener consumes this request when the test waits for the callback.
    // Do not read the response here: the test is single-threaded and the
    // listener has not started accepting yet.
}

fn query_param(url: &str, name: &str) -> String {
    let query = url.split_once('?').expect("authorization URL has query").1;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(key) == name {
            return percent_decode(value);
        }
    }
    panic!("missing query parameter {name}");
}

fn percent_encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = hex(bytes[index + 1]);
                let low = hex(bytes[index + 2]);
                output.push((high << 4) | low);
                index += 3;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(output).unwrap()
}

fn hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("bad percent encoding"),
    }
}

#[test]
fn es256_id_tokens_are_accepted() {
    let harness = Harness::with_config(
        ec_jwks(),
        ChatGptAuthConfig::new("herness-test").with_terms(TermsConfirmation::local_unpublished()),
    );
    let pending = harness.begin_new();
    let url = pending.authorization_url().to_owned();
    let state = query_param(&url, "state");
    let nonce = query_param(&url, "nonce");
    let claims = id_claims(
        "oaiapp_es256",
        &nonce,
        "subject-es256",
        "ec@example.com",
        NOW_MILLIS / 1000,
    );
    let id_token = sign_jwt_es256(&claims, "ec-key");
    harness.transport.push_exchange(Ok(TokenResponse::new(
        "access-es256",
        Some("refresh-es256"),
        Some(&id_token),
        3600,
        Some(PLAN_SCOPE),
    )
    .unwrap()));
    send_callback(
        &pending,
        &[
            ("code", "code-es256"),
            ("state", &state),
            ("client_id", "oaiapp_es256"),
        ],
    );
    pending.wait_for_callback(Duration::from_secs(2)).unwrap();
    let outcome = harness.auth.complete_sign_in(&pending).unwrap();
    assert!(outcome.plan_enabled);
    assert_eq!(outcome.account.subject(), "subject-es256");
}

#[test]
fn happy_path_new_registration_uses_dynamic_client_then_saves_issued_account() {
    let harness = Harness::new();
    let pending = harness.begin_new();
    let url = pending.authorization_url().to_owned();
    let state = query_param(&url, "state");
    let nonce = query_param(&url, "nonce");
    let challenge = query_param(&url, "code_challenge");
    let redirect_uri = query_param(&url, "redirect_uri");

    assert_eq!(query_param(&url, "client_id"), "dynamic_agent_client");
    assert_eq!(query_param(&url, "agent_name_hint"), "herness-test");
    assert!(query_param(&url, "ext_agent_host_id").starts_with("urn:uuid:"));
    assert_eq!(query_param(&url, "response_type"), "code");
    assert_eq!(query_param(&url, "scope"), PLAN_SCOPE);
    assert_eq!(query_param(&url, "resource"), "https://api.openai.com/v1");
    assert_eq!(query_param(&url, "code_challenge_method"), "S256");
    assert!(redirect_uri.starts_with("http://127.0.0.1:"));
    assert!(redirect_uri.ends_with("/auth/callback"));
    assert!(!url.contains("localhost"));
    assert!(!state.is_empty());
    assert!(!nonce.is_empty());
    // A fresh verifier produces a challenge that is not the verifier itself.
    assert_ne!(challenge, nonce);

    let claims = id_claims(
        "oaiapp_issued_one",
        &nonce,
        "subject-one",
        "one@example.com",
        NOW_MILLIS / 1000,
    );
    let id_token = sign_jwt(&claims, "test-key", TEST_KEY_PKCS8_B64);
    harness.transport.push_exchange(Ok(TokenResponse::new(
        CANARY_ACCESS,
        Some(CANARY_REFRESH),
        Some(&id_token),
        3600,
        Some(PLAN_SCOPE),
    )
    .unwrap()));
    send_callback(
        &pending,
        &[
            ("code", CANARY_CODE),
            ("state", &state),
            ("client_id", "oaiapp_issued_one"),
            ("scope", PLAN_SCOPE),
        ],
    );
    pending
        .wait_for_callback(Duration::from_secs(2))
        .expect("loopback callback");
    let outcome = harness.auth.complete_sign_in(&pending).unwrap();

    assert!(outcome.plan_enabled);
    assert_eq!(outcome.account.client_id().as_str(), "oaiapp_issued_one");
    assert_eq!(outcome.account.subject(), "subject-one");
    assert_eq!(outcome.account.email(), Some("one@example.com"));

    let capture = harness.transport.exchange_capture();
    assert_eq!(capture.client_id, "oaiapp_issued_one");
    assert_eq!(capture.code, CANARY_CODE);
    assert_eq!(capture.redirect_uri, redirect_uri);
    assert_eq!(capture.resource, "https://api.openai.com/v1");
    assert!(!capture.verifier.is_empty());
    assert_ne!(capture.client_id, "dynamic_agent_client");

    let account = outcome.account.clone();
    let stored = harness
        .auth
        .account_token_set_at(harness.connection, account.vault_account())
        .unwrap()
        .expect("stored token set");
    assert_eq!(stored.access_token().expose_secret(), CANARY_ACCESS);
    assert_eq!(
        stored.refresh_token().unwrap().expose_secret(),
        CANARY_REFRESH
    );
    assert_eq!(stored.id_token().unwrap().expose_secret(), id_token);
    assert_eq!(stored.account_subject(), Some("subject-one"));
    assert_eq!(stored.issued_client_id(), Some("oaiapp_issued_one"));
    assert!(stored.has_scope("chatgpt.tokens.use.direct"));
    assert_eq!(stored.plan_usage(), Some(true));

    let settings = harness.admin.directory().get(harness.connection).unwrap();
    assert_eq!(
        settings.selected_chatgpt_account(),
        Some(account.vault_account())
    );
    assert_eq!(
        harness.auth.state(harness.connection).unwrap(),
        ChatGptAuthState::Available {
            account: Some(account.clone())
        }
    );
    assert_eq!(
        harness.auth.host_id().unwrap(),
        harness.auth.host_id().unwrap()
    );
}

#[test]
fn host_id_is_generated_once_reused_on_restart_and_distinct_per_store() {
    let temp = tempfile::TempDir::new().unwrap();
    let first_path = temp.path().join("host-a").join("host-id");
    let second_path = temp.path().join("host-b").join("host-id");
    let store = Arc::new(FileHostIdStore::new(first_path.clone()));
    let first = HostIdManager::new(store.clone()).ensure().unwrap();
    assert!(first.as_str().starts_with("urn:uuid:"));
    let restarted = HostIdManager::new(store).ensure().unwrap();
    assert_eq!(first, restarted);
    assert_eq!(
        std::fs::read_to_string(&first_path).unwrap().trim(),
        first.as_str()
    );

    let other_store = Arc::new(FileHostIdStore::new(second_path));
    let other = HostIdManager::new(other_store).ensure().unwrap();
    assert_ne!(first, other);
}

#[test]
fn each_attempt_gets_fresh_state_nonce_and_pkce_values() {
    let harness = Harness::new();
    let first = harness.begin_new();
    let first_url = first.authorization_url().to_owned();
    first.cancel();
    let second = harness.begin_new();
    let second_url = second.authorization_url().to_owned();
    second.cancel();

    assert_ne!(
        query_param(&first_url, "state"),
        query_param(&second_url, "state")
    );
    assert_ne!(
        query_param(&first_url, "nonce"),
        query_param(&second_url, "nonce")
    );
    assert_ne!(
        query_param(&first_url, "code_challenge"),
        query_param(&second_url, "code_challenge")
    );
}

#[test]
fn state_mismatch_rejects_before_exchange_and_leaves_no_credentials() {
    let harness = Harness::new();
    let pending = harness.begin_new();
    let url = pending.authorization_url().to_owned();
    let nonce = query_param(&url, "nonce");
    let claims = id_claims(
        "oaiapp_state",
        &nonce,
        "sub",
        "e@example.com",
        NOW_MILLIS / 1000,
    );
    let id_token = sign_jwt(&claims, "test-key", TEST_KEY_PKCS8_B64);
    harness.transport.push_exchange(Ok(TokenResponse::new(
        "access",
        Some("refresh"),
        Some(&id_token),
        3600,
        Some(PLAN_SCOPE),
    )
    .unwrap()));
    send_callback(
        &pending,
        &[
            ("code", CANARY_CODE),
            ("state", "wrong-state"),
            ("client_id", "oaiapp_state"),
        ],
    );
    pending
        .wait_for_callback(Duration::from_secs(2))
        .expect("callback");
    assert_eq!(
        harness.auth.complete_sign_in(&pending).unwrap_err(),
        AuthError::StateMismatch
    );
    assert_eq!(harness.transport.exchange_calls(), 0);
    assert_eq!(harness.vault.write_count(), 0);
}

#[test]
fn id_token_rejections_do_not_save_or_select_credentials() {
    let harness = Harness::new();
    let wrong_key = OTHER_KEY_PKCS8_B64;

    type ClaimBuilder = Box<dyn Fn(&str, &str) -> Value>;
    let cases: Vec<(&str, ClaimBuilder, &str)> = vec![
        (
            "nonce",
            Box::new(|client, _nonce| {
                let mut claims = id_claims(
                    client,
                    "different-nonce",
                    "sub",
                    "e@example.com",
                    NOW_MILLIS / 1000,
                );
                claims["nonce"] = json!("different-nonce");
                claims
            }),
            TEST_KEY_PKCS8_B64,
        ),
        (
            "signature",
            Box::new(|client, nonce| {
                id_claims(client, nonce, "sub", "e@example.com", NOW_MILLIS / 1000)
            }),
            wrong_key,
        ),
        (
            "issuer",
            Box::new(|client, nonce| {
                let mut claims =
                    id_claims(client, nonce, "sub", "e@example.com", NOW_MILLIS / 1000);
                claims["iss"] = json!("https://evil.example.com");
                claims
            }),
            TEST_KEY_PKCS8_B64,
        ),
        (
            "audience",
            Box::new(|client, nonce| {
                let mut claims =
                    id_claims(client, nonce, "sub", "e@example.com", NOW_MILLIS / 1000);
                claims["aud"] = json!(["oaiapp_other"]);
                claims
            }),
            TEST_KEY_PKCS8_B64,
        ),
        (
            "expired",
            Box::new(|client, nonce| {
                let mut claims =
                    id_claims(client, nonce, "sub", "e@example.com", NOW_MILLIS / 1000);
                claims["exp"] = json!((NOW_MILLIS / 1000) - 3600);
                claims
            }),
            TEST_KEY_PKCS8_B64,
        ),
    ];

    for (name, claims_for, signer) in cases {
        let pending = harness.begin_new();
        let url = pending.authorization_url().to_owned();
        let state = query_param(&url, "state");
        let nonce = query_param(&url, "nonce");
        let client_id = format!("oaiapp_{name}");
        let claims = claims_for(&client_id, &nonce);
        let id_token = sign_jwt(&claims, "test-key", signer);
        harness.transport.push_exchange(Ok(TokenResponse::new(
            "access",
            Some("refresh"),
            Some(&id_token),
            3600,
            Some(PLAN_SCOPE),
        )
        .unwrap()));
        send_callback(
            &pending,
            &[
                ("code", CANARY_CODE),
                ("state", &state),
                ("client_id", &client_id),
            ],
        );
        pending.wait_for_callback(Duration::from_secs(2)).unwrap();
        let error = harness.auth.complete_sign_in(&pending).expect_err(name);
        assert!(
            matches!(
                error,
                AuthError::IdToken {
                    failure: IdTokenFailure::Nonce
                        | IdTokenFailure::Signature
                        | IdTokenFailure::Issuer
                        | IdTokenFailure::Audience
                        | IdTokenFailure::Expired
                }
            ),
            "{name}: {error:?}"
        );
        assert_eq!(
            harness.accounts.accounts(harness.connection).unwrap().len(),
            0,
            "{name}"
        );
        assert_eq!(harness.vault.write_count(), 0, "{name}");
    }
}

#[test]
fn missing_plan_scope_authenticates_but_does_not_select_or_enable() {
    let harness = Harness::new();
    let outcome = harness
        .sign_in(
            "oaiapp_noplan",
            "subject-noplan",
            "access-noplan",
            "refresh-noplan",
            "openid profile email offline_access resource.invoke",
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    assert!(!outcome.plan_enabled);
    assert_eq!(
        harness.accounts.accounts(harness.connection).unwrap().len(),
        1
    );
    let settings = harness.admin.directory().get(harness.connection).unwrap();
    assert!(settings.selected_chatgpt_account().is_none());
    assert_eq!(
        harness.auth.state(harness.connection).unwrap(),
        ChatGptAuthState::LoginRequired
    );
    assert_eq!(
        harness
            .auth
            .account_state(harness.connection, &outcome.account.reference())
            .unwrap(),
        ChatGptAuthState::AuthenticatedWithoutPlan {
            account: outcome.account.clone()
        }
    );
    let stored = harness
        .auth
        .account_token_set_at(harness.connection, outcome.account.vault_account())
        .unwrap()
        .unwrap();
    assert_eq!(stored.plan_usage(), Some(false));
    assert!(!stored.plan_scope_satisfied());

    // If a host explicitly selected the plan-less account, the Task 7 broker
    // still refuses to resolve an access token for inference.
    let settings = harness.admin.directory().get(harness.connection).unwrap();
    harness
        .admin
        .update(
            settings
                .select_chatgpt_account(outcome.account.vault_account().clone())
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        harness
            .auth
            .resolve_at(harness.connection, Timestamp::from_unix_millis(NOW_MILLIS))
            .unwrap_err(),
        CoreError::CredentialUnavailable {
            connection: harness.connection,
            failure: CredentialFailureKind::PlanScopeMissing,
        }
    );
    assert_eq!(
        harness.auth.state(harness.connection).unwrap(),
        ChatGptAuthState::AuthenticatedWithoutPlan {
            account: outcome.account.clone()
        }
    );
    assert_eq!(
        harness
            .admin
            .directory()
            .get(harness.connection)
            .unwrap()
            .public_info(ConnectionStatus::AuthRequired)
            .unwrap()
            .status(),
        ConnectionStatus::AuthRequired
    );
}

#[test]
fn an_empty_scope_response_is_not_treated_as_plan_usage() {
    let harness = Harness::new();
    let outcome = harness
        .sign_in(
            "oaiapp_empty_scope",
            "subject-empty-scope",
            "access-empty",
            "refresh-empty",
            "   ",
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    assert!(!outcome.plan_enabled);
    let stored = harness
        .auth
        .account_token_set_at(harness.connection, outcome.account.vault_account())
        .unwrap()
        .unwrap();
    assert_eq!(stored.plan_usage(), Some(false));
    assert!(!stored.plan_scope_satisfied());
    assert_eq!(
        harness.auth.state(harness.connection).unwrap(),
        ChatGptAuthState::LoginRequired
    );
}

#[test]
fn callback_replay_is_rejected_and_exchanges_only_once() {
    let harness = Harness::new();
    let pending = harness.begin_new();
    let url = pending.authorization_url().to_owned();
    let state = query_param(&url, "state");
    let nonce = query_param(&url, "nonce");
    let claims = id_claims(
        "oaiapp_replay",
        &nonce,
        "sub",
        "e@example.com",
        NOW_MILLIS / 1000,
    );
    let id_token = sign_jwt(&claims, "test-key", TEST_KEY_PKCS8_B64);
    harness.transport.push_exchange(Ok(TokenResponse::new(
        "access",
        Some("refresh"),
        Some(&id_token),
        3600,
        Some(PLAN_SCOPE),
    )
    .unwrap()));
    send_callback(
        &pending,
        &[
            ("code", CANARY_CODE),
            ("state", &state),
            ("client_id", "oaiapp_replay"),
        ],
    );
    pending.wait_for_callback(Duration::from_secs(2)).unwrap();
    harness.auth.complete_sign_in(&pending).unwrap();
    assert_eq!(
        harness.auth.complete_sign_in(&pending).unwrap_err(),
        AuthError::CallbackReplay
    );
    assert_eq!(harness.transport.exchange_calls(), 1);
}

#[test]
fn new_registration_without_issued_client_id_is_rejected() {
    let harness = Harness::new();
    let pending = harness.begin_new();
    let url = pending.authorization_url().to_owned();
    let state = query_param(&url, "state");
    send_callback(&pending, &[("code", CANARY_CODE), ("state", &state)]);
    pending.wait_for_callback(Duration::from_secs(2)).unwrap();
    assert_eq!(
        harness.auth.complete_sign_in(&pending).unwrap_err(),
        AuthError::MissingIssuedClientId
    );
    assert_eq!(harness.transport.exchange_calls(), 0);
    assert_eq!(harness.vault.write_count(), 0);
}

#[test]
fn dynamic_agent_client_is_never_accepted_as_an_issued_client() {
    let harness = Harness::new();
    let pending = harness.begin_new();
    let url = pending.authorization_url().to_owned();
    let state = query_param(&url, "state");
    send_callback(
        &pending,
        &[
            ("code", CANARY_CODE),
            ("state", &state),
            ("client_id", "dynamic_agent_client"),
        ],
    );
    pending.wait_for_callback(Duration::from_secs(2)).unwrap();
    assert_eq!(
        harness.auth.complete_sign_in(&pending).unwrap_err(),
        AuthError::InvalidIssuedClientId
    );
    assert_eq!(harness.transport.exchange_calls(), 0);
    assert_eq!(harness.vault.write_count(), 0);
}

#[test]
fn callback_client_mismatch_keeps_the_existing_account() {
    let harness = Harness::new();
    let first = harness
        .sign_in(
            "oaiapp_first",
            "subject-first",
            "access-first",
            "refresh-first",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    let before = harness
        .vault
        .raw(first.account.vault_account().as_str())
        .unwrap();

    let pending = harness.begin_reauth(&first.account);
    let url = pending.authorization_url().to_owned();
    let state = query_param(&url, "state");
    send_callback(
        &pending,
        &[
            ("code", CANARY_CODE),
            ("state", &state),
            ("client_id", "oaiapp_different"),
        ],
    );
    pending.wait_for_callback(Duration::from_secs(2)).unwrap();
    assert_eq!(
        harness.auth.complete_sign_in(&pending).unwrap_err(),
        AuthError::ClientMismatch
    );
    assert_eq!(harness.transport.exchange_calls(), 1);
    assert_eq!(
        harness
            .vault
            .raw(first.account.vault_account().as_str())
            .unwrap(),
        before
    );
    let settings = harness.admin.directory().get(harness.connection).unwrap();
    assert_eq!(
        settings.selected_chatgpt_account(),
        Some(first.account.vault_account())
    );
}

#[test]
fn returning_sign_in_reuses_issued_client_and_retained_hints() {
    let harness = Harness::new();
    let first = harness
        .sign_in(
            "oaiapp_returning",
            "subject-returning",
            "access-returning",
            "refresh-returning",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    let first_id_token = harness
        .auth
        .account_token_set_at(harness.connection, first.account.vault_account())
        .unwrap()
        .unwrap()
        .id_token()
        .unwrap()
        .expose_secret()
        .to_owned();

    let pending = harness.begin_reauth(&first.account);
    let url = pending.authorization_url().to_owned();
    assert_eq!(query_param(&url, "client_id"), "oaiapp_returning");
    assert!(
        !url.contains("agent_name_hint="),
        "reauthorization must omit agent_name_hint"
    );
    assert_eq!(query_param(&url, "id_token_hint"), first_id_token);
    assert_eq!(query_param(&url, "login_hint"), "user@example.com");
    assert!(query_param(&url, "ext_agent_host_id").starts_with("urn:uuid:"));

    let state = query_param(&url, "state");
    let nonce = query_param(&url, "nonce");
    let claims = id_claims(
        "oaiapp_returning",
        &nonce,
        "subject-returning",
        "user@example.com",
        NOW_MILLIS / 1000,
    );
    let id_token = sign_jwt(&claims, "test-key", TEST_KEY_PKCS8_B64);
    harness.transport.push_exchange(Ok(TokenResponse::new(
        "access-returning-2",
        Some("refresh-returning-2"),
        Some(&id_token),
        3600,
        Some(PLAN_SCOPE),
    )
    .unwrap()));
    send_callback(&pending, &[("code", "code-2"), ("state", &state)]);
    pending.wait_for_callback(Duration::from_secs(2)).unwrap();
    let second = harness.auth.complete_sign_in(&pending).unwrap();
    assert_eq!(second.account, first.account);
    let capture = harness.transport.exchange_capture();
    assert_eq!(capture.client_id, "oaiapp_returning");
    assert_eq!(harness.transport.exchange_calls(), 2);
    assert_eq!(
        harness
            .auth
            .account_token_set_at(harness.connection, first.account.vault_account())
            .unwrap()
            .unwrap()
            .access_token()
            .expose_secret(),
        "access-returning-2"
    );
}

#[test]
fn reauthorization_identity_mismatch_keeps_old_material() {
    let harness = Harness::new();
    let first = harness
        .sign_in(
            "oaiapp_identity",
            "subject-original",
            "access-original",
            "refresh-original",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    let before = harness
        .vault
        .raw(first.account.vault_account().as_str())
        .unwrap();

    let pending = harness.begin_reauth(&first.account);
    let url = pending.authorization_url().to_owned();
    let state = query_param(&url, "state");
    let nonce = query_param(&url, "nonce");
    let claims = id_claims(
        "oaiapp_identity",
        &nonce,
        "subject-different",
        "user@example.com",
        NOW_MILLIS / 1000,
    );
    let id_token = sign_jwt(&claims, "test-key", TEST_KEY_PKCS8_B64);
    harness.transport.push_exchange(Ok(TokenResponse::new(
        "access-attacker",
        Some("refresh-attacker"),
        Some(&id_token),
        3600,
        Some(PLAN_SCOPE),
    )
    .unwrap()));
    send_callback(&pending, &[("code", "code-3"), ("state", &state)]);
    pending.wait_for_callback(Duration::from_secs(2)).unwrap();
    assert_eq!(
        harness.auth.complete_sign_in(&pending).unwrap_err(),
        AuthError::AccountMismatch
    );
    assert_eq!(
        harness
            .vault
            .raw(first.account.vault_account().as_str())
            .unwrap(),
        before
    );
}

#[test]
fn reauthorization_without_plan_scope_keeps_the_old_usable_material() {
    let harness = Harness::new();
    let first = harness
        .sign_in(
            "oaiapp_reauth_plan",
            "subject-reauth-plan",
            "access-old",
            "refresh-old",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    let before = harness
        .vault
        .raw(first.account.vault_account().as_str())
        .unwrap();
    let pending = harness.begin_reauth(&first.account);
    let url = pending.authorization_url().to_owned();
    let state = query_param(&url, "state");
    let nonce = query_param(&url, "nonce");
    let claims = id_claims(
        "oaiapp_reauth_plan",
        &nonce,
        "subject-reauth-plan",
        "user@example.com",
        NOW_MILLIS / 1000,
    );
    let id_token = sign_jwt(&claims, "test-key", TEST_KEY_PKCS8_B64);
    harness.transport.push_exchange(Ok(TokenResponse::new(
        "access-no-plan",
        Some("refresh-no-plan"),
        Some(&id_token),
        3600,
        Some("openid profile email"),
    )
    .unwrap()));
    send_callback(&pending, &[("code", "code-4"), ("state", &state)]);
    pending.wait_for_callback(Duration::from_secs(2)).unwrap();
    assert_eq!(
        harness.auth.complete_sign_in(&pending).unwrap_err(),
        AuthError::PlanScopeMissing
    );
    assert_eq!(
        harness
            .vault
            .raw(first.account.vault_account().as_str())
            .unwrap(),
        before
    );
    assert_eq!(
        harness.auth.state(harness.connection).unwrap(),
        ChatGptAuthState::Available {
            account: Some(first.account)
        }
    );
}

#[test]
fn two_accounts_are_kept_separate_and_do_not_overwrite() {
    let harness = Harness::new();
    let first = harness
        .sign_in(
            "oaiapp_account_a",
            "subject-a",
            "access-a",
            "refresh-a",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    let first_raw = harness
        .vault
        .raw(first.account.vault_account().as_str())
        .unwrap();
    let second = harness
        .sign_in(
            "oaiapp_account_b",
            "subject-b",
            "access-b",
            "refresh-b",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();

    assert_ne!(
        first.account.vault_account(),
        second.account.vault_account()
    );
    assert_eq!(
        harness.accounts.accounts(harness.connection).unwrap().len(),
        2
    );
    assert_eq!(
        harness
            .vault
            .raw(first.account.vault_account().as_str())
            .unwrap(),
        first_raw
    );
    let settings = harness.admin.directory().get(harness.connection).unwrap();
    assert_eq!(
        settings.selected_chatgpt_account(),
        Some(second.account.vault_account())
    );
    assert_eq!(
        harness.auth.state(harness.connection).unwrap(),
        ChatGptAuthState::Available {
            account: Some(second.account.clone())
        }
    );
}

#[test]
fn port_conflict_falls_back_to_another_port_without_changing_host_or_path() {
    let occupied = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let config = ChatGptAuthConfig::new("herness-test")
        .with_preferred_port(occupied_port)
        .with_terms(TermsConfirmation::local_unpublished());
    let harness = Harness::with_config(test_jwks(), config);
    let pending = harness.begin_new();
    let redirect_uri = pending.redirect_uri().to_owned();
    assert!(redirect_uri.starts_with("http://127.0.0.1:"));
    assert!(redirect_uri.ends_with("/auth/callback"));
    assert_ne!(
        redirect_uri,
        format!("http://127.0.0.1:{occupied_port}/auth/callback")
    );
    assert!(!redirect_uri.contains("localhost"));
    pending.cancel();
}

#[test]
fn cancellation_closes_the_listener_and_never_exchanges_a_code() {
    let harness = Harness::new();
    let pending = harness.begin_new();
    let authority = pending
        .redirect_uri()
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_owned();
    harness.auth.cancel_sign_in(&pending).unwrap();
    let mut closed = false;
    for _ in 0..20 {
        if TcpStream::connect(&authority).is_err() {
            closed = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(closed, "cancellation left the loopback listener open");
    assert_eq!(
        harness.auth.complete_sign_in(&pending).unwrap_err(),
        AuthError::Cancelled
    );
    assert_eq!(harness.transport.exchange_calls(), 0);
    assert_eq!(harness.vault.write_count(), 0);

    // A later attempt is allowed again.
    let next = harness.begin_new();
    next.cancel();
}

#[test]
fn access_denied_and_exchange_failure_do_not_save_credentials() {
    let harness = Harness::new();
    let pending = harness.begin_new();
    let url = pending.authorization_url().to_owned();
    let state = query_param(&url, "state");
    send_callback(&pending, &[("error", "access_denied"), ("state", &state)]);
    pending.wait_for_callback(Duration::from_secs(2)).unwrap();
    assert_eq!(
        harness.auth.complete_sign_in(&pending).unwrap_err(),
        AuthError::AccessDenied
    );
    assert_eq!(harness.transport.exchange_calls(), 0);

    let pending = harness.begin_new();
    let url = pending.authorization_url().to_owned();
    let state = query_param(&url, "state");
    harness
        .transport
        .push_exchange(Err(TokenTransportError::InvalidGrant));
    send_callback(
        &pending,
        &[
            ("code", CANARY_CODE),
            ("state", &state),
            ("client_id", "oaiapp_failed"),
        ],
    );
    pending.wait_for_callback(Duration::from_secs(2)).unwrap();
    assert_eq!(
        harness.auth.complete_sign_in(&pending).unwrap_err(),
        AuthError::Transport {
            failure: TokenTransportError::InvalidGrant
        }
    );
    assert_eq!(harness.vault.write_count(), 0);
}

#[test]
fn missing_id_token_is_rejected_without_storing_credentials() {
    let harness = Harness::new();
    let pending = harness.begin_new();
    let url = pending.authorization_url().to_owned();
    let state = query_param(&url, "state");
    harness.transport.push_exchange(Ok(TokenResponse::new(
        "access",
        Some("refresh"),
        None,
        3600,
        Some(PLAN_SCOPE),
    )
    .unwrap()));
    send_callback(
        &pending,
        &[
            ("code", CANARY_CODE),
            ("state", &state),
            ("client_id", "oaiapp_no_id"),
        ],
    );
    pending.wait_for_callback(Duration::from_secs(2)).unwrap();
    assert_eq!(
        harness.auth.complete_sign_in(&pending).unwrap_err(),
        AuthError::MissingIdToken
    );
    assert_eq!(harness.vault.write_count(), 0);
}

#[test]
fn refresh_rotates_tokens_and_concurrent_refreshes_are_serialized() {
    let harness = Arc::new(Harness::new());
    harness
        .sign_in(
            "oaiapp_refresh",
            "subject-refresh",
            "access-old",
            "refresh-old",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    harness
        .transport
        .set_refresh_delay(Duration::from_millis(100));
    let later = NOW_MILLIS + 3_600_000 + 1;
    harness.clock.set(Timestamp::from_unix_millis(later));
    harness.transport.push_refresh(Ok(TokenResponse::new(
        "access-new",
        Some("refresh-new"),
        None,
        7200,
        Some(PLAN_SCOPE),
    )
    .unwrap()));

    let connection = harness.connection;
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let harness = Arc::clone(&harness);
            thread::spawn(move || {
                harness
                    .auth
                    .resolve_at(connection, Timestamp::from_unix_millis(later))
                    .map(|credential| credential.expose_secret().to_owned())
            })
        })
        .collect();
    for thread in threads {
        assert_eq!(thread.join().unwrap().unwrap(), "access-new");
    }
    assert_eq!(harness.transport.refresh_calls(), 1);
    let capture = harness.transport.refresh_capture();
    assert_eq!(capture.client_id, "oaiapp_refresh");
    assert_eq!(capture.refresh_token, "refresh-old");
    assert_eq!(capture.resource, "https://api.openai.com/v1");

    let stored = harness
        .auth
        .token_set_at(connection)
        .unwrap()
        .expect("stored token set");
    assert_eq!(stored.access_token().expose_secret(), "access-new");
    assert_eq!(
        stored.refresh_token().unwrap().expose_secret(),
        "refresh-new"
    );
    assert_eq!(
        stored.granted_scopes(),
        &[
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
            "offline_access".to_owned(),
            "resource.invoke".to_owned(),
            "chatgpt.tokens.use.direct".to_owned()
        ]
    );
    assert_eq!(
        stored.expires_at(),
        Some(Timestamp::from_unix_millis(later + 7_200_000))
    );
}

#[test]
fn failed_refresh_and_plan_scope_loss_stop_without_replacing_old_material() {
    let harness = Harness::new();
    let outcome = harness
        .sign_in(
            "oaiapp_refresh_fail",
            "subject-refresh-fail",
            "access-old",
            "refresh-old",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    let account = outcome.account.vault_account().as_str().to_owned();
    let before = harness.vault.raw(&account).unwrap();
    let later = NOW_MILLIS + 3_600_000 + 1;
    harness.clock.set(Timestamp::from_unix_millis(later));
    harness
        .transport
        .push_refresh(Err(TokenTransportError::InvalidGrant));
    assert_eq!(
        harness
            .auth
            .resolve_at(harness.connection, Timestamp::from_unix_millis(later))
            .unwrap_err(),
        CoreError::CredentialUnavailable {
            connection: harness.connection,
            failure: CredentialFailureKind::RefreshFailed,
        }
    );
    assert_eq!(harness.vault.raw(&account).unwrap(), before);
    assert_eq!(
        harness.auth.state(harness.connection).unwrap(),
        ChatGptAuthState::AuthRequired {
            account: Some(outcome.account.clone()),
            reason: AuthRequiredReason::Expired,
        }
    );

    let harness = Harness::new();
    let outcome = harness
        .sign_in(
            "oaiapp_scope_loss",
            "subject-scope-loss",
            "access-old",
            "refresh-old",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    let account = outcome.account.vault_account().as_str().to_owned();
    let before = harness.vault.raw(&account).unwrap();
    harness.clock.set(Timestamp::from_unix_millis(later));
    harness.transport.push_refresh(Ok(TokenResponse::new(
        "access-no-plan",
        Some("refresh-no-plan"),
        None,
        7200,
        Some("openid profile email"),
    )
    .unwrap()));
    assert_eq!(
        harness
            .auth
            .resolve_at(harness.connection, Timestamp::from_unix_millis(later))
            .unwrap_err(),
        CoreError::CredentialUnavailable {
            connection: harness.connection,
            failure: CredentialFailureKind::PlanScopeMissing,
        }
    );
    assert_eq!(harness.vault.raw(&account).unwrap(), before);
}

#[test]
fn credential_save_failure_keeps_the_previous_selection_and_material() {
    let harness = Harness::new();
    let first = harness
        .sign_in(
            "oaiapp_first",
            "subject-first",
            "access-first",
            "refresh-first",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    let before = harness
        .vault
        .raw(first.account.vault_account().as_str())
        .unwrap();
    harness.vault.fail_next_write(VaultFailure::UpdateFailed);
    let error = harness
        .sign_in(
            "oaiapp_second",
            "subject-second",
            "access-second",
            "refresh-second",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap_err();
    assert_eq!(
        error,
        AuthError::Vault {
            failure: CredentialFailureKind::KeychainWriteFailed
        }
    );
    assert_eq!(
        harness
            .vault
            .raw(first.account.vault_account().as_str())
            .unwrap(),
        before
    );
    let settings = harness.admin.directory().get(harness.connection).unwrap();
    assert_eq!(
        settings.selected_chatgpt_account(),
        Some(first.account.vault_account())
    );
    assert_eq!(
        harness.accounts.accounts(harness.connection).unwrap().len(),
        1
    );
}

#[test]
fn sign_out_removes_local_tokens_and_reports_unverified_revoke() {
    let harness = Harness::new();
    let outcome = harness
        .sign_in(
            "oaiapp_signout",
            "subject-signout",
            "access-signout",
            "refresh-signout",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    harness.transport.push_revoke(Ok(()));
    let signed_out = harness.sign_out(&outcome.account).unwrap();
    assert!(signed_out.local_credentials_removed);
    assert_eq!(
        signed_out.remote_revoke,
        RemoteRevokeStatus::RequestAcceptedUnverified
    );
    assert!(!signed_out.remote_revoke.is_confirmed());
    assert!(signed_out.issued_client_retained);
    assert!(signed_out.host_id_retained);
    assert_eq!(harness.transport.revoke_calls(), 1);
    assert!(
        harness
            .vault
            .raw(outcome.account.vault_account().as_str())
            .is_none()
    );
    let settings = harness.admin.directory().get(harness.connection).unwrap();
    assert!(settings.selected_chatgpt_account().is_none());
    assert_eq!(
        harness.auth.state(harness.connection).unwrap(),
        ChatGptAuthState::LoginRequired
    );
    // The non-secret mapping remains for a later sign-in.
    assert_eq!(
        harness.accounts.accounts(harness.connection).unwrap().len(),
        1
    );
}

#[test]
fn sign_out_delete_failure_reports_vault_failure_and_keeps_state() {
    let harness = Harness::new();
    let outcome = harness
        .sign_in(
            "oaiapp_delete_fail",
            "subject-delete-fail",
            "access-delete-fail",
            "refresh-delete-fail",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    harness.vault.fail_next_delete(VaultFailure::Denied);
    assert_eq!(
        harness.sign_out(&outcome.account).unwrap_err(),
        AuthError::Vault {
            failure: CredentialFailureKind::KeychainDenied
        }
    );
    assert!(
        harness
            .vault
            .raw(outcome.account.vault_account().as_str())
            .is_some()
    );
    assert_eq!(
        harness.auth.state(harness.connection).unwrap(),
        ChatGptAuthState::Available {
            account: Some(outcome.account)
        }
    );
}

#[test]
fn terms_gate_is_closed_by_default_and_never_opens_implicitly() {
    let harness = Harness::with_config(test_jwks(), ChatGptAuthConfig::new("herness-test"));
    assert_eq!(
        harness
            .auth
            .begin_sign_in(&SignInRequest::new_account(harness.connection))
            .unwrap_err(),
        AuthError::TermsGateClosed {
            reason: TermsGateReason::ConditionsUnconfirmed
        }
    );
    assert!(harness.browser.urls.lock().unwrap().is_empty());

    for reason in [
        TermsGateReason::LicenseUndecided,
        TermsGateReason::PublishedOrDistributed,
        TermsGateReason::PaidOffering,
        TermsGateReason::RemoteHosted,
    ] {
        let terms = TermsConfirmation {
            confirmed_on: "2026-11-08",
            gate: TermsGate::Closed(reason),
        };
        let harness = Harness::with_config(
            test_jwks(),
            ChatGptAuthConfig::new("herness-test").with_terms(terms),
        );
        assert_eq!(
            harness
                .auth
                .begin_sign_in(&SignInRequest::new_account(harness.connection))
                .unwrap_err(),
            AuthError::TermsGateClosed { reason }
        );
        assert!(harness.browser.urls.lock().unwrap().is_empty());
    }
}

#[test]
fn authorization_urls_tokens_and_identities_are_redacted_from_debug_output() {
    let harness = Harness::new();
    let outcome = harness
        .sign_in(
            "oaiapp_redact",
            "subject-canary-77db",
            "access-canary-51bd",
            "refresh-canary-e42a",
            PLAN_SCOPE,
            None,
            TEST_KEY_PKCS8_B64,
        )
        .unwrap();
    let pending = harness.begin_reauth(&outcome.account);
    let raw_url = pending.authorization_url().to_owned();
    assert!(raw_url.contains("id_token_hint="));
    let state = query_param(&raw_url, "state");
    let nonce = query_param(&raw_url, "nonce");
    let debug = format!("{pending:?}");
    for canary in [
        state.as_str(),
        nonce.as_str(),
        "access-canary-51bd",
        "refresh-canary-e42a",
    ] {
        assert!(!debug.contains(canary), "debug leaked {canary}: {debug}");
    }
    let redacted = pending.redacted_authorization_url();
    assert_eq!(redacted, "https://auth.openai.com/api/accounts/authorize");
    assert!(!redacted.contains("id_token_hint"));

    let request = TokenExchangeRequest::new(
        "oaiapp_redact",
        "code-canary-28f0",
        "verifier-canary-9182",
        "http://127.0.0.1:9999/auth/callback",
        "https://api.openai.com/v1",
    );
    let debug = format!("{request:?}");
    assert!(!debug.contains("code-canary-28f0"));
    assert!(!debug.contains("verifier-canary-9182"));

    let response = TokenResponse::new(
        "access-canary-51bd",
        Some("refresh-canary-e42a"),
        Some("id-token-canary-9c31"),
        3600,
        Some(PLAN_SCOPE),
    )
    .unwrap();
    let debug = format!("{response:?}");
    assert!(!debug.contains("access-canary-51bd"));
    assert!(!debug.contains("refresh-canary-e42a"));
    assert!(!debug.contains("id-token-canary-9c31"));

    let stored = harness
        .auth
        .token_set_at(harness.connection)
        .unwrap()
        .unwrap();
    let debug = format!("{stored:?}");
    assert!(!debug.contains("access-canary-51bd"));
    assert!(!debug.contains("refresh-canary-e42a"));
    assert!(!debug.contains(CANARY_ID));
    let account_debug = format!("{:?}", outcome.account);
    assert!(!account_debug.contains("subject-canary-77db"));
    assert!(!account_debug.contains("user@example.com"));

    pending.cancel();
    let error = AuthError::AccountMismatch;
    assert!(!format!("{error:?}").contains("canary"));
    assert!(!error.to_string().contains("canary"));
}
