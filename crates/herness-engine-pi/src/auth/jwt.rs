//! ID-token validation against the provider JWKS.
//!
//! The implementation supports RS256 (required) and ES256. It verifies the
//! signature before trusting any claim, then checks issuer, audience, expiry,
//! issued-at, nonce, and subject. No token value is included in an error.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents, UnparsedPublicKey,
};
use serde::Deserialize;

use herness_core::Timestamp;

use super::error::IdTokenFailure;
use super::jwk::JwkSet;
use super::types::{CLOCK_SKEW_MILLIS, ISSUER, VerifiedIdentity};

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    iss: String,
    aud: Audience,
    sub: String,
    exp: u64,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

/// Validates an ID token and returns its verified account identity.
///
/// `expected_nonce` is `Some` for a fresh authorization-code exchange and
/// `None` for a refresh response, where the original nonce no longer applies.
pub fn validate_id_token(
    token: &str,
    keys: &JwkSet,
    expected_client_id: &str,
    expected_nonce: Option<&str>,
    now: Timestamp,
) -> Result<VerifiedIdentity, IdTokenFailure> {
    let mut segments = token.split('.');
    let header_segment = segments.next().ok_or(IdTokenFailure::Malformed)?;
    let claims_segment = segments.next().ok_or(IdTokenFailure::Malformed)?;
    let signature_segment = segments.next().ok_or(IdTokenFailure::Malformed)?;
    if segments.next().is_some() {
        return Err(IdTokenFailure::Malformed);
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_segment)
        .map_err(|_| IdTokenFailure::Malformed)?;
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(claims_segment)
        .map_err(|_| IdTokenFailure::Malformed)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_segment)
        .map_err(|_| IdTokenFailure::Malformed)?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| IdTokenFailure::Malformed)?;
    let claims: JwtClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| IdTokenFailure::Malformed)?;

    verify_signature(
        &header,
        &format!("{header_segment}.{claims_segment}"),
        &signature,
        keys,
    )?;

    if claims.iss != ISSUER {
        return Err(IdTokenFailure::Issuer);
    }
    if !claims.aud.contains(expected_client_id) {
        return Err(IdTokenFailure::Audience);
    }
    if claims.sub.is_empty() {
        return Err(IdTokenFailure::MissingSubject);
    }
    let now_millis = now.as_unix_millis();
    let expires_millis = claims.exp.saturating_mul(1000);
    if expires_millis.saturating_add(CLOCK_SKEW_MILLIS) < now_millis {
        return Err(IdTokenFailure::Expired);
    }
    if let Some(issued_at) = claims.iat {
        let issued_millis = issued_at.saturating_mul(1000);
        if issued_millis > now_millis.saturating_add(CLOCK_SKEW_MILLIS) {
            return Err(IdTokenFailure::NotYetValid);
        }
    }
    if let Some(expected) = expected_nonce {
        match claims.nonce.as_deref() {
            Some(actual) if actual == expected => {}
            _ => return Err(IdTokenFailure::Nonce),
        }
    }

    Ok(VerifiedIdentity {
        issuer: claims.iss,
        subject: claims.sub,
        email: claims.email,
    })
}

fn verify_signature(
    header: &JwtHeader,
    signing_input: &str,
    signature: &[u8],
    keys: &JwkSet,
) -> Result<(), IdTokenFailure> {
    let mut saw_signature_failure = false;
    for key in &keys.keys {
        if let Some(kid) = header.kid.as_deref()
            && key.kid.as_deref() != Some(kid)
        {
            continue;
        }
        if let Some(alg) = key.alg.as_deref()
            && alg != header.alg
        {
            continue;
        }
        let result = match header.alg.as_str() {
            "RS256" if key.kty == "RSA" => verify_rsa(key, signing_input, signature),
            "ES256" if key.kty == "EC" => verify_ec(key, signing_input, signature),
            "RS256" | "ES256" => continue,
            _ => return Err(IdTokenFailure::UnsupportedAlgorithm),
        };
        match result {
            Ok(()) => return Ok(()),
            Err(failure) => {
                if failure == IdTokenFailure::Signature {
                    saw_signature_failure = true;
                }
            }
        }
    }
    if saw_signature_failure {
        Err(IdTokenFailure::Signature)
    } else {
        Err(IdTokenFailure::NoMatchingKey)
    }
}

fn verify_rsa(
    key: &super::jwk::Jwk,
    signing_input: &str,
    signature: &[u8],
) -> Result<(), IdTokenFailure> {
    let n = decode_component(key.n.as_deref())?;
    let e = decode_component(key.e.as_deref())?;
    let components = RsaPublicKeyComponents { n: &n, e: &e };
    components
        .verify(
            &RSA_PKCS1_2048_8192_SHA256,
            signing_input.as_bytes(),
            signature,
        )
        .map_err(|_| IdTokenFailure::Signature)
}

fn verify_ec(
    key: &super::jwk::Jwk,
    signing_input: &str,
    signature: &[u8],
) -> Result<(), IdTokenFailure> {
    if key.crv.as_deref() != Some("P-256") {
        return Err(IdTokenFailure::NoMatchingKey);
    }
    let x = decode_component(key.x.as_deref())?;
    let y = decode_component(key.y.as_deref())?;
    if x.len() != 32 || y.len() != 32 {
        return Err(IdTokenFailure::Malformed);
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .verify(signing_input.as_bytes(), signature)
        .map_err(|_| IdTokenFailure::Signature)
}

fn decode_component(value: Option<&str>) -> Result<Vec<u8>, IdTokenFailure> {
    let value = value.ok_or(IdTokenFailure::NoMatchingKey)?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| IdTokenFailure::Malformed)
}
