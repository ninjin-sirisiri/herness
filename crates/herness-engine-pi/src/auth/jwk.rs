//! Provider JWKS boundary and synthetic-key support.
//!
//! Task 8 never fetches a real JWKS. The production transport will implement
//! [`JwksSource`] in Task 9. Tests supply a static synthetic key set.

use serde::Deserialize;

use super::error::JwksError;

/// One JSON Web Key accepted for ID-token signature verification.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type, `RSA` or `EC`.
    pub kty: String,
    /// Optional key ID used to match a JWT header.
    #[serde(default)]
    pub kid: Option<String>,
    /// Optional algorithm restriction.
    #[serde(default)]
    pub alg: Option<String>,
    /// RSA modulus, base64url.
    #[serde(default)]
    pub n: Option<String>,
    /// RSA public exponent, base64url.
    #[serde(default)]
    pub e: Option<String>,
    /// EC curve name.
    #[serde(default)]
    pub crv: Option<String>,
    /// EC x coordinate, base64url.
    #[serde(default)]
    pub x: Option<String>,
    /// EC y coordinate, base64url.
    #[serde(default)]
    pub y: Option<String>,
}

/// A provider key set.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct JwkSet {
    /// Published keys.
    #[serde(default)]
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Parses a JWKS JSON document.
    pub fn parse(bytes: &[u8]) -> Result<Self, JwksError> {
        let set: Self = serde_json::from_slice(bytes).map_err(|_| JwksError::Malformed)?;
        if set.keys.is_empty() {
            return Err(JwksError::Malformed);
        }
        Ok(set)
    }

    /// Creates a set from already parsed keys.
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }
}

/// Injectable JWKS retrieval boundary.
pub trait JwksSource: Send + Sync {
    /// Returns the current key set. Implementations must not cache past a key
    /// rotation without honoring provider cache headers in Task 9.
    fn jwks(&self) -> Result<JwkSet, JwksError>;
}

/// Static key set used by tests and deterministic hosts.
#[derive(Debug, Clone)]
pub struct StaticJwks {
    set: JwkSet,
}

impl StaticJwks {
    /// Wraps a key set.
    pub fn new(set: JwkSet) -> Self {
        Self { set }
    }

    /// Key set.
    pub fn set(&self) -> &JwkSet {
        &self.set
    }
}

impl JwksSource for StaticJwks {
    fn jwks(&self) -> Result<JwkSet, JwksError> {
        Ok(self.set.clone())
    }
}
