//! Fresh state, nonce, and PKCE values for each authorization attempt.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};

use super::error::AuthError;

/// Values generated once for one authorization attempt.
pub struct AttemptSecrets {
    state: String,
    nonce: String,
    code_verifier: String,
    code_challenge: String,
}

impl AttemptSecrets {
    /// Generates a fresh attempt with 256-bit random state and nonce and a
    /// 43-character PKCE verifier.
    pub fn generate() -> Result<Self, AuthError> {
        let rng = SystemRandom::new();
        let mut state_bytes = [0_u8; 32];
        let mut nonce_bytes = [0_u8; 32];
        let mut verifier_bytes = [0_u8; 32];
        rng.fill(&mut state_bytes)
            .map_err(|_| AuthError::RandomUnavailable)?;
        rng.fill(&mut nonce_bytes)
            .map_err(|_| AuthError::RandomUnavailable)?;
        rng.fill(&mut verifier_bytes)
            .map_err(|_| AuthError::RandomUnavailable)?;
        let state = URL_SAFE_NO_PAD.encode(state_bytes);
        let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
        let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
        let code_challenge = code_challenge(&code_verifier);
        Ok(Self {
            state,
            nonce,
            code_verifier,
            code_challenge,
        })
    }

    /// Fresh state value for this attempt.
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Fresh OIDC nonce for this attempt.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// PKCE verifier. Never log this value.
    pub fn code_verifier(&self) -> &str {
        &self.code_verifier
    }

    /// Base64url SHA-256 PKCE challenge without padding.
    pub fn code_challenge(&self) -> &str {
        &self.code_challenge
    }
}

/// Computes the S256 PKCE challenge for a verifier.
pub fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Constant-time comparison for state and nonce values.
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}
