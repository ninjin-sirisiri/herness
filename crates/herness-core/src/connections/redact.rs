//! Redaction helpers for logs, sanitized errors, and diagnostics.
//!
//! These helpers are deliberately conservative. A URL keeps only its scheme,
//! host, explicit port, and path; user information, query strings, and
//! fragments are dropped. Sensitive request headers are replaced entirely.
//! Callers can also register known secrets (for example a value that failed to
//! parse) and scrub them from any diagnostic text before display.

use crate::contracts::errors::CoreError;

/// Replacement text used for every redacted value.
pub const REDACTED: &str = "[REDACTED]";

/// Longest URL prefix retained by [`redact_url`], in Unicode scalar values.
pub const MAX_REDACTED_URL_CHARS: usize = 512;

/// Removes user information, query strings, and fragments from a URL.
///
/// Input that does not contain a plausible `scheme://authority` shape is
/// replaced with `[invalid url]` instead of being echoed, because the raw text
/// may itself contain a secret. A truncated result retains at most
/// [`MAX_REDACTED_URL_CHARS`] Unicode scalar values and appends an ellipsis.
pub fn redact_url(input: &str) -> String {
    if input.chars().any(char::is_control) {
        return "[invalid url]".to_owned();
    }
    let trimmed = input.trim();
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return "[invalid url]".to_owned();
    };
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '-' | '.'))
    {
        return "[invalid url]".to_owned();
    }

    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host.is_empty() {
        return "[invalid url]".to_owned();
    }

    let remainder = &rest[authority_end..];
    let path_end = remainder.find(['?', '#']).unwrap_or(remainder.len());
    let path = &remainder[..path_end];

    let full: Vec<char> = format!("{scheme}://{host}{path}").chars().collect();
    if full.len() > MAX_REDACTED_URL_CHARS {
        let mut output: String = full.into_iter().take(MAX_REDACTED_URL_CHARS).collect();
        output.push('…');
        output
    } else {
        full.into_iter().collect()
    }
}

/// Sanitizes one HTTP header for logging.
///
/// `Authorization`, `Proxy-Authorization`, cookies, and common API-key headers
/// are replaced entirely. Other values are returned unchanged; callers should
/// still avoid logging request bodies and provider responses.
pub fn redact_header(name: &str, value: &str) -> (String, String) {
    let normalized = name.trim().to_ascii_lowercase();
    let sensitive = matches!(
        normalized.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key" | "api-key"
    );
    let value = if sensitive { REDACTED } else { value };
    (name.trim().to_owned(), value.to_owned())
}

/// Sanitizes a list of headers for logging.
pub fn redact_headers<'a, I>(headers: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    headers
        .into_iter()
        .map(|(name, value)| redact_header(name, value))
        .collect()
}

/// Replaces every known secret in `text` with [`REDACTED`].
///
/// Longer secrets are replaced first so a shorter overlapping value cannot
/// leave a fragment of a longer one behind. Empty secrets are ignored.
pub fn redact_known_secrets<'a, I>(text: &str, secrets: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let mut secrets: Vec<&str> = secrets
        .into_iter()
        .filter(|secret| !secret.is_empty())
        .collect();
    secrets.sort_unstable_by_key(|secret| std::cmp::Reverse(secret.len()));

    let mut output = text.to_owned();
    for secret in secrets {
        output = output.replace(secret, REDACTED);
    }
    output
}

/// Renders a sanitized error with known secrets scrubbed.
///
/// `CoreError` already avoids carrying secrets by construction; this helper
/// additionally protects synthetic adapter errors whose `detail` field may
/// contain text copied from an untrusted source.
pub fn redact_error<'a, I>(error: &CoreError, secrets: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    redact_known_secrets(&error.to_string(), secrets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::errors::ArgumentViolation;

    const CANARY: &str = "sk-canary-redaction-8291";

    #[test]
    fn url_redaction_drops_userinfo_query_and_fragment() {
        let url = format!("https://user:{CANARY}@api.example.com/v1?key={CANARY}#{CANARY}");
        let redacted = redact_url(&url);
        assert_eq!(redacted, "https://api.example.com/v1");
        assert!(!redacted.contains(CANARY));
    }

    #[test]
    fn unparseable_url_is_not_echoed() {
        assert_eq!(redact_url(&format!("not a url {CANARY}")), "[invalid url]");
        assert_eq!(redact_url(""), "[invalid url]");
    }

    #[test]
    fn sensitive_headers_are_replaced() {
        let headers = redact_headers([
            ("Authorization", format!("Bearer {CANARY}").as_str()),
            ("Proxy-Authorization", CANARY),
            ("Cookie", format!("session={CANARY}").as_str()),
            ("Content-Type", "application/json"),
        ]);
        let joined = format!("{headers:?}");
        assert!(!joined.contains(CANARY));
        assert!(joined.contains("application/json"));
    }

    #[test]
    fn synthetic_error_text_can_be_scrubbed() {
        let error = CoreError::InvalidValue {
            field: "endpoint".to_owned(),
            violation: ArgumentViolation::Invalid {
                detail: format!("upstream rejected {CANARY}"),
            },
        };
        let rendered = redact_error(&error, [CANARY]);
        assert!(!rendered.contains(CANARY));
        assert!(rendered.contains(REDACTED));
    }
}
