//! Trusted-source checks for the application IPC boundary.
//!
//! Tauri's capability file already limits the registered application commands
//! to the `main` window, and `build.rs` generates an explicit permission for
//! every custom command. This module adds a second, command-layer check that
//! does not depend on configuration being read correctly: the invoking webview
//! must be the single `main` webview and its current document must be the
//! bundled local application.
//!
//! No credential, permission, or execution command may skip this check.

use std::fmt;

use url::Url;

/// The only window/webview label allowed to call application commands.
pub const MAIN_LABEL: &str = "main";

/// Why an invocation or navigation was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    /// The invoking window label is not the trusted main window.
    UntrustedWindow,
    /// The invoking webview label is not the trusted main webview.
    UntrustedWebview,
    /// The document URL was missing or malformed.
    InvalidUrl,
    /// The document is not the bundled local application.
    UntrustedOrigin,
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UntrustedWindow => f.write_str("IPC is limited to the trusted main window"),
            Self::UntrustedWebview => f.write_str("IPC is limited to the trusted main webview"),
            Self::InvalidUrl => f.write_str("the invoking document URL is not valid"),
            Self::UntrustedOrigin => {
                f.write_str("IPC is limited to the bundled local application origin")
            }
        }
    }
}

impl std::error::Error for GuardError {}

/// Verifies the invoking window, webview, and document origin.
///
/// `window_label` must be the Tauri window label and `webview_label` the
/// webview label. A sub-webview of the main window therefore does not inherit
/// the command boundary. Remote documents, `data:`, `file:`, `about:`,
/// non-index local paths, queries, and fragments are rejected.
pub fn verify(
    window_label: &str,
    webview_label: &str,
    document_url: Option<&str>,
) -> Result<(), GuardError> {
    if window_label != MAIN_LABEL {
        return Err(GuardError::UntrustedWindow);
    }
    if webview_label != MAIN_LABEL {
        return Err(GuardError::UntrustedWebview);
    }
    let url = document_url.ok_or(GuardError::InvalidUrl)?;
    let parsed = Url::parse(url).map_err(|_| GuardError::InvalidUrl)?;
    if is_bundled_local_url(&parsed) {
        Ok(())
    } else {
        Err(GuardError::UntrustedOrigin)
    }
}

/// What the navigation handler must do for one requested URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Navigation {
    /// The local application entry document may load.
    LoadLocal,
    /// An external HTTP(S) link opens in the system browser instead of the
    /// WebView.
    OpenExternal,
    /// Every other navigation is refused.
    Refuse,
}

/// Classifies a navigation request. The WebView itself must never load a
/// remote document.
pub fn classify_navigation(url: &str) -> Navigation {
    let Ok(parsed) = Url::parse(url) else {
        return Navigation::Refuse;
    };
    if is_bundled_local_url(&parsed) {
        return Navigation::LoadLocal;
    }
    match parsed.scheme() {
        "http" | "https"
            if parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.host_str().is_some() =>
        {
            Navigation::OpenExternal
        }
        _ => Navigation::Refuse,
    }
}

fn is_bundled_local_url(url: &Url) -> bool {
    let host_ok = url.host_str() == Some("localhost") && url.port().is_none();
    let origin_ok = match url.scheme() {
        "tauri" => host_ok,
        // Tauri uses this origin for bundled assets on Windows. The target
        // build is macOS, but the check stays explicit rather than accepting
        // arbitrary http origins.
        "http" => url.host_str() == Some("tauri.localhost") && url.port().is_none(),
        _ => false,
    };
    origin_ok
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && matches!(url.path(), "" | "/" | "/index.html")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_main_document_is_trusted() {
        assert_eq!(
            verify("main", "main", Some("tauri://localhost/index.html")),
            Ok(())
        );
        assert_eq!(verify("main", "main", Some("tauri://localhost/")), Ok(()));
        assert_eq!(verify("main", "main", Some("tauri://localhost")), Ok(()));
    }

    #[test]
    fn other_windows_and_preview_webviews_are_rejected() {
        let url = Some("tauri://localhost/index.html");
        assert_eq!(
            verify("settings", "settings", url),
            Err(GuardError::UntrustedWindow)
        );
        assert_eq!(
            verify("preview", "preview", url),
            Err(GuardError::UntrustedWindow)
        );
        assert_eq!(
            verify("main", "main-preview", url),
            Err(GuardError::UntrustedWebview)
        );
        assert_eq!(
            verify("main", "preview", url),
            Err(GuardError::UntrustedWebview)
        );
    }

    #[test]
    fn remote_data_file_and_nested_origins_are_rejected() {
        for url in [
            "https://example.com/",
            "https://tauri.localhost/",
            "http://localhost:1420/",
            "tauri://localhost/documents/preview.html",
            "tauri://localhost/index.html?remote=1",
            "tauri://localhost/index.html#preview",
            "tauri://evil.example/index.html",
            "file:///tmp/index.html",
            "data:text/html,<h1>remote</h1>",
            "about:blank",
            "javascript:alert(1)",
        ] {
            assert_eq!(
                verify("main", "main", Some(url)),
                Err(GuardError::UntrustedOrigin),
                "{url} must be rejected"
            );
        }
        assert_eq!(verify("main", "main", None), Err(GuardError::InvalidUrl));
        assert_eq!(
            verify("main", "main", Some("not a url")),
            Err(GuardError::InvalidUrl)
        );
    }

    #[test]
    fn navigation_loads_only_local_and_sends_http_links_to_the_browser() {
        assert_eq!(
            classify_navigation("tauri://localhost/index.html"),
            Navigation::LoadLocal
        );
        assert_eq!(
            classify_navigation("https://example.com/docs"),
            Navigation::OpenExternal
        );
        assert_eq!(
            classify_navigation("http://example.com/"),
            Navigation::OpenExternal
        );
        assert_eq!(
            classify_navigation("https://user:pass@example.com/"),
            Navigation::Refuse
        );
        assert_eq!(
            classify_navigation("tauri://localhost/preview.html"),
            Navigation::Refuse
        );
        assert_eq!(
            classify_navigation("file:///etc/passwd"),
            Navigation::Refuse
        );
        assert_eq!(classify_navigation("data:text/html,x"), Navigation::Refuse);
        assert_eq!(classify_navigation("about:blank"), Navigation::Refuse);
    }
}
