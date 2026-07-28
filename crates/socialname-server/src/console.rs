//! Optional same-origin hosting for the monitoring console.
//!
//! The console is a static bundle that talks only to `/v1` on its own origin
//! and keeps a pasted scoped API key in page memory. Serving it from this
//! binary is what makes a self-hosted deployment usable in a browser without
//! introducing a second authentication path, a CORS origin, or a separate web
//! server. The route exists only when an operator points
//! `SOCIALNAME_CONSOLE_DIR` at a built bundle; the default surface is
//! unchanged.
//!
//! The handler is deliberately narrow: one flat directory, an allowlisted
//! extension set, a canonicalized-prefix check, and a bounded read. It serves
//! no product data, so it stays outside the authenticated boundary exactly
//! like an ordinary single-page application shell.

use std::path::{Path, PathBuf};

use axum::{
    body::Body,
    extract::{Path as RoutePath, State},
    http::{HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};

use crate::ServerState;

/// Bounds one console asset. The committed bundle is far smaller; the limit
/// exists so a misconfigured directory cannot stream something unbounded.
const MAXIMUM_ASSET_BYTES: u64 = 8 * 1_024 * 1_024;

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     connect-src 'self'; \
     img-src 'self' data:; \
     style-src 'self' 'unsafe-inline'; \
     script-src 'self'; \
     object-src 'none'; \
     frame-ancestors 'none'; \
     base-uri 'none'; \
     form-action 'none'";

pub(crate) async fn index(State(state): State<ServerState>) -> Response {
    serve(&state, "index.html").await
}

pub(crate) async fn asset(
    State(state): State<ServerState>,
    RoutePath(requested): RoutePath<String>,
) -> Response {
    serve(&state, &requested).await
}

async fn serve(state: &ServerState, requested: &str) -> Response {
    let Some(root) = state.config.console_directory() else {
        return not_found();
    };
    let Some(relative) = safe_relative_path(requested) else {
        return not_found();
    };
    let Some(content_type) = content_type(&relative) else {
        return not_found();
    };
    let candidate = root.join(&relative);

    // Canonicalization resolves symbolic links and `.` segments, so the prefix
    // check below is the authoritative containment test even if the directory
    // contains a link pointing outside the bundle.
    let (Ok(canonical_root), Ok(canonical_candidate)) =
        (root.canonicalize(), candidate.canonicalize())
    else {
        return not_found();
    };
    if !canonical_candidate.starts_with(&canonical_root) {
        return not_found();
    }
    let Ok(metadata) = tokio::fs::metadata(&canonical_candidate).await else {
        return not_found();
    };
    if !metadata.is_file() || metadata.len() > MAXIMUM_ASSET_BYTES {
        return not_found();
    }
    let Ok(bytes) = tokio::fs::read(&canonical_candidate).await else {
        return not_found();
    };

    let mut response = (StatusCode::OK, Body::from(bytes)).into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    response
}

/// Accepts one bounded relative path made of conservative file-name segments.
/// Anything else — absolute paths, parent traversal, separators inside a
/// segment, control characters, Windows drive prefixes — is refused before it
/// reaches the filesystem.
fn safe_relative_path(requested: &str) -> Option<PathBuf> {
    if requested.is_empty() || requested.len() > 256 {
        return None;
    }
    let mut relative = PathBuf::new();
    let mut segments = 0_usize;
    for segment in requested.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return None;
        }
        let acceptable = segment.len() <= 128
            && segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@')
            })
            && !segment.starts_with('.');
        if !acceptable {
            return None;
        }
        segments += 1;
        if segments > 4 {
            return None;
        }
        relative.push(segment);
    }
    Some(relative)
}

fn content_type(relative: &Path) -> Option<&'static str> {
    match relative.extension()?.to_str()? {
        "html" => Some("text/html; charset=utf-8"),
        "js" => Some("text/javascript; charset=utf-8"),
        "css" => Some("text/css; charset=utf-8"),
        "json" => Some("application/json"),
        "svg" => Some("image/svg+xml"),
        "png" => Some("image/png"),
        "ico" => Some("image/vnd.microsoft.icon"),
        "webmanifest" => Some("application/manifest+json"),
        "woff2" => Some("font/woff2"),
        _ => None,
    }
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Body::empty()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_separators_and_hidden_files_are_refused() {
        for candidate in [
            "",
            "..",
            "../secret",
            "assets/../../secret",
            "/etc/passwd",
            "C:/Windows/win.ini",
            "assets\\index.js",
            ".env",
            "assets/.env",
            "a/b/c/d/e/index.js",
            "index.html\0",
        ] {
            assert!(
                safe_relative_path(candidate).is_none(),
                "{candidate} must be refused"
            );
        }
    }

    #[test]
    fn ordinary_bundle_paths_are_accepted() {
        for candidate in ["index.html", "assets/index-abc123.js", "favicon.ico"] {
            assert!(
                safe_relative_path(candidate).is_some(),
                "{candidate} must be accepted"
            );
        }
    }

    #[test]
    fn only_allowlisted_extensions_have_a_content_type() {
        assert_eq!(
            content_type(Path::new("index.html")),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            content_type(Path::new("assets/app.js")),
            Some("text/javascript; charset=utf-8")
        );
        for refused in ["server.exe", "notes.txt", "archive.zip", "dump.sql", "app"] {
            assert!(
                content_type(Path::new(refused)).is_none(),
                "{refused} must have no content type"
            );
        }
    }
}
