use std::time::Instant;

use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use metrics::{counter, histogram};

use subtle::ConstantTimeEq;

use crate::server::AppState;

/// Axum middleware that records HTTP request metrics.
///
/// Records:
/// - `riley_auth_http_requests_total` counter with `method`, `path`, `status` labels
/// - `riley_auth_http_request_duration_seconds` histogram with `method`, `path` labels
pub async fn http_metrics_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let path = normalize_path(request.uri().path());

    let start = Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed().as_secs_f64();

    let status = response.status().as_u16().to_string();

    counter!("riley_auth_http_requests_total",
        "method" => method.clone(),
        "path" => path.clone(),
        "status" => status,
    )
    .increment(1);

    histogram!("riley_auth_http_request_duration_seconds",
        "method" => method,
        "path" => path,
    )
    .record(duration);

    response
}

/// Normalize request paths to prevent high-cardinality labels.
/// Replaces path segments that look like UUIDs or IDs with a placeholder.
/// Caps depth at 4 segments to prevent cardinality explosion from arbitrary paths.
fn normalize_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    // Cap at 5 parts (empty + 4 segments, e.g. "/a/b/c/d")
    // to prevent cardinality explosion from deeply nested 404 paths
    if segments.len() > 5 {
        return "/unknown".to_string();
    }
    let normalized: Vec<&str> = segments
        .iter()
        .map(|s| {
            if looks_like_id(s) {
                ":id"
            } else {
                s
            }
        })
        .collect();
    normalized.join("/")
}

/// Check if a path segment looks like an ID (UUID, numeric, or hex string).
fn looks_like_id(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // UUID pattern (8-4-4-4-12 hex chars)
    if s.len() == 36 && s.chars().filter(|c| *c == '-').count() == 4 {
        return s.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    }
    // Pure numeric
    if s.chars().all(|c| c.is_ascii_digit()) && s.len() > 3 {
        return true;
    }
    // Long hex string (>= 16 chars, all hex)
    if s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    false
}

/// Handler for the /metrics endpoint. Returns Prometheus text format.
pub async fn metrics_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    // Check bearer token if configured
    if let Some(ref token_config) = state.config.metrics.bearer_token {
        let expected = match token_config.resolve() {
            Ok(t) => t,
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "metrics token config error")
                    .into_response();
            }
        };

        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));

        match provided {
            Some(token)
                if token.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1 => {}
            _ => {
                return (StatusCode::UNAUTHORIZED, "invalid or missing bearer token")
                    .into_response();
            }
        }
    }

    let handle = state.metrics_handle.as_ref();
    match handle {
        Some(h) => {
            let output = h.render();
            (
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )],
                output,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "metrics not enabled").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_preserves_normal_paths() {
        assert_eq!(normalize_path("/health"), "/health");
        assert_eq!(normalize_path("/oauth/token"), "/oauth/token");
        assert_eq!(normalize_path("/admin/users"), "/admin/users");
        assert_eq!(normalize_path("/.well-known/jwks.json"), "/.well-known/jwks.json");
    }

    #[test]
    fn normalize_replaces_uuids() {
        assert_eq!(
            normalize_path("/admin/users/550e8400-e29b-41d4-a716-446655440000"),
            "/admin/users/:id"
        );
        assert_eq!(
            normalize_path("/admin/clients/a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            "/admin/clients/:id"
        );
    }

    #[test]
    fn normalize_replaces_long_hex() {
        assert_eq!(
            normalize_path("/auth/callback/abcdef0123456789"),
            "/auth/callback/:id"
        );
    }

    #[test]
    fn normalize_preserves_short_segments() {
        assert_eq!(normalize_path("/v1/api"), "/v1/api");
        assert_eq!(normalize_path("/auth/me"), "/auth/me");
    }

    #[test]
    fn looks_like_id_cases() {
        assert!(looks_like_id("550e8400-e29b-41d4-a716-446655440000"));
        assert!(looks_like_id("abcdef0123456789")); // 16-char hex
        assert!(looks_like_id("12345678")); // 8-digit number
        assert!(!looks_like_id("users"));
        assert!(!looks_like_id("me"));
        assert!(!looks_like_id(""));
        assert!(!looks_like_id("123")); // too short for numeric
    }

    #[test]
    fn normalize_caps_deep_paths() {
        // Deeply nested paths get collapsed to /unknown to prevent cardinality explosion
        assert_eq!(normalize_path("/a/b/c/d/e"), "/unknown");
        assert_eq!(normalize_path("/a/b/c/d/e/f/g"), "/unknown");
        // 4-segment paths are still preserved
        assert_eq!(normalize_path("/a/b/c/d"), "/a/b/c/d");
    }

    #[test]
    fn normalize_handles_edge_cases() {
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path(""), "");
        // Double slashes produce empty segments (preserved as-is)
        assert_eq!(normalize_path("//auth//me"), "//auth//me");
    }
}
