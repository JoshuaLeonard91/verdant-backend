use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use std::sync::LazyLock;

/// Maximum body size we'll inspect (1 MB). Larger payloads are passed through.
const MAX_INSPECT_SIZE: usize = 1_048_576;

// ---------------------------------------------------------------------------
// Category 1: always-deny patterns (all status codes)
// ---------------------------------------------------------------------------
static ALWAYS_DENY: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    aho_corasick::AhoCorasick::new([
        // Argon2 hashes
        "$argon2id$",
        "$argon2i$",
        "$argon2d$",
        // Bcrypt hashes
        "$2b$",
        "$2a$",
        "$2y$",
        // Rust panics / backtraces
        "panicked at",
        "stack backtrace",
        // Node.js stack traces
        "at Object.<anonymous>",
    ])
    .expect("always-deny automaton")
});

// ---------------------------------------------------------------------------
// Category 2a: error-only literal patterns (4xx/5xx only)
// ---------------------------------------------------------------------------
static ERROR_DENY: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    aho_corasick::AhoCorasick::new([
        // Windows paths
        "C:\\Users\\",
        "C:\\\\Users\\\\",
        // Unix paths
        "/home/",
        "/etc/passwd",
        "/usr/",
    ])
    .expect("error-deny automaton")
});

// ---------------------------------------------------------------------------
// Category 2b: error-only SQL patterns (4xx/5xx only, case-insensitive regex)
// ---------------------------------------------------------------------------
static SQL_PATTERNS: LazyLock<regex::bytes::RegexSet> = LazyLock::new(|| {
    regex::bytes::RegexSet::new([
        r"(?i)SELECT\s+.{1,200}\s+FROM\s+",
        r"(?i)INSERT\s+INTO\s+",
        r"(?i)UPDATE\s+\S+\s+SET\s+",
        r"(?i)DELETE\s+FROM\s+",
    ])
    .expect("sql regex set")
});

// ---------------------------------------------------------------------------
// Category 3 pre-check: fast literal scan for `"password"`
// ---------------------------------------------------------------------------
static PASSWORD_KEY: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    aho_corasick::AhoCorasick::new(["\"password\""]).expect("password-key automaton")
});

/// Returns `true` if `(method, path)` is an auth-related endpoint that
/// legitimately may carry token/credential fields in success responses.
fn is_auth_endpoint(method: &str, path: &str) -> bool {
    if method != "POST" {
        return false;
    }
    matches!(
        path,
        "/api/auth/register"
            | "/api/auth/login"
            | "/api/auth/login/2fa"
            | "/api/auth/refresh"
            | "/api/auth/verify-session"
            | "/api/2fa/setup"
            | "/api/2fa/verify-setup"
            | "/api/2fa/backup-codes/regenerate"
    ) || (path.starts_with("/api/channels/") && path.ends_with("/voice/join"))
}

/// Recursively checks a JSON value for a `"password"` key with a string value.
fn json_has_password_string(val: &serde_json::Value) -> bool {
    match val {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(_)) = map.get("password") {
                return true;
            }
            map.values().any(json_has_password_string)
        }
        serde_json::Value::Array(arr) => arr.iter().any(json_has_password_string),
        _ => false,
    }
}

/// The sanitized error we return when a response is blocked.
fn sanitized_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({
            "error": "Internal server error",
            "code": "RESPONSE_SANITIZED"
        })),
    )
        .into_response()
}

/// Runtime last-line-of-defense middleware that inspects outgoing JSON
/// responses for patterns that should never appear (password hashes,
/// internal paths, SQL fragments, stack traces).
///
/// Scopes pattern checks by status code to avoid false positives on user
/// content in success (2xx) responses.
pub async fn response_sanitizer(req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    let response = next.run(req).await;

    // --- Early exits ---

    // Skip non-JSON responses (HTML pages, binary, WebSocket upgrades, etc.)
    let is_json = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("application/json"));

    if !is_json {
        return response;
    }

    // Skip bodies that declare themselves larger than our threshold.
    if let Some(len) = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        if len > MAX_INSPECT_SIZE {
            return response;
        }
    }

    let status = response.status();
    let (parts, body) = response.into_parts();

    // Collect the body bytes. If this fails, fail closed.
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            tracing::error!(
                category = "body_read_failure",
                method = %method,
                path = %path,
                "Failed to read response body — returning sanitized response"
            );
            return sanitized_response();
        }
    };

    // Skip bodies larger than threshold (when content-length was absent).
    if body_bytes.len() > MAX_INSPECT_SIZE {
        return Response::from_parts(parts, Body::from(body_bytes));
    }

    let is_error = status.is_client_error() || status.is_server_error();

    // --- Category 1: always-deny (all status codes) ---
    if ALWAYS_DENY.is_match(&body_bytes) {
        tracing::error!(
            category = "always_deny",
            method = %method,
            path = %path,
            status = %status.as_u16(),
            "Response blocked: matched always-deny pattern"
        );
        return sanitized_response();
    }

    // --- Category 2: error-only deny (4xx/5xx) ---
    if is_error {
        if ERROR_DENY.is_match(&body_bytes) {
            tracing::error!(
                category = "error_deny_path",
                method = %method,
                path = %path,
                status = %status.as_u16(),
                "Response blocked: file path in error response"
            );
            return sanitized_response();
        }

        if SQL_PATTERNS.is_match(&body_bytes) {
            tracing::error!(
                category = "error_deny_sql",
                method = %method,
                path = %path,
                status = %status.as_u16(),
                "Response blocked: SQL fragment in error response"
            );
            return sanitized_response();
        }
    }

    // --- Category 3: JSON key check for "password" (skip allowlisted auth endpoints) ---
    if !is_auth_endpoint(&method, &path) && PASSWORD_KEY.is_match(&body_bytes) {
        // Pre-check hit — parse JSON for real check.
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            if json_has_password_string(&val) {
                tracing::error!(
                    category = "password_key",
                    method = %method,
                    path = %path,
                    status = %status.as_u16(),
                    "Response blocked: password string value in JSON response"
                );
                return sanitized_response();
            }
        }
    }

    // Clean — reconstruct the response.
    Response::from_parts(parts, Body::from(body_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use tower::ServiceExt;

    /// Helper: build a test app with a handler that returns the given status + JSON body.
    fn test_app(status: StatusCode, body: serde_json::Value) -> Router {
        let handler = move || async move { (status, axum::Json(body)).into_response() };
        Router::new()
            .route("/test", get(handler))
            .layer(middleware::from_fn(response_sanitizer))
    }

    /// Helper: build a test app where the route path is configurable.
    fn test_app_at(
        path: &str,
        method: &str,
        status: StatusCode,
        body: serde_json::Value,
    ) -> Router {
        let handler = move || async move { (status, axum::Json(body)).into_response() };
        let router = match method {
            "POST" => Router::new().route(path, axum::routing::post(handler)),
            _ => Router::new().route(path, get(handler)),
        };
        router.layer(middleware::from_fn(response_sanitizer))
    }

    async fn call(app: Router, path: &str) -> (StatusCode, String) {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    async fn call_post(app: Router, path: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    // --- Category 1: always-deny ---

    #[tokio::test]
    async fn blocks_argon2_hash() {
        let app = test_app(
            StatusCode::OK,
            serde_json::json!({"detail": "$argon2id$v=19$m=65536,t=3,p=4$hash"}),
        );
        let (status, body) = call(app, "/test").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("RESPONSE_SANITIZED"));
    }

    #[tokio::test]
    async fn blocks_bcrypt_hash() {
        let app = test_app(
            StatusCode::OK,
            serde_json::json!({"detail": "$2b$12$someBcryptHashValue"}),
        );
        let (status, body) = call(app, "/test").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("RESPONSE_SANITIZED"));
    }

    #[tokio::test]
    async fn blocks_rust_panic() {
        let app = test_app(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": "thread 'main' panicked at src/main.rs:42"}),
        );
        let (status, body) = call(app, "/test").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("RESPONSE_SANITIZED"));
    }

    // --- Category 2: error-only deny ---

    #[tokio::test]
    async fn blocks_sql_in_500() {
        let app = test_app(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": "SELECT id, name FROM users WHERE active = true"}),
        );
        let (status, body) = call(app, "/test").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("RESPONSE_SANITIZED"));
    }

    #[tokio::test]
    async fn allows_sql_in_200() {
        let app = test_app(
            StatusCode::OK,
            serde_json::json!({"content": "Hey run SELECT id FROM users for me"}),
        );
        let (status, body) = call(app, "/test").await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.contains("RESPONSE_SANITIZED"));
    }

    #[tokio::test]
    async fn blocks_unix_path_in_500() {
        let app = test_app(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": "File not found: /home/user/project/config.toml"}),
        );
        let (status, body) = call(app, "/test").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("RESPONSE_SANITIZED"));
    }

    #[tokio::test]
    async fn allows_unix_path_in_200() {
        let app = test_app(
            StatusCode::OK,
            serde_json::json!({"content": "Check /home/user/project for the file"}),
        );
        let (status, body) = call(app, "/test").await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.contains("RESPONSE_SANITIZED"));
    }

    // --- Category 3: password key ---

    #[tokio::test]
    async fn blocks_password_key_in_response() {
        let app = test_app(
            StatusCode::OK,
            serde_json::json!({"user": "alice", "password": "secret123"}),
        );
        let (status, body) = call(app, "/test").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("RESPONSE_SANITIZED"));
    }

    #[tokio::test]
    async fn allows_auth_endpoint_with_token() {
        let app = test_app_at(
            "/api/auth/login",
            "POST",
            StatusCode::OK,
            serde_json::json!({"accessToken": "eyJhbGciOi...", "password": "echoed"}),
        );
        let (status, body) = call_post(app, "/api/auth/login").await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.contains("RESPONSE_SANITIZED"));
    }

    // --- Pass-through cases ---

    #[tokio::test]
    async fn passes_non_json_response() {
        let handler = || async { (StatusCode::OK, "plain text with $argon2id$").into_response() };
        let app = Router::new()
            .route("/test", get(handler))
            .layer(middleware::from_fn(response_sanitizer));
        let (status, body) = call(app, "/test").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("$argon2id$"));
    }

    #[tokio::test]
    async fn passes_clean_json() {
        let app = test_app(
            StatusCode::OK,
            serde_json::json!({"message": "Hello, world!"}),
        );
        let (status, body) = call(app, "/test").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Hello, world!"));
    }

    #[tokio::test]
    async fn passes_oversized_body() {
        // Create a body > 1MB
        let big = "x".repeat(MAX_INSPECT_SIZE + 1);
        let handler = move || {
            let big = big.clone();
            async move {
                (
                    StatusCode::OK,
                    [("content-type", "application/json")],
                    format!("{{\"data\": \"{}$argon2id$\"}}", big),
                )
                    .into_response()
            }
        };
        let app = Router::new()
            .route("/test", get(handler))
            .layer(middleware::from_fn(response_sanitizer));
        let (status, _) = call(app, "/test").await;
        // Should pass through (too large to inspect)
        assert_eq!(status, StatusCode::OK);
    }
}
