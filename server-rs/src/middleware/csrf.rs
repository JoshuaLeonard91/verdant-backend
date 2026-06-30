use axum::{
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// Fetch Metadata CSRF protection (OWASP recommended).
///
/// Checks the `Sec-Fetch-Site` header on state-changing requests
/// (POST, PUT, PATCH, DELETE). This header is automatically set by
/// browsers and cannot be forged by JavaScript.
///
/// Policy:
/// - `same-origin` / `same-site` / `none` → allow
/// - absent (non-browser client, e.g. curl) → allow
/// - Tauri WebView (`Origin: http://tauri.localhost`) → allow
/// - `cross-site` (all other origins) → reject 403
pub async fn csrf_protection(req: Request, next: Next) -> Response {
    let method = req.method().clone();

    // Only check state-changing methods
    if matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }

    if let Some(fetch_site) = req.headers().get("sec-fetch-site") {
        if let Ok(value) = fetch_site.to_str() {
            match value {
                "same-origin" | "same-site" | "none" => {
                    // Safe — request from same origin, same site, or direct navigation
                }
                "cross-site" => {
                    // Tauri v2 WebView origin varies by platform:
                    //   Windows: http://tauri.localhost or https://tauri.localhost
                    //   macOS:   tauri://localhost
                    // Chromium marks these as cross-site to verdant.chat. Allow
                    // them — they're our desktop client, not an attacker.
                    let is_tauri = req
                        .headers()
                        .get("origin")
                        .and_then(|o| o.to_str().ok())
                        .is_some_and(|o| {
                            o == "http://tauri.localhost"
                                || o == "https://tauri.localhost"
                                || o == "tauri://localhost"
                        });

                    if !is_tauri {
                        tracing::warn!(
                            "CSRF blocked: cross-site {} request to {}",
                            method,
                            req.uri().path()
                        );
                        return (
                            StatusCode::FORBIDDEN,
                            axum::Json(json!({
                                "error": "Cross-site requests are not allowed",
                                "code": "CSRF_REJECTED"
                            })),
                        )
                            .into_response();
                    }
                }
                _ => {
                    // Unknown value — allow (defensive, future-proof)
                }
            }
        }
    }
    // Header absent → non-browser client (Tauri, curl, etc.) → allow

    next.run(req).await
}
