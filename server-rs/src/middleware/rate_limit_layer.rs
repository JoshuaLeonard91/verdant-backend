use axum::{
    body::Body,
    extract::Request,
    http::{Extensions, HeaderMap, HeaderValue},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use super::auth::UserId;
use super::rate_limit::{API_LIMIT, RateLimitInfo, is_loadtest_bypass};
use crate::state::AppState;

/// Axum middleware that applies global API rate limiting and adds X-RateLimit-* headers.
pub async fn rate_limit_headers(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Stress test bypass — skip all rate limiting
    if super::rate_limit::is_stress_test_bypass(&state, req.headers()) {
        return next.run(req).await;
    }

    // Loadtest bypass via X-Loadtest-Secret header — lets the loadtest
    // driver burst WS upgrades from one IP without tripping rate limits.
    if is_loadtest_bypass(&state, req.headers()) {
        return next.run(req).await;
    }

    // Extract identifier (userId if authed, else IP)
    let identifier = rate_limit_identifier(req.headers(), req.extensions());

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let window = now_secs / API_LIMIT.window_secs;
    let key = format!("{}:{}:{}", API_LIMIT.prefix, identifier, window);

    let current: u64 =
        match fred::interfaces::KeysInterface::incr_by::<i64, _>(&state.redis, &key, 1i64).await {
            Ok(val) => val as u64,
            Err(e) => {
                tracing::warn!(error = %e, "Global rate limit Redis error — using local fallback");
                state
                    .local_rate_limiter
                    .check_public(&key, window, API_LIMIT.window_secs)
            }
        };

    // Set TTL on first increment
    if current == 1 {
        let _: Result<(), _> = fred::interfaces::KeysInterface::expire(
            &state.redis,
            &key,
            API_LIMIT.window_secs as i64,
            None,
        )
        .await;
    }

    let reset_at = (window + 1) * API_LIMIT.window_secs;

    if current > API_LIMIT.max {
        let remaining = API_LIMIT
            .window_secs
            .saturating_sub(now_secs % API_LIMIT.window_secs);
        let body = serde_json::json!({
            "error": "Rate limited",
            "code": "RATE_LIMITED",
            "retryAfter": remaining,
        });
        let mut resp =
            (axum::http::StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
        if let Ok(val) = HeaderValue::from_str(&remaining.to_string()) {
            resp.headers_mut().insert("retry-after", val);
        }
        let info = RateLimitInfo {
            limit: API_LIMIT.max,
            remaining: 0,
            reset_at,
        };
        info.apply_headers(&mut resp);
        return resp;
    }

    // Proceed with the request
    let mut resp = next.run(req).await;
    let info = RateLimitInfo {
        limit: API_LIMIT.max,
        remaining: API_LIMIT.max.saturating_sub(current),
        reset_at,
    };
    info.apply_headers(&mut resp);
    resp
}

fn rate_limit_identifier(headers: &HeaderMap, extensions: &Extensions) -> String {
    rate_limit_identifier_with_trusted_proxies(headers, extensions, None)
}

fn rate_limit_identifier_with_trusted_proxies(
    headers: &HeaderMap,
    extensions: &Extensions,
    trusted_proxies: Option<&[crate::handlers::TrustedProxy]>,
) -> String {
    extensions
        .get::<UserId>()
        .map(|u| u.0.to_string())
        .unwrap_or_else(|| {
            extensions
                .get::<axum::extract::ConnectInfo<SocketAddr>>()
                .map(|ci| match trusted_proxies {
                    Some(trusted_proxies) => {
                        crate::handlers::extract_client_ip_with_trusted_proxies(
                            headers,
                            ci,
                            trusted_proxies,
                        )
                    }
                    None => crate::handlers::extract_client_ip(headers, ci),
                })
                .unwrap_or_else(|| "unknown".to_string())
        })
}

#[cfg(test)]
mod tests {
    use axum::extract::ConnectInfo;
    use axum::http::{Extensions, HeaderMap, HeaderValue};
    use std::net::SocketAddr;

    use crate::handlers::parse_trusted_proxy_cidrs;

    use super::rate_limit_identifier_with_trusted_proxies;

    const SOURCE: &str = include_str!("rate_limit_layer.rs");

    #[test]
    fn global_rate_limit_uses_normalized_client_ip_not_raw_proxy_peer() {
        let identifier_source = SOURCE
            .split("// Extract identifier")
            .nth(1)
            .expect("identifier extraction block should exist")
            .split("let now_secs")
            .next()
            .expect("rate-limit clock follows identifier extraction");

        assert!(
            identifier_source.contains("rate_limit_identifier"),
            "global unauthenticated limiter must reuse trusted-proxy client IP normalization"
        );
        assert!(
            !identifier_source.contains("ci.0.ip().to_string()"),
            "global unauthenticated limiter must not key directly on the reverse proxy peer"
        );
    }

    fn extensions_with_peer(peer: &str) -> Extensions {
        let mut extensions = Extensions::new();
        extensions.insert(ConnectInfo::<SocketAddr>(
            peer.parse().expect("valid peer socket address"),
        ));
        extensions
    }

    fn forwarded_headers(ip: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("do-connecting-ip", HeaderValue::from_static(ip));
        headers
    }

    #[test]
    fn global_rate_limit_distinguishes_clients_behind_trusted_proxy() {
        let trusted = parse_trusted_proxy_cidrs("127.0.0.1/32").unwrap();
        let first = rate_limit_identifier_with_trusted_proxies(
            &forwarded_headers("198.51.100.10"),
            &extensions_with_peer("127.0.0.1:3001"),
            Some(&trusted),
        );
        let second = rate_limit_identifier_with_trusted_proxies(
            &forwarded_headers("198.51.100.11"),
            &extensions_with_peer("127.0.0.1:3001"),
            Some(&trusted),
        );

        assert_eq!(first, "198.51.100.10");
        assert_eq!(second, "198.51.100.11");
        assert_ne!(first, second);
    }

    #[test]
    fn global_rate_limit_ignores_spoofed_headers_from_untrusted_peers() {
        let trusted = parse_trusted_proxy_cidrs("127.0.0.1/32").unwrap();
        let identifier = rate_limit_identifier_with_trusted_proxies(
            &forwarded_headers("198.51.100.10"),
            &extensions_with_peer("8.8.8.8:443"),
            Some(&trusted),
        );

        assert_eq!(identifier, "8.8.8.8");
    }
}
