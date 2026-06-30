use axum::{body::Body, extract::Request, http::HeaderValue, middleware::Next, response::Response};
use std::time::Instant;

/// Adds `Server-Timing: total;dur=X` header to every response.
pub async fn server_timing(req: Request<Body>, next: Next) -> Response {
    let start = Instant::now();
    let mut response = next.run(req).await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    let value = format!("total;dur={duration_ms:.1}");
    if let Ok(hv) = HeaderValue::from_str(&value) {
        response.headers_mut().insert("server-timing", hv);
    }
    response
}
