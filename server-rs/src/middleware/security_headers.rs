use axum::{extract::Request, middleware::Next, response::Response};

pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("x-xss-protection", "0".parse().unwrap());
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "permissions-policy",
        "camera=(), microphone=(self), geolocation=(), payment=(), usb=(), \
         bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=(), \
         autoplay=(self), fullscreen=(self), display-capture=(), \
         idle-detection=(), screen-wake-lock=()"
            .parse()
            .unwrap(),
    );
    // HSTS: 2 years, include subdomains, preload
    headers.insert(
        "strict-transport-security",
        "max-age=63072000; includeSubDomains; preload"
            .parse()
            .unwrap(),
    );
    // Cross-origin isolation: prevents Spectre/side-channel via cross-origin windows
    headers.insert("cross-origin-opener-policy", "same-origin".parse().unwrap());
    // Allow cross-origin resource loading so Tauri webviews (tauri://localhost)
    // and future asset-serving paths work correctly. COOP above still provides
    // Spectre isolation for cross-origin windows.
    headers.insert(
        "cross-origin-resource-policy",
        "cross-origin".parse().unwrap(),
    );
    // Prevent caching of API responses (sensitive data).
    // Uses or_insert so handlers serving static assets can set their own Cache-Control.
    headers
        .entry("cache-control")
        .or_insert("no-store".parse().unwrap());
    resp
}
