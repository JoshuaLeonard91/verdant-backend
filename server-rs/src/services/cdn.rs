use std::sync::OnceLock;

/// Global CDN base URL, initialized once at startup.
/// When set, relative keys are prefixed with this URL.
/// When unset (dev mode), relative keys are returned as-is.
///
/// # Hotlink protection (Cloudflare Dashboard — manual config)
///
/// To ensure direct-linked images still pass through CF Image Transforms
/// (which strip metadata), configure a Transform Rule in CF Dashboard:
///
///   Dashboard → Rules → Transform Rules → URL Rewrite:
///   - IF URI path does NOT contain `/cdn-cgi/image/`
///     AND Referer does NOT match `*.verdant.chat` or `*.pryzmapp.com`
///   - THEN rewrite URI to insert `/cdn-cgi/image/metadata=none,format=auto/`
///
/// This forces all non-app requests through the image pipeline.
static CDN_BASE_URL: OnceLock<Option<String>> = OnceLock::new();

/// Initialize the CDN resolver. Call once from main().
/// Auto-prepends `https://` if the URL has no scheme.
pub fn init(base_url: Option<String>) {
    let url = base_url.map(|mut u| {
        u = u.trim().to_string();
        // Auto-fix missing scheme — bare domain like "cdn.example.com" breaks reqwest
        if !u.is_empty() && !u.starts_with("http://") && !u.starts_with("https://") {
            tracing::warn!("CDN_BASE_URL missing scheme, prepending https://");
            u = format!("https://{u}");
        }
        u.trim_end_matches('/').to_string()
    });
    CDN_BASE_URL
        .set(url)
        .expect("cdn::init called more than once");
}

/// Returns true if CDN is configured.
pub fn enabled() -> bool {
    CDN_BASE_URL.get().and_then(|v| v.as_ref()).is_some()
}

/// Resolve a key or URL to a full CDN URL.
///
/// - `None` → `None`
/// - Starts with `http` → pass through (legacy full URL)
/// - Relative key + CDN configured → `{CDN_BASE_URL}/{key}`
/// - Relative key + no CDN → key as-is (dev mode)
pub fn resolve(key_or_url: Option<&str>) -> Option<String> {
    let value = key_or_url?;

    if value.is_empty() {
        return None;
    }

    // Already a full URL — pass through (legacy data or external URLs)
    if value.starts_with("http") {
        return Some(value.to_string());
    }

    // Relative key — prepend CDN base URL if configured
    match CDN_BASE_URL.get().and_then(|v| v.as_ref()) {
        Some(base) => Some(format!("{base}/{value}")),
        None => Some(value.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_none_returns_none() {
        // Can't call init() in tests since OnceLock is global,
        // but we can test the logic directly.
        assert_eq!(resolve(None), None);
        assert_eq!(resolve(Some("")), None);
    }

    #[test]
    fn resolve_full_url_passes_through() {
        assert_eq!(
            resolve(Some("https://old-cdn.example.com/avatars/123.png")),
            Some("https://old-cdn.example.com/avatars/123.png".to_string()),
        );
    }
}
