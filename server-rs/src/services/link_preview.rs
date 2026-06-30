use bytes::Bytes;
use futures_util::StreamExt;
use regex::Regex;
use reqwest::{Client, StatusCode, header};
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::{Semaphore, SemaphorePermit};
use url::Url;

use crate::services::sanitize::sanitize_text_preserve_edges;

const MAX_PREVIEW_URL_LEN: usize = 2048;
const MAX_HTML_BYTES: usize = 192 * 1024;
const MAX_IMAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_REDIRECTS: usize = 3;
const MAX_CONCURRENT_FETCHES: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const USER_AGENT: &str = "VerdantLinkPreview/1.0";

static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .dns_resolver(Arc::new(PublicDnsResolver))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .expect("failed to build link preview HTTP client")
});

static LINK_PREVIEW_FETCH_PERMITS: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_FETCHES));

static META_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<meta\s+([^>]*?)>").expect("valid meta regex"));
static ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#)
        .expect("valid attr regex")
});
static TITLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").expect("valid title regex"));
static TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<[^>]+>").expect("valid tag regex"));
static WHITESPACE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s+").expect("valid whitespace regex"));

#[derive(Debug)]
struct PublicResolverError;

impl fmt::Display for PublicResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("link preview target is not a public address")
    }
}

impl StdError for PublicResolverError {}

#[derive(Debug)]
struct PublicDnsResolver;

impl reqwest::dns::Resolve for PublicDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            resolve_public_socket_addrs(&host)
                .await
                .map(|addrs| Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
                .map_err(|_| Box::new(PublicResolverError) as Box<dyn StdError + Send + Sync>)
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinkPreview {
    pub url: String,
    pub title: String,
    pub description: Option<String>,
    pub site_name: Option<String>,
    pub image_proxy_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PreviewImage {
    pub content_type: &'static str,
    pub bytes: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkPreviewError {
    InvalidUrl,
    UnsafeTarget,
    UnsupportedContentType,
    TooLarge,
    Busy,
    UpstreamUnavailable,
    UpstreamRejected,
    NoPreview,
}

impl LinkPreviewError {
    pub fn user_message(&self) -> &'static str {
        match self {
            Self::InvalidUrl => "URL is invalid",
            Self::UnsafeTarget => "URL target is not allowed",
            Self::UnsupportedContentType => "URL content type is not supported",
            Self::TooLarge => "URL preview response is too large",
            Self::Busy => "Too many link preview requests are running",
            Self::UpstreamUnavailable => "URL preview is unavailable",
            Self::UpstreamRejected => "URL preview request was rejected",
            Self::NoPreview => "URL preview was not available",
        }
    }
}

pub async fn fetch_link_preview(raw_url: &str) -> Result<LinkPreview, LinkPreviewError> {
    let _permit = acquire_fetch_permit()?;
    let start_url = validate_public_preview_url(raw_url).await?;
    let (final_url, html) = fetch_html(start_url).await?;
    let parsed = parse_link_preview_html(&final_url, &html)?;
    Ok(parsed)
}

pub async fn fetch_preview_image(raw_url: &str) -> Result<PreviewImage, LinkPreviewError> {
    let _permit = acquire_fetch_permit()?;
    let start_url = validate_public_preview_url(raw_url).await?;
    let (final_url, response) = fetch_response(start_url, "image/*").await?;
    let status = response.status();
    if !status.is_success() {
        tracing::debug!(
            host = %final_url.host_str().unwrap_or(""),
            status = status.as_u16(),
            "link preview image fetch rejected by upstream"
        );
        return Err(map_upstream_status(status));
    }

    if let Some(length) = response.content_length()
        && length > MAX_IMAGE_BYTES as u64
    {
        return Err(LinkPreviewError::TooLarge);
    }

    let content_type = allowed_image_content_type(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
    )
    .ok_or(LinkPreviewError::UnsupportedContentType)?;

    let bytes = read_limited_bytes(response, MAX_IMAGE_BYTES).await?;
    if !has_passive_raster_signature(&bytes, content_type) {
        return Err(LinkPreviewError::UnsupportedContentType);
    }
    Ok(PreviewImage {
        content_type,
        bytes,
    })
}

fn acquire_fetch_permit() -> Result<SemaphorePermit<'static>, LinkPreviewError> {
    LINK_PREVIEW_FETCH_PERMITS.try_acquire().map_err(|_| {
        tracing::warn!("link preview fetch concurrency limit reached");
        LinkPreviewError::Busy
    })
}

async fn fetch_html(start_url: Url) -> Result<(Url, String), LinkPreviewError> {
    let (final_url, response) =
        fetch_response(start_url, "text/html,application/xhtml+xml").await?;
    let status = response.status();
    if !status.is_success() {
        tracing::debug!(
            host = %final_url.host_str().unwrap_or(""),
            status = status.as_u16(),
            "link preview HTML fetch rejected by upstream"
        );
        return Err(map_upstream_status(status));
    }

    if let Some(length) = response.content_length()
        && length > MAX_HTML_BYTES as u64
    {
        return Err(LinkPreviewError::TooLarge);
    }

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.is_empty()
        && !content_type.starts_with("text/html")
        && !content_type.starts_with("application/xhtml+xml")
    {
        return Err(LinkPreviewError::UnsupportedContentType);
    }

    let bytes = read_limited_bytes(response, MAX_HTML_BYTES).await?;
    let html = String::from_utf8_lossy(&bytes).into_owned();
    Ok((final_url, html))
}

async fn fetch_response(
    start_url: Url,
    accept: &'static str,
) -> Result<(Url, reqwest::Response), LinkPreviewError> {
    let mut current = start_url;
    for redirect_count in 0..=MAX_REDIRECTS {
        let response = HTTP_CLIENT
            .get(current.clone())
            .header(header::ACCEPT, accept)
            .header(header::REFERER, "https://verdant.chat/")
            .send()
            .await
            .map_err(|error| {
                tracing::debug!(
                    host = %current.host_str().unwrap_or(""),
                    error = %error.without_url(),
                    "link preview upstream request failed"
                );
                LinkPreviewError::UpstreamUnavailable
            })?;

        if response.status().is_redirection() {
            if redirect_count == MAX_REDIRECTS {
                return Err(LinkPreviewError::UnsafeTarget);
            }
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(LinkPreviewError::UnsafeTarget)?;
            let next = current
                .join(location)
                .map_err(|_| LinkPreviewError::InvalidUrl)?;
            current = validate_public_preview_url(next.as_str()).await?;
            continue;
        }

        return Ok((current, response));
    }

    Err(LinkPreviewError::UnsafeTarget)
}

pub async fn validate_public_preview_url(raw_url: &str) -> Result<Url, LinkPreviewError> {
    let parsed = validate_preview_url_syntax(raw_url)?;
    let host = parsed
        .host_str()
        .ok_or(LinkPreviewError::InvalidUrl)?
        .to_string();
    resolve_public_socket_addrs(&host).await?;
    Ok(parsed)
}

pub fn validate_preview_url_syntax(raw_url: &str) -> Result<Url, LinkPreviewError> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_PREVIEW_URL_LEN
        || trimmed
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | '\u{0}'))
    {
        return Err(LinkPreviewError::InvalidUrl);
    }
    let parsed = Url::parse(trimmed).map_err(|_| LinkPreviewError::InvalidUrl)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(LinkPreviewError::InvalidUrl);
    }

    let host = parsed
        .host_str()
        .ok_or(LinkPreviewError::InvalidUrl)?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return Err(LinkPreviewError::UnsafeTarget);
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err(LinkPreviewError::UnsafeTarget);
    }

    Ok(parsed)
}

pub fn parse_link_preview_html(
    page_url: &Url,
    html: &str,
) -> Result<LinkPreview, LinkPreviewError> {
    let meta = collect_meta(html);
    let html_title = title_from_html(html);
    let title = first_non_empty(&[
        meta.get("og:title"),
        meta.get("twitter:title"),
        html_title.as_ref(),
    ])
    .map(|value| clean_text(value, 160))
    .filter(|value| !value.is_empty())
    .ok_or(LinkPreviewError::NoPreview)?;

    let description = first_non_empty(&[
        meta.get("og:description"),
        meta.get("twitter:description"),
        meta.get("description"),
    ])
    .map(|value| clean_text(value, 260))
    .filter(|value| !value.is_empty());

    let site_name = first_non_empty(&[meta.get("og:site_name"), meta.get("application-name")])
        .map(|value| clean_text(value, 80))
        .filter(|value| !value.is_empty())
        .or_else(|| page_url.host_str().map(|host| host.to_string()));

    let image_proxy_url = first_non_empty(&[meta.get("og:image"), meta.get("twitter:image")])
        .and_then(|raw| page_url.join(raw).ok())
        .and_then(|image_url| validate_preview_url_syntax(image_url.as_str()).ok())
        .map(|image_url| {
            format!(
                "/api/link-previews/image?url={}",
                urlencoding::encode(image_url.as_str())
            )
        });

    Ok(LinkPreview {
        url: page_url.as_str().to_string(),
        title,
        description,
        site_name,
        image_proxy_url,
    })
}

fn collect_meta(html: &str) -> HashMap<String, String> {
    let mut meta = HashMap::new();
    for capture in META_TAG_RE.captures_iter(html) {
        let Some(attrs) = capture.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let attrs = collect_attrs(attrs);
        let key = attrs
            .get("property")
            .or_else(|| attrs.get("name"))
            .map(|value| value.to_ascii_lowercase());
        let content = attrs
            .get("content")
            .map(|value| decode_html_entities(value));
        if let (Some(key), Some(content)) = (key, content)
            && !key.is_empty()
            && !content.trim().is_empty()
        {
            meta.entry(key).or_insert(content);
        }
    }
    meta
}

fn collect_attrs(attrs: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for capture in ATTR_RE.captures_iter(attrs) {
        let Some(name) = capture.get(1).map(|m| m.as_str().to_ascii_lowercase()) else {
            continue;
        };
        let value = capture
            .get(2)
            .or_else(|| capture.get(3))
            .or_else(|| capture.get(4))
            .map(|m| m.as_str())
            .unwrap_or_default();
        values.insert(name, value.to_string());
    }
    values
}

fn title_from_html(html: &str) -> Option<String> {
    TITLE_RE
        .captures(html)
        .and_then(|capture| capture.get(1).map(|m| decode_html_entities(m.as_str())))
}

fn first_non_empty<'a>(values: &[Option<&'a String>]) -> Option<&'a str> {
    for value in values {
        if let Some(value) = value {
            let value = value.as_str();
            if !value.trim().is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn clean_text(value: &str, max_chars: usize) -> String {
    let decoded = decode_html_entities(value);
    let without_tags = TAG_RE.replace_all(&decoded, " ");
    let normalized = WHITESPACE_RE.replace_all(without_tags.trim(), " ");
    let sanitized = sanitize_text_preserve_edges(&normalized);
    let display = decode_html_entities(sanitized.trim());
    truncate_chars(display.trim(), max_chars)
}

fn decode_html_entities(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect::<String>()
}

async fn read_limited_bytes(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Bytes, LinkPreviewError> {
    let mut stream = response.bytes_stream();
    let mut received = 0usize;
    let mut chunks = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| LinkPreviewError::UpstreamUnavailable)?;
        received = received
            .checked_add(chunk.len())
            .ok_or(LinkPreviewError::TooLarge)?;
        if received > max_bytes {
            return Err(LinkPreviewError::TooLarge);
        }
        chunks.push(chunk);
    }
    let mut bytes = Vec::with_capacity(received);
    for chunk in chunks {
        bytes.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(bytes))
}

fn allowed_image_content_type(raw: &str) -> Option<&'static str> {
    let content_type = raw
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match content_type.as_str() {
        "image/jpeg" | "image/jpg" => Some("image/jpeg"),
        "image/png" => Some("image/png"),
        "image/gif" => Some("image/gif"),
        "image/webp" => Some("image/webp"),
        _ => None,
    }
}

fn has_passive_raster_signature(bytes: &[u8], content_type: &str) -> bool {
    match content_type {
        "image/jpeg" => bytes.starts_with(&[0xFF, 0xD8, 0xFF]),
        "image/png" => bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]),
        "image/gif" => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
        "image/webp" => bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP",
        _ => false,
    }
}

fn map_upstream_status(status: StatusCode) -> LinkPreviewError {
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        return LinkPreviewError::TooLarge;
    }
    if status.is_client_error() {
        return LinkPreviewError::UpstreamRejected;
    }
    LinkPreviewError::UpstreamUnavailable
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

async fn resolve_public_socket_addrs(host: &str) -> Result<Vec<SocketAddr>, LinkPreviewError> {
    let addresses = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|_| LinkPreviewError::UnsafeTarget)?;
    filter_public_socket_addrs(host, addresses)
}

fn filter_public_socket_addrs(
    host: &str,
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, LinkPreviewError> {
    let mut resolved_any = false;
    let mut public = Vec::new();
    for address in addresses {
        resolved_any = true;
        if !is_public_ip(address.ip()) {
            tracing::debug!(
                host = %host,
                "link preview target resolved to a non-public address"
            );
            return Err(LinkPreviewError::UnsafeTarget);
        }
        public.push(address);
    }
    if !resolved_any {
        return Err(LinkPreviewError::UnsafeTarget);
    }
    Ok(public)
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || octets[0] == 0
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_ipv4_compatible_ipv6(&segments)
        || is_ipv4_mapped_ipv6(&segments)
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || is_nat64_ipv6(&segments)
        || segments[0] == 0x2002
        || is_special_2001_ipv6(&segments)
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0x0000)
        || (segments[0] == 0x0100 && segments[1] == 0x0000))
}

fn is_ipv4_compatible_ipv6(segments: &[u16; 8]) -> bool {
    segments[..6].iter().all(|segment| *segment == 0)
}

fn is_ipv4_mapped_ipv6(segments: &[u16; 8]) -> bool {
    segments[..5].iter().all(|segment| *segment == 0) && segments[5] == 0xffff
}

fn is_nat64_ipv6(segments: &[u16; 8]) -> bool {
    (segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2..6].iter().all(|segment| *segment == 0))
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001)
}

fn is_special_2001_ipv6(segments: &[u16; 8]) -> bool {
    segments[0] == 0x2001
        && (segments[1] == 0x0000
            || segments[1] == 0x0002
            || segments[1] == 0x0db8
            || (segments[1] & 0xfff0) == 0x0010
            || (segments[1] & 0xfff0) == 0x0020)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("link_preview.rs");

    #[test]
    fn preview_fetches_are_bounded_by_concurrency_guard() {
        assert!(SOURCE.contains("LINK_PREVIEW_FETCH_PERMITS"));
        assert!(SOURCE.contains("try_acquire()"));
        assert!(SOURCE.contains("let _permit = acquire_fetch_permit()?;"));
        assert!(SOURCE.contains("LinkPreviewError::Busy"));
    }

    #[test]
    fn preview_url_syntax_rejects_unsafe_targets() {
        for url in [
            "http://example.com",
            "https://user:pass@example.com",
            "https://localhost/admin",
            "https://service.local/admin",
            "https://10.0.0.1/admin",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/admin",
            "https://example.com/a#fragment",
            "https://example.com/a\\b",
        ] {
            assert!(validate_preview_url_syntax(url).is_err(), "{url}");
        }
    }

    #[test]
    fn public_resolver_filter_rejects_non_public_addresses() {
        let private = [
            "127.0.0.1:0".parse().unwrap(),
            "10.0.0.1:0".parse().unwrap(),
            "[::ffff:127.0.0.1]:0".parse().unwrap(),
            "[64:ff9b::7f00:1]:0".parse().unwrap(),
            "[64:ff9b:1::7f00:1]:0".parse().unwrap(),
            "[2002:7f00:1::]:0".parse().unwrap(),
            "[2001:db8::1]:0".parse().unwrap(),
            "[100::1]:0".parse().unwrap(),
        ];
        assert_eq!(
            filter_public_socket_addrs("rebind.example", private).unwrap_err(),
            LinkPreviewError::UnsafeTarget
        );

        let public = [
            "93.184.216.34:0".parse().unwrap(),
            "[2606:4700:4700::1111]:0".parse().unwrap(),
        ];
        assert!(filter_public_socket_addrs("example.com", public).is_ok());
    }

    #[test]
    fn parses_open_graph_preview_and_image_proxy() {
        let page = Url::parse("https://example.com/articles/release").unwrap();
        let html = r#"
            <html>
              <head>
                <title>Fallback title</title>
                <meta property="og:title" content="Release &amp; Roadmap">
                <meta name="description" content="A short &lt;b&gt;summary&lt;/b&gt; for the preview.">
                <meta property="og:site_name" content="Verdant Docs">
                <meta property="og:image" content="/images/card.webp">
              </head>
            </html>
        "#;

        let preview = parse_link_preview_html(&page, html).unwrap();

        assert_eq!(preview.title, "Release & Roadmap");
        assert_eq!(
            preview.description.as_deref(),
            Some("A short summary for the preview.")
        );
        assert_eq!(preview.site_name.as_deref(), Some("Verdant Docs"));
        assert_eq!(
            preview.image_proxy_url.as_deref(),
            Some("/api/link-previews/image?url=https%3A%2F%2Fexample.com%2Fimages%2Fcard.webp")
        );
    }

    #[test]
    fn image_signatures_reject_svg_and_scriptable_content() {
        assert!(has_passive_raster_signature(
            b"\x89PNG\r\n\x1a\nrest",
            "image/png"
        ));
        assert!(!has_passive_raster_signature(
            br#"<svg onload="alert(1)"></svg>"#,
            "image/png"
        ));
        assert_eq!(allowed_image_content_type("image/svg+xml"), None);
    }
}
