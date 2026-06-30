//! URL safety service — checks URLs against Google Safe Browsing API v4.
//!
//! Used for:
//! - Announcement button URLs (checked before storage)
//! - Optionally: any user-posted URL (checked on message create)
//!
//! # Setup
//!
//! Set `GOOGLE_SAFE_BROWSING_KEY` env var with your API key.
//! Get one free at: https://console.cloud.google.com/apis/api/safebrowsing.googleapis.com
//!
//! Free tier: unlimited lookups for non-commercial use.
//! Commercial use: Google Web Risk API (100K/month free).
//!
//! # How It Works
//!
//! 1. POST URL(s) to Google's threatMatches:find endpoint
//! 2. Google checks against their phishing/malware/unwanted software databases
//! 3. Empty response = safe, non-empty = threat found
//! 4. Response includes threat type (MALWARE, SOCIAL_ENGINEERING, etc.)

use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);
const MAX_ANNOUNCEMENT_URL_LEN: usize = 2048;
const SAFE_BROWSING_UNAVAILABLE_MESSAGE: &str =
    "URL safety check is unavailable. Please try again later.";

/// Threat types returned by Google Safe Browsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreatType {
    Malware,
    SocialEngineering,
    UnwantedSoftware,
    PotentiallyHarmfulApplication,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct UrlCheckResult {
    pub safe: bool,
    pub threats: Vec<String>,
}

/// Check one or more URLs against Google Safe Browsing.
/// Returns Ok(result) with safety status, or Err if the API is unavailable.
pub async fn check_urls(urls: &[&str]) -> Result<Vec<UrlCheckResult>, String> {
    let api_key = std::env::var("GOOGLE_SAFE_BROWSING_KEY")
        .ok()
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
        .ok_or_else(|| "GOOGLE_SAFE_BROWSING_KEY is not configured".to_string())?;

    let threat_entries: Vec<serde_json::Value> = urls
        .iter()
        .map(|url| serde_json::json!({ "url": url }))
        .collect();

    let body = serde_json::json!({
        "client": {
            "clientId": "verdant-chat",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": threat_entries
        }
    });

    let resp = HTTP_CLIENT
        .post(format!(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        ))
        .json(&body)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| {
            let sanitized = e.without_url();
            format!("Safe Browsing API request failed: {sanitized}")
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Safe Browsing API error ({status}): {body}"));
    }

    #[derive(Deserialize)]
    struct ApiResponse {
        matches: Option<Vec<ThreatMatch>>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ThreatMatch {
        threat_type: String,
        threat: ThreatEntry,
    }

    #[derive(Deserialize)]
    struct ThreatEntry {
        url: String,
    }

    let api_resp: ApiResponse = resp.json().await.map_err(|e| format!("Parse error: {e}"))?;

    // Build result per URL
    let matches = api_resp.matches.unwrap_or_default();
    let results: Vec<UrlCheckResult> = urls
        .iter()
        .map(|url| {
            let threats: Vec<String> = matches
                .iter()
                .filter(|m| m.threat.url == *url)
                .map(|m| m.threat_type.clone())
                .collect();
            UrlCheckResult {
                safe: threats.is_empty(),
                threats,
            }
        })
        .collect();

    Ok(results)
}

/// Check a single URL. Convenience wrapper.
pub async fn is_url_safe(url: &str) -> Result<bool, String> {
    let results = check_urls(&[url]).await?;
    Ok(results.first().map(|r| r.safe).unwrap_or(true))
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(default)
}

fn safe_browsing_fail_open_enabled() -> bool {
    let production_like = std::env::var("NODE_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false);
    env_bool("GOOGLE_SAFE_BROWSING_FAIL_OPEN", !production_like)
}

/// Validate a URL for use in announcements/buttons.
/// Checks:
/// 1. Must be valid http/https URL
/// 2. Must pass Google Safe Browsing check
/// 3. Host must not be an IP address (common phishing pattern)
pub async fn validate_announcement_url(url: &str) -> Result<(), String> {
    if url.is_empty() || url.len() > MAX_ANNOUNCEMENT_URL_LEN {
        return Err(format!(
            "URL must be 1-{MAX_ANNOUNCEMENT_URL_LEN} characters"
        ));
    }
    if url.chars().any(|c| c.is_control()) {
        return Err("URL must not contain control characters".to_string());
    }

    // Parse URL
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {e}"))?;

    // Must be http or https
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("URL must use http or https".to_string());
    }

    // Must have a host
    let host = parsed.host_str().ok_or("URL must have a host")?;
    let host_for_log = host.to_string();

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URLs with embedded credentials are not allowed".to_string());
    }

    // Block IP addresses (common phishing). `url` keeps IPv6 brackets in
    // `host_str()`, so normalize them before parsing as an IP literal.
    let host_ip_candidate = host.trim_start_matches('[').trim_end_matches(']');
    if host_ip_candidate.parse::<std::net::IpAddr>().is_ok() {
        return Err("URLs with IP addresses are not allowed".to_string());
    }

    // Block localhost/private networks
    if host == "localhost" || host.ends_with(".local") || host == "127.0.0.1" || host == "0.0.0.0" {
        return Err("Local/private URLs are not allowed".to_string());
    }

    // Google Safe Browsing check
    match is_url_safe(url).await {
        Ok(true) => Ok(()),
        Ok(false) => Err("URL flagged as potentially harmful by Google Safe Browsing".to_string()),
        Err(e) => {
            // API error: development may fail open, production fails closed by default.
            tracing::warn!(host = %host_for_log, error = %e, "Safe Browsing check failed");
            if safe_browsing_fail_open_enabled() {
                Ok(())
            } else {
                Err(SAFE_BROWSING_UNAVAILABLE_MESSAGE.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_announcement_url;

    #[tokio::test]
    async fn announcement_url_rejects_local_targets() {
        assert!(
            validate_announcement_url("http://127.0.0.1/admin")
                .await
                .is_err()
        );
        assert!(
            validate_announcement_url("http://localhost/admin")
                .await
                .is_err()
        );
        assert!(
            validate_announcement_url("http://service.local/admin")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn announcement_url_rejects_embedded_credentials() {
        assert!(
            validate_announcement_url("https://verdant.chat@evil.example/release")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn announcement_url_rejects_ip_literal_targets() {
        for url in [
            "http://10.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/admin",
        ] {
            assert!(validate_announcement_url(url).await.is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn announcement_url_rejects_control_characters() {
        assert!(
            validate_announcement_url("https://example.com/release\nSet-Cookie:bad=1")
                .await
                .is_err()
        );
    }
}
