use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;

use crate::config::InstanceMode;
use crate::error::{AppError, AppResult};
use crate::middleware::rate_limit;
use crate::state::AppState;

fn updates_not_configured() -> AppError {
    AppError::WithCode {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "UPDATE_NOT_CONFIGURED",
        message: "Update service is not configured".into(),
    }
}

fn manifest_fetch_error(instance_mode: InstanceMode, error: impl std::fmt::Display) -> AppError {
    if instance_mode == InstanceMode::Official {
        tracing::error!("Failed to fetch update manifest: {error}");
        AppError::Internal
    } else {
        tracing::info!(
            mode = %instance_mode.as_str(),
            "Update manifest unavailable; treating updater as not configured"
        );
        updates_not_configured()
    }
}

const PRESIGNED_EXPIRY_SECS: u64 = 900; // 15 minutes
const MAX_LOG_PLATFORM_CHARS: usize = 64;
const MAX_LOG_VERSION_CHARS: usize = 32;

fn sanitize_platform_for_log(platform: &str) -> String {
    let sanitized: String = platform
        .chars()
        .take(MAX_LOG_PLATFORM_CHARS)
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '_',
        })
        .collect();

    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn sanitize_version_for_log(version: &str) -> String {
    let sanitized: String = version
        .chars()
        .take(MAX_LOG_VERSION_CHARS)
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-' | '+' => c,
            _ => '_',
        })
        .collect();

    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

// ─── GET /api/updates/latest ────────────────────────────────────────

/// Fetch the update manifest from S3, replace S3 keys with presigned
/// download URLs, and return the modified manifest as JSON.
/// This matches the Tauri v2 updater expected format.
pub async fn get_latest_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> AppResult<Json<Value>> {
    let ip = super::extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::UPDATE_LIMIT, &ip).await?;
    let s3 = state.s3.as_ref().ok_or_else(updates_not_configured)?;

    // Fetch latest.json from S3
    let manifest_text = s3
        .get_object_text("updates/latest.json")
        .await
        .map_err(|e| manifest_fetch_error(state.config.instance_mode, e))?;

    let mut manifest: Value = serde_json::from_str(&manifest_text).map_err(|e| {
        tracing::error!("Invalid update manifest JSON: {e}");
        AppError::Internal
    })?;

    // Replace S3 keys with presigned URLs in each platform entry
    if let Some(platforms) = manifest
        .get_mut("platforms")
        .and_then(|p| p.as_object_mut())
    {
        for (platform, entry) in platforms.iter_mut() {
            if let Some(url_val) = entry.get_mut("url") {
                if let Some(s3_key) = url_val.as_str() {
                    let presigned_result =
                        s3.presigned_get_url(s3_key, PRESIGNED_EXPIRY_SECS).await;
                    match presigned_result {
                        Ok(presigned) => *url_val = Value::String(presigned),
                        Err(_) => {
                            let platform = sanitize_platform_for_log(platform);
                            tracing::error!(
                                platform = %platform,
                                "Failed to generate update download URL"
                            );
                            return Err(updates_not_configured());
                        }
                    }
                }
            }
        }
    }

    Ok(Json(manifest))
}

// ─── GET /api/updates/download ──────────────────────────────────────

/// Installer filename patterns per platform.
fn installer_download_info(platform: &str, version: &str) -> Option<(String, &'static str)> {
    match platform {
        "windows" | "windows-exe" => Some((
            format!("Verdant_{version}_x64-setup.exe"),
            "application/octet-stream",
        )),
        "windows-msi" => Some((
            format!("Verdant_{version}_x64_en-US.msi"),
            "application/x-msi",
        )),
        "macos-arm" => Some((
            format!("darwin-aarch64/Verdant_{version}_aarch64.dmg"),
            "application/x-apple-diskimage",
        )),
        "macos-intel" => Some((
            format!("darwin-x86_64/Verdant_{version}_x64.dmg"),
            "application/x-apple-diskimage",
        )),
        "linux" => Some((
            format!("verdant_{version}_amd64.AppImage"),
            "application/octet-stream",
        )),
        _ => None,
    }
}

fn attachment_disposition(filename: &str) -> String {
    let safe: String = filename
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '_',
        })
        .collect();
    format!("attachment; filename=\"{safe}\"; filename*=UTF-8''{safe}")
}

#[derive(Deserialize)]
pub struct DownloadQuery {
    #[serde(default = "default_platform")]
    platform: String,
}

fn default_platform() -> String {
    "windows".to_string()
}

/// Serve a platform installer for manual browser downloads.
pub async fn download_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(query): Query<DownloadQuery>,
) -> AppResult<Response> {
    let ip = super::extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::UPDATE_LIMIT, &ip).await?;
    let s3 = state.s3.as_ref().ok_or_else(updates_not_configured)?;

    // Read manifest to get current version
    let manifest_text = s3
        .get_object_text("updates/latest.json")
        .await
        .map_err(|e| manifest_fetch_error(state.config.instance_mode, e))?;

    let manifest: Value = serde_json::from_str(&manifest_text).map_err(|e| {
        tracing::error!("Invalid update manifest JSON: {e}");
        AppError::Internal
    })?;

    let version = manifest
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal)?;

    let (filename, content_type) =
        installer_download_info(&query.platform, version).ok_or_else(|| {
            tracing::warn!(platform = %query.platform, "Update requested for unsupported platform");
            AppError::WithCode {
                status: StatusCode::BAD_REQUEST,
                code: "INVALID_PLATFORM",
                message: "Unsupported platform".into(),
            }
        })?;

    let installer_key = format!("updates/{version}/{filename}");
    let download_filename = filename.rsplit('/').next().unwrap_or(filename.as_str());
    let content_disposition = attachment_disposition(download_filename);
    let body = s3.get_object_bytes(&installer_key).await.map_err(|_| {
        let platform = sanitize_platform_for_log(&query.platform);
        let version = sanitize_version_for_log(version);
        tracing::error!(
            platform = %platform,
            version = %version,
            "Failed to fetch installer object"
        );
        AppError::Internal
    })?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response_headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&content_disposition).map_err(|e| {
            tracing::error!("Invalid installer Content-Disposition header: {e}");
            AppError::Internal
        })?,
    );
    response_headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).map_err(|e| {
            tracing::error!("Invalid installer Content-Length header: {e}");
            AppError::Internal
        })?,
    );
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));

    Ok((response_headers, Bytes::from(body)).into_response())
}

#[cfg(test)]
mod tests {
    use super::{manifest_fetch_error, sanitize_platform_for_log, sanitize_version_for_log};
    use crate::{config::InstanceMode, error::AppError};

    fn error_code(err: AppError) -> Option<String> {
        match err {
            AppError::WithCode { code, .. } => Some(code.to_string()),
            _ => None,
        }
    }

    #[test]
    fn sanitize_platform_for_log_keeps_safe_platform_names() {
        assert_eq!(sanitize_platform_for_log("windows-msi"), "windows-msi");
        assert_eq!(sanitize_platform_for_log("macos.arm_64"), "macos.arm_64");
    }

    #[test]
    fn sanitize_platform_for_log_replaces_unsafe_or_empty_values() {
        assert_eq!(
            sanitize_platform_for_log("linux/../../secret"),
            "linux_.._.._secret"
        );
        assert_eq!(sanitize_platform_for_log(""), "unknown");
    }

    #[test]
    fn sanitize_version_for_log_replaces_unsafe_or_empty_values() {
        assert_eq!(sanitize_version_for_log("1.2.3+build-4"), "1.2.3+build-4");
        assert_eq!(sanitize_version_for_log("../secret"), ".._secret");
        assert_eq!(sanitize_version_for_log(""), "unknown");
    }

    #[test]
    fn selfhost_manifest_fetch_error_is_not_configured() {
        assert_eq!(
            error_code(manifest_fetch_error(InstanceMode::Standalone, "missing")),
            Some("UPDATE_NOT_CONFIGURED".to_string())
        );
    }

    #[test]
    fn official_manifest_fetch_error_stays_internal() {
        assert!(matches!(
            manifest_fetch_error(InstanceMode::Official, "missing"),
            AppError::Internal
        ));
    }
}
