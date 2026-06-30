use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, Multipart, Path, Query, State, multipart::Field},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, LazyLock},
};

use std::time::Duration;

use futures_util::StreamExt;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::config::{LocalCapabilities, UploadPolicy};
use crate::error::{AppError, AppResult};
use crate::handlers::extract_client_ip;
use crate::middleware::{
    auth::{BotIdentity, OptionalBot, UserId},
    rate_limit,
};
use crate::services::audit;
use crate::services::banner_crop::{self, BannerCrop};
use crate::services::cdn;
use crate::services::content_scanner::{self, ScanMetadata, ScanVerdict};
use crate::services::entitlements::Entitlements;
use crate::services::image_sanitizer;
use crate::services::permissions::bits;
use crate::services::pg::bots::{SCOPE_UPLOADS_WRITE, has_scope};
use crate::state::AppState;
use crate::ws::{events, topics};

// ─── Constants ──────────────────────────────────────────────────────

const MAX_EMOJI_SIZE: usize = 256 * 1024; // 256KB
const MAX_STICKER_SIZE: usize = 512 * 1024; // 512KB
const MAX_BOT_IMAGE_SIZE: usize = 10 * 1024 * 1024; // 10MB
const CUSTOM_EXPRESSION_IMPORT_TIMEOUT_SECS: u64 = 8;

const ALLOWED_IMAGE_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "webp"];

static CUSTOM_EXPRESSION_IMPORT_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(CUSTOM_EXPRESSION_IMPORT_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(Arc::new(CustomExpressionImportResolver))
        .build()
        .expect("custom expression import client should build")
});

#[derive(Debug, Clone, Default)]
struct CustomExpressionImportResolver;

impl Resolve for CustomExpressionImportResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = crate::services::public_net::resolve_public_socket_addrs(&host)
                .await
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BannerCropPatchRequest {
    pub banner_crop: Option<BannerCrop>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCustomExpressionRequest {
    pub kind: String,
    pub name: String,
    pub source_peer_id: String,
    pub source_media_url: String,
    pub source_server_label: Option<String>,
    pub source_expression_name: Option<String>,
    pub source_sha256_hex: Option<String>,
}

// ─── Magic bytes validation ─────────────────────────────────────────

// Audit note: extension and Content-Type are advisory; storage paths validate
// the byte signature and strip metadata before accepting user-controlled files.
fn validate_image_magic_bytes(data: &[u8], ext: &str) -> bool {
    match ext {
        "png" => data.starts_with(&[0x89, 0x50, 0x4E, 0x47]),
        "jpg" | "jpeg" => data.starts_with(&[0xFF, 0xD8, 0xFF]),
        "gif" => data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a"),
        "webp" => data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP",
        _ => false,
    }
}

fn extract_ext(filename: &str) -> Option<String> {
    filename.rsplit('.').next().map(|e| e.to_lowercase())
}

fn content_type_for_image_ext(ext: &str) -> &'static str {
    match ext {
        "gif" => "image/gif",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        _ => "image/png",
    }
}

fn canonical_custom_expression_ext(ext: &str) -> String {
    match ext {
        "jpeg" => "jpg".to_string(),
        value => value.to_string(),
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_custom_expression_name(kind: CustomExpressionUploadKind, name: &str) -> AppResult<()> {
    if name.len() < 2 || name.len() > 32 {
        return Err(AppError::Validation(format!(
            "{} name must be 2-32 characters",
            kind.title_label()
        )));
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(AppError::Validation(format!(
            "{} name must be alphanumeric or underscore",
            kind.title_label()
        )));
    }
    Ok(())
}

async fn read_limited_field(
    mut field: Field<'_>,
    max_size: usize,
    too_large_message: &str,
) -> AppResult<Vec<u8>> {
    let mut data = Vec::new();

    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|_| AppError::Validation("Failed to read file data".into()))?
    {
        let next_len = data
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| AppError::Validation(too_large_message.to_string()))?;
        if next_len > max_size {
            return Err(AppError::Validation(too_large_message.to_string()));
        }
        data.extend_from_slice(&chunk);
    }

    Ok(data)
}

struct PreparedCustomExpressionMedia {
    data: Vec<u8>,
    ext: String,
    content_type: &'static str,
    sha256_hex: String,
}

async fn prepare_custom_expression_media(
    filename: &str,
    data: Vec<u8>,
    kind: CustomExpressionUploadKind,
) -> AppResult<PreparedCustomExpressionMedia> {
    let ext = extract_ext(filename)
        .ok_or_else(|| AppError::Validation("File must have an extension".into()))?;

    if !ALLOWED_IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::Validation(
            "Allowed: png, jpg, jpeg, gif, webp".into(),
        ));
    }

    if !validate_image_magic_bytes(&data, &ext) {
        return Err(AppError::Validation(
            "File content does not match extension".into(),
        ));
    }

    let data = image_sanitizer::strip_image_metadata(&data, &ext);

    let (data, ext) = if ext == "gif" {
        match convert_gif_to_webp(&data).await {
            Ok(webp_data) => {
                tracing::info!(
                    kind = kind.label(),
                    "Converted custom expression GIF->WebP: {}->{} bytes",
                    data.len(),
                    webp_data.len()
                );
                let clean_webp = image_sanitizer::strip_image_metadata(&webp_data, "webp");
                (clean_webp, "webp".to_string())
            }
            Err(e) => {
                tracing::warn!(
                    kind = kind.label(),
                    "GIF->WebP conversion failed, storing as GIF: {e}"
                );
                (data, ext)
            }
        }
    } else {
        (data, canonical_custom_expression_ext(&ext))
    };

    let content_type = content_type_for_image_ext(&ext);
    let sha256_hex = sha256_hex(&data);
    Ok(PreparedCustomExpressionMedia {
        data,
        ext,
        content_type,
        sha256_hex,
    })
}

fn source_input_for_emoji<'a>(
    source_peer_id: Option<&'a str>,
    source_origin: Option<&'a str>,
    source_server_label: Option<&'a str>,
    source_expression_name: Option<&'a str>,
    imported_by: Option<i64>,
    imported_at_ms: Option<i64>,
) -> crate::services::pg::emojis::CustomExpressionSourceInput<'a> {
    crate::services::pg::emojis::CustomExpressionSourceInput {
        source_peer_id,
        source_origin,
        source_server_label,
        source_expression_name,
        imported_by,
        imported_at_ms,
    }
}

fn source_input_for_sticker<'a>(
    source_peer_id: Option<&'a str>,
    source_origin: Option<&'a str>,
    source_server_label: Option<&'a str>,
    source_expression_name: Option<&'a str>,
    imported_by: Option<i64>,
    imported_at_ms: Option<i64>,
) -> crate::services::pg::stickers::CustomExpressionSourceInput<'a> {
    crate::services::pg::stickers::CustomExpressionSourceInput {
        source_peer_id,
        source_origin,
        source_server_label,
        source_expression_name,
        imported_by,
        imported_at_ms,
    }
}

struct CustomExpressionPersistSource<'a> {
    source_peer_id: Option<&'a str>,
    source_origin: Option<&'a str>,
    source_server_label: Option<&'a str>,
    source_expression_name: Option<&'a str>,
    imported_by: Option<i64>,
    imported_at_ms: Option<i64>,
}

async fn delete_uncommitted_custom_expression_object(
    state: &AppState,
    key: &str,
    kind: CustomExpressionUploadKind,
) {
    let Some(s3) = &state.s3 else {
        tracing::warn!(
            key_class = storage_key_log_class(key),
            kind = kind.label(),
            "custom expression cleanup skipped because object storage is unavailable"
        );
        return;
    };

    match s3.delete_object(key).await {
        Ok(()) => tracing::debug!(
            key_class = storage_key_log_class(key),
            kind = kind.label(),
            "custom expression uncommitted object cleaned up"
        ),
        Err(error) => tracing::warn!(
            key_class = storage_key_log_class(key),
            kind = kind.label(),
            error = %error,
            "custom expression uncommitted object cleanup failed"
        ),
    }
}

async fn persist_custom_expression_media(
    state: &AppState,
    kind: CustomExpressionUploadKind,
    server_id: i64,
    expression_id: i64,
    name: &str,
    user_id: i64,
    media: PreparedCustomExpressionMedia,
    source: CustomExpressionPersistSource<'_>,
) -> AppResult<(String, i64)> {
    let mut tx = state.pg.begin().await.map_err(|error| {
        tracing::error!(
            server_id,
            kind = kind.label(),
            hash_prefix = %&media.sha256_hex[..12],
            error = %error,
            "custom expression asset transaction start failed"
        );
        AppError::Internal
    })?;

    let asset_lock_key = crate::services::pg::custom_expression_assets::advisory_lock_key(
        kind.label(),
        &media.sha256_hex,
    );
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(asset_lock_key)
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            tracing::error!(
                server_id,
                kind = kind.label(),
                hash_prefix = %&media.sha256_hex[..12],
                error = %error,
                "custom expression asset digest lock failed"
            );
            AppError::Internal
        })?;

    let existing_asset = crate::services::pg::custom_expression_assets::by_kind_hash_tx(
        &mut tx,
        kind.label(),
        &media.sha256_hex,
    )
    .await
    .map_err(|error| {
        tracing::error!(
            server_id,
            kind = kind.label(),
            hash_prefix = %&media.sha256_hex[..12],
            error = %error,
            "custom expression asset lookup failed"
        );
        AppError::Internal
    })?;

    let key = existing_asset
        .as_ref()
        .map(|asset| asset.storage_key.clone())
        .unwrap_or_else(|| custom_expression_asset_key(kind, &media.sha256_hex, &media.ext));
    let uploaded_new_object = existing_asset.is_none();

    if uploaded_new_object {
        let s3 = require_s3(state)?;
        s3.put_object(&key, media.data.clone(), media.content_type)
            .await
            .map_err(|error| {
                tracing::error!(
                    key_class = storage_key_log_class(&key),
                    kind = kind.label(),
                    hash_prefix = %&media.sha256_hex[..12],
                    error = %error,
                    "S3 custom expression asset upload failed"
                );
                AppError::WithCode {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    code: "UPLOAD_FAILED",
                    message: "Upload could not be processed".into(),
                }
            })?;
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    let asset_id = existing_asset
        .as_ref()
        .map(|asset| asset.id)
        .unwrap_or_else(|| state.snowflake.next_id());
    let asset = crate::services::pg::custom_expression_assets::CustomExpressionAssetInput {
        id: asset_id,
        kind: kind.label(),
        sha256_hex: &media.sha256_hex,
        byte_size: media.data.len() as i64,
        content_type: media.content_type,
        extension: &media.ext,
        storage_key: &key,
        now_ms,
    };

    let inserted = match kind {
        CustomExpressionUploadKind::Emoji => {
            crate::services::pg::emojis::insert_with_asset_if_below_server_limit_tx(
                &mut tx,
                expression_id,
                server_id,
                name,
                user_id,
                now_ms,
                asset,
                source_input_for_emoji(
                    source.source_peer_id,
                    source.source_origin,
                    source.source_server_label,
                    source.source_expression_name,
                    source.imported_by,
                    source.imported_at_ms,
                ),
            )
            .await
            .map(|row| row.map(|emoji| emoji.url))
        }
        CustomExpressionUploadKind::Sticker => {
            crate::services::pg::stickers::insert_with_asset_if_below_server_limit_tx(
                &mut tx,
                expression_id,
                server_id,
                name,
                user_id,
                now_ms,
                asset,
                source_input_for_sticker(
                    source.source_peer_id,
                    source.source_origin,
                    source.source_server_label,
                    source.source_expression_name,
                    source.imported_by,
                    source.imported_at_ms,
                ),
            )
            .await
            .map(|row| row.map(|sticker| sticker.url))
        }
    };

    let inserted = match inserted {
        Ok(row) => row,
        Err(error) => {
            if uploaded_new_object {
                delete_uncommitted_custom_expression_object(state, &key, kind).await;
            }
            let _ = tx.rollback().await;
            tracing::error!(
                expression_id,
                server_id,
                kind = kind.label(),
                hash_prefix = %&media.sha256_hex[..12],
                error = %error,
                "custom expression dedupe insert failed"
            );
            return Err(AppError::Internal);
        }
    };

    let Some(storage_key) = inserted else {
        if uploaded_new_object {
            delete_uncommitted_custom_expression_object(state, &key, kind).await;
        }
        let _ = tx.rollback().await;
        tracing::warn!(
            expression_id,
            server_id,
            user_id,
            kind = kind.label(),
            max_items = kind.max_count(),
            "custom expression dedupe insert hit server quota"
        );
        return Err(server_custom_expression_quota_error(kind));
    };

    tx.commit().await.map_err(|error| {
        tracing::error!(
            expression_id,
            server_id,
            kind = kind.label(),
            hash_prefix = %&media.sha256_hex[..12],
            error = %error,
            "custom expression dedupe transaction commit failed"
        );
        AppError::Internal
    })?;

    Ok((storage_key, now_ms))
}

fn extract_s3_key(url: &str) -> Option<String> {
    if !url.starts_with("http") {
        return Some(url.to_string());
    }
    url.find("avatars/")
        .or_else(|| url.find("banners/"))
        .or_else(|| url.find("member-list-banners/"))
        .or_else(|| url.find("server-icons/"))
        .or_else(|| url.find("server-banners/"))
        .or_else(|| url.find("bot-avatars/"))
        .or_else(|| url.find("bot-banners/"))
        .or_else(|| url.find("emojis/"))
        .or_else(|| url.find("attachments/"))
        .or_else(|| url.find("bot-uploads/"))
        .map(|i| url[i..].to_string())
}

fn require_s3(state: &AppState) -> AppResult<&crate::services::s3::S3Service> {
    if state.config.upload_policy == UploadPolicy::Disabled {
        return Err(AppError::WithCode {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "UPLOADS_DISABLED",
            message: "File uploads are not configured".into(),
        });
    }

    state.s3.as_ref().ok_or_else(|| AppError::WithCode {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "UPLOADS_DISABLED",
        message: "File uploads are not configured".into(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CustomExpressionUploadKind {
    Emoji,
    Sticker,
}

impl CustomExpressionUploadKind {
    fn route_segment(self) -> &'static str {
        match self {
            Self::Emoji => "emojis",
            Self::Sticker => "stickers",
        }
    }

    fn storage_prefix(self) -> &'static str {
        match self {
            Self::Emoji => "emojis",
            Self::Sticker => "stickers",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Emoji => "emoji",
            Self::Sticker => "sticker",
        }
    }

    fn title_label(self) -> &'static str {
        match self {
            Self::Emoji => "Emoji",
            Self::Sticker => "Sticker",
        }
    }

    fn max_size(self) -> usize {
        match self {
            Self::Emoji => MAX_EMOJI_SIZE,
            Self::Sticker => MAX_STICKER_SIZE,
        }
    }

    fn limit_code(self) -> &'static str {
        match self {
            Self::Emoji => "EMOJI_LIMIT_REACHED",
            Self::Sticker => "STICKER_LIMIT_REACHED",
        }
    }

    fn max_count(self) -> i64 {
        match self {
            Self::Emoji => crate::services::pg::emojis::MAX_SERVER_CUSTOM_EMOJIS,
            Self::Sticker => crate::services::pg::stickers::MAX_SERVER_CUSTOM_STICKERS,
        }
    }

    fn from_wire(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "emoji" | "emojis" => Some(Self::Emoji),
            "sticker" | "stickers" => Some(Self::Sticker),
            _ => None,
        }
    }
}

fn server_custom_expression_quota_error(kind: CustomExpressionUploadKind) -> AppError {
    AppError::WithCode {
        status: StatusCode::CONFLICT,
        code: kind.limit_code(),
        message: format!(
            "This server already has the maximum of {} custom {}s",
            kind.max_count(),
            kind.label()
        ),
    }
}

fn custom_expression_asset_key(
    kind: CustomExpressionUploadKind,
    sha256_hex: &str,
    ext: &str,
) -> String {
    let ext = canonical_custom_expression_ext(ext);
    format!("{}/by-hash/{sha256_hex}.{ext}", kind.storage_prefix())
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str().map(str::to_ascii_lowercase)
            == right.host_str().map(str::to_ascii_lowercase)
        && left.port_or_known_default() == right.port_or_known_default()
}

fn import_url_host_is_public(parsed: &Url) -> bool {
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.trim().to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") {
        return false;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => crate::services::public_net::is_public_ip(ip),
        Err(_) => true,
    }
}

async fn ensure_import_url_resolves_public(url: &Url) -> AppResult<()> {
    let host = url
        .host_str()
        .ok_or_else(|| AppError::Validation("Source media URL is missing a host".into()))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        if crate::services::public_net::is_public_ip(ip) {
            return Ok(());
        }
        return Err(AppError::Validation(
            "Source media URL host is not public".into(),
        ));
    }
    crate::services::public_net::resolve_public_socket_addrs(host)
        .await
        .map(|_| ())
        .map_err(|error| {
            tracing::warn!(
                host = %host,
                error = %error,
                "custom expression import DNS resolution rejected"
            );
            AppError::WithCode {
                status: StatusCode::BAD_GATEWAY,
                code: "FEDERATION_MEDIA_FETCH_FAILED",
                message: "Could not resolve the federated peer media host".into(),
            }
        })
}

fn validate_custom_expression_import_url(raw: &str, peer_api_origin: &str) -> Result<Url, String> {
    let parsed = Url::parse(raw).map_err(|_| "Invalid source media URL".to_string())?;
    let peer = Url::parse(peer_api_origin).map_err(|_| "Invalid peer API origin".to_string())?;

    if parsed.scheme() != "https" || peer.scheme() != "https" {
        return Err("Federated custom expression imports require HTTPS".to_string());
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err("Source media URL must not contain credentials".to_string());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("Source media URL must not include query or fragment".to_string());
    }
    if !same_origin(&parsed, &peer) || !import_url_host_is_public(&parsed) {
        return Err("Source media URL is not on the trusted peer origin".to_string());
    }
    let path = parsed.path();
    if path.contains('\\')
        || path.contains('\0')
        || path.contains("/attachments/")
        || !path.starts_with("/api/federation/v1/media/custom-expressions/")
    {
        return Err("Source media URL path is not an allowed custom expression route".to_string());
    }

    Ok(parsed)
}

fn custom_expression_public_storage_key(
    kind: CustomExpressionUploadKind,
    url: &str,
) -> Option<String> {
    let candidate = if url.starts_with("http://") || url.starts_with("https://") {
        let index = url.find(kind.storage_prefix())?;
        &url[index..]
    } else {
        url
    };
    let candidate = candidate
        .split(['?', '#'])
        .next()
        .unwrap_or(candidate)
        .trim();

    if candidate.starts_with('/')
        || candidate.contains('\\')
        || candidate.contains('\0')
        || candidate.contains("attachments/")
        || candidate
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".."))
    {
        return None;
    }
    if !candidate.starts_with(&format!("{}/", kind.storage_prefix())) {
        return None;
    }
    Some(candidate.to_string())
}

fn import_filename_for_response(url: &Url, content_type: Option<&str>) -> String {
    let ext = content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .and_then(|value| match value {
            "image/png" => Some("png"),
            "image/jpeg" => Some("jpg"),
            "image/gif" => Some("gif"),
            "image/webp" => Some("webp"),
            _ => None,
        })
        .map(str::to_string)
        .or_else(|| extract_ext(url.path()))
        .unwrap_or_else(|| "png".to_string());
    format!("import.{ext}")
}

fn bounded_optional(value: Option<&str>, max_len: usize) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(max_len).collect::<String>())
}

async fn trusted_custom_expression_import_origin(
    state: &AppState,
    server_id: i64,
    peer_id: &str,
) -> AppResult<String> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT keys.api_origin
          FROM federation_peer_routes routes
          JOIN federation_peer_keys keys
            ON keys.peer_id = routes.peer_id
           AND keys.status = 'active'
         WHERE routes.peer_id = $1
           AND routes.scope_type = 'server'
           AND routes.scope_id = $2
           AND routes.status = 'active'
         ORDER BY keys.valid_until_ms NULLS LAST, keys.updated_at_ms DESC
         LIMIT 1
        "#,
    )
    .bind(peer_id)
    .bind(server_id)
    .fetch_optional(&state.pg)
    .await
    .map_err(|error| {
        tracing::error!(
            server_id,
            peer_id = %peer_id,
            error = %error,
            "custom expression import trusted peer lookup failed"
        );
        AppError::Internal
    })?;

    row.map(|(origin,)| origin)
        .ok_or_else(|| AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "FEDERATION_PEER_NOT_TRUSTED",
            message: "This server is not configured to import from that federated peer".into(),
        })
}

async fn fetch_custom_expression_import_media(
    url: Url,
    max_size: usize,
) -> AppResult<(String, Vec<u8>)> {
    let response = CUSTOM_EXPRESSION_IMPORT_CLIENT
        .get(url.clone())
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(
                host = %url.host_str().unwrap_or_default(),
                error = %error,
                "custom expression import media fetch failed"
            );
            AppError::WithCode {
                status: StatusCode::BAD_GATEWAY,
                code: "FEDERATION_MEDIA_FETCH_FAILED",
                message: "Could not fetch custom expression media from the federated peer".into(),
            }
        })?;

    if !response.status().is_success() {
        tracing::warn!(
            host = %url.host_str().unwrap_or_default(),
            status = response.status().as_u16(),
            "custom expression import media fetch returned non-success"
        );
        return Err(AppError::WithCode {
            status: StatusCode::BAD_GATEWAY,
            code: "FEDERATION_MEDIA_FETCH_FAILED",
            message: "Could not fetch custom expression media from the federated peer".into(),
        });
    }

    if let Some(content_length) = response.content_length()
        && content_length > max_size as u64
    {
        return Err(AppError::Validation(format!(
            "Source media too large (max {}KB)",
            max_size / 1024
        )));
    }

    let filename = import_filename_for_response(
        &url,
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    );
    let mut data = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            tracing::warn!(
                host = %url.host_str().unwrap_or_default(),
                error = %error,
                "custom expression import media stream failed"
            );
            AppError::WithCode {
                status: StatusCode::BAD_GATEWAY,
                code: "FEDERATION_MEDIA_FETCH_FAILED",
                message: "Could not fetch custom expression media from the federated peer".into(),
            }
        })?;
        let next_len = data
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| AppError::Validation("Source media too large".into()))?;
        if next_len > max_size {
            return Err(AppError::Validation(format!(
                "Source media too large (max {}KB)",
                max_size / 1024
            )));
        }
        data.extend_from_slice(&chunk);
    }
    Ok((filename, data))
}

pub fn attachment_media_url(api_url: &str, attachment_id: i64) -> String {
    format!(
        "{}/api/media/attachments/{}",
        api_url.trim_end_matches('/'),
        attachment_id
    )
}

fn is_attachment_storage_key(key: &str) -> bool {
    key.starts_with("attachments/")
        && !key.starts_with('/')
        && !key.contains('\\')
        && !key.contains('\0')
        && !key
            .split('/')
            .any(|segment| matches!(segment, "." | ".." | ""))
}

fn storage_key_log_class(key: &str) -> &'static str {
    match key.split('/').next().unwrap_or_default() {
        "attachments" => "attachment",
        "avatars" => "avatar",
        "banners" => "banner",
        "bot-images" => "bot_image",
        "bot-avatars" => "bot_avatar",
        "bot-banners" => "bot_banner",
        "member-list-banners" => "member_list_banner",
        "server-icons" => "server_icon",
        "server-banners" => "server_banner",
        "emojis" => "emoji",
        "stickers" => "sticker",
        _ => "unknown",
    }
}

fn attachment_storage_key_log_class(key: &str) -> &'static str {
    if is_attachment_storage_key(key) {
        "attachment"
    } else {
        "non_attachment"
    }
}

fn safe_header_filename(filename: &str) -> String {
    let safe = filename
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' | ' ' => ch,
            _ => '_',
        })
        .take(160)
        .collect::<String>()
        .trim()
        .trim_matches('.')
        .to_string();

    if safe.is_empty() {
        "attachment".to_string()
    } else {
        safe
    }
}

fn attachment_disposition(filename: &str, download: bool) -> HeaderValue {
    let disposition = if download { "attachment" } else { "inline" };
    let safe = safe_header_filename(filename);
    HeaderValue::from_str(&format!("{disposition}; filename=\"{safe}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

fn wants_attachment_download(query: &HashMap<String, String>) -> bool {
    query
        .get("download")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn existing_object_key(url: Option<&str>) -> Option<String> {
    let url = url?;
    if url.is_empty() {
        None
    } else {
        extract_s3_key(url)
    }
}

async fn delete_replaced_object(
    s3: &crate::services::s3::S3Service,
    old_key: Option<String>,
    new_key: &str,
) {
    let Some(old_key) = old_key else {
        return;
    };
    if old_key == new_key {
        return;
    }
    if let Err(e) = s3.delete_object(&old_key).await {
        tracing::warn!(
            key_class = storage_key_log_class(&old_key),
            error = %e,
            "Failed to delete replaced upload object"
        );
    }
}

fn require_flag(state: &AppState, flag: &str) -> AppResult<()> {
    let enabled = state
        .feature_flags
        .get_all()
        .get(flag)
        .copied()
        .unwrap_or(false);
    if !enabled {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "FEATURE_DISABLED",
            message: "This feature is not currently enabled".into(),
        });
    }
    Ok(())
}

fn upload_limit(entitlements: &Entitlements) -> usize {
    usize::try_from(entitlements.max_upload_bytes).unwrap_or(usize::MAX)
}

fn bot_image_upload_limit(local_capabilities: &LocalCapabilities) -> AppResult<usize> {
    if !local_capabilities.image_uploads {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "FEATURE_DISABLED",
            message: "Image uploads are not enabled for this instance".into(),
        });
    }

    Ok(usize::try_from(local_capabilities.max_upload_bytes)
        .unwrap_or(usize::MAX)
        .min(MAX_BOT_IMAGE_SIZE))
}

fn upload_limit_message(max_size: usize) -> String {
    format!("File too large (max {max_size} bytes)")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("uploads.rs");

    fn local_capabilities(max_upload_bytes: u64, image_uploads: bool) -> LocalCapabilities {
        LocalCapabilities {
            image_uploads,
            file_sharing: true,
            message_attachments: true,
            voice_chat: false,
            video_streaming: false,
            cross_server_emoji: false,
            animated_avatar: false,
            animated_banner: false,
            member_list_banner: false,
            max_upload_bytes,
            max_voice_bitrate: 0,
        }
    }

    #[test]
    fn bot_image_upload_limit_rejects_disabled_instance_capability() {
        let err = bot_image_upload_limit(&local_capabilities(5 * 1024 * 1024, false))
            .expect_err("disabled image uploads should be rejected");

        match err {
            AppError::WithCode { status, code, .. } => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert_eq!(code, "FEATURE_DISABLED");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn bot_image_upload_limit_uses_configured_limit_below_legacy_cap() {
        let limit = bot_image_upload_limit(&local_capabilities(5 * 1024 * 1024, true)).unwrap();

        assert_eq!(limit, 5 * 1024 * 1024);
        assert_eq!(
            upload_limit_message(limit),
            "File too large (max 5242880 bytes)"
        );
    }

    #[test]
    fn bot_image_upload_limit_keeps_legacy_cap_above_configured_limit() {
        let limit = bot_image_upload_limit(&local_capabilities(25 * 1024 * 1024, true)).unwrap();

        assert_eq!(limit, MAX_BOT_IMAGE_SIZE);
    }

    #[test]
    fn attachment_media_url_uses_api_route_not_public_cdn_key() {
        assert_eq!(
            attachment_media_url("https://api.example.test/", 42),
            "https://api.example.test/api/media/attachments/42"
        );
    }

    #[test]
    fn attachment_storage_key_accepts_only_attachment_objects() {
        assert!(is_attachment_storage_key("attachments/123/456.webp"));
        assert!(!is_attachment_storage_key("avatars/123.webp"));
        assert!(!is_attachment_storage_key("/attachments/123/456.webp"));
        assert!(!is_attachment_storage_key("attachments/123/../456.webp"));
        assert!(!is_attachment_storage_key("attachments/123//456.webp"));
    }

    #[test]
    fn attachment_storage_key_log_class_does_not_expose_object_keys() {
        assert_eq!(
            attachment_storage_key_log_class("attachments/123/456.webp"),
            "attachment"
        );
        assert_eq!(
            attachment_storage_key_log_class("avatars/private-user.webp"),
            "non_attachment"
        );
    }

    #[test]
    fn custom_expression_storage_key_log_class_is_bounded() {
        assert_eq!(storage_key_log_class("emojis/123/456.webp"), "emoji");
        assert_eq!(storage_key_log_class("stickers/123/456.webp"), "sticker");
        assert_eq!(
            storage_key_log_class("stickers/123/456.webp/extra"),
            "sticker"
        );
    }

    #[test]
    fn custom_expression_asset_key_is_digest_addressed_under_public_prefix() {
        assert_eq!(
            custom_expression_asset_key(
                CustomExpressionUploadKind::Emoji,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "webp"
            ),
            "emojis/by-hash/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.webp"
        );
        assert_eq!(
            custom_expression_asset_key(
                CustomExpressionUploadKind::Sticker,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "jpeg"
            ),
            "stickers/by-hash/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.jpg"
        );
    }

    #[test]
    fn custom_expression_import_url_policy_rejects_untrusted_and_private_media() {
        assert!(
            validate_custom_expression_import_url(
                "https://api.example.test/api/federation/v1/media/custom-expressions/emoji/123",
                "https://api.example.test",
            )
            .is_ok()
        );
        assert!(
            validate_custom_expression_import_url(
                "https://cdn.example.test/emojis/by-hash/abc.webp",
                "https://api.example.test",
            )
            .is_err()
        );
        assert!(
            validate_custom_expression_import_url(
                "http://127.0.0.1:3000/api/federation/v1/media/custom-expressions/emoji/123",
                "http://127.0.0.1:3000",
            )
            .is_err()
        );
        assert!(
            validate_custom_expression_import_url(
                "https://api.example.test/api/media/attachments/123",
                "https://api.example.test",
            )
            .is_err()
        );
    }

    #[test]
    fn custom_expression_import_client_uses_guarded_dns_without_proxy() {
        let client = SOURCE
            .split("static CUSTOM_EXPRESSION_IMPORT_CLIENT")
            .nth(1)
            .expect("custom expression import client should exist")
            .split("#[derive(Debug, Clone, Default)]")
            .next()
            .expect("custom expression import resolver follows client");

        assert!(
            client.contains(".no_proxy()"),
            "custom expression imports must not allow environment proxies to bypass URL/DNS policy"
        );
        assert!(
            client.contains(".dns_resolver(Arc::new(CustomExpressionImportResolver))"),
            "custom expression imports must use the guarded resolver for the actual connect path"
        );
    }

    #[test]
    fn custom_expression_import_resolution_uses_shared_public_net_policy() {
        let resolver = SOURCE
            .split("async fn ensure_import_url_resolves_public")
            .nth(1)
            .expect("custom expression import resolution guard should exist")
            .split("fn validate_custom_expression_import_url")
            .next()
            .expect("URL policy should follow resolution guard");

        assert!(resolver.contains("crate::services::public_net::is_public_ip"));
        assert!(resolver.contains("resolve_public_socket_addrs"));
        assert!(
            !resolver.contains("tokio::net::lookup_host"),
            "preflight must use the same public-address policy as the guarded request resolver"
        );
    }

    #[test]
    fn emoji_quota_error_uses_stable_code() {
        match server_custom_expression_quota_error(CustomExpressionUploadKind::Emoji) {
            AppError::WithCode {
                status,
                code,
                message,
            } => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert_eq!(code, "EMOJI_LIMIT_REACHED");
                assert!(message.contains("maximum"));
                assert!(
                    message.contains(
                        &crate::services::pg::emojis::MAX_SERVER_CUSTOM_EMOJIS.to_string()
                    )
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn custom_expression_upload_checks_quota_before_media_work_and_insert() {
        let upload = SOURCE
            .rsplit("async fn upload_custom_expression")
            .next()
            .expect("upload_custom_expression should exist")
            .split("pub async fn upload_attachment")
            .next()
            .expect("upload_custom_expression section should be present");

        let preflight = upload
            .find("is_at_server_limit")
            .expect("custom expression upload should preflight quota");
        let image_flag = upload
            .find("require_flag(&state, \"image_uploads\")")
            .expect("custom expression upload should require image uploads");
        let image_entitlement = upload
            .find("require_image_upload_entitlements(&state, user_id.0)")
            .expect("custom expression upload should require image upload entitlements");
        let upload_limit = upload
            .find("kind.max_size().min(upload_limit(&entitlements))")
            .expect("custom expression upload should respect image upload byte entitlements");
        let rate_limit = upload
            .find("rate_limit::enforce")
            .expect("custom expression upload should enforce upload rate limits");
        let read_limit = upload
            .rfind("max_upload_size")
            .expect("custom expression upload should use the bounded upload size");
        let scan = upload
            .find("scan_upload")
            .expect("custom expression upload should still scan media");
        let prepare = upload
            .find("prepare_custom_expression_media")
            .expect("custom expression upload should canonicalize media before hashing");
        let persist = upload
            .find("persist_custom_expression_media")
            .expect("custom expression upload should use the shared dedupe persistence path");

        assert!(image_flag < rate_limit);
        assert!(image_entitlement < rate_limit);
        assert!(upload_limit < rate_limit);
        assert!(upload_limit < read_limit);
        assert!(image_flag < preflight);
        assert!(image_entitlement < preflight);
        assert!(preflight < scan);
        assert!(preflight < prepare);
        assert!(scan < persist);
        assert!(upload.contains("CustomExpressionUploadKind::Sticker"));
        assert!(upload.contains("server_custom_expression_quota_error(kind)"));
        assert!(SOURCE.contains("delete_uncommitted_custom_expression_object"));
        assert!(upload.contains("CustomExpressionPersistSource"));
    }

    #[test]
    fn custom_expression_dedupe_cleanup_deletes_uncommitted_objects_under_digest_lock() {
        let cleanup = SOURCE
            .split("async fn delete_uncommitted_custom_expression_object")
            .nth(1)
            .expect("custom expression cleanup should exist")
            .split("async fn persist_custom_expression_media")
            .next()
            .expect("persist follows cleanup helper");
        let persist = SOURCE
            .split("async fn persist_custom_expression_media")
            .nth(1)
            .expect("persist helper should exist")
            .split("fn extract_s3_key")
            .next()
            .expect("extract follows persist helper");

        assert!(cleanup.contains("delete_object"));
        assert!(persist.contains("pg_advisory_xact_lock"));
        assert!(persist.contains("by_kind_hash_tx"));
        assert!(persist.contains("insert_with_asset_if_below_server_limit_tx"));
        assert!(persist.contains("tx.rollback().await"));
    }

    #[test]
    fn gif_conversion_timeout_drops_and_kills_ffmpeg_child() {
        let converter = SOURCE
            .rsplit("async fn convert_gif_to_webp")
            .next()
            .expect("convert_gif_to_webp should exist")
            .split("// \u{2500}\u{2500}\u{2500} POST /api/servers/:serverId/emojis")
            .next()
            .expect("convert_gif_to_webp section should be present");

        assert!(converter.contains("kill_on_drop(true)"));
        assert!(converter.contains("tokio::time::timeout(Duration::from_secs(10)"));
        assert!(converter.contains("wait_with_output()"));
    }

    #[test]
    fn dm_attachment_upload_reuses_send_authorization_before_media_side_effects() {
        let upload = SOURCE
            .rsplit("pub async fn upload_attachment")
            .next()
            .expect("upload_attachment should exist")
            .split("pub async fn get_attachment_media")
            .next()
            .expect("upload_attachment section should be present");

        let dm_send_auth = upload
            .find("ensure_dm_channel_send_allowed")
            .expect("DM attachment upload should reuse DM send authorization");
        let require_s3 = upload
            .find("let s3 = require_s3")
            .expect("attachment upload should still require S3");
        let read_field = upload
            .find("next_field()")
            .expect("attachment upload should read multipart field");
        let scan = upload
            .find("scan_upload")
            .expect("attachment upload should scan media");
        let put = upload
            .find("s3.put_object")
            .expect("attachment upload should store media");
        let insert = upload
            .find("pg::attachments::insert")
            .expect("attachment upload should insert attachment row");

        assert!(dm_send_auth < require_s3);
        assert!(dm_send_auth < read_field);
        assert!(dm_send_auth < scan);
        assert!(dm_send_auth < put);
        assert!(dm_send_auth < insert);
        assert!(!upload.contains("list_channel_ids_for_user(&state.pg, user_id.0)"));
        assert!(!upload.contains("unwrap_or_default()"));
    }
}

async fn require_image_upload_entitlements(
    state: &AppState,
    user_id: i64,
) -> AppResult<Entitlements> {
    let entitlements =
        crate::services::entitlements::current_for_user(&state.pg, &state.config, user_id).await;
    if !entitlements.image_uploads {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "FEATURE_DISABLED",
            message: "Image uploads are not enabled for this account or instance".into(),
        });
    }
    Ok(entitlements)
}

async fn require_file_sharing_entitlements(
    state: &AppState,
    user_id: i64,
) -> AppResult<Entitlements> {
    let entitlements =
        crate::services::entitlements::current_for_user(&state.pg, &state.config, user_id).await;
    if !entitlements.file_sharing {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "FEATURE_DISABLED",
            message: "File sharing is not enabled for this account or instance".into(),
        });
    }
    Ok(entitlements)
}

fn require_animated_avatar_entitlement(entitlements: &Entitlements, ext: &str) -> AppResult<()> {
    if ext == "gif" && !entitlements.animated_avatar {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "SUBSCRIPTION_REQUIRED",
            message: "Animated avatars are not enabled for this account or instance".into(),
        });
    }
    Ok(())
}

fn require_animated_banner_entitlement(entitlements: &Entitlements, ext: &str) -> AppResult<()> {
    if ext == "gif" && !entitlements.animated_banner {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "SUBSCRIPTION_REQUIRED",
            message: "Animated banners are not enabled for this account or instance".into(),
        });
    }
    Ok(())
}

fn require_member_list_banner_entitlement(entitlements: &Entitlements) -> AppResult<()> {
    if !entitlements.member_list_banner {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "SUBSCRIPTION_REQUIRED",
            message: "Member list banners are not enabled for this account or instance".into(),
        });
    }
    Ok(())
}

use super::emojis::broadcast_emojis_update as broadcast_emoji_version_update;

/// Suspend (soft-delete) a user + revoke every session in one transaction-
/// equivalent pair of writes. Used by both the CDN-warmup CSAM hit and
/// the inline content scanner's `Flagged` verdict.
async fn suspend_user_and_revoke_sessions(state: &AppState, uploader_id: i64) {
    if let Err(e) = crate::services::pg::users::soft_delete(&state.pg, uploader_id).await {
        tracing::warn!(uploader_id, error = %e, "uploads: PG user soft-delete failed");
    }
    if let Err(e) = crate::services::pg::sessions::delete_all_for_user(&state.pg, uploader_id).await
    {
        tracing::warn!(uploader_id, error = %e, "uploads: PG session purge failed");
    }
}

// ─── CDN warmup (triggers CSAM scan + cache) ────────────────────────

async fn cdn_warmup(
    state: &AppState,
    key: &str,
    uploader_id: i64,
    upload_type: &'static str,
    file_id: i64,
) -> AppResult<()> {
    if !cdn::enabled() {
        return Ok(());
    }

    let cdn_url = match cdn::resolve(Some(key)) {
        Some(url) => url,
        None => return Ok(()),
    };

    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let client = reqwest::Client::new();
        client.get(&cdn_url).send().await
    })
    .await;

    match result {
        Ok(Ok(resp)) if resp.status().as_u16() == 451 => {
            tracing::warn!(
                "CSAM FLAGGED via CDN: {upload_type} {file_id} by {uploader_id} — key={key}"
            );

            // 1. Copy to evidence bucket (if configured), then delete from public.
            if let (Some(s3_pub), Some(s3_ev)) = (&state.s3, &state.s3_evidence) {
                let evidence_key = format!("evidence/{uploader_id}/{file_id}");
                match s3_pub.get_object_bytes(key).await {
                    Ok(bytes) => {
                        let _ = s3_ev
                            .put_object_private(&evidence_key, bytes, "application/octet-stream")
                            .await;
                    }
                    Err(e) => tracing::error!("Failed to fetch flagged object for evidence: {e}"),
                }
                let _ = s3_pub.delete_object(key).await;
            }

            // 2. Soft-delete the user + drop every session.
            suspend_user_and_revoke_sessions(state, uploader_id).await;

            // 3. Audit log — the audit stream is the authoritative record.
            let audit_id = state.snowflake.next_id();
            audit::log_async(
                state.redis.clone(),
                audit::AuditEntry {
                    id: audit_id,
                    actor_id: 0,
                    action: audit::AuditAction::ContentFlagged,
                    target_type: upload_type,
                    target_id: file_id,
                    server_id: None,
                    metadata: Some(json!({
                        "scan_provider": "cloudflare_cdn",
                        "match_type": "csam_hash",
                        "uploader_id": uploader_id.to_string(),
                        "evidence_key": format!("evidence/{uploader_id}/{file_id}"),
                    })),
                    ip: None,
                },
                state.pg.clone(),
            );

            Err(AppError::WithCode {
                status: StatusCode::BAD_REQUEST,
                code: "UPLOAD_FAILED",
                message: "Upload could not be processed".into(),
            })
        }
        Ok(Ok(resp)) => {
            tracing::debug!("CDN warmup OK for {key}: status={}", resp.status());
            Ok(())
        }
        Ok(Err(e)) => {
            tracing::warn!("CDN warmup request failed for {key} (url={cdn_url}): {e}");
            Ok(())
        }
        Err(_) => {
            tracing::warn!("CDN warmup timed out for {key} (url={cdn_url})");
            Ok(())
        }
    }
}

// ─── Content scan helper (non-CDN fallback) ─────────────────────────

async fn revoke_flagged_bot_token(state: &AppState, bot: &BotIdentity) {
    let now_ms = chrono::Utc::now().timestamp_millis();
    if let Err(e) = crate::services::pg::bots::token_revoke(&state.pg, bot.token_id, now_ms).await {
        tracing::warn!(
            bot_id = bot.bot_id,
            token_id = bot.token_id,
            error = %e,
            "uploads: flagged bot token revoke failed"
        );
    }
}

async fn cdn_warmup_bot(
    state: &AppState,
    key: &str,
    bot: &BotIdentity,
    upload_type: &'static str,
    file_id: i64,
) -> AppResult<()> {
    if !cdn::enabled() {
        return Ok(());
    }

    let cdn_url = match cdn::resolve(Some(key)) {
        Some(url) => url,
        None => return Ok(()),
    };

    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let client = reqwest::Client::new();
        client.get(&cdn_url).send().await
    })
    .await;

    match result {
        Ok(Ok(resp)) if resp.status().as_u16() == 451 => {
            tracing::warn!(
                "CSAM FLAGGED via CDN: bot {upload_type} {file_id} by bot {} key={key}",
                bot.bot_id
            );

            let evidence_key = format!("evidence/bots/{}/{}", bot.bot_id, file_id);
            if let (Some(s3_pub), Some(s3_ev)) = (&state.s3, &state.s3_evidence) {
                match s3_pub.get_object_bytes(key).await {
                    Ok(bytes) => {
                        let _ = s3_ev
                            .put_object_private(&evidence_key, bytes, "application/octet-stream")
                            .await;
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch flagged bot object for evidence: {e}")
                    }
                }
                let _ = s3_pub.delete_object(key).await;
            }

            revoke_flagged_bot_token(state, bot).await;

            let audit_id = state.snowflake.next_id();
            audit::log_async(
                state.redis.clone(),
                audit::AuditEntry {
                    id: audit_id,
                    actor_id: 0,
                    action: audit::AuditAction::ContentFlagged,
                    target_type: upload_type,
                    target_id: file_id,
                    server_id: Some(bot.server_id),
                    metadata: Some(json!({
                        "scan_provider": "cloudflare_cdn",
                        "match_type": "csam_hash",
                        "bot_id": bot.bot_id.to_string(),
                        "bot_token_id": bot.token_id.to_string(),
                        "server_id": bot.server_id.to_string(),
                        "evidence_key": evidence_key,
                    })),
                    ip: None,
                },
                state.pg.clone(),
            );

            Err(AppError::WithCode {
                status: StatusCode::BAD_REQUEST,
                code: "UPLOAD_FAILED",
                message: "Upload could not be processed".into(),
            })
        }
        Ok(Ok(resp)) => {
            tracing::debug!(
                "CDN warmup OK for bot upload {key}: status={}",
                resp.status()
            );
            Ok(())
        }
        Ok(Err(e)) => {
            tracing::warn!("CDN warmup request failed for bot upload {key} (url={cdn_url}): {e}");
            Ok(())
        }
        Err(_) => {
            tracing::warn!("CDN warmup timed out for bot upload {key} (url={cdn_url})");
            Ok(())
        }
    }
}

async fn scan_upload(
    state: &AppState,
    data: &[u8],
    content_type: &str,
    sha256_hash: &str,
    uploader_id: i64,
    channel_id: i64,
    server_id: Option<i64>,
    filename: &str,
    upload_type: &'static str,
    file_id: i64,
    ext: &str,
    ip: &str,
) -> AppResult<&'static str> {
    // Security invariant: every upload path funnels scanner verdict handling
    // through here so flagged content gets the same evidence and denial path.
    if cdn::enabled() && upload_type != "attachment" {
        return Ok("cdn_pending");
    }

    if !content_scanner::should_scan(content_type) {
        return Ok("clean");
    }

    let metadata = ScanMetadata {
        uploader_id,
        channel_id,
        server_id,
        filename: filename.to_string(),
        content_type: content_type.to_string(),
        sha256_hash: sha256_hash.to_string(),
    };

    match state.content_scanner.scan(data, &metadata).await {
        ScanVerdict::Clean => Ok("clean"),
        ScanVerdict::Error(e) => {
            tracing::warn!(
                "Content scan error for {} {file_id} by {uploader_id}: {e}",
                upload_type
            );
            Ok("pending")
        }
        ScanVerdict::Flagged {
            match_type,
            confidence,
        } => {
            tracing::warn!(
                "FLAGGED {upload_type} {file_id} by {uploader_id}: match={match_type}, confidence={confidence}"
            );

            let evidence_key = format!("evidence/{uploader_id}/{file_id}.{ext}");
            let evidence_s3 = state.s3_evidence.as_ref().or(state.s3.as_ref());
            if let Some(s3) = evidence_s3 {
                if let Err(e) = s3
                    .put_object_private(&evidence_key, data.to_vec(), content_type)
                    .await
                {
                    tracing::error!("Failed to store evidence for {upload_type} {file_id}: {e}");
                }
            }

            // Look up uploader email via PG for audit metadata.
            let uploader_email: Option<String> =
                crate::services::pg::users::by_id(&state.pg, uploader_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|u| u.email);

            // Suspend the user + revoke every session.
            suspend_user_and_revoke_sessions(state, uploader_id).await;

            let audit_id = state.snowflake.next_id();
            audit::log_async(
                state.redis.clone(),
                audit::AuditEntry {
                    id: audit_id,
                    actor_id: 0,
                    action: audit::AuditAction::ContentFlagged,
                    target_type: upload_type,
                    target_id: file_id,
                    server_id: None,
                    metadata: Some(json!({
                        "scan_provider": state.content_scanner.provider_name(),
                        "match_type": match_type,
                        "confidence": confidence,
                        "uploader_id": uploader_id.to_string(),
                        "uploader_email": uploader_email.as_deref().unwrap_or("unknown"),
                        "uploader_ip": ip,
                        "channel_id": channel_id.to_string(),
                        "server_id": server_id.map(|s| s.to_string()),
                        "evidence_key": evidence_key,
                    })),
                    ip: None,
                },
                state.pg.clone(),
            );

            Err(AppError::WithCode {
                status: StatusCode::BAD_REQUEST,
                code: "UPLOAD_FAILED",
                message: "Upload could not be processed".into(),
            })
        }
    }
}

// ─── Helper: set avatar_url / banner_url via the typed UpdateUser patch ──

async fn scan_bot_upload(
    state: &AppState,
    data: &[u8],
    content_type: &str,
    sha256_hash: &str,
    bot: &BotIdentity,
    channel_id: i64,
    filename: &str,
    upload_type: &'static str,
    file_id: i64,
    ext: &str,
    ip: &str,
) -> AppResult<&'static str> {
    if cdn::enabled() {
        return Ok("cdn_pending");
    }

    if !content_scanner::should_scan(content_type) {
        return Ok("clean");
    }

    let metadata = ScanMetadata {
        uploader_id: bot.bot_id,
        channel_id,
        server_id: Some(bot.server_id),
        filename: filename.to_string(),
        content_type: content_type.to_string(),
        sha256_hash: sha256_hash.to_string(),
    };

    match state.content_scanner.scan(data, &metadata).await {
        ScanVerdict::Clean => Ok("clean"),
        ScanVerdict::Error(e) => {
            tracing::warn!(
                "Content scan error for bot {} {upload_type} {file_id}: {e}",
                bot.bot_id
            );
            Ok("pending")
        }
        ScanVerdict::Flagged {
            match_type,
            confidence,
        } => {
            tracing::warn!(
                "FLAGGED bot {upload_type} {file_id} by bot {}: match={match_type}, confidence={confidence}",
                bot.bot_id
            );

            let evidence_key = format!("evidence/bots/{}/{}.{}", bot.bot_id, file_id, ext);
            let evidence_s3 = state.s3_evidence.as_ref().or(state.s3.as_ref());
            if let Some(s3) = evidence_s3 {
                if let Err(e) = s3
                    .put_object_private(&evidence_key, data.to_vec(), content_type)
                    .await
                {
                    tracing::error!(
                        "Failed to store bot upload evidence for {upload_type} {file_id}: {e}"
                    );
                }
            }

            revoke_flagged_bot_token(state, bot).await;

            let audit_id = state.snowflake.next_id();
            audit::log_async(
                state.redis.clone(),
                audit::AuditEntry {
                    id: audit_id,
                    actor_id: 0,
                    action: audit::AuditAction::ContentFlagged,
                    target_type: upload_type,
                    target_id: file_id,
                    server_id: Some(bot.server_id),
                    metadata: Some(json!({
                        "scan_provider": state.content_scanner.provider_name(),
                        "match_type": match_type,
                        "confidence": confidence,
                        "bot_id": bot.bot_id.to_string(),
                        "bot_token_id": bot.token_id.to_string(),
                        "server_id": bot.server_id.to_string(),
                        "uploader_ip": ip,
                        "channel_id": channel_id.to_string(),
                        "evidence_key": evidence_key,
                    })),
                    ip: None,
                },
                state.pg.clone(),
            );

            Err(AppError::WithCode {
                status: StatusCode::BAD_REQUEST,
                code: "UPLOAD_FAILED",
                message: "Upload could not be processed".into(),
            })
        }
    }
}

async fn set_user_avatar(state: &AppState, user_id: i64, avatar_url: &str) -> AppResult<()> {
    crate::services::pg::users::update(
        &state.pg,
        user_id,
        crate::services::pg::users::UpdateUser {
            avatar_url: Some(avatar_url),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id, error = %e, "uploads: PG avatar_url write failed");
        AppError::Internal
    })
}

async fn set_user_banner(state: &AppState, user_id: i64, banner_url: &str) -> AppResult<()> {
    crate::services::pg::users::update(
        &state.pg,
        user_id,
        crate::services::pg::users::UpdateUser {
            banner_url: Some(banner_url),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id, error = %e, "uploads: PG banner_url write failed");
        AppError::Internal
    })
}

async fn set_user_member_list_banner(
    state: &AppState,
    user_id: i64,
    banner_url: &str,
) -> AppResult<()> {
    crate::services::pg::users::update(
        &state.pg,
        user_id,
        crate::services::pg::users::UpdateUser {
            member_list_banner_url: Some(banner_url),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id, error = %e, "uploads: PG member_list_banner_url write failed");
        AppError::Internal
    })
}

async fn set_server_icon(state: &AppState, server_id: i64, icon_url: &str) -> AppResult<()> {
    crate::services::pg::servers::update(
        &state.pg,
        server_id,
        crate::services::pg::servers::UpdateServer {
            icon_url: Some(icon_url),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(server_id, error = %e, "uploads: PG server icon_url write failed");
        AppError::Internal
    })
}

// ─── POST /api/users/me/avatar ──────────────────────────────────────

async fn load_bot_for_profile_write(
    state: &AppState,
    user_id: i64,
    server_id: i64,
    bot_id: i64,
) -> AppResult<crate::services::pg::bots::BotRow> {
    state
        .require_permission(user_id, server_id, bits::MANAGE_SERVER)
        .await?;

    let bot = crate::services::pg::bots::by_id(&state.pg, bot_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "uploads: PG bot read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("bot"))?;
    if bot.server_id != server_id {
        return Err(AppError::NotFound("bot"));
    }
    Ok(bot)
}

async fn set_bot_avatar(state: &AppState, bot_id: i64, avatar_url: &str) -> AppResult<()> {
    crate::services::pg::bots::update(
        &state.pg,
        bot_id,
        None,
        None,
        Some(avatar_url),
        None,
        None,
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!(bot_id, error = %e, "uploads: PG bot avatar_url write failed");
        AppError::Internal
    })
}

async fn set_bot_banner(state: &AppState, bot_id: i64, banner_url: &str) -> AppResult<()> {
    crate::services::pg::bots::update(
        &state.pg,
        bot_id,
        None,
        None,
        None,
        Some(banner_url),
        None,
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!(bot_id, error = %e, "uploads: PG bot banner_url write failed");
        AppError::Internal
    })
}

// POST /api/bot/uploads/images
pub async fn upload_bot_image(
    State(state): State<AppState>,
    optional_bot: OptionalBot,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    let OptionalBot(Some(bot)) = optional_bot else {
        return Err(AppError::TokenRequired);
    };
    tracing::info!("POST /api/bot/uploads/images bot_id={}", bot.bot_id);
    require_flag(&state, "image_uploads")?;
    let upload_limit = bot_image_upload_limit(&state.config.local_capabilities)?;
    rate_limit::enforce(
        &state,
        &rate_limit::UPLOAD_LIMIT,
        &format!("bot:{}", bot.bot_id),
    )
    .await?;

    if !has_scope(&bot.scopes, SCOPE_UPLOADS_WRITE) {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "BOT_SCOPE_MISSING",
            message: "Bot token is missing uploads:write".into(),
        });
    }

    let s3 = require_s3(&state)?;
    let field = multipart
        .next_field()
        .await
        .map_err(|_| AppError::Validation("Invalid multipart data".into()))?
        .ok_or_else(|| AppError::Validation("No file provided".into()))?;

    let filename = field.file_name().unwrap_or("image.png").to_string();
    let ext = extract_ext(&filename)
        .ok_or_else(|| AppError::Validation("File must have an extension".into()))?;

    if !ALLOWED_IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::Validation(
            "Allowed formats: png, jpg, jpeg, gif, webp".into(),
        ));
    }

    let too_large_message = upload_limit_message(upload_limit);
    let data = read_limited_field(field, upload_limit, &too_large_message).await?;

    if !validate_image_magic_bytes(&data, &ext) {
        return Err(AppError::Validation(
            "File content does not match extension".into(),
        ));
    }

    let data = image_sanitizer::strip_image_metadata(&data, &ext);
    let file_id = state.snowflake.next_id();
    let content_type = content_type_for_image_ext(&ext);
    let file_hash = sha256_hex(&data);
    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));

    scan_bot_upload(
        &state,
        &data,
        content_type,
        &file_hash,
        &bot,
        0,
        &filename,
        "bot_image",
        file_id,
        &ext,
        &client_ip,
    )
    .await?;

    let key = format!(
        "bot-uploads/{}/{}/{}.{}",
        bot.server_id, bot.bot_id, file_id, ext
    );
    let size = data.len() as i64;
    s3.put_object(&key, data, content_type).await.map_err(|e| {
        tracing::error!(
            key_class = storage_key_log_class(&key),
            error = %e,
            "S3 bot image upload failed"
        );
        AppError::WithCode {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "UPLOAD_FAILED",
            message: "Upload could not be processed".into(),
        }
    })?;

    cdn_warmup_bot(&state, &key, &bot, "bot_image", file_id).await?;

    let url = cdn::resolve(Some(&key)).unwrap_or_else(|| key.clone());
    tracing::info!(
        "Bot image uploaded id={} server={} bot={} size={}",
        file_id,
        bot.server_id,
        bot.bot_id,
        size
    );
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": file_id.to_string(),
            "url": url,
            "contentType": content_type,
            "size": size,
        })),
    )
        .into_response())
}

pub async fn upload_bot_avatar(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, bot_id_str)): Path<(String, String)>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    tracing::info!(
        "POST /api/servers/{}/bots/{}/avatar user_id={}",
        server_id_str,
        bot_id_str,
        user_id.0
    );
    require_flag(&state, "image_uploads")?;
    let entitlements = require_image_upload_entitlements(&state, user_id.0).await?;
    rate_limit::enforce(&state, &rate_limit::UPLOAD_LIMIT, &user_id.0.to_string()).await?;
    let server_id: i64 = server_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;
    let bot_id: i64 = bot_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;
    let bot = load_bot_for_profile_write(&state, user_id.0, server_id, bot_id).await?;
    let s3 = require_s3(&state)?;

    let field = multipart
        .next_field()
        .await
        .map_err(|_| AppError::Validation("Invalid multipart data".into()))?
        .ok_or_else(|| AppError::Validation("No file provided".into()))?;
    let filename = field.file_name().unwrap_or("avatar.png").to_string();
    let ext = extract_ext(&filename)
        .ok_or_else(|| AppError::Validation("File must have an extension".into()))?;
    if !ALLOWED_IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::Validation(
            "Allowed formats: png, jpg, jpeg, gif, webp".into(),
        ));
    }
    require_animated_avatar_entitlement(&entitlements, &ext)?;
    let data = read_limited_field(field, upload_limit(&entitlements), "File too large").await?;
    if !validate_image_magic_bytes(&data, &ext) {
        return Err(AppError::Validation(
            "File content does not match extension".into(),
        ));
    }

    let data = image_sanitizer::strip_image_metadata(&data, &ext);
    let content_type = content_type_for_image_ext(&ext);
    let file_hash = sha256_hex(&data);
    let file_id = state.snowflake.next_id();
    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));

    scan_upload(
        &state,
        &data,
        content_type,
        &file_hash,
        user_id.0,
        0,
        Some(server_id),
        &filename,
        "bot_avatar",
        file_id,
        &ext,
        &client_ip,
    )
    .await?;

    let old_key = existing_object_key(bot.avatar_url.as_deref());

    let key = format!("bot-avatars/{server_id}/{bot_id}/{file_id}.{ext}");
    s3.put_object(&key, data, content_type).await.map_err(|e| {
        tracing::error!(
            key_class = storage_key_log_class(&key),
            error = %e,
            "S3 bot avatar upload failed"
        );
        AppError::WithCode {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "UPLOAD_FAILED",
            message: "Upload could not be processed".into(),
        }
    })?;
    cdn_warmup(&state, &key, user_id.0, "bot_avatar", file_id).await?;
    set_bot_avatar(&state, bot_id, &key).await?;
    delete_replaced_object(s3, old_key, &key).await;

    let url = cdn::resolve(Some(&key)).unwrap_or_else(|| key.clone());
    Ok((StatusCode::OK, Json(json!({ "avatarUrl": url }))).into_response())
}

pub async fn delete_bot_avatar(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, bot_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/bots/{}/avatar user_id={}",
        server_id_str,
        bot_id_str,
        user_id.0
    );
    let server_id: i64 = server_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;
    let bot_id: i64 = bot_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;
    let bot = load_bot_for_profile_write(&state, user_id.0, server_id, bot_id).await?;
    let s3 = require_s3(&state)?;
    if let Some(url) = bot.avatar_url.as_deref() {
        if !url.is_empty() {
            if let Some(old_key) = extract_s3_key(url) {
                let _ = s3.delete_object(&old_key).await;
            }
        }
    }
    set_bot_avatar(&state, bot_id, "").await?;
    Ok(Json(json!({ "avatarUrl": serde_json::Value::Null })))
}

pub async fn upload_bot_banner(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, bot_id_str)): Path<(String, String)>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    tracing::info!(
        "POST /api/servers/{}/bots/{}/banner user_id={}",
        server_id_str,
        bot_id_str,
        user_id.0
    );
    require_flag(&state, "image_uploads")?;
    let entitlements = require_image_upload_entitlements(&state, user_id.0).await?;
    rate_limit::enforce(&state, &rate_limit::UPLOAD_LIMIT, &user_id.0.to_string()).await?;
    let server_id: i64 = server_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;
    let bot_id: i64 = bot_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;
    let bot = load_bot_for_profile_write(&state, user_id.0, server_id, bot_id).await?;
    let s3 = require_s3(&state)?;

    let field = multipart
        .next_field()
        .await
        .map_err(|_| AppError::Validation("Invalid multipart data".into()))?
        .ok_or_else(|| AppError::Validation("No file provided".into()))?;
    let filename = field.file_name().unwrap_or("banner.png").to_string();
    let ext = extract_ext(&filename)
        .ok_or_else(|| AppError::Validation("File must have an extension".into()))?;
    if !ALLOWED_IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::Validation(
            "Allowed formats: png, jpg, jpeg, gif, webp".into(),
        ));
    }
    require_animated_banner_entitlement(&entitlements, &ext)?;
    let data = read_limited_field(field, upload_limit(&entitlements), "File too large").await?;
    if !validate_image_magic_bytes(&data, &ext) {
        return Err(AppError::Validation(
            "File content does not match extension".into(),
        ));
    }

    let data = image_sanitizer::strip_image_metadata(&data, &ext);
    let content_type = content_type_for_image_ext(&ext);
    let file_hash = sha256_hex(&data);
    let file_id = state.snowflake.next_id();
    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));

    scan_upload(
        &state,
        &data,
        content_type,
        &file_hash,
        user_id.0,
        0,
        Some(server_id),
        &filename,
        "bot_banner",
        file_id,
        &ext,
        &client_ip,
    )
    .await?;

    let old_key = existing_object_key(bot.banner_url.as_deref());

    let key = format!("bot-banners/{server_id}/{bot_id}/{file_id}.{ext}");
    s3.put_object(&key, data, content_type).await.map_err(|e| {
        tracing::error!(
            key_class = storage_key_log_class(&key),
            error = %e,
            "S3 bot banner upload failed"
        );
        AppError::WithCode {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "UPLOAD_FAILED",
            message: "Upload could not be processed".into(),
        }
    })?;
    cdn_warmup(&state, &key, user_id.0, "bot_banner", file_id).await?;
    set_bot_banner(&state, bot_id, &key).await?;
    crate::services::pg::bots::update_banner_crop(&state.pg, bot_id, None)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "upload_bot_banner: PG banner crop clear failed");
            AppError::Internal
        })?;
    delete_replaced_object(s3, old_key, &key).await;

    let url = cdn::resolve(Some(&key)).unwrap_or_else(|| key.clone());
    Ok((
        StatusCode::OK,
        Json(json!({ "bannerUrl": url, "bannerCrop": serde_json::Value::Null })),
    )
        .into_response())
}

pub async fn delete_bot_banner(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, bot_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/bots/{}/banner user_id={}",
        server_id_str,
        bot_id_str,
        user_id.0
    );
    let server_id: i64 = server_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;
    let bot_id: i64 = bot_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;
    let bot = load_bot_for_profile_write(&state, user_id.0, server_id, bot_id).await?;
    let s3 = require_s3(&state)?;
    if let Some(url) = bot.banner_url.as_deref() {
        if !url.is_empty() {
            if let Some(old_key) = extract_s3_key(url) {
                let _ = s3.delete_object(&old_key).await;
            }
        }
    }
    set_bot_banner(&state, bot_id, "").await?;
    crate::services::pg::bots::update_banner_crop(&state.pg, bot_id, None)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "delete_bot_banner: PG banner crop clear failed");
            AppError::Internal
        })?;
    Ok(Json(
        json!({ "bannerUrl": serde_json::Value::Null, "bannerCrop": serde_json::Value::Null }),
    ))
}

pub async fn upload_avatar(
    State(state): State<AppState>,
    user_id: UserId,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    tracing::info!("POST /api/users/me/avatar user_id={}", user_id.0);
    require_flag(&state, "image_uploads")?;
    let entitlements = require_image_upload_entitlements(&state, user_id.0).await?;
    rate_limit::enforce(&state, &rate_limit::UPLOAD_LIMIT, &user_id.0.to_string()).await?;
    let s3 = require_s3(&state)?;

    let field = multipart
        .next_field()
        .await
        .map_err(|_| AppError::Validation("Invalid multipart data".into()))?
        .ok_or_else(|| AppError::Validation("No file provided".into()))?;

    let filename = field.file_name().unwrap_or("upload.png").to_string();
    let ext = extract_ext(&filename)
        .ok_or_else(|| AppError::Validation("File must have an extension".into()))?;

    if !ALLOWED_IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::Validation(
            "Allowed formats: png, jpg, jpeg, gif, webp".into(),
        ));
    }

    require_animated_avatar_entitlement(&entitlements, &ext)?;
    let data = read_limited_field(field, upload_limit(&entitlements), "File too large").await?;

    if !validate_image_magic_bytes(&data, &ext) {
        return Err(AppError::Validation(
            "File content does not match extension".into(),
        ));
    }

    let data = image_sanitizer::strip_image_metadata(&data, &ext);

    let content_type = content_type_for_image_ext(&ext);
    let file_hash = sha256_hex(&data);
    let file_id = state.snowflake.next_id();
    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));

    scan_upload(
        &state,
        &data,
        content_type,
        &file_hash,
        user_id.0,
        0,
        None,
        &filename,
        "avatar",
        file_id,
        &ext,
        &client_ip,
    )
    .await?;

    // Best-effort delete of the old S3 object — read existing url from PG.
    let old_key = match crate::services::pg::users::by_id(&state.pg, user_id.0).await {
        Ok(Some(existing)) => existing_object_key(existing.avatar_url.as_deref()),
        _ => None,
    };

    let key = format!("avatars/{}/{file_id}.{ext}", user_id.0);
    s3.put_object(&key, data, content_type).await.map_err(|e| {
        tracing::error!(
            key_class = storage_key_log_class(&key),
            error = %e,
            "S3 avatar upload failed"
        );
        AppError::WithCode {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "UPLOAD_FAILED",
            message: "Upload could not be processed".into(),
        }
    })?;

    cdn_warmup(&state, &key, user_id.0, "avatar", file_id).await?;

    set_user_avatar(&state, user_id.0, &key).await?;
    delete_replaced_object(s3, old_key, &key).await;

    let url = cdn::resolve(Some(&key)).unwrap_or_else(|| key.clone());
    tracing::info!("Avatar uploaded user_id={}", user_id.0);
    state.user_profiles.invalidate(user_id.0);

    broadcast_profile_update(&state, user_id.0, Some(&url), None, None).await;

    Ok((StatusCode::OK, Json(json!({ "avatarUrl": url }))).into_response())
}

// ─── DELETE /api/users/me/avatar ────────────────────────────────────

pub async fn delete_avatar(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<Value>> {
    tracing::info!("DELETE /api/users/me/avatar user_id={}", user_id.0);
    let s3 = require_s3(&state)?;

    let record = crate::services::pg::users::by_id(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "delete_avatar: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))?;

    if let Some(url) = record.avatar_url.as_deref() {
        if !url.is_empty() {
            if let Some(old_key) = extract_s3_key(url) {
                let _ = s3.delete_object(&old_key).await;
            }
        }
    }

    // Empty string is the legacy "unset" sentinel; reads map to None.
    set_user_avatar(&state, user_id.0, "").await?;

    tracing::info!("Avatar deleted user_id={}", user_id.0);
    state.user_profiles.invalidate(user_id.0);
    broadcast_profile_update(&state, user_id.0, Some(""), None, None).await;
    Ok(Json(json!({ "avatarUrl": serde_json::Value::Null })))
}

// ─── POST /api/users/me/banner ───────────────────────────────────────

pub async fn upload_banner(
    State(state): State<AppState>,
    user_id: UserId,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    tracing::info!("POST /api/users/me/banner user_id={}", user_id.0);
    require_flag(&state, "image_uploads")?;
    let entitlements = require_image_upload_entitlements(&state, user_id.0).await?;
    rate_limit::enforce(&state, &rate_limit::UPLOAD_LIMIT, &user_id.0.to_string()).await?;
    let s3 = require_s3(&state)?;

    let field = multipart
        .next_field()
        .await
        .map_err(|_| AppError::Validation("Invalid multipart data".into()))?
        .ok_or_else(|| AppError::Validation("No file provided".into()))?;

    let filename = field.file_name().unwrap_or("banner.png").to_string();
    let ext = extract_ext(&filename)
        .ok_or_else(|| AppError::Validation("File must have an extension".into()))?;

    if !ALLOWED_IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::Validation(
            "Allowed formats: png, jpg, jpeg, gif, webp".into(),
        ));
    }

    require_animated_banner_entitlement(&entitlements, &ext)?;
    let data = read_limited_field(field, upload_limit(&entitlements), "File too large").await?;

    if !validate_image_magic_bytes(&data, &ext) {
        return Err(AppError::Validation(
            "File content does not match extension".into(),
        ));
    }

    let data = image_sanitizer::strip_image_metadata(&data, &ext);

    let content_type = content_type_for_image_ext(&ext);
    let file_hash = sha256_hex(&data);
    let file_id = state.snowflake.next_id();
    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));

    scan_upload(
        &state,
        &data,
        content_type,
        &file_hash,
        user_id.0,
        0,
        None,
        &filename,
        "banner",
        file_id,
        &ext,
        &client_ip,
    )
    .await?;

    let record = crate::services::pg::users::by_id(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "upload_banner: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))?;
    let old_key = existing_object_key(record.banner_url.as_deref());

    let key = format!("banners/{}/{file_id}.{ext}", user_id.0);
    s3.put_object(&key, data, content_type).await.map_err(|e| {
        tracing::error!(
            key_class = storage_key_log_class(&key),
            error = %e,
            "S3 banner upload failed"
        );
        AppError::WithCode {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "UPLOAD_FAILED",
            message: "Upload could not be processed".into(),
        }
    })?;

    cdn_warmup(&state, &key, user_id.0, "banner", file_id).await?;

    set_user_banner(&state, user_id.0, &key).await?;
    crate::services::pg::users::update_banner_crop(&state.pg, user_id.0, None)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "upload_banner: PG banner crop clear failed");
            AppError::Internal
        })?;
    delete_replaced_object(s3, old_key, &key).await;

    let url = cdn::resolve(Some(&key)).unwrap_or_else(|| key.clone());
    tracing::info!("Banner uploaded user_id={}", user_id.0);
    state.user_profiles.invalidate(user_id.0);

    broadcast_profile_update(&state, user_id.0, None, Some(&url), Some(None)).await;

    Ok((
        StatusCode::OK,
        Json(json!({ "bannerUrl": url, "bannerCrop": serde_json::Value::Null })),
    )
        .into_response())
}

// ─── PATCH /api/users/me/banner/crop ────────────────────────────────

pub async fn update_my_banner_crop(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<BannerCropPatchRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!("PATCH /api/users/me/banner/crop user_id={}", user_id.0);
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;

    let crop = body.banner_crop.map(|crop| crop.validate()).transpose()?;
    crate::services::pg::users::update_banner_crop(&state.pg, user_id.0, crop)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "update_my_banner_crop: PG write failed");
            AppError::Internal
        })?;

    state.user_profiles.invalidate(user_id.0);

    let uid_str = user_id.0.to_string();
    let server_ids = crate::services::pg::servers::list_server_ids_for_user(&state.pg, user_id.0)
        .await
        .unwrap_or_default();
    let json_text = events::user_profile_update_json(
        &uid_str,
        None,
        None,
        None,
        None,
        None,
        Some(crop),
        None,
        None,
    );
    for sid in server_ids {
        let topic = topics::presence_topic(sid);
        topics::publish_json(&state, &topic, &json_text).await;
    }

    Ok(Json(json!({ "bannerCrop": banner_crop::to_json(crop) })))
}

// ─── DELETE /api/users/me/banner ────────────────────────────────────

pub async fn delete_banner(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<Value>> {
    tracing::info!("DELETE /api/users/me/banner user_id={}", user_id.0);
    let s3 = require_s3(&state)?;

    let record = crate::services::pg::users::by_id(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "delete_banner: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))?;

    if let Some(url) = record.banner_url.as_deref() {
        if !url.is_empty() {
            if let Some(old_key) = extract_s3_key(url) {
                let _ = s3.delete_object(&old_key).await;
            }
        }
    }

    set_user_banner(&state, user_id.0, "").await?;
    crate::services::pg::users::update_banner_crop(&state.pg, user_id.0, None)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "delete_banner: PG banner crop clear failed");
            AppError::Internal
        })?;

    tracing::info!("Banner deleted user_id={}", user_id.0);
    state.user_profiles.invalidate(user_id.0);
    broadcast_profile_update(&state, user_id.0, None, Some(""), Some(None)).await;
    Ok(Json(
        json!({ "bannerUrl": serde_json::Value::Null, "bannerCrop": serde_json::Value::Null }),
    ))
}

// ─── POST /api/servers/:serverId/icon ───────────────────────────────

// ─── POST /api/users/me/member-list-banner ───────────────────────────

pub async fn upload_member_list_banner(
    State(state): State<AppState>,
    user_id: UserId,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    tracing::info!(
        "POST /api/users/me/member-list-banner user_id={}",
        user_id.0
    );
    require_flag(&state, "image_uploads")?;
    let entitlements = require_image_upload_entitlements(&state, user_id.0).await?;
    require_member_list_banner_entitlement(&entitlements)?;
    rate_limit::enforce(&state, &rate_limit::UPLOAD_LIMIT, &user_id.0.to_string()).await?;
    let s3 = require_s3(&state)?;

    let field = multipart
        .next_field()
        .await
        .map_err(|_| AppError::Validation("Invalid multipart data".into()))?
        .ok_or_else(|| AppError::Validation("No file provided".into()))?;

    let filename = field
        .file_name()
        .unwrap_or("member-list-banner.png")
        .to_string();
    let ext = extract_ext(&filename)
        .ok_or_else(|| AppError::Validation("File must have an extension".into()))?;

    if !ALLOWED_IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::Validation(
            "Allowed formats: png, jpg, jpeg, gif, webp".into(),
        ));
    }

    require_animated_banner_entitlement(&entitlements, &ext)?;
    let data = read_limited_field(field, upload_limit(&entitlements), "File too large").await?;

    if !validate_image_magic_bytes(&data, &ext) {
        return Err(AppError::Validation(
            "File content does not match extension".into(),
        ));
    }

    let data = image_sanitizer::strip_image_metadata(&data, &ext);

    let content_type = content_type_for_image_ext(&ext);
    let file_hash = sha256_hex(&data);
    let file_id = state.snowflake.next_id();
    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));

    scan_upload(
        &state,
        &data,
        content_type,
        &file_hash,
        user_id.0,
        0,
        None,
        &filename,
        "member_list_banner",
        file_id,
        &ext,
        &client_ip,
    )
    .await?;

    let record = crate::services::pg::users::by_id(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "upload_member_list_banner: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))?;
    let old_key = existing_object_key(record.member_list_banner_url.as_deref());

    let key = format!("member-list-banners/{}/{file_id}.{ext}", user_id.0);
    s3.put_object(&key, data, content_type).await.map_err(|e| {
        tracing::error!(
            key_class = storage_key_log_class(&key),
            error = %e,
            "S3 member list banner upload failed"
        );
        AppError::WithCode {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "UPLOAD_FAILED",
            message: "Upload could not be processed".into(),
        }
    })?;

    cdn_warmup(&state, &key, user_id.0, "member_list_banner", file_id).await?;

    set_user_member_list_banner(&state, user_id.0, &key).await?;
    crate::services::pg::users::update_member_list_banner_crop(&state.pg, user_id.0, None)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "upload_member_list_banner: PG crop clear failed");
            AppError::Internal
        })?;
    delete_replaced_object(s3, old_key, &key).await;

    let url = cdn::resolve(Some(&key)).unwrap_or_else(|| key.clone());
    tracing::info!("Member list banner uploaded user_id={}", user_id.0);
    state.user_profiles.invalidate(user_id.0);
    broadcast_member_list_banner_update(&state, user_id.0, Some(&url), Some(None)).await;

    Ok((
        StatusCode::OK,
        Json(json!({
            "memberListBannerUrl": url,
            "memberListBannerCrop": serde_json::Value::Null,
        })),
    )
        .into_response())
}

// ─── PATCH /api/users/me/member-list-banner/crop ─────────────────────

pub async fn update_my_member_list_banner_crop(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<BannerCropPatchRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PATCH /api/users/me/member-list-banner/crop user_id={}",
        user_id.0
    );
    let entitlements =
        crate::services::entitlements::current_for_user(&state.pg, &state.config, user_id.0).await;
    require_member_list_banner_entitlement(&entitlements)?;
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;

    let crop = body.banner_crop.map(|crop| crop.validate()).transpose()?;
    crate::services::pg::users::update_member_list_banner_crop(&state.pg, user_id.0, crop)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "update_my_member_list_banner_crop: PG write failed");
            AppError::Internal
        })?;

    state.user_profiles.invalidate(user_id.0);
    broadcast_member_list_banner_update(&state, user_id.0, None, Some(crop)).await;

    Ok(Json(json!({
        "memberListBannerCrop": banner_crop::to_json(crop),
    })))
}

// ─── DELETE /api/users/me/member-list-banner ─────────────────────────

pub async fn delete_member_list_banner(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/users/me/member-list-banner user_id={}",
        user_id.0
    );
    let s3 = require_s3(&state)?;

    let record = crate::services::pg::users::by_id(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "delete_member_list_banner: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))?;

    if let Some(url) = record.member_list_banner_url.as_deref() {
        if !url.is_empty() {
            if let Some(old_key) = extract_s3_key(url) {
                let _ = s3.delete_object(&old_key).await;
            }
        }
    }

    set_user_member_list_banner(&state, user_id.0, "").await?;
    crate::services::pg::users::update_member_list_banner_crop(&state.pg, user_id.0, None)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "delete_member_list_banner: PG crop clear failed");
            AppError::Internal
        })?;

    tracing::info!("Member list banner deleted user_id={}", user_id.0);
    state.user_profiles.invalidate(user_id.0);
    broadcast_member_list_banner_update(&state, user_id.0, Some(""), Some(None)).await;
    Ok(Json(json!({
        "memberListBannerUrl": serde_json::Value::Null,
        "memberListBannerCrop": serde_json::Value::Null,
    })))
}

pub async fn upload_server_icon(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    tracing::info!(
        "POST /api/servers/{}/icon user_id={}",
        server_id_str,
        user_id.0
    );
    require_flag(&state, "image_uploads")?;
    let entitlements = require_image_upload_entitlements(&state, user_id.0).await?;
    rate_limit::enforce(&state, &rate_limit::UPLOAD_LIMIT, &user_id.0.to_string()).await?;
    let server_id: i64 = server_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let s3 = require_s3(&state)?;

    let field = multipart
        .next_field()
        .await
        .map_err(|_| AppError::Validation("Invalid multipart data".into()))?
        .ok_or_else(|| AppError::Validation("No file provided".into()))?;

    let filename = field.file_name().unwrap_or("icon.png").to_string();
    let ext = extract_ext(&filename)
        .ok_or_else(|| AppError::Validation("File must have an extension".into()))?;

    if !ALLOWED_IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::Validation(
            "Allowed formats: png, jpg, jpeg, gif, webp".into(),
        ));
    }

    let data = read_limited_field(field, upload_limit(&entitlements), "File too large").await?;

    if !validate_image_magic_bytes(&data, &ext) {
        return Err(AppError::Validation(
            "File content does not match extension".into(),
        ));
    }

    let data = image_sanitizer::strip_image_metadata(&data, &ext);

    let content_type = content_type_for_image_ext(&ext);
    let file_hash = sha256_hex(&data);
    let file_id = state.snowflake.next_id();
    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));

    scan_upload(
        &state,
        &data,
        content_type,
        &file_hash,
        user_id.0,
        0,
        Some(server_id),
        &filename,
        "icon",
        file_id,
        &ext,
        &client_ip,
    )
    .await?;

    let srv = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "upload_server_icon: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;

    let old_key = existing_object_key(srv.icon_url.as_deref());

    let key = format!("server-icons/{server_id}/{file_id}.{ext}");
    s3.put_object(&key, data, content_type).await.map_err(|e| {
        tracing::error!(
            key_class = storage_key_log_class(&key),
            error = %e,
            "S3 server icon upload failed"
        );
        AppError::WithCode {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "UPLOAD_FAILED",
            message: "Upload could not be processed".into(),
        }
    })?;

    cdn_warmup(&state, &key, user_id.0, "icon", file_id).await?;

    set_server_icon(&state, server_id, &key).await?;
    delete_replaced_object(s3, old_key, &key).await;

    tracing::info!("Server icon uploaded server={} by={}", server_id, user_id.0);
    let response_json = broadcast_server_update(&state, server_id).await?;

    Ok((StatusCode::OK, Json(response_json)).into_response())
}

// ─── DELETE /api/servers/:serverId/icon ──────────────────────────────

pub async fn delete_server_icon(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/icon user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id: i64 = server_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let s3 = require_s3(&state)?;

    let srv = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "delete_server_icon: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;

    if let Some(url) = srv.icon_url.as_deref() {
        if !url.is_empty() {
            if let Some(old_key) = extract_s3_key(url) {
                let _ = s3.delete_object(&old_key).await;
            }
        }
    }

    set_server_icon(&state, server_id, "").await?;

    tracing::info!("Server icon deleted server={} by={}", server_id, user_id.0);
    let response_json = broadcast_server_update(&state, server_id).await?;

    Ok(Json(response_json))
}

// ─── POST /api/servers/:serverId/banner ─────────────────────────────

pub async fn upload_server_banner(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    tracing::info!(
        "POST /api/servers/{}/banner user_id={}",
        server_id_str,
        user_id.0
    );
    require_flag(&state, "image_uploads")?;
    let entitlements = require_image_upload_entitlements(&state, user_id.0).await?;
    rate_limit::enforce(&state, &rate_limit::UPLOAD_LIMIT, &user_id.0.to_string()).await?;
    let server_id: i64 = server_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let s3 = require_s3(&state)?;

    let field = multipart
        .next_field()
        .await
        .map_err(|_| AppError::Validation("Invalid multipart data".into()))?
        .ok_or_else(|| AppError::Validation("No file provided".into()))?;

    let filename = field.file_name().unwrap_or("banner.png").to_string();
    let ext = extract_ext(&filename)
        .ok_or_else(|| AppError::Validation("File must have an extension".into()))?;

    if !ALLOWED_IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::Validation(
            "Allowed formats: png, jpg, jpeg, gif, webp".into(),
        ));
    }

    let data = read_limited_field(field, upload_limit(&entitlements), "File too large").await?;

    if !validate_image_magic_bytes(&data, &ext) {
        return Err(AppError::Validation(
            "File content does not match extension".into(),
        ));
    }

    let data = image_sanitizer::strip_image_metadata(&data, &ext);

    let content_type = content_type_for_image_ext(&ext);
    let file_hash = sha256_hex(&data);
    let file_id = state.snowflake.next_id();
    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));

    scan_upload(
        &state,
        &data,
        content_type,
        &file_hash,
        user_id.0,
        0,
        Some(server_id),
        &filename,
        "banner",
        file_id,
        &ext,
        &client_ip,
    )
    .await?;

    let srv = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "upload_server_banner: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;

    let old_key = existing_object_key(srv.banner_url.as_deref());

    let key = format!("server-banners/{server_id}/{file_id}.{ext}");
    s3.put_object(&key, data, content_type).await.map_err(|e| {
        tracing::error!(
            key_class = storage_key_log_class(&key),
            error = %e,
            "S3 server banner upload failed"
        );
        AppError::WithCode {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "UPLOAD_FAILED",
            message: "Upload could not be processed".into(),
        }
    })?;

    cdn_warmup(&state, &key, user_id.0, "banner", file_id).await?;

    // New artwork should start centered. Reusing the previous focal offset can
    // make a replacement appear cropped to the old banner's top or bottom.
    let new_offset = Some(50);
    crate::services::pg::servers::update(
        &state.pg,
        server_id,
        crate::services::pg::servers::UpdateServer {
            banner_url: Some(&key),
            banner_offset_y: new_offset,
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(server_id, error = %e, "upload_server_banner: PG write failed");
        AppError::Internal
    })?;
    crate::services::pg::servers::update_banner_crop(&state.pg, server_id, None)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "upload_server_banner: PG banner crop clear failed");
            AppError::Internal
        })?;
    delete_replaced_object(s3, old_key, &key).await;

    tracing::info!(
        "Server banner uploaded server={} by={}",
        server_id,
        user_id.0
    );
    let response_json = broadcast_server_update(&state, server_id).await?;

    Ok((StatusCode::OK, Json(response_json)).into_response())
}

// ─── DELETE /api/servers/:serverId/banner ───────────────────────────

pub async fn delete_server_banner(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/banner user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id: i64 = server_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let s3 = require_s3(&state)?;

    let srv = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "delete_server_banner: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;

    if let Some(url) = srv.banner_url.as_deref() {
        if !url.is_empty() {
            if let Some(old_key) = extract_s3_key(url) {
                let _ = s3.delete_object(&old_key).await;
            }
        }
    }

    crate::services::pg::servers::update(
        &state.pg,
        server_id,
        crate::services::pg::servers::UpdateServer {
            banner_url: Some(""),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(server_id, error = %e, "delete_server_banner: PG write failed");
        AppError::Internal
    })?;
    crate::services::pg::servers::update_banner_crop(&state.pg, server_id, None)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "delete_server_banner: PG banner crop clear failed");
            AppError::Internal
        })?;

    tracing::info!(
        "Server banner deleted server={} by={}",
        server_id,
        user_id.0
    );
    let response_json = broadcast_server_update(&state, server_id).await?;

    Ok(Json(response_json))
}

/// Convert animated GIF bytes to animated WebP via FFmpeg subprocess.
async fn convert_gif_to_webp(gif_data: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut command = tokio::process::Command::new("ffmpeg");
    command
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "gif",
            "-i",
            "pipe:0",
            "-c:v",
            "libwebp",
            "-lossless",
            "0",
            "-quality",
            "75",
            "-loop",
            "0",
            "-an",
            "-f",
            "webp",
            "pipe:1",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(|e| {
        tracing::error!("Failed to spawn FFmpeg: {e}");
        AppError::Internal
    })?;

    let mut stdin = child.stdin.take().expect("stdin piped");
    stdin
        .write_all(gif_data)
        .await
        .map_err(|_| AppError::Internal)?;
    drop(stdin);

    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .map_err(|_| {
            tracing::error!("FFmpeg conversion timed out");
            AppError::Internal
        })?
        .map_err(|e| {
            tracing::error!("FFmpeg conversion failed: {e}");
            AppError::Internal
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("FFmpeg exited with error: {stderr}");
        return Err(AppError::Internal);
    }

    let webp_data = output.stdout;

    if webp_data.len() < 12 || &webp_data[0..4] != b"RIFF" || &webp_data[8..12] != b"WEBP" {
        tracing::error!("FFmpeg output is not valid WebP");
        return Err(AppError::Internal);
    }

    if webp_data.len() > 512 * 1024 {
        tracing::error!("FFmpeg WebP output too large: {} bytes", webp_data.len());
        return Err(AppError::Internal);
    }

    Ok(webp_data)
}

// ─── POST /api/servers/:serverId/emojis (upload) ────────────────────

pub async fn upload_emoji(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    multipart: Multipart,
) -> AppResult<Response> {
    upload_custom_expression(
        state,
        user_id,
        server_id_str,
        headers,
        ConnectInfo(addr),
        multipart,
        CustomExpressionUploadKind::Emoji,
    )
    .await
}

pub async fn upload_sticker(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    multipart: Multipart,
) -> AppResult<Response> {
    upload_custom_expression(
        state,
        user_id,
        server_id_str,
        headers,
        ConnectInfo(addr),
        multipart,
        CustomExpressionUploadKind::Sticker,
    )
    .await
}

async fn upload_custom_expression(
    state: AppState,
    user_id: UserId,
    server_id_str: String,
    headers: HeaderMap,
    addr: ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
    kind: CustomExpressionUploadKind,
) -> AppResult<Response> {
    tracing::info!(
        "POST /api/servers/{}/{} (upload) user_id={}",
        server_id_str,
        kind.route_segment(),
        user_id.0
    );
    require_flag(&state, "custom_emoji")?;
    require_flag(&state, "image_uploads")?;
    let entitlements = require_image_upload_entitlements(&state, user_id.0).await?;
    let max_upload_size = kind.max_size().min(upload_limit(&entitlements));
    rate_limit::enforce(&state, &rate_limit::UPLOAD_LIMIT, &user_id.0.to_string()).await?;
    let server_id: i64 = server_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let at_limit = match kind {
        CustomExpressionUploadKind::Emoji => {
            crate::services::pg::emojis::is_at_server_limit(&state.pg, server_id).await
        }
        CustomExpressionUploadKind::Sticker => {
            crate::services::pg::stickers::is_at_server_limit(&state.pg, server_id).await
        }
    }
    .map_err(|e| {
        tracing::error!(
            server_id,
            kind = kind.label(),
            error = %e,
            "upload_custom_expression: PG quota preflight failed"
        );
        AppError::Internal
    })?;

    if at_limit {
        tracing::warn!(
            server_id,
            user_id = user_id.0,
            kind = kind.label(),
            max_items = kind.max_count(),
            "upload_custom_expression: server custom expression quota reached"
        );
        return Err(server_custom_expression_quota_error(kind));
    }

    let mut file_data: Option<(String, Vec<u8>)> = None;
    let mut expression_name: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::Validation("Invalid multipart data".into()))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "file" => {
                let fallback = format!("{}.png", kind.label());
                let filename = field.file_name().unwrap_or(&fallback).to_string();
                let data = read_limited_field(
                    field,
                    max_upload_size,
                    &format!(
                        "{} file too large (max {}KB)",
                        kind.title_label(),
                        max_upload_size / 1024
                    ),
                )
                .await?;
                file_data = Some((filename, data));
            }
            "name" => {
                let text = field
                    .text()
                    .await
                    .map_err(|_| AppError::Validation("Failed to read name".into()))?;
                expression_name = Some(text);
            }
            _ => {}
        }
    }

    let (filename, data) =
        file_data.ok_or_else(|| AppError::Validation("No file provided".into()))?;
    let name = expression_name
        .ok_or_else(|| AppError::Validation(format!("{} name is required", kind.title_label())))?;

    validate_custom_expression_name(kind, &name)?;

    let expression_id = state.snowflake.next_id();
    let media = prepare_custom_expression_media(&filename, data, kind).await?;
    let client_ip = extract_client_ip(&headers, &addr);

    scan_upload(
        &state,
        &media.data,
        media.content_type,
        &media.sha256_hex,
        user_id.0,
        0,
        Some(server_id),
        &filename,
        kind.label(),
        expression_id,
        &media.ext,
        &client_ip,
    )
    .await?;

    let (key, now_ms) = persist_custom_expression_media(
        &state,
        kind,
        server_id,
        expression_id,
        &name,
        user_id.0,
        media,
        CustomExpressionPersistSource {
            source_peer_id: None,
            source_origin: None,
            source_server_label: None,
            source_expression_name: None,
            imported_by: None,
            imported_at_ms: None,
        },
    )
    .await?;

    cdn_warmup(&state, &key, user_id.0, kind.label(), expression_id).await?;

    let url = cdn::resolve(Some(&key)).unwrap_or_else(|| key.clone());
    tracing::info!(
        "Custom expression uploaded kind={} id={} server={} by={}",
        kind.label(),
        expression_id,
        server_id,
        user_id.0
    );

    if matches!(kind, CustomExpressionUploadKind::Emoji) {
        broadcast_emoji_version_update(&state, server_id).await;
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": expression_id.to_string(),
            "serverId": server_id_str,
            "name": name,
            "url": url,
            "createdBy": user_id.0.to_string(),
            "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
                .map(|t| t.to_rfc3339())
                .unwrap_or_default(),
        })),
    )
        .into_response())
}

pub async fn import_custom_expression(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<ImportCustomExpressionRequest>,
) -> AppResult<Response> {
    tracing::info!(
        "POST /api/servers/{}/custom-expressions/import user_id={}",
        server_id_str,
        user_id.0
    );
    require_flag(&state, "custom_emoji")?;
    require_flag(&state, "image_uploads")?;
    let entitlements = require_image_upload_entitlements(&state, user_id.0).await?;
    rate_limit::enforce(&state, &rate_limit::UPLOAD_LIMIT, &user_id.0.to_string()).await?;
    let server_id: i64 = server_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;
    let kind = CustomExpressionUploadKind::from_wire(&body.kind)
        .ok_or_else(|| AppError::Validation("Invalid custom expression kind".into()))?;
    validate_custom_expression_name(kind, &body.name)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let at_limit = match kind {
        CustomExpressionUploadKind::Emoji => {
            crate::services::pg::emojis::is_at_server_limit(&state.pg, server_id).await
        }
        CustomExpressionUploadKind::Sticker => {
            crate::services::pg::stickers::is_at_server_limit(&state.pg, server_id).await
        }
    }
    .map_err(|error| {
        tracing::error!(
            server_id,
            kind = kind.label(),
            error = %error,
            "custom expression import quota preflight failed"
        );
        AppError::Internal
    })?;
    if at_limit {
        return Err(server_custom_expression_quota_error(kind));
    }

    let source_peer_id = body.source_peer_id.trim();
    if source_peer_id.is_empty() || source_peer_id.len() > 253 {
        return Err(AppError::Validation("Invalid source peer".into()));
    }
    let peer_api_origin =
        trusted_custom_expression_import_origin(&state, server_id, source_peer_id).await?;
    let import_url =
        validate_custom_expression_import_url(&body.source_media_url, &peer_api_origin)
            .map_err(AppError::Validation)?;
    ensure_import_url_resolves_public(&import_url).await?;

    let max_upload_size = kind.max_size().min(upload_limit(&entitlements));
    let (filename, data) =
        fetch_custom_expression_import_media(import_url, max_upload_size).await?;
    let media = prepare_custom_expression_media(&filename, data, kind).await?;
    if let Some(expected_hash) = body.source_sha256_hex.as_deref() {
        let expected_hash = expected_hash.trim().to_ascii_lowercase();
        if !valid_sha256_hex(&expected_hash) || expected_hash != media.sha256_hex {
            return Err(AppError::Validation(
                "Source media hash does not match fetched media".into(),
            ));
        }
    }

    let expression_id = state.snowflake.next_id();
    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));
    scan_upload(
        &state,
        &media.data,
        media.content_type,
        &media.sha256_hex,
        user_id.0,
        0,
        Some(server_id),
        &filename,
        kind.label(),
        expression_id,
        &media.ext,
        &client_ip,
    )
    .await?;

    let source_server_label = bounded_optional(body.source_server_label.as_deref(), 120);
    let source_expression_name = bounded_optional(body.source_expression_name.as_deref(), 32);
    let imported_at_ms = chrono::Utc::now().timestamp_millis();
    let (key, now_ms) = persist_custom_expression_media(
        &state,
        kind,
        server_id,
        expression_id,
        &body.name,
        user_id.0,
        media,
        CustomExpressionPersistSource {
            source_peer_id: Some(source_peer_id),
            source_origin: Some(&peer_api_origin),
            source_server_label: source_server_label.as_deref(),
            source_expression_name: source_expression_name.as_deref(),
            imported_by: Some(user_id.0),
            imported_at_ms: Some(imported_at_ms),
        },
    )
    .await?;

    cdn_warmup(&state, &key, user_id.0, kind.label(), expression_id).await?;
    if matches!(kind, CustomExpressionUploadKind::Emoji) {
        broadcast_emoji_version_update(&state, server_id).await;
    }

    let url = cdn::resolve(Some(&key)).unwrap_or_else(|| key.clone());
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": expression_id.to_string(),
            "serverId": server_id_str,
            "kind": kind.label(),
            "name": body.name,
            "url": url,
            "createdBy": user_id.0.to_string(),
            "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
                .map(|t| t.to_rfc3339())
                .unwrap_or_default(),
            "source": {
                "peerId": source_peer_id,
                "origin": peer_api_origin,
                "serverLabel": source_server_label,
                "expressionName": source_expression_name,
                "importedBy": user_id.0.to_string(),
                "importedAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(imported_at_ms)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default(),
            }
        })),
    )
        .into_response())
}

pub async fn get_federation_custom_expression_media(
    State(state): State<AppState>,
    Path((kind_str, expression_id_str)): Path<(String, String)>,
) -> AppResult<Response> {
    let kind = CustomExpressionUploadKind::from_wire(&kind_str)
        .ok_or_else(|| AppError::Validation("Invalid custom expression kind".into()))?;
    let expression_id = crate::handlers::parse_id(&expression_id_str)?;
    let url = match kind {
        CustomExpressionUploadKind::Emoji => {
            let row = crate::services::pg::emojis::by_id(&state.pg, expression_id)
                .await
                .map_err(|error| {
                    tracing::error!(expression_id, error = %error, "federation emoji media read failed");
                    AppError::Internal
                })?
                .ok_or(AppError::NotFound("emoji"))?;
            row.url
        }
        CustomExpressionUploadKind::Sticker => {
            let row = crate::services::pg::stickers::by_id(&state.pg, expression_id)
                .await
                .map_err(|error| {
                    tracing::error!(expression_id, error = %error, "federation sticker media read failed");
                    AppError::Internal
                })?
                .ok_or(AppError::NotFound("sticker"))?;
            row.url
        }
    };
    let key = custom_expression_public_storage_key(kind, &url).ok_or_else(|| {
        tracing::warn!(
            expression_id,
            kind = kind.label(),
            "federation custom expression media rejected unsafe storage key"
        );
        AppError::NotFound("custom expression media")
    })?;
    let ext = extract_ext(&key).unwrap_or_else(|| "png".to_string());
    let content_type = content_type_for_image_ext(&ext);
    let s3 = require_s3(&state)?;
    let data = s3.get_object_bytes(&key).await.map_err(|error| {
        tracing::warn!(
            expression_id,
            kind = kind.label(),
            key_class = storage_key_log_class(&key),
            error = %error,
            "federation custom expression media object read failed"
        );
        AppError::NotFound("custom expression media")
    })?;

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=300"),
            ),
        ],
        Body::from(data),
    )
        .into_response())
}

pub async fn upload_attachment(
    State(state): State<AppState>,
    user_id: UserId,
    Path(channel_id_str): Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    tracing::info!(
        "POST /api/channels/{}/attachments user_id={}",
        channel_id_str,
        user_id.0
    );
    require_flag(&state, "file_sharing")?;
    let entitlements = require_file_sharing_entitlements(&state, user_id.0).await?;
    rate_limit::enforce(&state, &rate_limit::UPLOAD_LIMIT, &user_id.0.to_string()).await?;
    let channel_id: i64 = channel_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid ID".into()))?;

    // Security invariant: server attachments require membership, visibility,
    // and ATTACH_FILES; DM attachments require current DM membership.
    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "upload_attachment: PG channel read failed");
            AppError::Internal
        })?;

    let server_id: Option<i64> = match channel.as_ref().and_then(|c| c.server_id) {
        Some(sid) => {
            state
                .require_membership(user_id.0, sid)
                .await
                .map_err(|_| AppError::NotFound("channel"))?;
            state
                .permissions
                .check_channel_permission(user_id.0, channel_id, sid, bits::VIEW_CHANNEL)
                .await
                .map_err(|_| AppError::NotFound("channel"))?;
            state
                .permissions
                .check_channel_permission(user_id.0, channel_id, sid, bits::ATTACH_FILES)
                .await?;
            Some(sid)
        }
        None => {
            // No row in `channels` ⇒ maybe a DM channel (lives in dm_channels).
            // Reuse the send predicate so blocked or no-longer-eligible DMs do
            // not allow pending attachment writes.
            crate::services::channel_access::ensure_dm_channel_send_allowed(
                &state, user_id.0, channel_id,
            )
            .await?;
            None
        }
    };

    let s3 = require_s3(&state)?;

    let field = multipart
        .next_field()
        .await
        .map_err(|_| AppError::Validation("Invalid multipart data".into()))?
        .ok_or_else(|| AppError::Validation("No file provided".into()))?;

    let original_filename = field.file_name().unwrap_or("file").to_string();
    let ext = extract_ext(&original_filename).unwrap_or_else(|| "bin".to_string());

    if !ALLOWED_IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::Validation(
            "Only image files are allowed (png, jpg, jpeg, gif, webp)".into(),
        ));
    }

    let data = read_limited_field(field, upload_limit(&entitlements), "File too large").await?;

    if !validate_image_magic_bytes(&data, &ext) {
        return Err(AppError::Validation(
            "File content does not match extension".into(),
        ));
    }

    let data = image_sanitizer::strip_image_metadata(&data, &ext);

    let attachment_id = state.snowflake.next_id();
    let content_type = content_type_for_image_ext(&ext);
    let file_hash = sha256_hex(&data);
    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));

    let scan_status = scan_upload(
        &state,
        &data,
        content_type,
        &file_hash,
        user_id.0,
        channel_id,
        server_id,
        &original_filename,
        "attachment",
        attachment_id,
        &ext,
        &client_ip,
    )
    .await?;

    let size = data.len() as i64;
    let key = format!("attachments/{channel_id}/{attachment_id}.{ext}");

    s3.put_object(&key, data, content_type).await.map_err(|e| {
        tracing::error!(
            attachment_id,
            channel_id,
            key_class = attachment_storage_key_log_class(&key),
            error = %e,
            "S3 attachment upload failed"
        );
        AppError::WithCode {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "UPLOAD_FAILED",
            message: "Upload could not be processed".into(),
        }
    })?;

    let safe_filename = original_filename
        .replace(['/', '\\', '\0'], "_")
        .chars()
        .take(255)
        .collect::<String>();

    // PG is the authoritative attachment store. message_id stays NULL
    // until the message is sent — `pg::attachments::attach_to_message`
    // links them when the MESSAGE_CREATE write lands.
    let now_ms = chrono::Utc::now().timestamp_millis();
    crate::services::pg::attachments::insert(
        &state.pg,
        crate::services::pg::attachments::InsertAttachment {
            id: attachment_id,
            channel_id,
            uploader_id: user_id.0,
            filename: &safe_filename,
            url: &key,
            content_type,
            size_bytes: size,
            hash: &file_hash,
            scan_status,
            now_ms,
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(attachment_id, channel_id, error = %e, "upload_attachment: PG write failed");
        AppError::Internal
    })?;

    let url = attachment_media_url(&state.config.instance_api_url, attachment_id);
    tracing::info!(
        "Attachment uploaded id={} channel={} size={} by={}",
        attachment_id,
        channel_id,
        size,
        user_id.0
    );
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": attachment_id.to_string(),
            "filename": safe_filename,
            "url": url,
            "contentType": content_type,
            "size": size,
        })),
    )
        .into_response())
}

// ─── GET /api/media/attachments/:attachmentId ────────────────────────

pub async fn get_attachment_media(
    State(state): State<AppState>,
    user_id: UserId,
    Path(attachment_id_str): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> AppResult<Response> {
    let attachment_id = crate::handlers::parse_id(&attachment_id_str)?;
    rate_limit::enforce(
        &state,
        &rate_limit::ATTACHMENT_MEDIA_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let attachment = crate::services::pg::attachments::by_id(&state.pg, attachment_id)
        .await
        .map_err(|e| {
            tracing::error!(attachment_id, error = %e, "get_attachment_media: PG attachment read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("attachment"))?;

    if !is_attachment_storage_key(&attachment.url) {
        tracing::warn!(
            attachment_id,
            key_class = attachment_storage_key_log_class(&attachment.url),
            "get_attachment_media: refused non-attachment storage key"
        );
        return Err(AppError::NotFound("attachment"));
    }

    if let Some(message_id) = attachment.message_id {
        let message_visibility = sqlx::query_as::<_, (i64, i32)>(
            "SELECT channel_id, flags FROM messages WHERE id = $1 AND channel_id = $2 LIMIT 1",
        )
        .bind(message_id)
        .bind(attachment.channel_id)
        .fetch_optional(&state.pg)
        .await
        .map_err(|e| {
            tracing::error!(
                attachment_id,
                message_id,
                error = %e,
                "get_attachment_media: PG message visibility read failed"
            );
            AppError::Internal
        })?;

        let Some((_channel_id, flags)) = message_visibility else {
            return Err(AppError::NotFound("attachment"));
        };
        if (flags & crate::services::pg::messages::FLAG_DELETED) != 0 {
            return Err(AppError::NotFound("attachment"));
        }
    } else if attachment.uploader_id != user_id.0 {
        return Err(AppError::NotFound("attachment"));
    }

    let server_id = crate::services::channel_access::verify_channel_access(
        &state,
        user_id.0,
        attachment.channel_id,
    )
    .await
    .map_err(|err| match err {
        AppError::Internal => AppError::Internal,
        _ => AppError::NotFound("attachment"),
    })?;
    if let Some(sid) = server_id {
        state
            .permissions
            .check_channel_permission(user_id.0, attachment.channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .map_err(|_| AppError::NotFound("attachment"))?;
    }

    let s3 = require_s3(&state)?;
    let bytes = s3.get_object_bytes(&attachment.url).await.map_err(|e| {
        tracing::error!(
            attachment_id,
            key_class = attachment_storage_key_log_class(&attachment.url),
            error = %e,
            "get_attachment_media: storage read failed"
        );
        AppError::NotFound("attachment")
    })?;

    let content_len = bytes.len();
    let mut response = Response::new(Body::from(bytes));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&attachment.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        attachment_disposition(&attachment.filename, wants_attachment_download(&query)),
    );
    if let Ok(value) = HeaderValue::from_str(&content_len.to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::VARY, HeaderValue::from_static("authorization"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );

    Ok(response)
}

// ─── Broadcast user profile changes to all shared servers ────────────

async fn broadcast_profile_update(
    state: &AppState,
    user_id: i64,
    avatar_url: Option<&str>,
    banner_url: Option<&str>,
    banner_crop: Option<Option<BannerCrop>>,
) {
    let uid_str = user_id.to_string();
    let server_ids = crate::services::pg::servers::list_server_ids_for_user(&state.pg, user_id)
        .await
        .unwrap_or_default();

    let json_text = events::user_profile_update_json(
        &uid_str,
        avatar_url,
        banner_url,
        None,
        None,
        None,
        banner_crop,
        None,
        None,
    );
    let proto_msg = events::user_profile_update_proto(
        uid_str,
        avatar_url.map(String::from),
        banner_url.map(String::from),
        None,
        None,
        None,
    );

    for sid in server_ids {
        let topic = topics::presence_topic(sid);
        topics::publish(state, &topic, &json_text, &proto_msg).await;
    }
}

async fn broadcast_member_list_banner_update(
    state: &AppState,
    user_id: i64,
    member_list_banner_url: Option<&str>,
    member_list_banner_crop: Option<Option<BannerCrop>>,
) {
    let uid_str = user_id.to_string();
    let server_ids = crate::services::pg::servers::list_server_ids_for_user(&state.pg, user_id)
        .await
        .unwrap_or_default();

    let json_text = events::user_profile_update_json(
        &uid_str,
        None,
        None,
        None,
        None,
        None,
        None,
        member_list_banner_url,
        member_list_banner_crop,
    );
    for sid in server_ids {
        let topic = topics::presence_topic(sid);
        topics::publish_json(state, &topic, &json_text).await;
    }
}

async fn broadcast_server_update(state: &AppState, server_id: i64) -> AppResult<Value> {
    let record = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "uploads: PG server reload failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;
    let member_count = crate::services::pg::servers::member_count(&state.pg, server_id)
        .await
        .unwrap_or(0);
    let response_json = crate::handlers::servers::server_row_to_json(&record, member_count);
    let topic = topics::presence_topic(server_id);
    let json_text = events::server_update_json(&response_json);
    topics::publish_json(state, &topic, &json_text).await;
    Ok(response_json)
}
