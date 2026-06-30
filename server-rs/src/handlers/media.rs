use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Instant;
use tokio::sync::RwLock;

use crate::error::{AppError, AppResult};
use crate::middleware::{auth::UserId, rate_limit};
use crate::state::AppState;

/// Shared reqwest client for connection pooling across all Klipy requests.
static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client")
});

/// Server-side cache for enriched categories (with content-type-specific previews).
/// Key: content type path ("gifs", "stickers", etc.), Value: (response JSON, timestamp).
static CATEGORIES_CACHE: LazyLock<RwLock<HashMap<&'static str, (Value, Instant)>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// How long enriched categories stay cached (30 minutes).
const CATEGORIES_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Max categories to enrich with content-type-specific previews.
const MAX_ENRICHED_CATEGORIES: usize = 12;
const KLIPY_MEDIA_HOSTS: &[&str] = &["media.klipy.com", "static.klipy.com"];

/// Klipy content types — each maps to a URL path segment.
#[derive(Debug, Clone, Copy)]
enum ContentType {
    Gifs,
    Stickers,
    Clips,
    StaticMemes,
}

impl ContentType {
    /// URL path segment for the Klipy API.
    fn path(self) -> &'static str {
        match self {
            ContentType::Gifs => "gifs",
            ContentType::Stickers => "stickers",
            ContentType::Clips => "clips",
            ContentType::StaticMemes => "static-memes",
        }
    }

    /// Type tag for the normalized response.
    fn type_tag(self) -> &'static str {
        match self {
            ContentType::Gifs => "gif",
            ContentType::Stickers => "sticker",
            ContentType::Clips => "clip",
            ContentType::StaticMemes => "meme",
        }
    }
}

#[derive(Deserialize)]
pub struct MediaQuery {
    pub q: Option<String>,
    pub limit: Option<u32>,
    pub page: Option<u32>,
    pub content_filter: Option<String>,
}

/// Call Klipy API and return the raw JSON.
/// NOTE: Klipy's API embeds the key in the URL path (`api/v1/{app_key}/...`).
/// We avoid logging the full URL to prevent key leakage in logs.
async fn klipy_request(
    api_key: &str,
    content_type: ContentType,
    endpoint: &str,
    query_string: &str,
) -> Result<Value, AppError> {
    let url = format!(
        "https://api.klipy.com/api/v1/{}/{}/{}?{}",
        api_key,
        content_type.path(),
        endpoint,
        query_string
    );

    tracing::debug!("Klipy request: {}/{}", content_type.path(), endpoint,);

    let resp = HTTP_CLIENT.get(&url).send().await.map_err(|e| {
        // Sanitize: reqwest errors include the full URL which contains the API key
        tracing::error!(
            "Klipy API network error for {}/{}: {}",
            content_type.path(),
            endpoint,
            e.without_url()
        );
        AppError::Internal
    })?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        tracing::error!(
            "Klipy API {}/{} returned {status}: {body}",
            content_type.path(),
            endpoint
        );
        return Err(AppError::Internal);
    }

    let json: Value = resp.json().await.map_err(|e| {
        tracing::error!("Klipy response parse error: {e}");
        AppError::Internal
    })?;

    Ok(json)
}

/// Normalize Klipy response into `{ results: [...] }` for the client.
///
/// Klipy returns: `{ result: bool, data: { data: [...], current_page, per_page, has_next } }`
/// Each item is normalized with a `type` field for the client to distinguish content types.
fn normalize_response(klipy_json: &Value, content_type: ContentType) -> Value {
    let empty = vec![];
    let items = klipy_json
        .get("data")
        .and_then(|d| d.get("data"))
        .and_then(|d| d.as_array())
        .unwrap_or(&empty);

    // Extract pagination metadata from Klipy's data envelope
    let data_obj = klipy_json.get("data");
    let has_next = data_obj
        .and_then(|d| d.get("has_next"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let current_page = data_obj
        .and_then(|d| d.get("current_page"))
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    let type_tag = content_type.type_tag();

    let results: Vec<Value> = items
        .iter()
        .filter_map(|item| {
            // Clips use "slug" as identifier; other types use "id"
            let id = item.get("id").or_else(|| item.get("slug")).map(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| v.to_string())
            })?;
            let title = item.get("title").and_then(|t| t.as_str()).unwrap_or("");

            let file = item.get("file")?;

            // Clips have a flat file structure: { mp4: "url", gif: "url", webp: "url" }
            // with dimensions in a separate file_meta object.
            // All other types use nested size variants: { hd: { gif: { url, width, height } } }
            let (orig_url, orig_w, orig_h, tiny_url, tiny_w, tiny_h) =
                if matches!(content_type, ContentType::Clips) {
                    let file_meta = item.get("file_meta");

                    // Original: prefer mp4 for video playback
                    let (orig_url, orig_w, orig_h) =
                        extract_clip_media_url(file, file_meta, &["mp4", "gif"])?;

                    // Preview: prefer gif/webp thumbnail
                    let (tiny_url, tiny_w, tiny_h) =
                        extract_clip_media_url(file, file_meta, &["gif", "webp"])
                            .unwrap_or_else(|| (orig_url.clone(), orig_w, orig_h));

                    (orig_url, orig_w, orig_h, tiny_url, tiny_w, tiny_h)
                } else {
                    let original = pick_variant(file, &["hd", "md", "sm"]);
                    let tiny = pick_variant(file, &["xs", "sm", "md"]);
                    let (ou, ow, oh) = extract_media_url(&original, content_type, false)?;
                    let (tu, tw, th) = extract_media_url(&tiny, content_type, true)?;
                    (ou, ow, oh, tu, tw, th)
                };

            Some(json!({
                "id": id,
                "title": title,
                "type": type_tag,
                "images": {
                    "original": { "url": orig_url, "width": orig_w, "height": orig_h },
                    "tinygif": { "url": tiny_url, "width": tiny_w, "height": tiny_h }
                }
            }))
        })
        .collect();

    json!({ "results": results, "hasNext": has_next, "page": current_page })
}

/// Pick the first available size variant from a file object.
fn pick_variant<'a>(file: &'a Value, sizes: &[&str]) -> Option<&'a Value> {
    for size in sizes {
        if let Some(v) = file.get(*size) {
            if !v.is_null() {
                return Some(v);
            }
        }
    }
    None
}

fn is_allowed_klipy_media_url(raw: &str) -> bool {
    if raw.is_empty()
        || raw.len() > 4096
        || raw
            .chars()
            .any(|c| matches!(c, '\r' | '\n' | '\t' | '\0' | '\\'))
    {
        return false;
    }

    let Ok(parsed) = url::Url::parse(raw) else {
        return false;
    };
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return false;
    }

    parsed
        .host_str()
        .map(|host| {
            let host = host.to_ascii_lowercase();
            KLIPY_MEDIA_HOSTS.contains(&host.as_str())
        })
        .unwrap_or(false)
}

fn extract_clip_media_url(
    file: &Value,
    file_meta: Option<&Value>,
    formats: &[&str],
) -> Option<(String, u64, u64)> {
    for fmt in formats {
        let Some(url) = file.get(*fmt).and_then(|v| v.as_str()) else {
            continue;
        };
        if !is_allowed_klipy_media_url(url) {
            continue;
        }
        let meta = file_meta.and_then(|m| m.get(*fmt));
        let width = meta
            .and_then(|m| m.get("width"))
            .and_then(|n| n.as_u64())
            .unwrap_or(320);
        let height = meta
            .and_then(|m| m.get("height"))
            .and_then(|n| n.as_u64())
            .unwrap_or(180);
        return Some((url.to_string(), width, height));
    }
    None
}

/// Extract a media URL from a Klipy file variant.
/// When `for_preview` is true, prefer smaller WebP format for bandwidth savings.
/// When false (original/full quality), prefer GIF for animation fidelity.
fn extract_media_url(
    variant: &Option<&Value>,
    content_type: ContentType,
    for_preview: bool,
) -> Option<(String, u64, u64)> {
    let v = (*variant)?;

    let formats: &[&str] = match (content_type, for_preview) {
        (ContentType::Clips, _) => &["mp4", "gif", "webp"],
        (ContentType::StaticMemes, true) => &["webp", "png", "gif"],
        (ContentType::StaticMemes, false) => &["png", "webp", "gif"],
        (_, true) => &["webp", "gif"],  // preview: webp first
        (_, false) => &["webp", "gif"], // original: webp first (smaller, faster decode)
    };

    for fmt in formats {
        if let Some(f) = v.get(*fmt) {
            if let (Some(url), Some(w), Some(h)) = (
                f.get("url").and_then(|u| u.as_str()),
                f.get("width").and_then(|n| n.as_u64()),
                f.get("height").and_then(|n| n.as_u64()),
            ) {
                if is_allowed_klipy_media_url(url) {
                    return Some((url.to_string(), w, h));
                }
            }
        }
    }
    None
}

// ─── Helper: get API key or return 503 ─────────────────────────────────────

fn get_api_key(state: &AppState) -> Result<&str, AppError> {
    state
        .config
        .klipy_api_key
        .as_deref()
        .ok_or_else(|| AppError::WithCode {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "MEDIA_NOT_CONFIGURED",
            message: "Media service is not configured".into(),
        })
}

/// Build the query string for a trending request.
fn trending_qs(params: &MediaQuery) -> String {
    let per_page = params.limit.unwrap_or(20).min(50);
    let page = params.page.unwrap_or(1).clamp(1, 5);
    let mut qs = format!("per_page={}&page={}&customer_id=app", per_page, page);
    if let Some(ref filter) = params.content_filter {
        qs.push_str(&format!("&content_filter={}", urlencoding::encode(filter)));
    }
    qs
}

/// Build the query string for a search request.
fn search_qs(params: &MediaQuery) -> Result<String, AppError> {
    let query = params.q.as_deref().unwrap_or("");
    if query.is_empty() {
        return Err(AppError::Validation("Search query is required".into()));
    }
    let per_page = params.limit.unwrap_or(20).min(50);
    let page = params.page.unwrap_or(1).clamp(1, 5);
    let mut qs = format!(
        "q={}&per_page={}&page={}&customer_id=app",
        urlencoding::encode(query),
        per_page,
        page
    );
    if let Some(ref filter) = params.content_filter {
        qs.push_str(&format!("&content_filter={}", urlencoding::encode(filter)));
    }
    Ok(qs)
}

// ─── GIFs ──────────────────────────────────────────────────────────────────

/// GET /api/gifs/trending
pub async fn gifs_trending(
    State(state): State<AppState>,
    user_id: UserId,
    Query(params): Query<MediaQuery>,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(&state, &rate_limit::MEDIA_LIMIT, &user_id.0.to_string()).await?;
    let api_key = get_api_key(&state)?;
    let qs = trending_qs(&params);
    let json = klipy_request(api_key, ContentType::Gifs, "trending", &qs).await?;
    Ok(Json(normalize_response(&json, ContentType::Gifs)))
}

/// GET /api/gifs/search
pub async fn gifs_search(
    State(state): State<AppState>,
    user_id: UserId,
    Query(params): Query<MediaQuery>,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(&state, &rate_limit::MEDIA_LIMIT, &user_id.0.to_string()).await?;
    let api_key = get_api_key(&state)?;
    let qs = search_qs(&params)?;
    let json = klipy_request(api_key, ContentType::Gifs, "search", &qs).await?;
    Ok(Json(normalize_response(&json, ContentType::Gifs)))
}

// ─── Stickers ──────────────────────────────────────────────────────────────

/// GET /api/stickers/trending
pub async fn stickers_trending(
    State(state): State<AppState>,
    user_id: UserId,
    Query(params): Query<MediaQuery>,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(&state, &rate_limit::MEDIA_LIMIT, &user_id.0.to_string()).await?;
    let api_key = get_api_key(&state)?;
    let qs = trending_qs(&params);
    let json = klipy_request(api_key, ContentType::Stickers, "trending", &qs).await?;
    Ok(Json(normalize_response(&json, ContentType::Stickers)))
}

/// GET /api/stickers/search
pub async fn stickers_search(
    State(state): State<AppState>,
    user_id: UserId,
    Query(params): Query<MediaQuery>,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(&state, &rate_limit::MEDIA_LIMIT, &user_id.0.to_string()).await?;
    let api_key = get_api_key(&state)?;
    let qs = search_qs(&params)?;
    let json = klipy_request(api_key, ContentType::Stickers, "search", &qs).await?;
    Ok(Json(normalize_response(&json, ContentType::Stickers)))
}

// ─── Clips ─────────────────────────────────────────────────────────────────

/// GET /api/clips/trending
pub async fn clips_trending(
    State(state): State<AppState>,
    user_id: UserId,
    Query(params): Query<MediaQuery>,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(&state, &rate_limit::MEDIA_LIMIT, &user_id.0.to_string()).await?;
    let api_key = get_api_key(&state)?;
    let qs = trending_qs(&params);
    let json = klipy_request(api_key, ContentType::Clips, "trending", &qs).await?;
    Ok(Json(normalize_response(&json, ContentType::Clips)))
}

/// GET /api/clips/search
pub async fn clips_search(
    State(state): State<AppState>,
    user_id: UserId,
    Query(params): Query<MediaQuery>,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(&state, &rate_limit::MEDIA_LIMIT, &user_id.0.to_string()).await?;
    let api_key = get_api_key(&state)?;
    let qs = search_qs(&params)?;
    let json = klipy_request(api_key, ContentType::Clips, "search", &qs).await?;
    Ok(Json(normalize_response(&json, ContentType::Clips)))
}

// ─── Memes ─────────────────────────────────────────────────────────────────

/// GET /api/memes/trending
pub async fn memes_trending(
    State(state): State<AppState>,
    user_id: UserId,
    Query(params): Query<MediaQuery>,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(&state, &rate_limit::MEDIA_LIMIT, &user_id.0.to_string()).await?;
    let api_key = get_api_key(&state)?;
    let qs = trending_qs(&params);
    let json = klipy_request(api_key, ContentType::StaticMemes, "trending", &qs).await?;
    Ok(Json(normalize_response(&json, ContentType::StaticMemes)))
}

/// GET /api/memes/search
pub async fn memes_search(
    State(state): State<AppState>,
    user_id: UserId,
    Query(params): Query<MediaQuery>,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(&state, &rate_limit::MEDIA_LIMIT, &user_id.0.to_string()).await?;
    let api_key = get_api_key(&state)?;
    let qs = search_qs(&params)?;
    let json = klipy_request(api_key, ContentType::StaticMemes, "search", &qs).await?;
    Ok(Json(normalize_response(&json, ContentType::StaticMemes)))
}

// ─── Categories (shared across all content types) ────────────────────────

/// Normalize Klipy categories response into `{ categories: [...] }`.
/// Klipy returns: `{ result: bool, data: { locale, categories: [{ category, query, preview_url }] } }`
fn normalize_categories(klipy_json: &Value) -> Value {
    let empty = vec![];
    let items = klipy_json
        .get("data")
        .and_then(|d| d.get("categories"))
        .and_then(|c| c.as_array())
        .unwrap_or(&empty);

    let categories: Vec<Value> = items
        .iter()
        .take(24)
        .filter_map(|item| {
            let name = item.get("category").and_then(|n| n.as_str())?;
            let slug = item.get("query").and_then(|s| s.as_str()).unwrap_or(name);
            let image = item
                .get("preview_url")
                .and_then(|i| i.as_str())
                .unwrap_or("");
            Some(json!({ "name": name, "slug": slug, "image": image }))
        })
        .collect();

    json!({ "categories": categories })
}

async fn categories_handler(state: &AppState, content_type: ContentType) -> AppResult<Json<Value>> {
    let cache_key = content_type.path();

    // Check cache first
    {
        let cache = CATEGORIES_CACHE.read().await;
        if let Some((cached, ts)) = cache.get(cache_key) {
            if ts.elapsed() < CATEGORIES_TTL {
                return Ok(Json(cached.clone()));
            }
        }
    }

    let api_key = get_api_key(state)?;
    let raw = klipy_request(api_key, content_type, "categories", "").await?;
    let mut result = normalize_categories(&raw);

    // For non-GIF types, enrich category tiles with content-type-specific previews.
    // Fetch previews in parallel (up to MAX_ENRICHED_CATEGORIES concurrent requests).
    if !matches!(content_type, ContentType::Gifs) {
        if let Some(cats) = result.get_mut("categories").and_then(|c| c.as_array_mut()) {
            let limit = cats.len().min(MAX_ENRICHED_CATEGORIES);
            let mut futures = Vec::with_capacity(limit);

            for i in 0..limit {
                let slug = cats[i]
                    .get("slug")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let api_key = api_key.to_string();
                futures.push(async move {
                    if slug.is_empty() {
                        return (i, None);
                    }
                    let qs = format!(
                        "q={}&per_page=1&customer_id=app",
                        urlencoding::encode(&slug)
                    );
                    match klipy_request(&api_key, content_type, "search", &qs).await {
                        Ok(search_json) => {
                            let normalized = normalize_response(&search_json, content_type);
                            let url = normalized
                                .get("results")
                                .and_then(|r| r.as_array())
                                .and_then(|a| a.first())
                                .and_then(|f| f.get("images"))
                                .and_then(|i| i.get("tinygif"))
                                .and_then(|t| t.get("url"))
                                .and_then(|u| u.as_str())
                                .map(|s| s.to_string());
                            (i, url)
                        }
                        Err(_) => (i, None),
                    }
                });
            }

            let results = futures_util::future::join_all(futures).await;
            for (i, url) in results {
                if let Some(url) = url {
                    cats[i]["image"] = json!(url);
                }
            }
        }
    }

    // Cache the enriched result
    {
        let mut cache = CATEGORIES_CACHE.write().await;
        cache.insert(cache_key, (result.clone(), Instant::now()));
    }

    Ok(Json(result))
}

/// GET /api/gifs/categories
pub async fn gifs_categories(State(state): State<AppState>) -> AppResult<Json<Value>> {
    categories_handler(&state, ContentType::Gifs).await
}

/// GET /api/stickers/categories
pub async fn stickers_categories(State(state): State<AppState>) -> AppResult<Json<Value>> {
    categories_handler(&state, ContentType::Stickers).await
}

/// GET /api/clips/categories
pub async fn clips_categories(State(state): State<AppState>) -> AppResult<Json<Value>> {
    categories_handler(&state, ContentType::Clips).await
}

/// GET /api/memes/categories
pub async fn memes_categories(State(state): State<AppState>) -> AppResult<Json<Value>> {
    categories_handler(&state, ContentType::StaticMemes).await
}

// ─── Recent (per-user history via Klipy) ─────────────────────────────────

#[derive(Deserialize)]
pub struct RecentQuery {
    pub limit: Option<u32>,
}

async fn recent_handler(
    state: &AppState,
    content_type: ContentType,
    customer_id: &str,
    params: &RecentQuery,
) -> AppResult<Json<Value>> {
    let api_key = get_api_key(state)?;
    let per_page = params.limit.unwrap_or(20).min(50);
    let qs = format!("per_page={}", per_page);
    let endpoint = format!("recent/{}", urlencoding::encode(customer_id));
    let json = klipy_request(api_key, content_type, &endpoint, &qs).await?;
    Ok(Json(normalize_response(&json, content_type)))
}

/// GET /api/gifs/recent/:customer_id
pub async fn gifs_recent(
    State(state): State<AppState>,
    user_id: crate::middleware::auth::UserId,
    Path(customer_id): Path<String>,
    Query(params): Query<RecentQuery>,
) -> AppResult<Json<Value>> {
    // Prevent IDOR: customer_id must match the authenticated user
    if customer_id != user_id.0.to_string() {
        return Err(crate::error::AppError::Forbidden);
    }
    recent_handler(&state, ContentType::Gifs, &customer_id, &params).await
}

/// GET /api/stickers/recent/:customer_id
pub async fn stickers_recent(
    State(state): State<AppState>,
    user_id: crate::middleware::auth::UserId,
    Path(customer_id): Path<String>,
    Query(params): Query<RecentQuery>,
) -> AppResult<Json<Value>> {
    if customer_id != user_id.0.to_string() {
        return Err(crate::error::AppError::Forbidden);
    }
    recent_handler(&state, ContentType::Stickers, &customer_id, &params).await
}

/// GET /api/clips/recent/:customer_id
pub async fn clips_recent(
    State(state): State<AppState>,
    user_id: crate::middleware::auth::UserId,
    Path(customer_id): Path<String>,
    Query(params): Query<RecentQuery>,
) -> AppResult<Json<Value>> {
    if customer_id != user_id.0.to_string() {
        return Err(crate::error::AppError::Forbidden);
    }
    recent_handler(&state, ContentType::Clips, &customer_id, &params).await
}

/// GET /api/memes/recent/:customer_id
pub async fn memes_recent(
    State(state): State<AppState>,
    user_id: crate::middleware::auth::UserId,
    Path(customer_id): Path<String>,
    Query(params): Query<RecentQuery>,
) -> AppResult<Json<Value>> {
    if customer_id != user_id.0.to_string() {
        return Err(crate::error::AppError::Forbidden);
    }
    recent_handler(&state, ContentType::StaticMemes, &customer_id, &params).await
}

// ─── Startup preload ──────────────────────────────────────────────────────

/// Preload enriched categories for all content types into the server-side cache.
/// Call once at startup so the first user request is instant.
pub fn spawn_categories_preload(state: AppState) {
    tokio::spawn(async move {
        let Some(api_key) = state.config.klipy_api_key.as_deref() else {
            tracing::debug!("Klipy API key not configured, skipping category preload");
            return;
        };
        tracing::info!("Preloading Klipy categories...");

        let types = [
            ContentType::Gifs,
            ContentType::Stickers,
            ContentType::Clips,
            ContentType::StaticMemes,
        ];
        for ct in types {
            match preload_categories(api_key, ct).await {
                Ok(_) => tracing::info!("Preloaded {} categories", ct.path()),
                Err(e) => tracing::warn!("Failed to preload {} categories: {e}", ct.path()),
            }
        }
    });
}

async fn preload_categories(api_key: &str, content_type: ContentType) -> Result<(), AppError> {
    let raw = klipy_request(api_key, content_type, "categories", "").await?;
    let mut result = normalize_categories(&raw);

    if !matches!(content_type, ContentType::Gifs) {
        if let Some(cats) = result.get_mut("categories").and_then(|c| c.as_array_mut()) {
            let limit = cats.len().min(MAX_ENRICHED_CATEGORIES);
            let mut futures = Vec::with_capacity(limit);

            for i in 0..limit {
                let slug = cats[i]
                    .get("slug")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let api_key = api_key.to_string();
                futures.push(async move {
                    if slug.is_empty() {
                        return (i, None);
                    }
                    let qs = format!(
                        "q={}&per_page=1&customer_id=app",
                        urlencoding::encode(&slug)
                    );
                    match klipy_request(&api_key, content_type, "search", &qs).await {
                        Ok(search_json) => {
                            let normalized = normalize_response(&search_json, content_type);
                            let url = normalized
                                .get("results")
                                .and_then(|r| r.as_array())
                                .and_then(|a| a.first())
                                .and_then(|f| f.get("images"))
                                .and_then(|i| i.get("tinygif"))
                                .and_then(|t| t.get("url"))
                                .and_then(|u| u.as_str())
                                .map(|s| s.to_string());
                            (i, url)
                        }
                        Err(_) => (i, None),
                    }
                });
            }

            let results = futures_util::future::join_all(futures).await;
            for (i, url) in results {
                if let Some(url) = url {
                    cats[i]["image"] = json!(url);
                }
            }
        }
    }

    let mut cache = CATEGORIES_CACHE.write().await;
    cache.insert(content_type.path(), (result, Instant::now()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn klipy_media_url_policy_is_exact_and_https_only() {
        assert!(is_allowed_klipy_media_url(
            "https://media.klipy.com/clips/a.mp4"
        ));
        assert!(is_allowed_klipy_media_url(
            "https://static.klipy.com/gifs/a.webp?size=small"
        ));

        assert!(!is_allowed_klipy_media_url(
            "http://media.klipy.com/clips/a.mp4"
        ));
        assert!(!is_allowed_klipy_media_url(
            "https://media.klipy.com.evil.example/a.mp4"
        ));
        assert!(!is_allowed_klipy_media_url(
            "https://user:pass@media.klipy.com/a.mp4"
        ));
        assert!(!is_allowed_klipy_media_url(
            "https://media.klipy.com/a.mp4#token"
        ));
        assert!(!is_allowed_klipy_media_url(
            "https://media.klipy.com\\@evil.example/a.mp4"
        ));
    }

    #[test]
    fn normalize_response_drops_untrusted_klipy_media_urls() {
        let raw = json!({
            "data": {
                "data": [
                    {
                        "id": "gif-1",
                        "title": "bad gif",
                        "file": {
                            "hd": {
                                "webp": {
                                    "url": "https://evil.example/gif.webp",
                                    "width": 320,
                                    "height": 240
                                }
                            },
                            "xs": {
                                "webp": {
                                    "url": "https://evil.example/gif-small.webp",
                                    "width": 64,
                                    "height": 64
                                }
                            }
                        }
                    }
                ]
            }
        });

        let normalized = normalize_response(&raw, ContentType::Gifs);
        assert_eq!(
            normalized
                .get("results")
                .and_then(|results| results.as_array())
                .map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn normalize_response_falls_back_to_allowed_clip_variant() {
        let raw = json!({
            "data": {
                "data": [
                    {
                        "slug": "clip-1",
                        "title": "clip",
                        "file": {
                            "mp4": "https://evil.example/clip.mp4",
                            "gif": "https://media.klipy.com/clip.gif",
                            "webp": "https://static.klipy.com/clip.webp"
                        },
                        "file_meta": {
                            "gif": { "width": 320, "height": 180 },
                            "webp": { "width": 160, "height": 90 }
                        }
                    }
                ]
            }
        });

        let normalized = normalize_response(&raw, ContentType::Clips);
        let first = normalized
            .get("results")
            .and_then(|results| results.as_array())
            .and_then(|results| results.first())
            .expect("clip should survive with the allowed fallback variant");

        assert_eq!(
            first
                .pointer("/images/original/url")
                .and_then(|value| value.as_str()),
            Some("https://media.klipy.com/clip.gif")
        );
        assert_eq!(
            first
                .pointer("/images/tinygif/url")
                .and_then(|value| value.as_str()),
            Some("https://media.klipy.com/clip.gif")
        );
    }
}
