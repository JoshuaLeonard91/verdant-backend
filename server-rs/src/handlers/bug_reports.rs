use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::error::{AppError, AppResult};
use crate::middleware::{auth::UserId, rate_limit};
use crate::services::sanitize::sanitize_text;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

const VALID_CATEGORIES: &[&str] = &[
    "general",
    "crash",
    "ui",
    "messaging",
    "voice",
    "auth",
    "other",
];

/// Cap the per-user history to the last 50 reports.
const BUG_REPORTS_MAX_LEN: i64 = 50;

#[derive(Deserialize)]
pub struct CreateBugReportBody {
    pub title: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/// Compute a fingerprint from category + sorted lowercase keywords of the title.
/// Truncated to 16 hex chars for compact grouping.
fn compute_fingerprint(category: &str, title: &str) -> String {
    let mut words: Vec<&str> = title
        .split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|w| w.len() > 2) // drop tiny words like "a", "in", "to"
        .collect();
    words.sort_unstable();
    words.dedup();

    let input = format!(
        "{}:{}",
        category,
        words
            .iter()
            .map(|w| w.to_lowercase())
            .collect::<Vec<_>>()
            .join(",")
    );

    let hash = Sha256::digest(input.as_bytes());
    hex::encode(&hash[..8]) // 8 bytes = 16 hex chars
}

fn optional_metadata(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn bug_report_json(
    id: i64,
    title: String,
    description: String,
    category: String,
    client_version: Option<String>,
    os: Option<String>,
    fingerprint: String,
    status: String,
    created_at_ms: i64,
) -> Value {
    let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(created_at_ms)
        .unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH)
        .to_rfc3339();

    json!({
        "id": id.to_string(),
        "title": title,
        "description": description,
        "category": category,
        "clientVersion": client_version,
        "os": os,
        "fingerprint": fingerprint,
        "status": status,
        "createdAt": created_at,
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/bug-reports
///
/// Submit a bug report. Auth required, rate limited 5/60s. Stored
/// durably in Postgres for admin review and status tracking.
pub async fn create_bug_report(
    State(state): State<AppState>,
    user_id: UserId,
    headers: HeaderMap,
    Json(body): Json<CreateBugReportBody>,
) -> AppResult<impl IntoResponse> {
    rate_limit::enforce(
        &state,
        &rate_limit::BUG_REPORT_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;

    // Validate title
    let title_raw = body.title.unwrap_or_default();
    if title_raw.len() > 200 {
        return Err(AppError::Validation(
            "Title must be at most 200 characters".into(),
        ));
    }
    let title = sanitize_text(&title_raw).trim().to_string();
    if title.is_empty() {
        return Err(AppError::Validation("Title is required".into()));
    }

    // Validate description
    let desc_raw = body.description.unwrap_or_default();
    if desc_raw.len() > 5000 {
        return Err(AppError::Validation(
            "Description must be at most 5000 characters".into(),
        ));
    }
    let description = sanitize_text(&desc_raw).trim().to_string();
    if description.is_empty() {
        return Err(AppError::Validation("Description is required".into()));
    }

    // Validate category
    let category = body.category.as_deref().unwrap_or("general").to_string();
    if !VALID_CATEGORIES.contains(&category.as_str()) {
        return Err(AppError::Validation("Invalid category".into()));
    }

    // Extract client metadata from headers
    let client_version = optional_metadata(
        headers
            .get("x-client-version")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default(),
    );
    let os = optional_metadata(
        headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(256).collect::<String>())
            .unwrap_or_default(),
    );

    let fingerprint = compute_fingerprint(&category, &title);
    let id = state.snowflake.next_id();
    let created_at_ms = chrono::Utc::now().timestamp_millis();

    sqlx::query(
        r#"
        INSERT INTO bug_reports (
            id,
            reporter_id,
            title,
            description,
            category,
            client_version,
            os,
            fingerprint,
            status,
            created_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'open', $9)
        "#,
    )
    .bind(id)
    .bind(user_id.0)
    .bind(&title)
    .bind(&description)
    .bind(&category)
    .bind(client_version.as_deref())
    .bind(os.as_deref())
    .bind(&fingerprint)
    .bind(created_at_ms)
    .execute(&state.pg)
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "failed to create bug report");
        AppError::Internal
    })?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id.to_string(),
            "fingerprint": fingerprint,
        })),
    ))
}

/// GET /api/bug-reports/me
///
/// List the authenticated user's own bug reports, newest first, max 50.
pub async fn list_my_bug_reports(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<impl IntoResponse> {
    let rows = sqlx::query(
        r#"
        SELECT id, title, description, category, client_version, os, fingerprint, status, created_at_ms
          FROM bug_reports
         WHERE reporter_id = $1
         ORDER BY created_at_ms DESC
         LIMIT $2
        "#,
    )
    .bind(user_id.0)
    .bind(BUG_REPORTS_MAX_LEN)
    .fetch_all(&state.pg)
    .await
    .map_err(|err| {
        tracing::error!(error = %err, user_id = user_id.0, "failed to list user bug reports");
        AppError::Internal
    })?;

    let reports: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            bug_report_json(
                row.get::<i64, _>("id"),
                row.get("title"),
                row.get("description"),
                row.get("category"),
                row.get("client_version"),
                row.get("os"),
                row.get("fingerprint"),
                row.get("status"),
                row.get("created_at_ms"),
            )
        })
        .collect();

    Ok(Json(json!(reports)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bug_report_response_uses_public_shape_and_null_optional_metadata() {
        let value = bug_report_json(
            42,
            "UI flickers".to_string(),
            "The sidebar flickers after reconnect".to_string(),
            "ui".to_string(),
            None,
            None,
            "abc123".to_string(),
            "open".to_string(),
            1_714_579_200_000,
        );

        assert_eq!(value["id"], "42");
        assert_eq!(value["title"], "UI flickers");
        assert_eq!(value["category"], "ui");
        assert_eq!(value["clientVersion"], Value::Null);
        assert_eq!(value["os"], Value::Null);
        assert_eq!(value["fingerprint"], "abc123");
        assert_eq!(value["status"], "open");
        assert_eq!(value["createdAt"], "2024-05-01T16:00:00+00:00");
    }
}
