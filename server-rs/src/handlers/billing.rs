use axum::{Json, extract::State};
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::middleware::{auth::UserId, rate_limit};
use crate::state::AppState;

const STRIPE_API_VERSION: &str = "2026-02-25.clover";

fn billing_unavailable() -> AppError {
    AppError::WithCode {
        status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
        code: "BILLING_NOT_CONFIGURED",
        message: "Billing is not configured.".into(),
    }
}

async fn stripe_post_form(
    secret_key: &str,
    path: &str,
    params: Vec<(String, String)>,
) -> AppResult<Value> {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("https://api.stripe.com/v1/{path}"))
        .bearer_auth(secret_key)
        .header("Stripe-Version", STRIPE_API_VERSION)
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Stripe request failed");
            AppError::Internal
        })?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let stripe_code = serde_json::from_str::<Value>(&body).ok().and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("code"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
        tracing::error!(status = %status, stripe_code = ?stripe_code, "Stripe API returned error");
        return Err(AppError::Internal);
    }
    serde_json::from_str(&body).map_err(|e| {
        tracing::error!(error = %e, "Stripe response parse failed");
        AppError::Internal
    })
}

async fn ensure_customer(state: &AppState, user_id: i64) -> AppResult<String> {
    if let Some(row) =
        crate::services::pg::subscription::billing_customer_by_user(&state.pg, user_id)
            .await
            .map_err(|e| {
                tracing::error!(user_id, error = %e, "billing customer lookup failed");
                AppError::Internal
            })?
    {
        return Ok(row.stripe_customer_id);
    }

    let secret = state
        .config
        .stripe_secret_key
        .as_deref()
        .ok_or_else(billing_unavailable)?;
    let user = crate::services::pg::users::by_id(&state.pg, user_id)
        .await
        .map_err(|e| {
            tracing::error!(user_id, error = %e, "billing user lookup failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))?;

    let customer = stripe_post_form(
        secret,
        "customers",
        vec![
            ("email".to_string(), user.email),
            ("name".to_string(), user.username),
            ("metadata[user_id]".to_string(), user_id.to_string()),
        ],
    )
    .await?;

    let customer_id = customer
        .get("id")
        .and_then(Value::as_str)
        .ok_or(AppError::Internal)?
        .to_string();

    crate::services::pg::subscription::upsert_billing_customer(
        &state.pg,
        user_id,
        &customer_id,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id, error = %e, "billing customer upsert failed");
        AppError::Internal
    })?;

    Ok(customer_id)
}

pub async fn create_checkout_session(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(
        &state,
        &rate_limit::ADMIN_LIMIT,
        &format!("billing:{}", user_id.0),
    )
    .await?;
    crate::services::app_bans::ensure_user_not_banned(&state, user_id.0).await?;

    let secret = state
        .config
        .stripe_secret_key
        .as_deref()
        .ok_or_else(billing_unavailable)?;
    let price_id = state
        .config
        .stripe_premium_price_id
        .as_deref()
        .ok_or_else(billing_unavailable)?;
    let frontend_url = state
        .config
        .frontend_url
        .as_deref()
        .unwrap_or("https://verdant.chat");
    let success_url = state
        .config
        .billing_success_url
        .clone()
        .unwrap_or_else(|| format!("{frontend_url}/billing/success"));
    let cancel_url = state
        .config
        .billing_cancel_url
        .clone()
        .unwrap_or_else(|| format!("{frontend_url}/billing/cancel"));
    let customer_id = ensure_customer(&state, user_id.0).await?;

    let session = stripe_post_form(
        secret,
        "checkout/sessions",
        vec![
            ("customer".to_string(), customer_id),
            ("mode".to_string(), "subscription".to_string()),
            ("line_items[0][price]".to_string(), price_id.to_string()),
            ("line_items[0][quantity]".to_string(), "1".to_string()),
            ("client_reference_id".to_string(), user_id.0.to_string()),
            ("metadata[user_id]".to_string(), user_id.0.to_string()),
            ("success_url".to_string(), success_url),
            ("cancel_url".to_string(), cancel_url),
        ],
    )
    .await?;

    let url = session
        .get("url")
        .and_then(Value::as_str)
        .ok_or(AppError::Internal)?;
    Ok(Json(json!({ "url": url })))
}

pub async fn create_portal_session(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(
        &state,
        &rate_limit::ADMIN_LIMIT,
        &format!("billing:{}", user_id.0),
    )
    .await?;
    crate::services::app_bans::ensure_user_not_banned(&state, user_id.0).await?;

    let secret = state
        .config
        .stripe_secret_key
        .as_deref()
        .ok_or_else(billing_unavailable)?;
    let customer_id = ensure_customer(&state, user_id.0).await?;
    let frontend_url = state
        .config
        .frontend_url
        .as_deref()
        .unwrap_or("https://verdant.chat");
    let return_url = format!("{frontend_url}/settings/subscription");

    let session = stripe_post_form(
        secret,
        "billing_portal/sessions",
        vec![
            ("customer".to_string(), customer_id),
            ("return_url".to_string(), return_url),
        ],
    )
    .await?;

    let url = session
        .get("url")
        .and_then(Value::as_str)
        .ok_or(AppError::Internal)?;
    Ok(Json(json!({ "url": url })))
}
