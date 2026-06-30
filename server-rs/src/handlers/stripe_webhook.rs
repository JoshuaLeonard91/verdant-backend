use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, State},
    http::HeaderMap,
};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use std::net::SocketAddr;

use crate::error::{AppError, AppResult};
use crate::middleware::rate_limit;
use crate::state::AppState;

fn object_str<'a>(object: &'a Value, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn object_i64(object: &Value, key: &str) -> Option<i64> {
    object.get(key).and_then(Value::as_i64)
}

fn user_id_from_object(object: &Value) -> Option<i64> {
    object
        .get("metadata")
        .and_then(|m| m.get("user_id"))
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<i64>().ok())
        .or_else(|| {
            object
                .get("client_reference_id")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<i64>().ok())
        })
}

async fn resolve_user_id(state: &AppState, object: &Value) -> AppResult<Option<i64>> {
    if let Some(user_id) = user_id_from_object(object) {
        return Ok(Some(user_id));
    }
    let Some(customer_id) = object_str(object, "customer") else {
        return Ok(None);
    };
    Ok(
        crate::services::pg::subscription::billing_customer_by_stripe_customer(
            &state.pg,
            customer_id,
        )
        .await
        .map_err(|e| {
            tracing::error!(customer_id, error = %e, "Stripe customer lookup failed");
            AppError::Internal
        })?
        .map(|row| row.user_id),
    )
}

async fn apply_subscription_state(
    tx: &mut Transaction<'_, Postgres>,
    user_id: i64,
    subscription_id: Option<&str>,
    status: Option<&str>,
    current_period_end_secs: Option<i64>,
) -> AppResult<()> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let current_period_end_ms = current_period_end_secs.map(|s| s * 1000);
    crate::services::pg::subscription::update_billing_subscription_tx(
        tx,
        user_id,
        subscription_id,
        status,
        current_period_end_ms,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id, error = %e, "billing subscription mapping update failed");
        AppError::Internal
    })?;

    let active = matches!(status, Some("active" | "trialing"));
    if active {
        let expires_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            current_period_end_ms.unwrap_or(now_ms + 31 * 24 * 60 * 60 * 1000),
        )
        .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::days(31));
        crate::services::pg::users::set_subscription_tx(
            tx,
            user_id,
            Some(crate::services::subscription::TIER_PREMIUM),
            Some(expires_at.timestamp_millis()),
            true,
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!(user_id, error = %e, "subscription activation failed");
            AppError::Internal
        })?;
    } else {
        crate::services::pg::users::set_subscription_tx(tx, user_id, None, None, false, None)
            .await
            .map_err(|e| {
                tracing::error!(user_id, error = %e, "subscription revoke failed");
                AppError::Internal
            })?;
    }
    Ok(())
}

fn is_subscription_state_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "checkout.session.completed"
            | "customer.subscription.created"
            | "customer.subscription.updated"
            | "customer.subscription.deleted"
    )
}

async fn has_newer_subscription_state_event(
    tx: &mut Transaction<'_, Postgres>,
    user_id: i64,
    event_id: &str,
    event_created_secs: Option<i64>,
) -> Result<bool, sqlx::Error> {
    let Some(created_secs) = event_created_secs else {
        return Ok(false);
    };
    let exists = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
              FROM subscription_events
             WHERE user_id = $1
               AND stripe_event_id IS DISTINCT FROM $2
               AND event_type = ANY($3::text[])
               AND (metadata->>'created') ~ '^[0-9]+$'
               AND (metadata->>'created')::bigint > $4
        )
        "#,
    )
    .bind(user_id)
    .bind(if event_id.is_empty() {
        None
    } else {
        Some(event_id)
    })
    .bind(&[
        "checkout.session.completed",
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
    ])
    .bind(created_secs)
    .fetch_one(&mut **tx)
    .await?;
    Ok(exists)
}

pub async fn stripe_webhook(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Json<Value>> {
    let ip = crate::handlers::extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::STRIPE_WEBHOOK_LIMIT, &ip).await?;

    let webhook_secret = state
        .config
        .stripe_webhook_secret
        .as_deref()
        .ok_or_else(|| AppError::WithCode {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            code: "STRIPE_WEBHOOK_NOT_CONFIGURED",
            message: "Stripe webhook is not configured.".into(),
        })?;
    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::WithCode {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: "STRIPE_SIGNATURE_MISSING",
            message: "Invalid Stripe webhook.".into(),
        })?;

    crate::services::stripe_webhook::verify_signature(
        &body,
        sig,
        webhook_secret,
        chrono::Utc::now().timestamp(),
        300,
    )
    .map_err(|e| {
        tracing::warn!(error = ?e, "Stripe webhook signature rejected");
        AppError::WithCode {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: "STRIPE_SIGNATURE_INVALID",
            message: "Invalid Stripe webhook.".into(),
        }
    })?;

    let event: Value = serde_json::from_slice(&body).map_err(|_| AppError::WithCode {
        status: axum::http::StatusCode::BAD_REQUEST,
        code: "STRIPE_EVENT_INVALID",
        message: "Invalid Stripe webhook.".into(),
    })?;
    let event_id = object_str(&event, "id").unwrap_or("");
    let event_type = object_str(&event, "type").unwrap_or("");
    let object = event
        .get("data")
        .and_then(|d| d.get("object"))
        .cloned()
        .unwrap_or(Value::Null);

    let Some(user_id) = resolve_user_id(&state, &object).await? else {
        tracing::warn!(
            event_id,
            event_type,
            "Stripe webhook ignored: no Verdant user mapping"
        );
        return Ok(Json(json!({ "received": true, "ignored": true })));
    };

    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut tx = state.pg.begin().await.map_err(|e| {
        tracing::error!(event_id, error = %e, "Stripe webhook tx begin failed");
        AppError::Internal
    })?;
    let event_row = crate::services::pg::subscription::SubscriptionEventRow {
        id: state.snowflake.next_id(),
        user_id,
        event_type: event_type.to_string(),
        stripe_event_id: if event_id.is_empty() {
            None
        } else {
            Some(event_id.to_string())
        },
        amount_cents: 0,
        metadata: event.clone(),
        created_at_ms: now_ms,
    };
    let inserted = crate::services::pg::subscription::insert_idempotent_tx(&mut tx, &event_row)
        .await
        .map_err(|e| {
            tracing::error!(event_id, error = %e, "Stripe webhook event insert failed");
            AppError::Internal
        })?;
    if !inserted {
        tx.rollback().await.map_err(|e| {
            tracing::error!(event_id, error = %e, "Stripe webhook duplicate tx rollback failed");
            AppError::Internal
        })?;
        return Ok(Json(json!({ "received": true, "duplicate": true })));
    }

    let skip_subscription_state = if is_subscription_state_event(event_type) {
        has_newer_subscription_state_event(
            &mut tx,
            user_id,
            event_id,
            object_i64(&event, "created"),
        )
        .await
        .map_err(|e| {
            tracing::error!(event_id, error = %e, "Stripe webhook ordering check failed");
            AppError::Internal
        })?
    } else {
        false
    };

    match event_type {
        "checkout.session.completed" => {
            if let Some(customer_id) = object_str(&object, "customer") {
                crate::services::pg::subscription::upsert_billing_customer_tx(
                    &mut tx,
                    user_id,
                    customer_id,
                    now_ms,
                )
                .await
                .map_err(|e| {
                    tracing::error!(user_id, error = %e, "Stripe customer upsert from checkout failed");
                    AppError::Internal
                })?;
            }
            if !skip_subscription_state {
                apply_subscription_state(
                    &mut tx,
                    user_id,
                    object_str(&object, "subscription"),
                    Some("active"),
                    None,
                )
                .await?;
            }
        }
        "customer.subscription.created" | "customer.subscription.updated" => {
            if !skip_subscription_state {
                apply_subscription_state(
                    &mut tx,
                    user_id,
                    object_str(&object, "id"),
                    object_str(&object, "status"),
                    object_i64(&object, "current_period_end"),
                )
                .await?;
            }
        }
        "customer.subscription.deleted" => {
            if !skip_subscription_state {
                apply_subscription_state(
                    &mut tx,
                    user_id,
                    object_str(&object, "id"),
                    Some("canceled"),
                    object_i64(&object, "current_period_end"),
                )
                .await?;
            }
        }
        "invoice.payment_failed" => {
            tracing::warn!(user_id, event_id, "Stripe invoice payment failed");
        }
        "invoice.paid" => {
            tracing::info!(user_id, event_id, "Stripe invoice paid");
        }
        _ => {}
    }

    tx.commit().await.map_err(|e| {
        tracing::error!(event_id, error = %e, "Stripe webhook tx commit failed");
        AppError::Internal
    })?;

    if skip_subscription_state {
        return Ok(Json(json!({ "received": true, "stale": true })));
    }

    Ok(Json(json!({ "received": true })))
}

#[cfg(test)]
mod tests {
    const SOURCE: &str = include_str!("stripe_webhook.rs");

    #[test]
    fn stripe_webhook_records_idempotency_before_subscription_mutation() {
        let handler = SOURCE
            .split("pub async fn stripe_webhook")
            .nth(1)
            .expect("stripe_webhook handler source should exist")
            .split("#[cfg(test)]")
            .next()
            .expect("handler body should precede tests");
        let idempotency = handler
            .find("insert_idempotent")
            .expect("handler should record Stripe event idempotency");
        let mutation = handler
            .find("match event_type")
            .expect("handler should branch into Stripe side effects");

        assert!(
            idempotency < mutation,
            "Stripe event idempotency must be reserved before subscription side effects"
        );
    }
}
