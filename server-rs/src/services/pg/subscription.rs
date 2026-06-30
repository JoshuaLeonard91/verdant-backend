//! Subscription events — Stripe webhook archive. Replay-protection via
//! unique `stripe_event_id`. Redis stream `subscription-events` is the
//! live tail.

use sqlx::{PgPool, Postgres, Transaction};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BillingCustomerRow {
    pub user_id: i64,
    pub stripe_customer_id: String,
    pub stripe_subscription_id: Option<String>,
    pub stripe_subscription_status: Option<String>,
    pub current_period_end_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SubscriptionEventRow {
    pub id: i64,
    pub user_id: i64,
    pub event_type: String,
    pub stripe_event_id: Option<String>,
    pub amount_cents: i32,
    pub metadata: serde_json::Value,
    pub created_at_ms: i64,
}

/// Insert if not seen before (Stripe retries the same webhook).
/// Returns true if a new row was inserted, false if it was a duplicate.
pub async fn insert_idempotent(
    pool: &PgPool,
    r: &SubscriptionEventRow,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        r#"
        INSERT INTO subscription_events
            (id, user_id, event_type, stripe_event_id, amount_cents, metadata, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (stripe_event_id) WHERE stripe_event_id IS NOT NULL DO NOTHING
        "#,
    )
    .bind(r.id)
    .bind(r.user_id)
    .bind(&r.event_type)
    .bind(&r.stripe_event_id)
    .bind(r.amount_cents)
    .bind(&r.metadata)
    .bind(r.created_at_ms)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn insert_idempotent_tx(
    tx: &mut Transaction<'_, Postgres>,
    r: &SubscriptionEventRow,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        r#"
        INSERT INTO subscription_events
            (id, user_id, event_type, stripe_event_id, amount_cents, metadata, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (stripe_event_id) WHERE stripe_event_id IS NOT NULL DO NOTHING
        "#,
    )
    .bind(r.id)
    .bind(r.user_id)
    .bind(&r.event_type)
    .bind(&r.stripe_event_id)
    .bind(r.amount_cents)
    .bind(&r.metadata)
    .bind(r.created_at_ms)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn list_for_user(
    pool: &PgPool,
    user_id: i64,
    limit: i64,
) -> Result<Vec<SubscriptionEventRow>, sqlx::Error> {
    sqlx::query_as::<_, SubscriptionEventRow>(
        r#"
        SELECT * FROM subscription_events
         WHERE user_id = $1
         ORDER BY created_at_ms DESC
         LIMIT $2
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn billing_customer_by_user(
    pool: &PgPool,
    user_id: i64,
) -> Result<Option<BillingCustomerRow>, sqlx::Error> {
    sqlx::query_as::<_, BillingCustomerRow>("SELECT * FROM billing_customers WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}

pub async fn billing_customer_by_stripe_customer(
    pool: &PgPool,
    stripe_customer_id: &str,
) -> Result<Option<BillingCustomerRow>, sqlx::Error> {
    sqlx::query_as::<_, BillingCustomerRow>(
        "SELECT * FROM billing_customers WHERE stripe_customer_id = $1",
    )
    .bind(stripe_customer_id)
    .fetch_optional(pool)
    .await
}

pub async fn upsert_billing_customer(
    pool: &PgPool,
    user_id: i64,
    stripe_customer_id: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO billing_customers
            (user_id, stripe_customer_id, created_at_ms, updated_at_ms)
        VALUES ($1, $2, $3, $3)
        ON CONFLICT (user_id) DO UPDATE
            SET stripe_customer_id = EXCLUDED.stripe_customer_id,
                updated_at_ms = EXCLUDED.updated_at_ms
        "#,
    )
    .bind(user_id)
    .bind(stripe_customer_id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn upsert_billing_customer_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: i64,
    stripe_customer_id: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO billing_customers
            (user_id, stripe_customer_id, created_at_ms, updated_at_ms)
        VALUES ($1, $2, $3, $3)
        ON CONFLICT (user_id) DO UPDATE
            SET stripe_customer_id = EXCLUDED.stripe_customer_id,
                updated_at_ms = EXCLUDED.updated_at_ms
        "#,
    )
    .bind(user_id)
    .bind(stripe_customer_id)
    .bind(now_ms)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn update_billing_subscription(
    pool: &PgPool,
    user_id: i64,
    stripe_subscription_id: Option<&str>,
    stripe_subscription_status: Option<&str>,
    current_period_end_ms: Option<i64>,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE billing_customers
           SET stripe_subscription_id = $2,
               stripe_subscription_status = $3,
               current_period_end_ms = $4,
               updated_at_ms = $5
         WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .bind(stripe_subscription_id)
    .bind(stripe_subscription_status)
    .bind(current_period_end_ms)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_billing_subscription_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: i64,
    stripe_subscription_id: Option<&str>,
    stripe_subscription_status: Option<&str>,
    current_period_end_ms: Option<i64>,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE billing_customers
           SET stripe_subscription_id = $2,
               stripe_subscription_status = $3,
               current_period_end_ms = $4,
               updated_at_ms = $5
         WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .bind(stripe_subscription_id)
    .bind(stripe_subscription_status)
    .bind(current_period_end_ms)
    .bind(now_ms)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
