//! Login history audit log.
//!
//! Redis stream `login-history` is the live tail (admin panel, fraud
//! dashboards do XRANGE / XREAD). Postgres is the durability archive
//! via `pg::login::insert`. Fire-and-forget — login itself never fails
//! because the audit sinks are down.

use fred::clients::Client;
use fred::interfaces::StreamsInterface;
use sqlx::PgPool;

use crate::services::pg::login as pg_login;
use crate::services::risk::RiskLevel;

pub struct LogLoginParams {
    pub id: i64,
    pub user_id: Option<i64>,
    pub session_id: Option<i64>,
    pub ip: String,
    pub user_agent: Option<String>,
    pub device_hash: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub success: bool,
    pub risk_level: RiskLevel,
    pub failure_reason: Option<String>,
}

const LOGIN_HISTORY_STREAM: &str = "login-history";

pub async fn log_login(redis: &Client, p: LogLoginParams, pg: PgPool) {
    let user_id_str = p.user_id.map(|v| v.to_string()).unwrap_or_default();
    let session_id_str = p.session_id.map(|v| v.to_string()).unwrap_or_default();
    let ua_str = p.user_agent.clone().unwrap_or_default();
    let dh_str = p.device_hash.clone().unwrap_or_default();
    let city_str = p.city.clone().unwrap_or_default();
    let country_str = p.country.clone().unwrap_or_default();
    let risk_str = p.risk_level.as_str().to_string();
    let fail_str = p.failure_reason.clone().unwrap_or_default();
    let now_ms = chrono::Utc::now().timestamp_millis();

    let fields: Vec<(&str, String)> = vec![
        ("id", p.id.to_string()),
        ("user_id", user_id_str.clone()),
        ("session_id", session_id_str),
        ("ip", p.ip.clone()),
        ("user_agent", ua_str.clone()),
        ("device_hash", dh_str.clone()),
        ("city", city_str.clone()),
        ("country", country_str.clone()),
        (
            "success",
            if p.success {
                "1".to_string()
            } else {
                "0".to_string()
            },
        ),
        ("risk_level", risk_str.clone()),
        ("failure_reason", fail_str.clone()),
    ];

    let result: Result<String, _> = redis
        .xadd(LOGIN_HISTORY_STREAM, false, None, "*", fields)
        .await;

    if let Err(e) = result {
        tracing::warn!(error = %e, "login_log: failed to XADD login-history entry");
    }

    // PG durability tier — fire-and-forget so the auth path never
    // blocks on the audit sink.
    let row = pg_login::LoginRow {
        id: p.id,
        user_id: p.user_id,
        session_id: p.session_id,
        success: p.success,
        failure_reason: p.failure_reason.clone(),
        ip: p.ip.clone(),
        user_agent: p.user_agent.clone(),
        device_hash: p.device_hash.clone(),
        city: p.city.clone(),
        country: p.country.clone(),
        risk_level: Some(risk_str),
        created_at_ms: now_ms,
    };
    tokio::spawn(async move {
        if let Err(e) = pg_login::insert(&pg, &row).await {
            tracing::warn!(error = %e, "login_log PG dual-write failed");
        }
    });
}
