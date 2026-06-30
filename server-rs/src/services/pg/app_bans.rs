//! App-wide account and IP ban storage helpers.

use std::net::IpAddr;

use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AccountBanRow {
    pub id: i64,
    pub user_id: i64,
    pub reason: Option<String>,
    pub created_by: Option<i64>,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IpBanRow {
    pub id: i64,
    pub ip: String,
    pub reason: Option<String>,
    pub created_by: Option<i64>,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanStatus {
    Active,
    Expired,
    Revoked,
    None,
}

pub fn normalize_exact_ip(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.contains('/') {
        return None;
    }
    trimmed.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

pub fn classify_ban(
    expires_at_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
    now_ms: i64,
) -> BanStatus {
    if revoked_at_ms.is_some() {
        return BanStatus::Revoked;
    }
    if let Some(expires_at_ms) = expires_at_ms {
        if expires_at_ms <= now_ms {
            return BanStatus::Expired;
        }
    }
    BanStatus::Active
}

pub async fn active_account_ban(
    pool: &PgPool,
    user_id: i64,
    now_ms: i64,
) -> Result<Option<AccountBanRow>, sqlx::Error> {
    sqlx::query_as::<_, AccountBanRow>(
        r#"
        SELECT *
          FROM account_bans
         WHERE user_id = $1
           AND revoked_at_ms IS NULL
           AND (expires_at_ms IS NULL OR expires_at_ms > $2)
         ORDER BY created_at_ms DESC
         LIMIT 1
        "#,
    )
    .bind(user_id)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
}

pub async fn active_ip_ban(
    pool: &PgPool,
    ip: &str,
    now_ms: i64,
) -> Result<Option<IpBanRow>, sqlx::Error> {
    let Some(normalized) = normalize_exact_ip(ip) else {
        return Ok(None);
    };
    sqlx::query_as::<_, IpBanRow>(
        r#"
        SELECT *
          FROM ip_bans
         WHERE ip = $1
           AND revoked_at_ms IS NULL
           AND (expires_at_ms IS NULL OR expires_at_ms > $2)
         ORDER BY created_at_ms DESC
         LIMIT 1
        "#,
    )
    .bind(normalized)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_exact_ip_accepts_ips_and_rejects_cidr_or_garbage() {
        assert_eq!(
            normalize_exact_ip(" 203.0.113.9 "),
            Some("203.0.113.9".to_string())
        );
        assert_eq!(
            normalize_exact_ip("2001:db8::1"),
            Some(
                IpAddr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                    .to_string()
            )
        );
        assert_eq!(normalize_exact_ip("203.0.113.0/24"), None);
        assert_eq!(normalize_exact_ip("not-an-ip"), None);
    }

    #[test]
    fn classify_ban_treats_null_expiry_as_active_until_revoked() {
        assert_eq!(classify_ban(None, None, 1_000), BanStatus::Active);
        assert_eq!(classify_ban(Some(2_000), None, 1_000), BanStatus::Active);
        assert_eq!(classify_ban(Some(999), None, 1_000), BanStatus::Expired);
        assert_eq!(classify_ban(None, Some(900), 1_000), BanStatus::Revoked);
    }
}
