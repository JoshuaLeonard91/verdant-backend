use std::collections::HashSet;

use sqlx::PgPool;

/// Risk level assessed during login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    None,
    Low,
    High,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::High => "high",
        }
    }
}

/// Assess login risk based on known devices and countries seen on
/// prior sessions for this user. PG-backed via `pg::sessions::list_for_user`.
pub async fn assess_login_risk(
    pool: &PgPool,
    user_id: i64,
    device_hash: &str,
    country: Option<&str>,
) -> RiskLevel {
    let sessions = crate::services::pg::sessions::list_for_user(pool, user_id)
        .await
        .unwrap_or_default();
    if sessions.is_empty() {
        return RiskLevel::None;
    }

    let mut devices: HashSet<String> = HashSet::new();
    let mut countries: HashSet<String> = HashSet::new();
    for s in sessions {
        if let Some(d) = s.device_hash {
            if !d.is_empty() {
                devices.insert(d);
            }
        }
        if let Some(c) = s.country {
            if !c.is_empty() {
                countries.insert(c);
            }
        }
    }

    if devices.is_empty() && countries.is_empty() {
        return RiskLevel::None;
    }

    let is_new_country = country.map(|c| !countries.contains(c)).unwrap_or(false);

    if is_new_country {
        return RiskLevel::High;
    }

    if !devices.contains(device_hash) {
        return RiskLevel::Low;
    }

    RiskLevel::None
}
