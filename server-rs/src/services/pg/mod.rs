//! Postgres storage layer.
//!
//! One submodule per entity slice. Each function takes `&PgPool` (or
//! `&mut PgConnection` for tx-bound work) plus typed args, and returns
//! `Result<T, sqlx::Error>`. Handlers map `sqlx::Error` to `AppError`
//! at their boundary — keeping the storage layer free of HTTP types.
//!
//! Batching: hot-path writes use `INSERT ... VALUES ($1,$2),($3,$4)...`
//! via sqlx's `QueryBuilder` so N rows take one round trip. Reads with
//! multiple ids use `WHERE x = ANY($1::bigint[])`.
//!
//! Timestamps: every column is `bigint` epoch-millis (matches the
//! Verdant snowflake epoch and the existing wire protocol). Handler-
//! facing Row types use `chrono::DateTime<Utc>`, so the PG layer
//! converts at the boundary via `ms_to_dt` / `dt_to_ms`.
//!
//! No business logic lives here. Handlers stay in handlers/, services
//! stay in services/. This module is a typed query layer only.

pub mod account_links;
pub mod announcements;
pub mod app_bans;
pub mod attachments;
pub mod audit;
pub mod auth;
pub mod bot_outbox;
pub mod bots;
pub mod categories;
pub mod channels;
pub mod custom_expression_assets;
pub mod dms;
pub mod emojis;
pub mod federation;
pub mod feeds;
pub mod login;
pub mod messages;
pub mod moderation;
pub mod reactions;
pub mod read_states;
pub mod relationships;
pub mod roles;
pub mod server_invites;
pub mod servers;
pub mod sessions;
pub mod stickers;
pub mod subscription;
pub mod users;

use chrono::{DateTime, Utc};

/// Convert epoch millis (the PG column shape) into a `chrono` UTC
/// timestamp (the handler-facing shape). Negative or out-of-range
/// values fold to `UNIX_EPOCH` rather than panicking — easier to
/// debug than a runtime crash on a bad row.
#[inline]
pub fn ms_to_dt(ms: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp_millis(ms).unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
}

/// Optional variant.
#[inline]
pub fn ms_to_dt_opt(ms: Option<i64>) -> Option<DateTime<Utc>> {
    ms.and_then(DateTime::<Utc>::from_timestamp_millis)
}

/// Convert a chrono UTC timestamp into epoch millis. Used when handler
/// code constructs Row-typed values that need to flow into PG inserts.
#[inline]
pub fn dt_to_ms(dt: DateTime<Utc>) -> i64 {
    dt.timestamp_millis()
}

#[inline]
pub fn dt_to_ms_opt(dt: Option<DateTime<Utc>>) -> Option<i64> {
    dt.map(dt_to_ms)
}

/// Current time in epoch millis. The whole codebase uses
/// `Utc::now().timestamp_millis()`; centralising it here lets test
/// fixtures stub if/when needed.
#[inline]
pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}
