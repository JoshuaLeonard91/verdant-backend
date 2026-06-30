//! PostgreSQL row-level security runtime context.
//!
//! RLS policies read `app.user_id` from the current transaction. Always set
//! it with `set_config(..., is_local := true)` inside a transaction so pooled
//! connections cannot leak one user's context into another request.

use sqlx::{PgPool, Postgres, Transaction};

pub const RLS_MIGRATION: &str = include_str!("../../migrations/0023_postgres_rls.sql");

pub const RLS_PROTECTED_TABLES: &[&str] = &[
    "servers",
    "server_members",
    "categories",
    "channels",
    "channel_overrides",
    "roles",
    "member_roles",
    "emojis",
    "pinned_messages",
    "dm_channels",
    "dm_members",
    "relationships",
    "messages",
    "attachments",
    "reactions",
    "read_states",
    "bots",
    "feeds",
    "announcements",
    "moderation_actions",
    "reports",
];

pub async fn begin_user_transaction(
    pool: &PgPool,
    user_id: i64,
) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    set_user_id(&mut tx, user_id).await?;
    Ok(tx)
}

pub async fn set_user_id(
    tx: &mut Transaction<'_, Postgres>,
    user_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('app.user_id', $1, true)")
        .bind(user_id.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Kept for older call sites. Migrations are applied by sqlx at boot.
pub async fn apply_migrations() {}

#[cfg(test)]
mod tests {
    use super::{RLS_MIGRATION, RLS_PROTECTED_TABLES};

    #[test]
    fn rls_migration_enables_expected_tables() {
        for table in RLS_PROTECTED_TABLES {
            let needle = format!("ALTER TABLE IF EXISTS {table} ENABLE ROW LEVEL SECURITY");
            assert!(
                RLS_MIGRATION.contains(&needle),
                "missing RLS enable statement for {table}"
            );
        }
    }

    #[test]
    fn rls_migration_has_channel_and_message_guardrails() {
        for needle in [
            "CREATE OR REPLACE FUNCTION app.user_channel_permissions",
            "CREATE OR REPLACE FUNCTION app.can_view_channel",
            "CREATE OR REPLACE FUNCTION app.can_view_moderation_actions",
            "CREATE POLICY rls_channels_view_select",
            "CREATE POLICY rls_messages_access_select",
            "CREATE POLICY rls_messages_author_insert",
            "CREATE POLICY rls_messages_author_or_moderator_update",
            "CREATE POLICY rls_reactions_message_access_select",
            "CREATE POLICY rls_read_states_own_rows",
        ] {
            assert!(RLS_MIGRATION.contains(needle), "missing {needle}");
        }
    }

    #[test]
    fn rls_migration_does_not_force_owner_before_runtime_cutover() {
        assert!(
            !RLS_MIGRATION.contains("FORCE ROW LEVEL SECURITY"),
            "FORCE RLS would break current owner-pool background and migration paths"
        );
    }
}
