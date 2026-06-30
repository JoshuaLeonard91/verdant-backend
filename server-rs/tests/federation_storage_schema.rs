use verdant_server::federation::{
    maintenance::REPLAY_NONCE_CLEANUP_INTERVAL_SECS,
    storage::{
        FEDERATION_RUNTIME_MIGRATION, REPLAY_NONCE_PRUNE_BATCH_LIMIT, REPLAY_NONCE_PRUNE_SQL,
    },
};

#[test]
fn federation_runtime_migration_declares_isolated_runtime_tables() {
    for table in [
        "federation_peer_keys",
        "federation_peer_routes",
        "federation_remote_principals",
        "federation_remote_roles",
        "federation_remote_categories",
        "federation_remote_channels",
        "federation_remote_dms",
        "federation_replay_nonces",
        "federation_inbound_events",
        "federation_outbound_events",
    ] {
        let needle = format!("CREATE TABLE IF NOT EXISTS {table}");
        assert!(
            FEDERATION_RUNTIME_MIGRATION.contains(&needle),
            "missing table {table}"
        );
    }
}

#[test]
fn federation_runtime_migration_has_replay_and_idempotency_constraints() {
    for needle in [
        "CONSTRAINT federation_peer_keys_unique_key UNIQUE (peer_id, key_id)",
        "CONSTRAINT federation_peer_routes_unique_scope UNIQUE (peer_id, scope_type, scope_id)",
        "CONSTRAINT federation_remote_principals_unique_remote UNIQUE (home_peer_id, remote_user_id)",
        "CONSTRAINT federation_replay_nonces_unique_nonce UNIQUE (source_peer_id, nonce)",
        "CONSTRAINT federation_inbound_events_unique_remote UNIQUE (source_peer_id, remote_event_id)",
        "CONSTRAINT federation_outbound_events_unique_remote UNIQUE (destination_peer_id, event_id)",
        "CREATE INDEX IF NOT EXISTS idx_federation_outbound_events_retry",
    ] {
        assert!(
            FEDERATION_RUNTIME_MIGRATION.contains(needle),
            "missing replay/idempotency guardrail: {needle}"
        );
    }
}

#[test]
fn federation_replay_nonce_cleanup_is_bounded_and_started() {
    for needle in [
        "DELETE FROM federation_replay_nonces",
        "WHERE expires_at_ms < $1",
        "ORDER BY expires_at_ms ASC, id ASC",
        "LIMIT $2",
    ] {
        assert!(
            REPLAY_NONCE_PRUNE_SQL.contains(needle),
            "missing replay nonce cleanup guardrail: {needle}"
        );
    }
    assert_eq!(REPLAY_NONCE_PRUNE_BATCH_LIMIT, 10_000);
    assert_eq!(REPLAY_NONCE_CLEANUP_INTERVAL_SECS, 60 * 60);

    let main_rs = include_str!("../src/main.rs");
    assert!(
        main_rs
            .contains("verdant_server::federation::maintenance::spawn_replay_nonce_cleanup_task"),
        "server startup must schedule federation replay nonce cleanup"
    );
}

#[test]
fn federation_runtime_migration_declares_peer_routes_for_outbound_visibility() {
    for needle in [
        "CREATE TABLE IF NOT EXISTS federation_peer_routes",
        "peer_id text NOT NULL",
        "scope_type text NOT NULL CHECK (scope_type IN ('server','channel','dm','principal'))",
        "scope_id bigint NOT NULL",
        "status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked'))",
        "CONSTRAINT federation_peer_routes_unique_scope UNIQUE (peer_id, scope_type, scope_id)",
        "CREATE INDEX IF NOT EXISTS idx_federation_peer_routes_scope",
        "WHERE status = 'active'",
    ] {
        assert!(
            FEDERATION_RUNTIME_MIGRATION.contains(needle),
            "missing peer-route outbound visibility guardrail: {needle}"
        );
    }
}

#[test]
fn federation_runtime_migration_keeps_events_auditable_without_secret_specific_columns() {
    for needle in [
        "payload_hash text NOT NULL",
        "event_body_json jsonb NOT NULL",
        "char_length(event_body_json::text) <= 131072",
        "last_error_code text",
        "attempt_count integer NOT NULL DEFAULT 0",
        "accepted_at_ms bigint",
    ] {
        assert!(
            FEDERATION_RUNTIME_MIGRATION.contains(needle),
            "missing audit field: {needle}"
        );
    }

    assert!(
        !FEDERATION_RUNTIME_MIGRATION.contains("message_content"),
        "federation event records should use generic bounded event bodies, not message-specific content columns"
    );
}

#[test]
fn federation_runtime_migration_maps_remote_principals_and_messages_to_local_rows() {
    for needle in [
        "local_user_id bigint",
        "remote_username text",
        "CONSTRAINT federation_remote_principals_local_user_unique",
        "CREATE TABLE IF NOT EXISTS federation_remote_roles",
        "CONSTRAINT federation_remote_roles_unique_remote UNIQUE (source_peer_id, remote_role_id)",
        "CONSTRAINT federation_remote_roles_unique_local UNIQUE (local_role_id)",
        "CREATE TABLE IF NOT EXISTS federation_remote_categories",
        "CONSTRAINT federation_remote_categories_unique_remote UNIQUE (source_peer_id, remote_category_id)",
        "CONSTRAINT federation_remote_categories_unique_local UNIQUE (local_category_id)",
        "CREATE TABLE IF NOT EXISTS federation_remote_channels",
        "CONSTRAINT federation_remote_channels_unique_remote UNIQUE (source_peer_id, remote_channel_id)",
        "CONSTRAINT federation_remote_channels_unique_local UNIQUE (local_channel_id)",
        "local_server_id bigint NOT NULL REFERENCES servers(id)",
        "local_role_id bigint NOT NULL REFERENCES roles(id)",
        "local_category_id bigint NOT NULL REFERENCES categories(id)",
        "local_channel_id bigint NOT NULL REFERENCES channels(id)",
        "CREATE TABLE IF NOT EXISTS federation_remote_messages",
        "CONSTRAINT federation_remote_messages_unique_remote UNIQUE (source_peer_id, remote_message_id)",
        "CONSTRAINT federation_remote_messages_unique_local UNIQUE (local_message_id)",
        "CREATE TABLE IF NOT EXISTS federation_remote_dms",
        "CONSTRAINT federation_remote_dms_unique_remote UNIQUE (source_peer_id, remote_dm_id)",
        "local_remote_user_id bigint NOT NULL",
        "local_channel_id bigint NOT NULL",
        "local_author_user_id bigint NOT NULL",
    ] {
        assert!(
            FEDERATION_RUNTIME_MIGRATION.contains(needle),
            "missing remote/local mapping schema: {needle}"
        );
    }
}

#[test]
fn federation_runtime_migration_allows_supported_channel_category_event_kinds() {
    for needle in [
        "'category_create'",
        "'category_update'",
        "'category_delete'",
        "'channel_create'",
        "'channel_update'",
        "'channel_delete'",
        "'channel_reorder'",
        "'channel_override_set'",
        "'channel_override_delete'",
    ] {
        assert!(
            FEDERATION_RUNTIME_MIGRATION.contains(needle),
            "missing supported channel/category event kind in migration: {needle}"
        );
    }
}

#[test]
fn federation_runtime_migration_allows_supported_relationship_event_kinds() {
    for needle in [
        "'relationship_request'",
        "'relationship_accept'",
        "'relationship_remove'",
        "'relationship_block'",
    ] {
        assert!(
            FEDERATION_RUNTIME_MIGRATION.contains(needle),
            "missing supported relationship event kind in migration: {needle}"
        );
    }
}

#[test]
fn federation_runtime_migration_allows_supported_message_pin_event_kinds() {
    for needle in ["'message_pin'", "'message_unpin'"] {
        assert!(
            FEDERATION_RUNTIME_MIGRATION.contains(needle),
            "missing supported message pin event kind in migration: {needle}"
        );
    }
}

#[test]
fn federation_runtime_migration_allows_supported_membership_moderation_event_kinds() {
    for needle in [
        "'membership_remove'",
        "'membership_ban'",
        "'membership_unban'",
    ] {
        assert!(
            FEDERATION_RUNTIME_MIGRATION.contains(needle),
            "missing supported membership moderation event kind in migration: {needle}"
        );
    }
}

#[test]
fn federation_runtime_migration_allows_supported_role_definition_event_kinds() {
    for needle in [
        "'role_create'",
        "'role_update'",
        "'role_delete'",
        "'role_reorder'",
    ] {
        assert!(
            FEDERATION_RUNTIME_MIGRATION.contains(needle),
            "missing supported role definition event kind in migration: {needle}"
        );
    }
}

#[test]
fn federation_runtime_migration_allows_supported_member_role_event_kinds() {
    for needle in ["'member_role_assign'", "'member_role_remove'"] {
        assert!(
            FEDERATION_RUNTIME_MIGRATION.contains(needle),
            "missing supported member role event kind in migration: {needle}"
        );
    }
}

#[test]
fn federation_runtime_migration_allows_supported_emoji_event_kinds() {
    for needle in ["'emoji_rename'", "'emoji_delete'"] {
        assert!(
            FEDERATION_RUNTIME_MIGRATION.contains(needle),
            "missing supported emoji event kind in migration: {needle}"
        );
    }
}

#[test]
fn federation_runtime_migration_allows_supported_read_state_event_kind() {
    assert!(
        FEDERATION_RUNTIME_MIGRATION.contains("'read_state_update'"),
        "missing supported read state event kind in migration"
    );
}

#[test]
fn federation_runtime_migration_allows_supported_group_dm_event_kind() {
    assert!(
        FEDERATION_RUNTIME_MIGRATION.contains("'dm_group_create'"),
        "missing supported group DM event kind in migration"
    );
}
