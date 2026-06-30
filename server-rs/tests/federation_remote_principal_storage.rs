use verdant_server::federation::storage::REMOTE_PRINCIPAL_UPSERT_SQL;

#[test]
fn remote_principal_upsert_sql_creates_disabled_projection_and_mapping() {
    for needle in [
        "INSERT INTO users",
        "password_hash",
        "ON CONFLICT DO NOTHING",
        "SELECT id FROM users WHERE lower(email) = lower($1)",
        "INSERT INTO federation_remote_principals",
        "remote_username",
        "ON CONFLICT ON CONSTRAINT federation_remote_principals_unique_remote DO UPDATE",
        "COALESCE(federation_remote_principals.local_user_id, EXCLUDED.local_user_id)",
        "RETURNING local_user_id",
    ] {
        assert!(
            REMOTE_PRINCIPAL_UPSERT_SQL.contains(needle),
            "missing remote-principal upsert guardrail: {needle}"
        );
    }
}
