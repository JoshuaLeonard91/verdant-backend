use sqlx::{PgPool, postgres::PgPoolOptions};
use verdant_server::services::{
    field_crypto::FieldEncryptionKeyring,
    pg::{
        auth,
        users::{self, InsertUser},
    },
};

const TEST_KEY: &str = "b55f7f6657f90b0771c71f56ab29a70fd23c9e247a57de9532a53bc55790d251";
const WRONG_KEY: &str = "a55f7f6657f90b0771c71f56ab29a70fd23c9e247a57de9532a53bc55790d252";

async fn test_pool() -> Result<Option<PgPool>, Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("VERDANT_FIELD_CRYPTO_TEST_DATABASE_URL").ok() else {
        eprintln!(
            "skipping field encryption storage test: VERDANT_FIELD_CRYPTO_TEST_DATABASE_URL is not set"
        );
        return Ok(None);
    };
    assert_scratch_database_url(&database_url)?;

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await?;
    let migrations_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    sqlx::migrate::Migrator::new(migrations_path)
        .await?
        .run(&pool)
        .await?;
    Ok(Some(pool))
}

fn assert_scratch_database_url(database_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(database_url)?;
    let db_name = parsed.path().trim_start_matches('/');
    if !db_name.contains("verdant_field_crypto_test") {
        return Err("field encryption storage tests require a scratch database name containing verdant_field_crypto_test".into());
    }

    let local_host = matches!(
        parsed.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("::1")
    );
    let allow_nonlocal = std::env::var("VERDANT_ALLOW_NONLOCAL_FIELD_CRYPTO_TEST_DB")
        .ok()
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    if !local_host && !allow_nonlocal {
        return Err("field encryption storage tests refuse non-local databases unless VERDANT_ALLOW_NONLOCAL_FIELD_CRYPTO_TEST_DB=1".into());
    }
    Ok(())
}

fn next_test_id(offset: i64) -> i64 {
    chrono::Utc::now().timestamp_millis() * 1000 + offset
}

#[tokio::test]
async fn encrypted_user_email_is_stored_and_resolved_through_blind_index()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = test_pool().await? else {
        return Ok(());
    };
    let keyring = FieldEncryptionKeyring::from_hex_secret(TEST_KEY, 1)?;
    let wrong_keyring = FieldEncryptionKeyring::from_hex_secret(WRONG_KEY, 1)?;
    let user_id = next_test_id(1);
    let email = format!("FieldCrypto+{user_id}@Example.com");

    users::insert_with_crypto(
        &pool,
        InsertUser {
            id: user_id,
            email: &email,
            password_hash: "argon2id-test-hash",
            username: &format!("field_crypto_{user_id}"),
            display_name: None,
            username_set: true,
            email_verified: true,
            now_ms: chrono::Utc::now().timestamp_millis(),
        },
        Some(&keyring),
    )
    .await?;

    let raw: (String, Vec<u8>, Vec<u8>, i16, String) = sqlx::query_as(
        "SELECT email, email_ciphertext, email_nonce, email_key_version, email_blind_index
           FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(raw.0, email);
    assert_eq!(raw.2.len(), 12);
    assert_eq!(raw.3, 1);
    assert_eq!(raw.4.len(), 64);
    assert!(
        !raw.1
            .windows(email.len())
            .any(|part| part == email.as_bytes())
    );

    let found =
        users::by_email_lower_with_crypto(&pool, &email.to_ascii_lowercase(), Some(&keyring))
            .await?
            .expect("encrypted email lookup");
    assert_eq!(found.id, user_id);
    assert_eq!(found.email, email);

    assert!(
        users::by_id_with_crypto(&pool, user_id, Some(&wrong_keyring))
            .await
            .is_err(),
        "wrong key must not silently return encrypted email rows"
    );

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await?;
    Ok(())
}

#[tokio::test]
async fn legacy_user_email_rows_can_be_backfilled_without_changing_plaintext_column()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = test_pool().await? else {
        return Ok(());
    };
    let keyring = FieldEncryptionKeyring::from_hex_secret(TEST_KEY, 1)?;
    let user_id = next_test_id(2);
    let email = format!("Backfill+{user_id}@Example.com");

    users::insert(
        &pool,
        InsertUser {
            id: user_id,
            email: &email,
            password_hash: "argon2id-test-hash",
            username: &format!("field_backfill_{user_id}"),
            display_name: None,
            username_set: true,
            email_verified: true,
            now_ms: chrono::Utc::now().timestamp_millis(),
        },
    )
    .await?;

    let count = users::backfill_encrypted_email_batch(&pool, &keyring, 100).await?;
    assert!(count >= 1);

    let raw: (String, Vec<u8>, Vec<u8>, i16, String) = sqlx::query_as(
        "SELECT email, email_ciphertext, email_nonce, email_key_version, email_blind_index
           FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(raw.0, email);
    assert_eq!(raw.2.len(), 12);
    assert_eq!(raw.3, 1);
    assert_eq!(raw.4.len(), 64);

    let found = users::by_email_lower_with_crypto(&pool, &email, Some(&keyring))
        .await?
        .expect("backfilled email lookup");
    assert_eq!(found.id, user_id);
    assert_eq!(found.email, email);

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await?;
    Ok(())
}

#[tokio::test]
async fn encrypted_email_verification_is_stored_and_resolved_by_token_hash()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = test_pool().await? else {
        return Ok(());
    };
    let keyring = FieldEncryptionKeyring::from_hex_secret(TEST_KEY, 1)?;
    let wrong_keyring = FieldEncryptionKeyring::from_hex_secret(WRONG_KEY, 1)?;
    let user_id = next_test_id(3);
    let verification_id = next_test_id(4);
    let email = format!("VerifyCrypto+{verification_id}@Example.com");
    let token_hash = format!("verify-token-{verification_id}");

    users::insert_with_crypto(
        &pool,
        InsertUser {
            id: user_id,
            email: &email,
            password_hash: "argon2id-test-hash",
            username: &format!("field_verify_{user_id}"),
            display_name: None,
            username_set: true,
            email_verified: false,
            now_ms: chrono::Utc::now().timestamp_millis(),
        },
        Some(&keyring),
    )
    .await?;

    auth::email_verify_insert_with_crypto(
        &pool,
        verification_id,
        user_id,
        &email,
        &token_hash,
        chrono::Utc::now().timestamp_millis() + 86_400_000,
        chrono::Utc::now().timestamp_millis(),
        Some(&keyring),
    )
    .await?;

    let raw: (String, Vec<u8>, Vec<u8>, i16) = sqlx::query_as(
        "SELECT email, email_ciphertext, email_nonce, email_key_version
           FROM email_verifications WHERE id = $1",
    )
    .bind(verification_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(raw.0, email);
    assert_eq!(raw.2.len(), 12);
    assert_eq!(raw.3, 1);
    assert!(
        !raw.1
            .windows(email.len())
            .any(|part| part == email.as_bytes())
    );

    let found = auth::email_verify_by_token_hash_with_crypto(&pool, &token_hash, Some(&keyring))
        .await?
        .expect("encrypted email verification lookup");
    assert_eq!(found.id, verification_id);
    assert_eq!(found.user_id, user_id);
    assert_eq!(found.email, email);

    assert!(
        auth::email_verify_by_token_hash_with_crypto(&pool, &token_hash, Some(&wrong_keyring))
            .await
            .is_err(),
        "wrong key must not silently return encrypted email verification rows"
    );

    sqlx::query("DELETE FROM email_verifications WHERE id = $1")
        .bind(verification_id)
        .execute(&pool)
        .await?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await?;
    Ok(())
}

#[tokio::test]
async fn legacy_email_verification_rows_can_be_backfilled_without_changing_plaintext_column()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = test_pool().await? else {
        return Ok(());
    };
    let keyring = FieldEncryptionKeyring::from_hex_secret(TEST_KEY, 1)?;
    let user_id = next_test_id(5);
    let verification_id = next_test_id(6);
    let email = format!("VerifyBackfill+{verification_id}@Example.com");
    let token_hash = format!("verify-backfill-token-{verification_id}");

    users::insert(
        &pool,
        InsertUser {
            id: user_id,
            email: &email,
            password_hash: "argon2id-test-hash",
            username: &format!("field_verify_backfill_{user_id}"),
            display_name: None,
            username_set: true,
            email_verified: false,
            now_ms: chrono::Utc::now().timestamp_millis(),
        },
    )
    .await?;

    auth::email_verify_insert(
        &pool,
        verification_id,
        user_id,
        &email,
        &token_hash,
        chrono::Utc::now().timestamp_millis() + 86_400_000,
        chrono::Utc::now().timestamp_millis(),
    )
    .await?;

    let count = auth::backfill_encrypted_email_verifications_batch(&pool, &keyring, 100).await?;
    assert!(count >= 1);

    let raw: (String, Vec<u8>, Vec<u8>, i16) = sqlx::query_as(
        "SELECT email, email_ciphertext, email_nonce, email_key_version
           FROM email_verifications WHERE id = $1",
    )
    .bind(verification_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(raw.0, email);
    assert_eq!(raw.2.len(), 12);
    assert_eq!(raw.3, 1);

    let found = auth::email_verify_by_token_hash_with_crypto(&pool, &token_hash, Some(&keyring))
        .await?
        .expect("backfilled email verification lookup");
    assert_eq!(found.id, verification_id);
    assert_eq!(found.email, email);

    sqlx::query("DELETE FROM email_verifications WHERE id = $1")
        .bind(verification_id)
        .execute(&pool)
        .await?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await?;
    Ok(())
}
