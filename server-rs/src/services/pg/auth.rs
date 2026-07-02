//! Auth side-tables: invite_codes (signup), password_resets, email_verifications.
//! Sessions live in `pg::sessions`.

use crate::services::field_crypto::{
    EncryptedField, FieldAad, FieldCryptoError, FieldEncryptionKeyring,
};
use sqlx::PgPool;

const EMAIL_VERIFICATION_TABLE: &str = "email_verifications";
const EMAIL_VERIFICATION_COLUMN: &str = "email";

// ─── invite_codes ────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct InviteCodeRow {
    pub code: String,
    pub invited_by: i64,
    pub used_by: Option<i64>,
    pub used_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

pub async fn invite_get(pool: &PgPool, code: &str) -> Result<Option<InviteCodeRow>, sqlx::Error> {
    sqlx::query_as::<_, InviteCodeRow>("SELECT * FROM invite_codes WHERE code = $1")
        .bind(code)
        .fetch_optional(pool)
        .await
}

pub async fn invite_insert(
    pool: &PgPool,
    code: &str,
    invited_by: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO invite_codes (code, invited_by, created_at_ms) VALUES ($1,$2,$3)")
        .bind(code)
        .bind(invited_by)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(())
}

/// Mark an invite consumed. Idempotent — does nothing if already used.
pub async fn invite_consume(
    pool: &PgPool,
    code: &str,
    used_by: i64,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE invite_codes SET used_by = $2, used_at_ms = $3 WHERE code = $1 AND used_by IS NULL",
    )
    .bind(code)
    .bind(used_by)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn invite_delete(pool: &PgPool, code: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM invite_codes WHERE code = $1")
        .bind(code)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn invite_list_by_user(
    pool: &PgPool,
    invited_by: i64,
) -> Result<Vec<InviteCodeRow>, sqlx::Error> {
    sqlx::query_as::<_, InviteCodeRow>(
        "SELECT * FROM invite_codes WHERE invited_by = $1 ORDER BY created_at_ms DESC",
    )
    .bind(invited_by)
    .fetch_all(pool)
    .await
}

// ─── password_resets ─────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct PasswordResetRow {
    pub id: i64,
    pub user_id: i64,
    pub token_hash: String,
    pub expires_at_ms: i64,
    pub used_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

pub async fn password_reset_insert(
    pool: &PgPool,
    id: i64,
    user_id: i64,
    token_hash: &str,
    expires_at_ms: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO password_resets (id, user_id, token_hash, expires_at_ms, created_at_ms)
        VALUES ($1,$2,$3,$4,$5)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at_ms)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn password_reset_by_token_hash(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<PasswordResetRow>, sqlx::Error> {
    sqlx::query_as::<_, PasswordResetRow>("SELECT * FROM password_resets WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(pool)
        .await
}

pub async fn password_reset_consume(
    pool: &PgPool,
    id: i64,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE password_resets SET used_at_ms = $2 WHERE id = $1 AND used_at_ms IS NULL",
    )
    .bind(id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

// ─── email_verifications ─────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct EmailVerifyRow {
    pub id: i64,
    pub user_id: i64,
    pub email: String,
    pub token_hash: String,
    pub expires_at_ms: i64,
    pub used_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct EmailVerifyRaw {
    id: i64,
    user_id: i64,
    email: String,
    email_ciphertext: Option<Vec<u8>>,
    email_nonce: Option<Vec<u8>>,
    email_key_version: Option<i16>,
    token_hash: String,
    expires_at_ms: i64,
    used_at_ms: Option<i64>,
    created_at_ms: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct EmailVerificationBackfillCandidate {
    id: i64,
    email: String,
}

const EMAIL_VERIFY_SELECT_COLS: &str = "
    id, user_id, email, email_ciphertext, email_nonce, email_key_version,
    token_hash, expires_at_ms, used_at_ms, created_at_ms
";

pub const EMAIL_VERIFICATION_BACKFILL_CLAIM_SQL: &str = r#"
    SELECT id, email
      FROM email_verifications
     WHERE email_ciphertext IS NULL
        OR email_nonce IS NULL
        OR email_key_version IS NULL
     ORDER BY id ASC
     LIMIT $1
     FOR UPDATE SKIP LOCKED
"#;

pub const EMAIL_VERIFICATION_BACKFILL_UPDATE_SQL: &str = r#"
    UPDATE email_verifications
       SET email_ciphertext = $2,
           email_nonce = $3,
           email_key_version = $4
     WHERE id = $1
"#;

fn email_verify_row_from_raw(
    raw: EmailVerifyRaw,
    keyring: Option<&FieldEncryptionKeyring>,
) -> Result<EmailVerifyRow, sqlx::Error> {
    let email = match keyring {
        Some(keyring) => {
            decrypt_email_verification_from_raw(keyring, &raw)?.unwrap_or_else(|| raw.email.clone())
        }
        None => raw.email.clone(),
    };
    Ok(EmailVerifyRow {
        id: raw.id,
        user_id: raw.user_id,
        email,
        token_hash: raw.token_hash,
        expires_at_ms: raw.expires_at_ms,
        used_at_ms: raw.used_at_ms,
        created_at_ms: raw.created_at_ms,
    })
}

fn decrypt_email_verification_from_raw(
    keyring: &FieldEncryptionKeyring,
    raw: &EmailVerifyRaw,
) -> Result<Option<String>, sqlx::Error> {
    let (Some(ciphertext), Some(nonce), Some(key_version)) = (
        raw.email_ciphertext.as_ref(),
        raw.email_nonce.as_ref(),
        raw.email_key_version,
    ) else {
        return Ok(None);
    };
    let nonce: [u8; 12] = nonce
        .as_slice()
        .try_into()
        .map_err(|_| sqlx::Error::Protocol("invalid encrypted email verification nonce".into()))?;
    let encrypted =
        EncryptedField::from_parts(key_version, nonce, ciphertext.clone()).map_err(|_| {
            sqlx::Error::Protocol("invalid encrypted email verification metadata".into())
        })?;
    let bytes = keyring
        .decrypt_bytes(&encrypted, &email_verification_aad(raw.id))
        .map_err(|_| {
            sqlx::Error::Protocol("encrypted email verification decryption failed".into())
        })?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| sqlx::Error::Protocol("encrypted email verification is not utf-8".into()))
}

fn field_crypto_sql_error(context: &'static str, err: FieldCryptoError) -> sqlx::Error {
    sqlx::Error::Protocol(format!("{context}: {err}"))
}

pub async fn email_verify_insert(
    pool: &PgPool,
    id: i64,
    user_id: i64,
    email: &str,
    token_hash: &str,
    expires_at_ms: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    email_verify_insert_with_crypto(
        pool,
        id,
        user_id,
        email,
        token_hash,
        expires_at_ms,
        now_ms,
        None,
    )
    .await
}

pub async fn email_verify_insert_with_crypto(
    pool: &PgPool,
    id: i64,
    user_id: i64,
    email: &str,
    token_hash: &str,
    expires_at_ms: i64,
    now_ms: i64,
    keyring: Option<&FieldEncryptionKeyring>,
) -> Result<(), sqlx::Error> {
    let encrypted_email = keyring
        .map(|keyring| prepare_email_verification_encryption(keyring, id, email))
        .transpose()
        .map_err(|err| field_crypto_sql_error("could not encrypt email verification", err))?;
    let email_ciphertext: Option<&[u8]> = encrypted_email.as_ref().map(|v| v.ciphertext());
    let email_nonce: Option<&[u8]> = encrypted_email.as_ref().map(|v| v.nonce().as_slice());
    let email_key_version = encrypted_email.as_ref().map(|v| v.key_version());

    sqlx::query(
        r#"
        INSERT INTO email_verifications
            (id, user_id, email, email_ciphertext, email_nonce, email_key_version,
             token_hash, expires_at_ms, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(email)
    .bind(email_ciphertext)
    .bind(email_nonce)
    .bind(email_key_version)
    .bind(token_hash)
    .bind(expires_at_ms)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn email_verify_by_token_hash(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<EmailVerifyRow>, sqlx::Error> {
    email_verify_by_token_hash_with_crypto(pool, token_hash, None).await
}

pub async fn email_verify_by_token_hash_with_crypto(
    pool: &PgPool,
    token_hash: &str,
    keyring: Option<&FieldEncryptionKeyring>,
) -> Result<Option<EmailVerifyRow>, sqlx::Error> {
    let raw = sqlx::query_as::<_, EmailVerifyRaw>(&format!(
        "SELECT {EMAIL_VERIFY_SELECT_COLS} FROM email_verifications WHERE token_hash = $1"
    ))
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    raw.map(|row| email_verify_row_from_raw(row, keyring))
        .transpose()
}

pub async fn email_verify_consume(
    pool: &PgPool,
    id: i64,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE email_verifications SET used_at_ms = $2 WHERE id = $1 AND used_at_ms IS NULL",
    )
    .bind(id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn backfill_encrypted_email_verifications_batch(
    pool: &PgPool,
    keyring: &FieldEncryptionKeyring,
    requested_limit: i64,
) -> Result<usize, sqlx::Error> {
    let limit = email_verification_backfill_batch_limit(requested_limit);
    let mut tx = pool.begin().await?;
    let candidates = sqlx::query_as::<_, EmailVerificationBackfillCandidate>(
        EMAIL_VERIFICATION_BACKFILL_CLAIM_SQL,
    )
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;

    for candidate in &candidates {
        let encrypted_email =
            prepare_email_verification_encryption(keyring, candidate.id, &candidate.email)
                .map_err(|err| {
                    field_crypto_sql_error("could not encrypt email verification", err)
                })?;
        sqlx::query(EMAIL_VERIFICATION_BACKFILL_UPDATE_SQL)
            .bind(candidate.id)
            .bind(encrypted_email.ciphertext())
            .bind(encrypted_email.nonce().as_slice())
            .bind(encrypted_email.key_version())
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(candidates.len())
}

fn email_verification_backfill_batch_limit(requested_limit: i64) -> i64 {
    requested_limit.clamp(1, 1_000)
}

#[derive(Debug, Clone)]
pub struct EncryptedEmailVerificationWrite {
    field: EncryptedField,
}

impl EncryptedEmailVerificationWrite {
    pub fn key_version(&self) -> i16 {
        self.field.key_version()
    }

    pub fn nonce(&self) -> &[u8; 12] {
        self.field.nonce()
    }

    pub fn ciphertext(&self) -> &[u8] {
        self.field.ciphertext()
    }
}

fn email_verification_aad(row_id: i64) -> FieldAad {
    FieldAad::new(EMAIL_VERIFICATION_TABLE, EMAIL_VERIFICATION_COLUMN, row_id)
}

fn prepare_email_verification_encryption(
    keyring: &FieldEncryptionKeyring,
    row_id: i64,
    email: &str,
) -> Result<EncryptedEmailVerificationWrite, FieldCryptoError> {
    let field = keyring.encrypt_bytes(email.as_bytes(), &email_verification_aad(row_id))?;
    Ok(EncryptedEmailVerificationWrite { field })
}

#[cfg(test)]
fn decrypt_email_verification_field(
    keyring: &FieldEncryptionKeyring,
    row_id: i64,
    encrypted: &EncryptedEmailVerificationWrite,
) -> Result<String, FieldCryptoError> {
    let bytes = keyring.decrypt_bytes(&encrypted.field, &email_verification_aad(row_id))?;
    String::from_utf8(bytes).map_err(|_| FieldCryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::field_crypto::FieldEncryptionKeyring;

    const FIELD_KEY: &str = "b55f7f6657f90b0771c71f56ab29a70fd23c9e247a57de9532a53bc55790d251";

    #[test]
    fn email_verification_crypto_write_hides_plaintext_and_decrypts_at_service_boundary() {
        let keyring = FieldEncryptionKeyring::from_hex_secret(FIELD_KEY, 1).expect("field key");
        let encrypted =
            prepare_email_verification_encryption(&keyring, 42, "VerifyTarget@Example.com")
                .expect("encrypted email verification");

        assert!(
            !encrypted
                .ciphertext()
                .windows(6)
                .any(|part| part == b"Verify")
        );

        let plaintext = decrypt_email_verification_field(&keyring, 42, &encrypted)
            .expect("decrypted email verification");
        assert_eq!(plaintext, "VerifyTarget@Example.com");
    }

    #[test]
    fn email_verification_decrypt_requires_matching_row_id_aad() {
        let keyring = FieldEncryptionKeyring::from_hex_secret(FIELD_KEY, 1).expect("field key");
        let encrypted = prepare_email_verification_encryption(&keyring, 42, "josh@example.com")
            .expect("encrypted email verification");

        assert!(decrypt_email_verification_field(&keyring, 43, &encrypted).is_err());
    }
}
