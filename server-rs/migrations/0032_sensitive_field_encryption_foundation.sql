-- App-level field encryption runway for sensitive identity fields.
--
-- These columns are nullable so existing deployments can migrate safely.
-- A later migration/backfill will dual-write encrypted values, verify counts,
-- switch reads/lookups to encrypted columns plus blind indexes, then remove
-- plaintext storage where the product can tolerate it.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_ciphertext bytea NULL,
    ADD COLUMN IF NOT EXISTS email_nonce bytea NULL,
    ADD COLUMN IF NOT EXISTS email_key_version smallint NULL,
    ADD COLUMN IF NOT EXISTS email_blind_index text NULL,
    ADD CONSTRAINT users_email_encrypted_shape CHECK (
        (
            email_ciphertext IS NULL
            AND email_nonce IS NULL
            AND email_key_version IS NULL
            AND email_blind_index IS NULL
        )
        OR (
            email_ciphertext IS NOT NULL
            AND email_nonce IS NOT NULL
            AND length(email_nonce) = 12
            AND email_key_version IS NOT NULL
            AND email_key_version > 0
            AND email_blind_index IS NOT NULL
            AND char_length(email_blind_index) = 64
        )
    );

CREATE UNIQUE INDEX IF NOT EXISTS users_email_blind_index_uniq
    ON users (email_blind_index)
    WHERE email_blind_index IS NOT NULL;

ALTER TABLE email_verifications
    ADD COLUMN IF NOT EXISTS email_ciphertext bytea NULL,
    ADD COLUMN IF NOT EXISTS email_nonce bytea NULL,
    ADD COLUMN IF NOT EXISTS email_key_version smallint NULL,
    ADD CONSTRAINT email_verifications_email_encrypted_shape CHECK (
        (
            email_ciphertext IS NULL
            AND email_nonce IS NULL
            AND email_key_version IS NULL
        )
        OR (
            email_ciphertext IS NOT NULL
            AND email_nonce IS NOT NULL
            AND length(email_nonce) = 12
            AND email_key_version IS NOT NULL
            AND email_key_version > 0
        )
    );
