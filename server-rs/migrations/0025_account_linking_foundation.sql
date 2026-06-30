-- Account linking foundation.
--
-- This stores user-consented identity mappings only. It does not merge
-- sessions, roles, messages, uploads, moderation, billing, Redis/NATS, or any
-- official runtime authority across instances.

CREATE TABLE IF NOT EXISTS account_link_intents (
    id bigint PRIMARY KEY,
    local_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer_instance_id text NOT NULL CHECK (char_length(issuer_instance_id) BETWEEN 1 AND 128),
    audience_instance_id text NOT NULL CHECK (char_length(audience_instance_id) BETWEEN 1 AND 128),
    state_hash text NOT NULL UNIQUE,
    requested_scopes text[] NOT NULL DEFAULT ARRAY[]::text[],
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'cancelled', 'expired')),
    expires_at_ms bigint NOT NULL,
    completed_at_ms bigint,
    cancelled_at_ms bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_account_link_intents_user_status
    ON account_link_intents (local_user_id, status, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS idx_account_link_intents_expires
    ON account_link_intents (expires_at_ms)
    WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS account_links (
    id bigint PRIMARY KEY,
    local_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider text NOT NULL DEFAULT 'official' CHECK (char_length(provider) BETWEEN 1 AND 64),
    issuer_instance_id text NOT NULL CHECK (char_length(issuer_instance_id) BETWEEN 1 AND 128),
    issuer_user_id text NOT NULL CHECK (char_length(issuer_user_id) BETWEEN 1 AND 128),
    issuer_username text CHECK (issuer_username IS NULL OR char_length(issuer_username) <= 64),
    issuer_display_name text CHECK (issuer_display_name IS NULL OR char_length(issuer_display_name) <= 120),
    scopes text[] NOT NULL DEFAULT ARRAY[]::text[],
    status text NOT NULL DEFAULT 'linked' CHECK (status IN ('linked', 'revoked')),
    proof_jti_hash text,
    linked_at_ms bigint NOT NULL,
    revoked_at_ms bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_account_links_local_user
    ON account_links (local_user_id, updated_at_ms DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_account_links_active_local_provider
    ON account_links (local_user_id, provider, issuer_instance_id)
    WHERE revoked_at_ms IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_account_links_active_remote_identity
    ON account_links (provider, issuer_instance_id, issuer_user_id)
    WHERE revoked_at_ms IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_account_links_proof_jti_hash
    ON account_links (proof_jti_hash)
    WHERE proof_jti_hash IS NOT NULL;
