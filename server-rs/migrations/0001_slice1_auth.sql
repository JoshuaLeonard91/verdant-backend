-- Slice 1: sessions, registration / signup invite codes, password resets,
-- email verifications. Plus a *stub* `users` table so FKs can resolve;
-- 0002 fills in the user fields.
--
-- Snowflake IDs everywhere. Timestamps as bigint epoch-millis to match the
-- rest of the codebase (the WS protocol speaks epoch-millis). We do NOT use
-- timestamptz here because every consumer downstream wants i64 millis.
--
-- Cascading deletes on user_id so a user delete is a single row drop.

CREATE TABLE users (
    id              bigint      PRIMARY KEY,
    email           text        NOT NULL,
    password_hash   text        NOT NULL,
    username        text        NOT NULL,
    -- profile + preferences land in 0002. Stub the columns sessions need now.
    deleted_at_ms   bigint      NULL,
    created_at_ms   bigint      NOT NULL,
    updated_at_ms   bigint      NOT NULL
);

-- Lower-case unique indexes so email/username compares are case-insensitive
-- without forcing every query to LOWER() on the column.
CREATE UNIQUE INDEX users_email_lower_uniq    ON users ((lower(email)));
CREATE UNIQUE INDEX users_username_lower_uniq ON users ((lower(username)));
-- Soft-delete filter index: most reads filter out deleted users, so a
-- partial index on the active rows keeps lookups fast as the deleted set
-- grows.
CREATE INDEX users_active_idx ON users (id) WHERE deleted_at_ms IS NULL;

-- ─── sessions ─────────────────────────────────────────────────────────────
CREATE TABLE sessions (
    id                      bigint  PRIMARY KEY,
    user_id                 bigint  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- token_hash is sha-256 hex of the bearer token (we never store the
    -- token plaintext). UNIQUE so token validation hits a single row.
    token_hash              text    NOT NULL,
    -- single-use revocation token used by the "new device" email flow.
    revoke_token_hash       text    NULL,
    -- email verify code hash for high-risk auth, separate from the bearer.
    verify_token_hash       text    NULL,
    expires_at_ms           bigint  NOT NULL,    -- 0 = never
    verified                boolean NOT NULL DEFAULT false,
    ip                      text    NULL,
    user_agent              text    NULL,
    device_hash             text    NULL,
    city                    text    NULL,
    region                  text    NULL,
    country                 text    NULL,
    risk_level              text    NULL,
    verify_expires_at_ms    bigint  NULL,
    verify_attempts         integer NOT NULL DEFAULT 0,
    created_at_ms           bigint  NOT NULL,
    last_used_at_ms         bigint  NOT NULL
);

-- token_hash → session is the auth-middleware hot path; must be uniq + indexed.
CREATE UNIQUE INDEX sessions_token_hash_uniq ON sessions (token_hash);
-- revoke_token_hash is sparse (only set when an email revoke link is issued).
CREATE UNIQUE INDEX sessions_revoke_token_uniq
    ON sessions (revoke_token_hash) WHERE revoke_token_hash IS NOT NULL;
-- list-user's-sessions + revoke-all both fan out from user_id.
CREATE INDEX sessions_user_idx ON sessions (user_id);
-- Cleanup batches scan expiring sessions.
CREATE INDEX sessions_expires_idx ON sessions (expires_at_ms) WHERE expires_at_ms > 0;

-- ─── invite_codes (registration / signup keys, NOT server invites) ────────
-- Server invites live in their own table later (slice 7).
CREATE TABLE invite_codes (
    code            text    PRIMARY KEY,
    invited_by      bigint  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    used_by         bigint  NULL REFERENCES users(id) ON DELETE SET NULL,
    used_at_ms      bigint  NULL,
    created_at_ms   bigint  NOT NULL
);

CREATE INDEX invite_codes_invited_by_idx ON invite_codes (invited_by);

-- ─── password_resets ──────────────────────────────────────────────────────
CREATE TABLE password_resets (
    id              bigint  PRIMARY KEY,
    user_id         bigint  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      text    NOT NULL,
    expires_at_ms   bigint  NOT NULL,
    used_at_ms      bigint  NULL,
    created_at_ms   bigint  NOT NULL
);

CREATE UNIQUE INDEX password_resets_token_uniq ON password_resets (token_hash);
CREATE INDEX password_resets_user_idx ON password_resets (user_id);

-- ─── email_verifications ──────────────────────────────────────────────────
-- Used both for first-time email verification and for change-of-email flows
-- where the *target* email differs from the user's current email column.
CREATE TABLE email_verifications (
    id              bigint  PRIMARY KEY,
    user_id         bigint  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email           text    NOT NULL,
    token_hash      text    NOT NULL,
    expires_at_ms   bigint  NOT NULL,
    used_at_ms      bigint  NULL,
    created_at_ms   bigint  NOT NULL
);

CREATE UNIQUE INDEX email_verifications_token_uniq ON email_verifications (token_hash);
CREATE INDEX email_verifications_user_idx ON email_verifications (user_id);
