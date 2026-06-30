-- Slice 2: fill out users, then relationships, dm_channels, dm_members.
--
-- Why we split the users columns across migrations: 0001 needed users to
-- exist as an FK target for sessions/invite_codes. Now we add every other
-- column the app actually reads. Doing it in one CREATE in 0002 would have
-- forced 0001 to depend on the full users schema before sessions could land.
--
-- Soft-deletes keep history; reads everywhere filter `deleted_at_ms IS NULL`.

-- ─── users (extend with profile / preferences / 2fa / subscription) ───────
ALTER TABLE users
    ADD COLUMN display_name      text     NULL,
    ADD COLUMN avatar_url        text     NULL,         -- s3 key, NOT cdn url
    ADD COLUMN banner_url        text     NULL,
    ADD COLUMN bio               text     NULL,
    ADD COLUMN status_type       text     NOT NULL DEFAULT 'offline',
    ADD COLUMN email_verified    boolean  NOT NULL DEFAULT false,
    ADD COLUMN username_set      boolean  NOT NULL DEFAULT false,
    ADD COLUMN server_order      bigint[] NOT NULL DEFAULT '{}',
    ADD COLUMN favorite_order    bigint[] NOT NULL DEFAULT '{}',
    ADD COLUMN preferences       jsonb    NOT NULL DEFAULT '{}'::jsonb,
    -- 2FA: TOTP shared secret encrypted with AES-GCM (never plaintext).
    -- backup_code_hashes are HMAC-SHA256 hex of unused codes.
    ADD COLUMN totp_secret           bytea   NULL,
    ADD COLUMN totp_enabled_at_ms    bigint  NULL,
    ADD COLUMN backup_code_hashes    text[]  NOT NULL DEFAULT '{}',
    -- Subscription state. NULL tier == free.
    ADD COLUMN subscription_tier            text    NULL,
    ADD COLUMN subscription_expires_at_ms   bigint  NULL,
    ADD COLUMN subscribed                   boolean NOT NULL DEFAULT false,
    ADD COLUMN subscription_ring_style      text    NULL;

-- ─── relationships ────────────────────────────────────────────────────────
-- Friend graph. Composite PK + reciprocal queries via target_idx.
-- rel_type:
--   1 = friend (mutual)
--   2 = request_sent
--   3 = request_received
--   4 = blocked
CREATE TABLE relationships (
    user_id         bigint    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_id       bigint    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rel_type        smallint  NOT NULL,
    notes           text      NULL,
    nickname_color  text      NULL,
    created_at_ms   bigint    NOT NULL,
    PRIMARY KEY (user_id, target_id),
    CHECK (user_id <> target_id),
    CHECK (rel_type BETWEEN 1 AND 4)
);

-- Reverse-lookup: list everyone who has X as a target (block-check, etc.).
CREATE INDEX relationships_target_idx ON relationships (target_id);

-- ─── dm_channels + dm_members ────────────────────────────────────────────
-- DM channels share id-space with `channels` (slice 3) — a bigint id is
-- routed to whichever table claims it. We don't enforce the disjointness
-- with a CHECK because cross-table CHECK is awkward; the application layer
-- guarantees it via snowflake generation.
CREATE TABLE dm_channels (
    id              bigint    PRIMARY KEY,
    -- 1 = direct (2 members), 2 = group DM (3-10 members)
    type            smallint  NOT NULL CHECK (type IN (1, 2)),
    name            text      NULL,                 -- group only
    owner_id        bigint    NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at_ms   bigint    NOT NULL
);

CREATE TABLE dm_members (
    channel_id      bigint    NOT NULL REFERENCES dm_channels(id) ON DELETE CASCADE,
    user_id         bigint    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_color      text      NULL,
    joined_at_ms    bigint    NOT NULL,
    PRIMARY KEY (channel_id, user_id)
);

-- (user_id, channel_id) order so "list user's DMs" hits the index head.
CREATE INDEX dm_members_user_idx ON dm_members (user_id, channel_id);
