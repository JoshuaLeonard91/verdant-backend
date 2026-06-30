-- Slice 7: bots, bot_tokens, feeds, announcements, server_invites,
-- moderation_actions (bans/mutes/kicks), reports.
--
-- Lower-volume than messages. Standard tables, no partitioning.

-- ─── bots ─────────────────────────────────────────────────────────────────
CREATE TABLE bots (
    id              bigint    PRIMARY KEY,
    server_id       bigint    NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name            text      NOT NULL,
    avatar_url      text      NULL,         -- s3 key
    created_at_ms   bigint    NOT NULL
);

CREATE INDEX bots_server_idx ON bots (server_id);

-- ─── bot_tokens ──────────────────────────────────────────────────────────
-- One bot can have N tokens (rotation). Hash is unique so token validation
-- hits a single index probe.
CREATE TABLE bot_tokens (
    id              bigint    PRIMARY KEY,
    bot_id          bigint    NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
    token_hash      text      NOT NULL,
    name            text      NOT NULL,
    revoked_at_ms   bigint    NULL,
    last_used_at_ms bigint    NULL,
    created_at_ms   bigint    NOT NULL
);

CREATE UNIQUE INDEX bot_tokens_hash_uniq ON bot_tokens (token_hash);
CREATE INDEX bot_tokens_bot_idx ON bot_tokens (bot_id);

-- ─── feeds (announcement feeds inside servers) ───────────────────────────
-- publish_role_ids / visible_role_ids are bigint[] arrays. Empty = wide open
-- (publish: @everyone; visible: all server members). Postgres array
-- containment operators (`@>`, `&&`) make role-membership intersection
-- queries cheap once a GIN index is added if needed later.
CREATE TABLE feeds (
    id                  bigint    PRIMARY KEY,
    server_id           bigint    NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name                text      NOT NULL,
    description         text      NULL,
    icon                text      NULL,
    position            integer   NOT NULL DEFAULT 0,
    publish_role_ids    bigint[]  NOT NULL DEFAULT '{}',
    visible_role_ids    bigint[]  NOT NULL DEFAULT '{}',
    created_at_ms       bigint    NOT NULL
);

CREATE INDEX feeds_server_idx ON feeds (server_id, position);

-- ─── announcements ───────────────────────────────────────────────────────
-- content is opaque-to-server JSON (rendered client-side as rich cards).
-- server_id is denormalized so the "list this server's announcements" query
-- doesn't need to JOIN feeds.
CREATE TABLE announcements (
    id              bigint    PRIMARY KEY,
    feed_id         bigint    NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    server_id       bigint    NOT NULL,
    content         jsonb     NOT NULL,
    posted_by       bigint    NULL REFERENCES users(id),
    bot_id          bigint    NULL REFERENCES bots(id),
    updated_at_ms   bigint    NULL,
    deleted_at_ms   bigint    NULL,
    created_at_ms   bigint    NOT NULL
);

-- "list announcements in this feed, newest first, hide deleted" — partial
-- index keeps the active set tight even as soft-deletes grow.
CREATE INDEX announcements_feed_active_idx
    ON announcements (feed_id, created_at_ms DESC) WHERE deleted_at_ms IS NULL;
CREATE INDEX announcements_server_idx ON announcements (server_id, created_at_ms DESC);

-- ─── server_invites (invite codes for joining servers) ───────────────────
CREATE TABLE server_invites (
    code            text      PRIMARY KEY,
    server_id       bigint    NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    inviter_id      bigint    NOT NULL REFERENCES users(id),
    max_uses        integer   NOT NULL DEFAULT 0,    -- 0 = unlimited
    uses            integer   NOT NULL DEFAULT 0,
    expires_at_ms   bigint    NULL,
    created_at_ms   bigint    NOT NULL
);

CREATE INDEX server_invites_server_idx ON server_invites (server_id);
CREATE INDEX server_invites_expires_idx ON server_invites (expires_at_ms) WHERE expires_at_ms IS NOT NULL;

-- ─── moderation_actions (bans / mutes / kicks) ───────────────────────────
-- Live state lives in Redis (ban set / mute set per server) so the hot
-- "is X banned in server Y" check is O(1). PG is the durable record +
-- audit trail. expires_at_ms applies to mutes only; bans use NULL.
CREATE TABLE moderation_actions (
    id                  bigint    PRIMARY KEY,
    server_id           bigint    NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    target_user_id      bigint    NOT NULL REFERENCES users(id),
    action_type         text      NOT NULL CHECK (action_type IN ('ban','mute','kick')),
    reason              text      NULL,
    moderator_id        bigint    NOT NULL REFERENCES users(id),
    expires_at_ms       bigint    NULL,                 -- mutes only; null = permanent
    revoked_at_ms       bigint    NULL,                 -- unbans / unmutes set this
    created_at_ms       bigint    NOT NULL
);

-- "is user X currently banned/muted in server Y" — partial index on active.
CREATE INDEX moderation_active_target_idx
    ON moderation_actions (server_id, target_user_id, action_type)
    WHERE revoked_at_ms IS NULL;
-- "moderation log for this server, newest first"
CREATE INDEX moderation_server_log_idx
    ON moderation_actions (server_id, created_at_ms DESC);

-- ─── reports (user-submitted abuse reports) ──────────────────────────────
CREATE TABLE reports (
    id              bigint    PRIMARY KEY,
    reporter_id     bigint    NOT NULL REFERENCES users(id),
    target_type     text      NOT NULL,    -- 'message' | 'user' | 'server' | 'channel'
    target_id       bigint    NOT NULL,
    reason          text      NOT NULL,
    status          text      NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','reviewed','actioned','dismissed')),
    resolved_at_ms  bigint    NULL,
    created_at_ms   bigint    NOT NULL
);

-- "moderation queue: oldest pending first" — partial index for the inbox.
CREATE INDEX reports_pending_idx ON reports (created_at_ms) WHERE status = 'pending';
CREATE INDEX reports_reporter_idx ON reports (reporter_id, created_at_ms DESC);
