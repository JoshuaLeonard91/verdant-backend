-- Slice 3: servers + members + categories + channels + channel_overrides
-- + roles + member_roles + emojis + pinned_messages.
--
-- This is the bulk of the per-server state graph. Permissions cache reads
-- 6 of these tables at IDENTIFY warmup, so indexes are tuned for the
-- (server_id) → list, (channel_id) → row access patterns.

-- ─── servers ─────────────────────────────────────────────────────────────
CREATE TABLE servers (
    id                              bigint  PRIMARY KEY,
    name                            text    NOT NULL,
    owner_id                        bigint  NOT NULL REFERENCES users(id),
    icon_url                        text    NULL,
    banner_url                      text    NULL,
    accent_color                    text    NULL,            -- '#RRGGBB'
    banner_offset_y                 integer NOT NULL DEFAULT 50,
    voice_bitrate                   integer NOT NULL DEFAULT 64000,
    welcome_channel_id              bigint  NULL,            -- soft FK; channel may be deleted
    announce_channel_id             bigint  NULL,
    welcome_message                 text    NULL,
    welcome_screen_description      text    NULL,
    welcome_screen_channels         jsonb   NOT NULL DEFAULT '[]'::jsonb,
    emoji_version                   integer NOT NULL DEFAULT 0,
    deleted_at_ms                   bigint  NULL,
    created_at_ms                   bigint  NOT NULL
);

-- Active-only filter: 99% of reads care about live servers.
CREATE INDEX servers_active_idx ON servers (id) WHERE deleted_at_ms IS NULL;

-- ─── server_members (M:N users ↔ servers) ────────────────────────────────
-- Replaces VDB_TABLE_SERVER_MEMBERS_BY_USER and ..._BY_SERVER (one table,
-- two indexes covers both directions).
CREATE TABLE server_members (
    server_id       bigint  NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id         bigint  NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    joined_at_ms    bigint  NOT NULL,
    PRIMARY KEY (server_id, user_id)
);

-- "list user's servers" — leading user_id covers it.
CREATE INDEX server_members_user_idx ON server_members (user_id, server_id);

-- ─── categories (sidebar grouping) ───────────────────────────────────────
CREATE TABLE categories (
    id              bigint    PRIMARY KEY,
    server_id       bigint    NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name            text      NOT NULL,
    position        integer   NOT NULL DEFAULT 0,
    emoji           text      NULL,
    created_at_ms   bigint    NOT NULL
);

CREATE INDEX categories_server_pos_idx ON categories (server_id, position);

-- ─── channels ────────────────────────────────────────────────────────────
-- type:
--   0 = text
--   1 = direct DM      (lives in dm_channels; this is the discriminator)
--   2 = group DM       (lives in dm_channels)
--   3 = voice
-- For server text/voice channels, server_id is set. For DM rows in this
-- table — there are none; DMs use dm_channels.
CREATE TABLE channels (
    id                bigint    PRIMARY KEY,
    server_id         bigint    NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    type              smallint  NOT NULL,
    name              text      NULL,
    topic             text      NULL,
    position          integer   NOT NULL DEFAULT 0,
    category_id       bigint    NULL REFERENCES categories(id) ON DELETE SET NULL,
    read_only         boolean   NOT NULL DEFAULT false,
    slowmode_seconds  integer   NOT NULL DEFAULT 0,
    created_at_ms     bigint    NOT NULL
);

CREATE INDEX channels_server_pos_idx ON channels (server_id, position);

-- ─── channel_overrides (Discord-style per-role overrides on channels) ────
CREATE TABLE channel_overrides (
    channel_id      bigint  NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    role_id         bigint  NOT NULL,                      -- FK enforced after roles below
    allow_bits      bigint  NOT NULL DEFAULT 0,
    deny_bits       bigint  NOT NULL DEFAULT 0,
    PRIMARY KEY (channel_id, role_id)
);

-- ─── roles ───────────────────────────────────────────────────────────────
CREATE TABLE roles (
    id              bigint    PRIMARY KEY,
    server_id       bigint    NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name            text      NOT NULL,
    color           integer   NOT NULL DEFAULT 0,        -- 0xRRGGBB
    permissions     bigint    NOT NULL DEFAULT 0,        -- bitfield
    position        integer   NOT NULL DEFAULT 0,
    created_at_ms   bigint    NOT NULL
);

-- "list server's roles, sorted by position desc" — primary read pattern.
CREATE INDEX roles_server_pos_idx ON roles (server_id, position DESC);

-- Now add the deferred FK from channel_overrides → roles. We couldn't
-- declare it inline because roles wasn't created yet (CREATE order).
ALTER TABLE channel_overrides
    ADD CONSTRAINT channel_overrides_role_fk
        FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE;

-- ─── member_roles (M:N users ↔ roles, scoped by server) ──────────────────
-- VDB stored this as a per-user blob. Native PG join table is faster for
-- the queries we actually run: "what roles does user X have in server Y"
-- (scoped lookup) and "who has role R" (cascade on role delete).
CREATE TABLE member_roles (
    user_id         bigint  NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    server_id       bigint  NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    role_id         bigint  NOT NULL REFERENCES roles(id)   ON DELETE CASCADE,
    PRIMARY KEY (user_id, server_id, role_id)
);

-- "what roles does user X have in server Y" — covered by PK head.
-- "who has role R" — needs role_idx.
CREATE INDEX member_roles_role_idx        ON member_roles (role_id);
-- "members of server Y with their roles" — list members + roles in one scan.
CREATE INDEX member_roles_server_user_idx ON member_roles (server_id, user_id);

-- ─── emojis ──────────────────────────────────────────────────────────────
CREATE TABLE emojis (
    id              bigint    PRIMARY KEY,
    server_id       bigint    NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name            text      NOT NULL,
    url             text      NOT NULL,         -- s3 key
    created_by      bigint    NOT NULL REFERENCES users(id),
    created_at_ms   bigint    NOT NULL
);

CREATE INDEX emojis_server_idx ON emojis (server_id);

-- ─── pinned_messages ─────────────────────────────────────────────────────
-- Pinned messages are a per-channel bounded list (max 50 enforced in app).
-- Stored as a table — VDB had it embedded on the channel row, but a table
-- gives us cheaper inserts under contention and a clean cascade-on-delete.
CREATE TABLE pinned_messages (
    channel_id      bigint    NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    message_id      bigint    NOT NULL,
    pinned_by       bigint    NOT NULL REFERENCES users(id),
    pinned_at_ms    bigint    NOT NULL,
    PRIMARY KEY (channel_id, message_id)
);

-- "list pins for this channel, newest first" — cheap with this index.
CREATE INDEX pinned_messages_channel_idx ON pinned_messages (channel_id, pinned_at_ms DESC);
