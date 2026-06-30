-- Federation runtime foundation.
--
-- This schema is intentionally isolated from the discovery registry. It records
-- trusted S2S keys, remote principals, replay nonces, and event delivery
-- metadata without granting remote peers access to local runtime infrastructure.

CREATE TABLE IF NOT EXISTS federation_peer_keys (
    id bigint PRIMARY KEY,
    peer_id text NOT NULL CHECK (char_length(peer_id) BETWEEN 1 AND 253),
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
    api_origin text NOT NULL CHECK (char_length(api_origin) <= 2048),
    public_key_ed25519 bytea NOT NULL CHECK (octet_length(public_key_ed25519) = 32),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    valid_after_ms bigint,
    valid_until_ms bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT federation_peer_keys_unique_key UNIQUE (peer_id, key_id),
    CONSTRAINT federation_peer_keys_valid_window CHECK (
        valid_until_ms IS NULL
        OR valid_after_ms IS NULL
        OR valid_until_ms > valid_after_ms
    )
);

CREATE INDEX IF NOT EXISTS idx_federation_peer_keys_active
    ON federation_peer_keys (peer_id, key_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS federation_peer_routes (
    id bigint PRIMARY KEY,
    peer_id text NOT NULL CHECK (char_length(peer_id) BETWEEN 1 AND 253),
    scope_type text NOT NULL CHECK (scope_type IN ('server','channel','dm','principal')),
    scope_id bigint NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT federation_peer_routes_unique_scope UNIQUE (peer_id, scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_federation_peer_routes_scope
    ON federation_peer_routes (scope_type, scope_id, updated_at_ms DESC)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS federation_remote_principals (
    id bigint PRIMARY KEY,
    home_peer_id text NOT NULL CHECK (char_length(home_peer_id) BETWEEN 1 AND 253),
    remote_user_id text NOT NULL CHECK (char_length(remote_user_id) BETWEEN 1 AND 256),
    local_user_id bigint REFERENCES users(id) ON DELETE RESTRICT,
    remote_username text CHECK (remote_username IS NULL OR char_length(remote_username) <= 120),
    display_name text CHECK (display_name IS NULL OR char_length(display_name) <= 120),
    avatar_url text CHECK (avatar_url IS NULL OR char_length(avatar_url) <= 2048),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'stale', 'revoked')),
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT federation_remote_principals_unique_remote UNIQUE (home_peer_id, remote_user_id),
    CONSTRAINT federation_remote_principals_local_user_unique UNIQUE (local_user_id)
);

CREATE INDEX IF NOT EXISTS idx_federation_remote_principals_home
    ON federation_remote_principals (home_peer_id, updated_at_ms DESC);

CREATE TABLE IF NOT EXISTS federation_remote_roles (
    id bigint PRIMARY KEY,
    source_peer_id text NOT NULL CHECK (char_length(source_peer_id) BETWEEN 1 AND 253),
    remote_role_id text NOT NULL CHECK (char_length(remote_role_id) BETWEEN 1 AND 256),
    local_server_id bigint NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    local_role_id bigint NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_by_local_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT federation_remote_roles_unique_remote UNIQUE (source_peer_id, remote_role_id),
    CONSTRAINT federation_remote_roles_unique_local UNIQUE (local_role_id)
);

CREATE INDEX IF NOT EXISTS idx_federation_remote_roles_server
    ON federation_remote_roles (local_server_id, updated_at_ms DESC);

CREATE TABLE IF NOT EXISTS federation_remote_categories (
    id bigint PRIMARY KEY,
    source_peer_id text NOT NULL CHECK (char_length(source_peer_id) BETWEEN 1 AND 253),
    remote_category_id text NOT NULL CHECK (char_length(remote_category_id) BETWEEN 1 AND 256),
    local_server_id bigint NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    local_category_id bigint NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
    created_by_local_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT federation_remote_categories_unique_remote UNIQUE (source_peer_id, remote_category_id),
    CONSTRAINT federation_remote_categories_unique_local UNIQUE (local_category_id)
);

CREATE INDEX IF NOT EXISTS idx_federation_remote_categories_server
    ON federation_remote_categories (local_server_id, updated_at_ms DESC);

CREATE TABLE IF NOT EXISTS federation_remote_channels (
    id bigint PRIMARY KEY,
    source_peer_id text NOT NULL CHECK (char_length(source_peer_id) BETWEEN 1 AND 253),
    remote_channel_id text NOT NULL CHECK (char_length(remote_channel_id) BETWEEN 1 AND 256),
    local_server_id bigint NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    local_channel_id bigint NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    created_by_local_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT federation_remote_channels_unique_remote UNIQUE (source_peer_id, remote_channel_id),
    CONSTRAINT federation_remote_channels_unique_local UNIQUE (local_channel_id)
);

CREATE INDEX IF NOT EXISTS idx_federation_remote_channels_server
    ON federation_remote_channels (local_server_id, updated_at_ms DESC);

CREATE TABLE IF NOT EXISTS federation_remote_messages (
    id bigint PRIMARY KEY,
    source_peer_id text NOT NULL CHECK (char_length(source_peer_id) BETWEEN 1 AND 253),
    remote_message_id text NOT NULL CHECK (char_length(remote_message_id) BETWEEN 1 AND 256),
    local_message_id bigint NOT NULL,
    local_message_created_at_ms bigint NOT NULL,
    local_channel_id bigint NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    local_author_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT federation_remote_messages_unique_remote UNIQUE (source_peer_id, remote_message_id),
    CONSTRAINT federation_remote_messages_unique_local UNIQUE (local_message_id)
);

CREATE INDEX IF NOT EXISTS idx_federation_remote_messages_channel
    ON federation_remote_messages (local_channel_id, updated_at_ms DESC);

CREATE TABLE IF NOT EXISTS federation_remote_dms (
    id bigint PRIMARY KEY,
    source_peer_id text NOT NULL CHECK (char_length(source_peer_id) BETWEEN 1 AND 253),
    remote_dm_id text NOT NULL CHECK (char_length(remote_dm_id) BETWEEN 1 AND 256),
    local_channel_id bigint NOT NULL REFERENCES dm_channels(id) ON DELETE CASCADE,
    remote_user_id text NOT NULL CHECK (char_length(remote_user_id) BETWEEN 1 AND 256),
    local_remote_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    local_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT federation_remote_dms_unique_remote UNIQUE (source_peer_id, remote_dm_id)
);

CREATE INDEX IF NOT EXISTS idx_federation_remote_dms_local_user
    ON federation_remote_dms (local_user_id, updated_at_ms DESC);

CREATE TABLE IF NOT EXISTS federation_replay_nonces (
    id bigint PRIMARY KEY,
    source_peer_id text NOT NULL CHECK (char_length(source_peer_id) BETWEEN 1 AND 253),
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
    nonce text NOT NULL CHECK (char_length(nonce) BETWEEN 16 AND 128),
    request_timestamp_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT federation_replay_nonces_unique_nonce UNIQUE (source_peer_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_federation_replay_nonces_expiry
    ON federation_replay_nonces (expires_at_ms);

CREATE TABLE IF NOT EXISTS federation_inbound_events (
    id bigint PRIMARY KEY,
    source_peer_id text NOT NULL CHECK (char_length(source_peer_id) BETWEEN 1 AND 253),
    remote_event_id text NOT NULL CHECK (char_length(remote_event_id) BETWEEN 1 AND 256),
    event_kind text NOT NULL CHECK (event_kind IN (
        'invite_preview',
        'principal_upsert',
        'membership_join',
        'membership_leave',
        'membership_remove',
        'membership_ban',
        'membership_unban',
        'role_create',
        'role_update',
        'role_delete',
        'role_reorder',
        'category_create',
        'category_update',
        'category_delete',
        'channel_create',
        'channel_update',
        'channel_delete',
        'channel_reorder',
        'channel_override_set',
        'channel_override_delete',
        'member_role_assign',
        'member_role_remove',
        'emoji_rename',
        'emoji_delete',
        'message_create',
        'message_update',
        'message_delete',
        'message_pin',
        'message_unpin',
        'reaction_add',
        'reaction_remove',
        'relationship_request',
        'relationship_accept',
        'relationship_remove',
        'relationship_block',
        'presence_update',
        'typing_start',
        'read_state_update',
        'dm_create',
        'dm_group_create'
    )),
    protocol_version smallint NOT NULL DEFAULT 1 CHECK (protocol_version = 1),
    payload_hash text NOT NULL CHECK (char_length(payload_hash) = 64),
    status text NOT NULL DEFAULT 'received' CHECK (status IN ('received', 'accepted', 'rejected', 'duplicate')),
    rejection_code text CHECK (rejection_code IS NULL OR char_length(rejection_code) <= 96),
    accepted_at_ms bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT federation_inbound_events_unique_remote UNIQUE (source_peer_id, remote_event_id)
);

CREATE INDEX IF NOT EXISTS idx_federation_inbound_events_status
    ON federation_inbound_events (status, updated_at_ms DESC);

CREATE TABLE IF NOT EXISTS federation_outbound_events (
    id bigint PRIMARY KEY,
    destination_peer_id text NOT NULL CHECK (char_length(destination_peer_id) BETWEEN 1 AND 253),
    event_id text NOT NULL CHECK (char_length(event_id) BETWEEN 1 AND 256),
    event_kind text NOT NULL CHECK (event_kind IN (
        'invite_preview',
        'principal_upsert',
        'membership_join',
        'membership_leave',
        'membership_remove',
        'membership_ban',
        'membership_unban',
        'role_create',
        'role_update',
        'role_delete',
        'role_reorder',
        'category_create',
        'category_update',
        'category_delete',
        'channel_create',
        'channel_update',
        'channel_delete',
        'channel_reorder',
        'channel_override_set',
        'channel_override_delete',
        'member_role_assign',
        'member_role_remove',
        'emoji_rename',
        'emoji_delete',
        'message_create',
        'message_update',
        'message_delete',
        'message_pin',
        'message_unpin',
        'reaction_add',
        'reaction_remove',
        'relationship_request',
        'relationship_accept',
        'relationship_remove',
        'relationship_block',
        'presence_update',
        'typing_start',
        'read_state_update',
        'dm_create',
        'dm_group_create'
    )),
    protocol_version smallint NOT NULL DEFAULT 1 CHECK (protocol_version = 1),
    payload_hash text NOT NULL CHECK (char_length(payload_hash) = 64),
    event_body_json jsonb NOT NULL CHECK (char_length(event_body_json::text) <= 131072),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'dead')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at_ms bigint,
    last_error_code text CHECK (last_error_code IS NULL OR char_length(last_error_code) <= 96),
    sent_at_ms bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT federation_outbound_events_unique_remote UNIQUE (destination_peer_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_federation_outbound_events_retry
    ON federation_outbound_events (status, next_attempt_at_ms, updated_at_ms)
    WHERE status IN ('pending', 'failed');
