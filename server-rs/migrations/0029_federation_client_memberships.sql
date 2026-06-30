-- Durable home-backend pointers for federated server membership.
--
-- This table belongs to the user's home backend. It records enough metadata to
-- show a federated server on the client rail after restart and to request a
-- fresh target-backend client capability. It must not store remote runtime
-- data, message bodies, attachment URLs, presence maps, or credential material.

CREATE TABLE IF NOT EXISTS federation_client_memberships (
    id bigint PRIMARY KEY,
    home_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_peer_id text NOT NULL CHECK (char_length(target_peer_id) BETWEEN 1 AND 253),
    target_api_origin text NOT NULL CHECK (char_length(target_api_origin) <= 2048),
    target_server_id bigint NOT NULL CHECK (target_server_id > 0),
    remote_user_id text NOT NULL CHECK (char_length(remote_user_id) BETWEEN 1 AND 256),
    invite_code_hash text NOT NULL CHECK (
        invite_code_hash ~ '^sha256:[0-9a-fA-F]{64}$'
    ),
    status text NOT NULL DEFAULT 'active' CHECK (
        status IN ('active','pending','revoked','left','removed')
    ),
    server_name text CHECK (server_name IS NULL OR char_length(server_name) <= 120),
    server_icon_url text CHECK (server_icon_url IS NULL OR char_length(server_icon_url) <= 2048),
    server_banner_url text CHECK (server_banner_url IS NULL OR char_length(server_banner_url) <= 2048),
    last_capability_status text CHECK (
        last_capability_status IS NULL
        OR last_capability_status IN ('ready','pending','failed')
    ),
    last_error_code text CHECK (last_error_code IS NULL OR char_length(last_error_code) <= 96),
    last_refreshed_at_ms bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT federation_client_memberships_unique_remote_server UNIQUE (home_user_id, target_peer_id, target_server_id)
);

CREATE INDEX IF NOT EXISTS idx_federation_client_memberships_home_user
    ON federation_client_memberships (home_user_id, updated_at_ms DESC)
    WHERE status IN ('active','pending');

CREATE INDEX IF NOT EXISTS idx_federation_client_memberships_target
    ON federation_client_memberships (target_peer_id, target_server_id, updated_at_ms DESC);
