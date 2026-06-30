-- Federation discovery registry foundation.
--
-- Metadata only: this table is not used for runtime messages, presence,
-- moderation actions, account sessions, Redis/NATS fanout, or cross-server DB
-- federation.

CREATE TABLE IF NOT EXISTS federation_instances (
    id bigint PRIMARY KEY,
    domain text NOT NULL UNIQUE,
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
    api_url text NOT NULL,
    public_url text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('standalone', 'linked', 'federated')),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'revoked', 'rejected')),
    public_discovery boolean NOT NULL DEFAULT false,
    discovery_description text CHECK (discovery_description IS NULL OR char_length(discovery_description) <= 512),
    invite_url text CHECK (invite_url IS NULL OR char_length(invite_url) <= 2048),
    server_version text CHECK (server_version IS NULL OR char_length(server_version) <= 64),
    min_client_version text CHECK (min_client_version IS NULL OR char_length(min_client_version) <= 64),
    upload_policy text CHECK (upload_policy IS NULL OR upload_policy IN ('disabled', 'media_validation_only', 'operator_managed')),
    content_scanning jsonb NOT NULL DEFAULT '{"provider":"none","enabled":false}'::jsonb,
    capabilities jsonb NOT NULL DEFAULT '{}'::jsonb,
    public_key text CHECK (public_key IS NULL OR char_length(public_key) <= 4096),
    public_key_fingerprint text,
    verification_method text NOT NULL DEFAULT 'dns_txt' CHECK (verification_method IN ('dns_txt', 'http_well_known')),
    verification_token_hash text NOT NULL,
    verified_at_ms bigint,
    revoked_at_ms bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_federation_instances_public_discovery
    ON federation_instances (status, public_discovery, updated_at_ms DESC);

CREATE INDEX IF NOT EXISTS idx_federation_instances_domain
    ON federation_instances (domain);
