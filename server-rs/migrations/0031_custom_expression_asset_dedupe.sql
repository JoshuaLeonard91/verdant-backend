CREATE TABLE IF NOT EXISTS custom_expression_assets (
    id              bigint    PRIMARY KEY,
    kind            text      NOT NULL CHECK (kind IN ('emoji', 'sticker')),
    sha256_hex      text      NOT NULL CHECK (char_length(sha256_hex) = 64),
    byte_size       bigint    NOT NULL CHECK (byte_size >= 0),
    content_type    text      NOT NULL CHECK (char_length(content_type) BETWEEN 1 AND 128),
    extension       text      NOT NULL CHECK (extension IN ('png', 'jpg', 'jpeg', 'gif', 'webp')),
    storage_key     text      NOT NULL CHECK (
        char_length(storage_key) BETWEEN 1 AND 512
        AND storage_key NOT LIKE 'attachments/%'
        AND storage_key NOT LIKE '/%'
        AND position(chr(92) in storage_key) = 0
    ),
    ref_count       bigint    NOT NULL DEFAULT 0 CHECK (ref_count >= 0),
    created_at_ms   bigint    NOT NULL,
    updated_at_ms   bigint    NOT NULL,
    CONSTRAINT custom_expression_assets_kind_hash_unique UNIQUE (kind, sha256_hex),
    CONSTRAINT custom_expression_assets_storage_key_unique UNIQUE (storage_key)
);

CREATE INDEX IF NOT EXISTS custom_expression_assets_hash_idx
    ON custom_expression_assets (sha256_hex);

ALTER TABLE emojis
    ADD COLUMN IF NOT EXISTS asset_id bigint REFERENCES custom_expression_assets(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS asset_hash text CHECK (asset_hash IS NULL OR char_length(asset_hash) = 64),
    ADD COLUMN IF NOT EXISTS source_peer_id text CHECK (source_peer_id IS NULL OR char_length(source_peer_id) <= 253),
    ADD COLUMN IF NOT EXISTS source_origin text CHECK (source_origin IS NULL OR char_length(source_origin) <= 512),
    ADD COLUMN IF NOT EXISTS source_server_label text CHECK (source_server_label IS NULL OR char_length(source_server_label) <= 120),
    ADD COLUMN IF NOT EXISTS source_expression_name text CHECK (source_expression_name IS NULL OR char_length(source_expression_name) <= 32),
    ADD COLUMN IF NOT EXISTS imported_by bigint REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS imported_at_ms bigint;

ALTER TABLE stickers
    ADD COLUMN IF NOT EXISTS asset_id bigint REFERENCES custom_expression_assets(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS asset_hash text CHECK (asset_hash IS NULL OR char_length(asset_hash) = 64),
    ADD COLUMN IF NOT EXISTS source_peer_id text CHECK (source_peer_id IS NULL OR char_length(source_peer_id) <= 253),
    ADD COLUMN IF NOT EXISTS source_origin text CHECK (source_origin IS NULL OR char_length(source_origin) <= 512),
    ADD COLUMN IF NOT EXISTS source_server_label text CHECK (source_server_label IS NULL OR char_length(source_server_label) <= 120),
    ADD COLUMN IF NOT EXISTS source_expression_name text CHECK (source_expression_name IS NULL OR char_length(source_expression_name) <= 32),
    ADD COLUMN IF NOT EXISTS imported_by bigint REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS imported_at_ms bigint;

CREATE INDEX IF NOT EXISTS emojis_asset_hash_idx ON emojis (asset_hash);
CREATE INDEX IF NOT EXISTS stickers_asset_hash_idx ON stickers (asset_hash);
