-- Bot profile customization and role assignments.
-- Additive only: existing bot rows keep working with preset visuals.

ALTER TABLE bots ADD COLUMN IF NOT EXISTS description text NULL;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS banner_url text NULL;

CREATE TABLE IF NOT EXISTS bot_roles (
    bot_id        bigint NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
    server_id     bigint NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    role_id       bigint NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (bot_id, server_id, role_id)
);

CREATE INDEX IF NOT EXISTS bot_roles_server_idx ON bot_roles (server_id, role_id);
CREATE INDEX IF NOT EXISTS bot_roles_bot_idx ON bot_roles (bot_id);
