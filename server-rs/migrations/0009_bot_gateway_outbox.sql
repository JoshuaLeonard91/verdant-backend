-- Bot gateway durable event backbone.
--
-- Bot tokens gain explicit scopes plus optional feed/channel allowlists.
-- Empty feed allowlists preserve the original low-friction REST behavior for
-- public feed announcements while keeping gateway delivery explicit.

ALTER TABLE bot_tokens
    ADD COLUMN IF NOT EXISTS scopes text[] NOT NULL
        DEFAULT ARRAY['announcements:write','feeds:read']::text[];

ALTER TABLE bot_tokens
    ADD COLUMN IF NOT EXISTS allowed_feed_ids bigint[] NOT NULL DEFAULT '{}';

ALTER TABLE bot_tokens
    ADD COLUMN IF NOT EXISTS allowed_channel_ids bigint[] NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS bot_event_outbox (
    id              bigint PRIMARY KEY,
    event_type      text NOT NULL,
    server_id       bigint NULL REFERENCES servers(id) ON DELETE CASCADE,
    channel_id      bigint NULL REFERENCES channels(id) ON DELETE CASCADE,
    feed_id         bigint NULL REFERENCES feeds(id) ON DELETE CASCADE,
    actor_user_id   bigint NULL REFERENCES users(id) ON DELETE SET NULL,
    actor_bot_id    bigint NULL REFERENCES bots(id) ON DELETE SET NULL,
    payload         jsonb NOT NULL,
    created_at_ms   bigint NOT NULL
);

CREATE INDEX IF NOT EXISTS bot_event_outbox_server_id_idx
    ON bot_event_outbox (server_id, id);

CREATE INDEX IF NOT EXISTS bot_event_outbox_channel_id_idx
    ON bot_event_outbox (channel_id, id)
    WHERE channel_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS bot_event_outbox_feed_id_idx
    ON bot_event_outbox (feed_id, id)
    WHERE feed_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS bot_event_outbox_created_at_idx
    ON bot_event_outbox (created_at_ms);

CREATE TABLE IF NOT EXISTS bot_idempotency_keys (
    bot_id          bigint NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
    key             text NOT NULL,
    response        jsonb NOT NULL,
    created_at_ms   bigint NOT NULL,
    PRIMARY KEY (bot_id, key)
);

CREATE INDEX IF NOT EXISTS bot_idempotency_keys_created_at_idx
    ON bot_idempotency_keys (created_at_ms);
