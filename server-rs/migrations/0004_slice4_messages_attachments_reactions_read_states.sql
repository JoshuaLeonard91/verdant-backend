-- Slice 4: messages, attachments, reactions, read_states. The hot path.
--
-- `messages` is range-partitioned monthly on created_at_ms. The 2025
-- Verdant epoch starts at 2025-01-01T00:00:00Z = 1735689600000 ms; we
-- pre-create partitions through end-of-2027 here so the test rig and
-- the first ~24 months of prod don't need any cron-driven roll-forward.
-- A small maintenance job will create future partitions later.
--
-- The (id, created_at_ms) compound PK is required because `messages` is
-- partitioned on created_at_ms — Postgres requires the partition key be
-- part of every unique constraint.

-- ─── messages (partitioned) ──────────────────────────────────────────────
CREATE TABLE messages (
    id              bigint    NOT NULL,
    channel_id      bigint    NOT NULL,
    author_id       bigint    NOT NULL,         -- 0 == system message
    type            smallint  NOT NULL DEFAULT 0,
    flags           integer   NOT NULL DEFAULT 0,  -- bit 0 = soft-deleted
    content         text      NOT NULL DEFAULT '',
    reply_to        bigint    NULL,             -- soft FK; partitioned-target
    edited_at_ms    bigint    NULL,
    created_at_ms   bigint    NOT NULL,
    PRIMARY KEY (id, created_at_ms)
) PARTITION BY RANGE (created_at_ms);

-- Per-partition indexes get inherited automatically once declared on the
-- parent. Our two read patterns on messages are:
--   (a) latest N for channel — channel_id + id desc
--   (b) page-before(channel, before_id) — same index serves it
--   (c) get-message-by-id — covered by PK
CREATE INDEX messages_channel_id_idx ON messages (channel_id, id DESC);
-- Reply-chain queries: rare but cheap with a partial index.
CREATE INDEX messages_reply_to_idx ON messages (reply_to) WHERE reply_to IS NOT NULL;

-- Pre-create partitions monthly through end of 2027.
-- Verdant epoch: 2025-01-01T00:00:00Z = 1735689600000 ms.
-- Each month's range is [first-day-00:00, first-day-of-next-month-00:00).
-- We script this once here rather than running a generator at deploy time
-- so the migration is self-contained.

CREATE TABLE messages_2025_01 PARTITION OF messages FOR VALUES FROM (1735689600000) TO (1738368000000);  -- jan 2025
CREATE TABLE messages_2025_02 PARTITION OF messages FOR VALUES FROM (1738368000000) TO (1740787200000);  -- feb 2025
CREATE TABLE messages_2025_03 PARTITION OF messages FOR VALUES FROM (1740787200000) TO (1743465600000);  -- mar 2025
CREATE TABLE messages_2025_04 PARTITION OF messages FOR VALUES FROM (1743465600000) TO (1746057600000);  -- apr 2025
CREATE TABLE messages_2025_05 PARTITION OF messages FOR VALUES FROM (1746057600000) TO (1748736000000);  -- may 2025
CREATE TABLE messages_2025_06 PARTITION OF messages FOR VALUES FROM (1748736000000) TO (1751328000000);  -- jun 2025
CREATE TABLE messages_2025_07 PARTITION OF messages FOR VALUES FROM (1751328000000) TO (1754006400000);  -- jul 2025
CREATE TABLE messages_2025_08 PARTITION OF messages FOR VALUES FROM (1754006400000) TO (1756684800000);  -- aug 2025
CREATE TABLE messages_2025_09 PARTITION OF messages FOR VALUES FROM (1756684800000) TO (1759276800000);  -- sep 2025
CREATE TABLE messages_2025_10 PARTITION OF messages FOR VALUES FROM (1759276800000) TO (1761955200000);  -- oct 2025
CREATE TABLE messages_2025_11 PARTITION OF messages FOR VALUES FROM (1761955200000) TO (1764547200000);  -- nov 2025
CREATE TABLE messages_2025_12 PARTITION OF messages FOR VALUES FROM (1764547200000) TO (1767225600000);  -- dec 2025
CREATE TABLE messages_2026_01 PARTITION OF messages FOR VALUES FROM (1767225600000) TO (1769904000000);  -- jan 2026
CREATE TABLE messages_2026_02 PARTITION OF messages FOR VALUES FROM (1769904000000) TO (1772323200000);  -- feb 2026
CREATE TABLE messages_2026_03 PARTITION OF messages FOR VALUES FROM (1772323200000) TO (1775001600000);  -- mar 2026
CREATE TABLE messages_2026_04 PARTITION OF messages FOR VALUES FROM (1775001600000) TO (1777593600000);  -- apr 2026
CREATE TABLE messages_2026_05 PARTITION OF messages FOR VALUES FROM (1777593600000) TO (1780272000000);  -- may 2026
CREATE TABLE messages_2026_06 PARTITION OF messages FOR VALUES FROM (1780272000000) TO (1782864000000);  -- jun 2026
CREATE TABLE messages_2026_07 PARTITION OF messages FOR VALUES FROM (1782864000000) TO (1785542400000);  -- jul 2026
CREATE TABLE messages_2026_08 PARTITION OF messages FOR VALUES FROM (1785542400000) TO (1788220800000);  -- aug 2026
CREATE TABLE messages_2026_09 PARTITION OF messages FOR VALUES FROM (1788220800000) TO (1790812800000);  -- sep 2026
CREATE TABLE messages_2026_10 PARTITION OF messages FOR VALUES FROM (1790812800000) TO (1793491200000);  -- oct 2026
CREATE TABLE messages_2026_11 PARTITION OF messages FOR VALUES FROM (1793491200000) TO (1796083200000);  -- nov 2026
CREATE TABLE messages_2026_12 PARTITION OF messages FOR VALUES FROM (1796083200000) TO (1798761600000);  -- dec 2026
CREATE TABLE messages_2027_01 PARTITION OF messages FOR VALUES FROM (1798761600000) TO (1801440000000);  -- jan 2027
CREATE TABLE messages_2027_02 PARTITION OF messages FOR VALUES FROM (1801440000000) TO (1803859200000);  -- feb 2027
CREATE TABLE messages_2027_03 PARTITION OF messages FOR VALUES FROM (1803859200000) TO (1806537600000);  -- mar 2027
CREATE TABLE messages_2027_04 PARTITION OF messages FOR VALUES FROM (1806537600000) TO (1809129600000);  -- apr 2027
CREATE TABLE messages_2027_05 PARTITION OF messages FOR VALUES FROM (1809129600000) TO (1811808000000);  -- may 2027
CREATE TABLE messages_2027_06 PARTITION OF messages FOR VALUES FROM (1811808000000) TO (1814400000000);  -- jun 2027
CREATE TABLE messages_2027_07 PARTITION OF messages FOR VALUES FROM (1814400000000) TO (1817078400000);  -- jul 2027
CREATE TABLE messages_2027_08 PARTITION OF messages FOR VALUES FROM (1817078400000) TO (1819756800000);  -- aug 2027
CREATE TABLE messages_2027_09 PARTITION OF messages FOR VALUES FROM (1819756800000) TO (1822348800000);  -- sep 2027
CREATE TABLE messages_2027_10 PARTITION OF messages FOR VALUES FROM (1822348800000) TO (1825027200000);  -- oct 2027
CREATE TABLE messages_2027_11 PARTITION OF messages FOR VALUES FROM (1825027200000) TO (1827619200000);  -- nov 2027
CREATE TABLE messages_2027_12 PARTITION OF messages FOR VALUES FROM (1827619200000) TO (1830297600000);  -- dec 2027

-- ─── attachments ─────────────────────────────────────────────────────────
-- Stored as a flat table (not partitioned) — attachments are looked up
-- both by id (admin / scan) and by message_id (render). Volume is far
-- lower than messages (most msgs have zero), so partitioning would be
-- premature.
CREATE TABLE attachments (
    id              bigint    PRIMARY KEY,
    message_id      bigint    NULL,                  -- null until message-association write
    channel_id      bigint    NOT NULL,
    uploader_id     bigint    NOT NULL REFERENCES users(id),
    filename        text      NOT NULL,
    url             text      NOT NULL,              -- s3 key
    content_type    text      NOT NULL,
    size_bytes      bigint    NOT NULL,
    hash            text      NOT NULL,              -- sha256 hex of bytes
    scan_status     text      NOT NULL DEFAULT 'pending',
    created_at_ms   bigint    NOT NULL
);

-- "fetch attachments for message" — partial index keeps the common case fast.
CREATE INDEX attachments_message_idx ON attachments (message_id) WHERE message_id IS NOT NULL;
-- "user's attachment history" — admin / quota.
CREATE INDEX attachments_uploader_idx ON attachments (uploader_id, created_at_ms DESC);
-- Hash-based dedup for upload reuse.
CREATE INDEX attachments_hash_idx ON attachments (hash);

-- ─── reactions ───────────────────────────────────────────────────────────
-- Redis Lua scripts are still the fast path (ADD/REMOVE atomic with cap
-- enforcement). PG is the durability backstop and the source on cache miss.
-- Composite PK gives us "did user U react with emoji E to msg M" in a
-- single index probe.
CREATE TABLE reactions (
    message_id      bigint    NOT NULL,
    emoji           text      NOT NULL,
    user_id         bigint    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at_ms   bigint    NOT NULL,
    PRIMARY KEY (message_id, emoji, user_id)
);

-- "list all reactions for a message" — covered by PK head.
-- "list all reactions for a batch of messages" — `WHERE message_id = ANY($1)`.
CREATE INDEX reactions_message_idx ON reactions (message_id);

-- ─── read_states ─────────────────────────────────────────────────────────
-- Per-user, per-channel last-read pointer. GREATEST semantics on update —
-- never roll back if an out-of-order ACK arrives from another device.
-- Updates are written with: ON CONFLICT DO UPDATE
--   SET last_read_message_id = GREATEST(read_states.last_read_message_id, EXCLUDED.last_read_message_id),
--       updated_at_ms        = GREATEST(read_states.updated_at_ms,        EXCLUDED.updated_at_ms);
CREATE TABLE read_states (
    user_id                 bigint  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel_id              bigint  NOT NULL,
    last_read_message_id    bigint  NOT NULL,
    updated_at_ms           bigint  NOT NULL,
    PRIMARY KEY (user_id, channel_id)
);
