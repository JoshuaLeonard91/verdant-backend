-- Slice 6 (numbered 0005 — slice 5 DMs already covered in 0002):
-- audit_entries, login_entries, subscription_events.
--
-- All three are append-only event logs. Redis streams are the live tail
-- (services/audit.rs, services/login_log.rs); PG is the durability tier.
-- A small drainer service flushes Redis stream → PG every few seconds in
-- bulk INSERTs so the hot path doesn't take a per-event PG round trip.
--
-- audit_entries and login_entries are partitioned monthly; subscription_events
-- is low-volume (Stripe webhooks) and stays unpartitioned.

-- ─── audit_entries (partitioned by created_at_ms) ────────────────────────
CREATE TABLE audit_entries (
    id              bigint    NOT NULL,
    actor_id        bigint    NOT NULL,
    action          text      NOT NULL,         -- 'create' | 'delete' | 'update' | …
    target_type     text      NOT NULL,         -- 'user' | 'server' | 'channel' | …
    target_id       bigint    NOT NULL,
    server_id       bigint    NULL,             -- null for global events
    metadata        jsonb     NOT NULL DEFAULT '{}'::jsonb,
    ip              text      NULL,
    created_at_ms   bigint    NOT NULL,
    PRIMARY KEY (id, created_at_ms)
) PARTITION BY RANGE (created_at_ms);

CREATE INDEX audit_actor_idx  ON audit_entries (actor_id, created_at_ms DESC);
CREATE INDEX audit_server_idx ON audit_entries (server_id, created_at_ms DESC) WHERE server_id IS NOT NULL;

-- pre-create matching monthly partitions (subset — we generate on demand
-- in the maintenance job, so just bootstrap a year).
CREATE TABLE audit_entries_2025_01 PARTITION OF audit_entries FOR VALUES FROM (1735689600000) TO (1738368000000);
CREATE TABLE audit_entries_2025_02 PARTITION OF audit_entries FOR VALUES FROM (1738368000000) TO (1740787200000);
CREATE TABLE audit_entries_2025_03 PARTITION OF audit_entries FOR VALUES FROM (1740787200000) TO (1743465600000);
CREATE TABLE audit_entries_2025_04 PARTITION OF audit_entries FOR VALUES FROM (1743465600000) TO (1746057600000);
CREATE TABLE audit_entries_2025_05 PARTITION OF audit_entries FOR VALUES FROM (1746057600000) TO (1748736000000);
CREATE TABLE audit_entries_2025_06 PARTITION OF audit_entries FOR VALUES FROM (1748736000000) TO (1751328000000);
CREATE TABLE audit_entries_2025_07 PARTITION OF audit_entries FOR VALUES FROM (1751328000000) TO (1754006400000);
CREATE TABLE audit_entries_2025_08 PARTITION OF audit_entries FOR VALUES FROM (1754006400000) TO (1756684800000);
CREATE TABLE audit_entries_2025_09 PARTITION OF audit_entries FOR VALUES FROM (1756684800000) TO (1759276800000);
CREATE TABLE audit_entries_2025_10 PARTITION OF audit_entries FOR VALUES FROM (1759276800000) TO (1761955200000);
CREATE TABLE audit_entries_2025_11 PARTITION OF audit_entries FOR VALUES FROM (1761955200000) TO (1764547200000);
CREATE TABLE audit_entries_2025_12 PARTITION OF audit_entries FOR VALUES FROM (1764547200000) TO (1767225600000);
CREATE TABLE audit_entries_2026_01 PARTITION OF audit_entries FOR VALUES FROM (1767225600000) TO (1769904000000);
CREATE TABLE audit_entries_2026_02 PARTITION OF audit_entries FOR VALUES FROM (1769904000000) TO (1772323200000);
CREATE TABLE audit_entries_2026_03 PARTITION OF audit_entries FOR VALUES FROM (1772323200000) TO (1775001600000);
CREATE TABLE audit_entries_2026_04 PARTITION OF audit_entries FOR VALUES FROM (1775001600000) TO (1777593600000);
CREATE TABLE audit_entries_2026_05 PARTITION OF audit_entries FOR VALUES FROM (1777593600000) TO (1780272000000);
CREATE TABLE audit_entries_2026_06 PARTITION OF audit_entries FOR VALUES FROM (1780272000000) TO (1782864000000);
CREATE TABLE audit_entries_2026_07 PARTITION OF audit_entries FOR VALUES FROM (1782864000000) TO (1785542400000);
CREATE TABLE audit_entries_2026_08 PARTITION OF audit_entries FOR VALUES FROM (1785542400000) TO (1788220800000);
CREATE TABLE audit_entries_2026_09 PARTITION OF audit_entries FOR VALUES FROM (1788220800000) TO (1790812800000);
CREATE TABLE audit_entries_2026_10 PARTITION OF audit_entries FOR VALUES FROM (1790812800000) TO (1793491200000);
CREATE TABLE audit_entries_2026_11 PARTITION OF audit_entries FOR VALUES FROM (1793491200000) TO (1796083200000);
CREATE TABLE audit_entries_2026_12 PARTITION OF audit_entries FOR VALUES FROM (1796083200000) TO (1798761600000);

-- ─── login_entries (partitioned by created_at_ms) ────────────────────────
-- Both successful + failed login attempts. user_id is nullable because a
-- failed login on a wrong email has no associated user. session_id is
-- nullable for failed logins / pending verification.
CREATE TABLE login_entries (
    id              bigint    NOT NULL,
    user_id         bigint    NULL,
    session_id      bigint    NULL,
    success         boolean   NOT NULL,
    failure_reason  text      NULL,
    ip              text      NOT NULL,
    user_agent      text      NULL,
    device_hash     text      NULL,
    city            text      NULL,
    country         text      NULL,
    risk_level      text      NULL,
    created_at_ms   bigint    NOT NULL,
    PRIMARY KEY (id, created_at_ms)
) PARTITION BY RANGE (created_at_ms);

CREATE INDEX login_entries_user_idx ON login_entries (user_id, created_at_ms DESC) WHERE user_id IS NOT NULL;
CREATE INDEX login_entries_failed_idx ON login_entries (created_at_ms DESC) WHERE success = false;

CREATE TABLE login_entries_2025_01 PARTITION OF login_entries FOR VALUES FROM (1735689600000) TO (1738368000000);
CREATE TABLE login_entries_2025_02 PARTITION OF login_entries FOR VALUES FROM (1738368000000) TO (1740787200000);
CREATE TABLE login_entries_2025_03 PARTITION OF login_entries FOR VALUES FROM (1740787200000) TO (1743465600000);
CREATE TABLE login_entries_2025_04 PARTITION OF login_entries FOR VALUES FROM (1743465600000) TO (1746057600000);
CREATE TABLE login_entries_2025_05 PARTITION OF login_entries FOR VALUES FROM (1746057600000) TO (1748736000000);
CREATE TABLE login_entries_2025_06 PARTITION OF login_entries FOR VALUES FROM (1748736000000) TO (1751328000000);
CREATE TABLE login_entries_2025_07 PARTITION OF login_entries FOR VALUES FROM (1751328000000) TO (1754006400000);
CREATE TABLE login_entries_2025_08 PARTITION OF login_entries FOR VALUES FROM (1754006400000) TO (1756684800000);
CREATE TABLE login_entries_2025_09 PARTITION OF login_entries FOR VALUES FROM (1756684800000) TO (1759276800000);
CREATE TABLE login_entries_2025_10 PARTITION OF login_entries FOR VALUES FROM (1759276800000) TO (1761955200000);
CREATE TABLE login_entries_2025_11 PARTITION OF login_entries FOR VALUES FROM (1761955200000) TO (1764547200000);
CREATE TABLE login_entries_2025_12 PARTITION OF login_entries FOR VALUES FROM (1764547200000) TO (1767225600000);
CREATE TABLE login_entries_2026_01 PARTITION OF login_entries FOR VALUES FROM (1767225600000) TO (1769904000000);
CREATE TABLE login_entries_2026_02 PARTITION OF login_entries FOR VALUES FROM (1769904000000) TO (1772323200000);
CREATE TABLE login_entries_2026_03 PARTITION OF login_entries FOR VALUES FROM (1772323200000) TO (1775001600000);
CREATE TABLE login_entries_2026_04 PARTITION OF login_entries FOR VALUES FROM (1775001600000) TO (1777593600000);
CREATE TABLE login_entries_2026_05 PARTITION OF login_entries FOR VALUES FROM (1777593600000) TO (1780272000000);
CREATE TABLE login_entries_2026_06 PARTITION OF login_entries FOR VALUES FROM (1780272000000) TO (1782864000000);
CREATE TABLE login_entries_2026_07 PARTITION OF login_entries FOR VALUES FROM (1782864000000) TO (1785542400000);
CREATE TABLE login_entries_2026_08 PARTITION OF login_entries FOR VALUES FROM (1785542400000) TO (1788220800000);
CREATE TABLE login_entries_2026_09 PARTITION OF login_entries FOR VALUES FROM (1788220800000) TO (1790812800000);
CREATE TABLE login_entries_2026_10 PARTITION OF login_entries FOR VALUES FROM (1790812800000) TO (1793491200000);
CREATE TABLE login_entries_2026_11 PARTITION OF login_entries FOR VALUES FROM (1793491200000) TO (1796083200000);
CREATE TABLE login_entries_2026_12 PARTITION OF login_entries FOR VALUES FROM (1796083200000) TO (1798761600000);

-- ─── subscription_events (Stripe webhook log, low-volume — not partitioned) ──
CREATE TABLE subscription_events (
    id                  bigint    PRIMARY KEY,
    user_id             bigint    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type          text      NOT NULL,        -- 'purchase', 'renewal', 'refund', …
    stripe_event_id     text      NULL,
    amount_cents        integer   NOT NULL DEFAULT 0,
    metadata            jsonb     NOT NULL DEFAULT '{}'::jsonb,
    created_at_ms       bigint    NOT NULL
);

CREATE INDEX subscription_events_user_idx ON subscription_events (user_id, created_at_ms DESC);
-- Stripe replay-protection: if we see the same stripe_event_id twice, skip.
CREATE UNIQUE INDEX subscription_events_stripe_uniq ON subscription_events (stripe_event_id) WHERE stripe_event_id IS NOT NULL;
