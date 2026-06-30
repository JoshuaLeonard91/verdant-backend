-- Per-user notification preferences. Embedded as a JSONB array on the
-- user row — bounded list (~50 entries max in practice), no need for
-- a separate join table. Each element shape:
--   { "target_type": int, "target_id": int8, "muted": bool, "desktop_enabled": bool }
--
-- Read-modify-write happens at the application layer (handlers/
-- notifications.rs walks the array and mutates / pushes). PG handles
-- the JSONB write atomically.

ALTER TABLE users
    ADD COLUMN notification_prefs jsonb NOT NULL DEFAULT '[]'::jsonb;
