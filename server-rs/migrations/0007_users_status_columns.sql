-- Two columns the UserRow shape carries that I missed in 0002:
--   status_auto       — whether AFK auto-idle can override preferred_status
--   preferred_status  — the user's chosen status ("online", "idle", "dnd").
--
-- The legacy `status_type` column stays — it's the *current* presence,
-- whereas `preferred_status` is the user's setting. Auto-idle systems
-- read preferred_status when status_auto = true to decide what to set.

ALTER TABLE users
    ADD COLUMN status_auto       boolean NOT NULL DEFAULT true,
    ADD COLUMN preferred_status  text    NOT NULL DEFAULT 'online';
