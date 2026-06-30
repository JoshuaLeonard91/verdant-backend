-- Additive bot visual presets for client-rendered static bot avatars/banners.
-- Presets are validated server-side; no arbitrary uploaded image URL is needed.

ALTER TABLE bots ADD COLUMN IF NOT EXISTS avatar_preset text NULL;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS banner_preset text NULL;
