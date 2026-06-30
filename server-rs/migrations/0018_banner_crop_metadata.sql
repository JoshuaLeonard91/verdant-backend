ALTER TABLE users
    ADD COLUMN IF NOT EXISTS banner_crop_x double precision NULL,
    ADD COLUMN IF NOT EXISTS banner_crop_y double precision NULL,
    ADD COLUMN IF NOT EXISTS banner_crop_width double precision NULL,
    ADD COLUMN IF NOT EXISTS banner_crop_height double precision NULL;

ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS banner_crop_x double precision NULL,
    ADD COLUMN IF NOT EXISTS banner_crop_y double precision NULL,
    ADD COLUMN IF NOT EXISTS banner_crop_width double precision NULL,
    ADD COLUMN IF NOT EXISTS banner_crop_height double precision NULL;

ALTER TABLE bots
    ADD COLUMN IF NOT EXISTS banner_crop_x double precision NULL,
    ADD COLUMN IF NOT EXISTS banner_crop_y double precision NULL,
    ADD COLUMN IF NOT EXISTS banner_crop_width double precision NULL,
    ADD COLUMN IF NOT EXISTS banner_crop_height double precision NULL;
