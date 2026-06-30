ALTER TABLE roles
    ADD COLUMN IF NOT EXISTS color_only boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS show_as_section boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS color_priority integer NOT NULL DEFAULT 0;

UPDATE roles
SET color_priority = position
WHERE color_priority = 0
  AND color <> 0;

UPDATE roles
SET permissions = 0,
    position = 0,
    show_as_section = false
WHERE color_only = true;
