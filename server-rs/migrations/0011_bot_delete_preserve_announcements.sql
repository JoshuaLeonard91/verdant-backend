-- Preserve historical feed announcements when deleting a bot.
-- Existing announcements keep rendering, but future bot deletes no longer fail
-- on the announcements.bot_id foreign key.

ALTER TABLE announcements
    DROP CONSTRAINT IF EXISTS announcements_bot_id_fkey;

ALTER TABLE announcements
    ADD CONSTRAINT announcements_bot_id_fkey
    FOREIGN KEY (bot_id)
    REFERENCES bots(id)
    ON DELETE SET NULL;
