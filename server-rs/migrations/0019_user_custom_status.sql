ALTER TABLE users
    ADD COLUMN IF NOT EXISTS custom_status_text TEXT,
    ADD COLUMN IF NOT EXISTS custom_status_emoji TEXT;
