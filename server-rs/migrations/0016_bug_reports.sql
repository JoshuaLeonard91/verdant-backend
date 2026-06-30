-- Slice 16: durable bug reports for support/admin review.

CREATE TABLE IF NOT EXISTS bug_reports (
    id              bigint PRIMARY KEY,
    reporter_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title           text NOT NULL CHECK (char_length(title) <= 200),
    description     text NOT NULL CHECK (char_length(description) <= 5000),
    category        text NOT NULL,
    client_version  text NULL,
    os              text NULL,
    fingerprint     text NOT NULL,
    status          text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    created_at_ms   bigint NOT NULL,
    closed_at_ms    bigint NULL,
    closed_by       bigint NULL REFERENCES users(id) ON DELETE SET NULL,
    close_note      text NULL
);

ALTER TABLE bug_reports
    ADD COLUMN IF NOT EXISTS reporter_id bigint REFERENCES users(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS title text,
    ADD COLUMN IF NOT EXISTS description text,
    ADD COLUMN IF NOT EXISTS category text,
    ADD COLUMN IF NOT EXISTS client_version text,
    ADD COLUMN IF NOT EXISTS os text,
    ADD COLUMN IF NOT EXISTS fingerprint text,
    ADD COLUMN IF NOT EXISTS status text DEFAULT 'open',
    ADD COLUMN IF NOT EXISTS created_at_ms bigint,
    ADD COLUMN IF NOT EXISTS closed_at_ms bigint,
    ADD COLUMN IF NOT EXISTS closed_by bigint REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS close_note text;

CREATE INDEX IF NOT EXISTS bug_reports_status_created_idx
    ON bug_reports (status, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS bug_reports_reporter_created_idx
    ON bug_reports (reporter_id, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS bug_reports_fingerprint_idx
    ON bug_reports (fingerprint);
