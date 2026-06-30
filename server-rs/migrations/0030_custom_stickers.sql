CREATE TABLE IF NOT EXISTS stickers (
    id              bigint    PRIMARY KEY,
    server_id       bigint    NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name            text      NOT NULL,
    url             text      NOT NULL,
    created_by      bigint    NOT NULL REFERENCES users(id),
    created_at_ms   bigint    NOT NULL
);

CREATE INDEX IF NOT EXISTS stickers_server_idx ON stickers (server_id);

ALTER TABLE IF EXISTS stickers ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'stickers'::regclass AND polname = 'rls_stickers_member_select') THEN
        CREATE POLICY rls_stickers_member_select ON stickers
            FOR SELECT USING (app.can_access_server(server_id));
    END IF;
END $$;
