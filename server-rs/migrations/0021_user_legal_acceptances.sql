CREATE TABLE IF NOT EXISTS user_legal_acceptances (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    terms_version TEXT NOT NULL,
    privacy_version TEXT NOT NULL,
    accepted_at_ms BIGINT NOT NULL,
    accepted_ip TEXT,
    user_agent TEXT,
    source TEXT NOT NULL DEFAULT 'client_signup',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, terms_version, privacy_version, source)
);

CREATE INDEX IF NOT EXISTS idx_user_legal_acceptances_user_id
    ON user_legal_acceptances(user_id);

CREATE INDEX IF NOT EXISTS idx_user_legal_acceptances_accepted_at
    ON user_legal_acceptances(accepted_at_ms);
