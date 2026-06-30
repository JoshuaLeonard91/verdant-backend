-- Account-link revocation propagation.
--
-- Official issuers remember opaque proof grants so linked self-hosts can poll
-- revocation state by proof JTI hash. This remains identity metadata only.

ALTER TABLE account_links
    ADD COLUMN IF NOT EXISTS revocation_checked_at_ms bigint;

ALTER TABLE account_links
    DROP CONSTRAINT IF EXISTS account_links_status_check;

ALTER TABLE account_links
    ADD CONSTRAINT account_links_status_check
    CHECK (status IN ('linked', 'revoked', 'stale'));

CREATE TABLE IF NOT EXISTS account_link_issued_grants (
    id bigint PRIMARY KEY,
    issuer_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    audience_instance_id text NOT NULL CHECK (char_length(audience_instance_id) BETWEEN 1 AND 128),
    audience_api_origin text NOT NULL CHECK (char_length(audience_api_origin) BETWEEN 1 AND 2048),
    proof_jti_hash text NOT NULL UNIQUE CHECK (proof_jti_hash ~ '^[a-f0-9]{64}$'),
    scopes text[] NOT NULL DEFAULT ARRAY[]::text[],
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    issued_at_ms bigint NOT NULL,
    revoked_at_ms bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_account_link_issued_grants_user
    ON account_link_issued_grants (issuer_user_id, updated_at_ms DESC);

CREATE INDEX IF NOT EXISTS idx_account_link_issued_grants_status
    ON account_link_issued_grants (status, updated_at_ms DESC);
