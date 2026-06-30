-- Slice 14: app-wide moderation bans and Stripe billing mappings.

CREATE TABLE IF NOT EXISTS account_bans (
    id              bigint PRIMARY KEY,
    user_id         bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason          text NULL,
    created_by      bigint NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at_ms   bigint NOT NULL,
    expires_at_ms   bigint NULL,
    revoked_at_ms   bigint NULL
);

CREATE INDEX IF NOT EXISTS account_bans_active_user_idx
    ON account_bans (user_id, created_at_ms DESC)
    WHERE revoked_at_ms IS NULL;

CREATE TABLE IF NOT EXISTS ip_bans (
    id              bigint PRIMARY KEY,
    ip              text NOT NULL,
    reason          text NULL,
    created_by      bigint NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at_ms   bigint NOT NULL,
    expires_at_ms   bigint NULL,
    revoked_at_ms   bigint NULL
);

CREATE INDEX IF NOT EXISTS ip_bans_active_ip_idx
    ON ip_bans (ip, created_at_ms DESC)
    WHERE revoked_at_ms IS NULL;

CREATE TABLE IF NOT EXISTS billing_customers (
    user_id                    bigint PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    stripe_customer_id          text NOT NULL UNIQUE,
    stripe_subscription_id      text NULL UNIQUE,
    stripe_subscription_status  text NULL,
    current_period_end_ms       bigint NULL,
    created_at_ms               bigint NOT NULL,
    updated_at_ms               bigint NOT NULL
);

CREATE INDEX IF NOT EXISTS billing_customers_subscription_idx
    ON billing_customers (stripe_subscription_id)
    WHERE stripe_subscription_id IS NOT NULL;
