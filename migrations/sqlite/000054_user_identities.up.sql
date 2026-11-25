-- External identity bindings (DingTalk now; WeCom / Feishu later).
-- A local user may hold several rows, one per external login provider.
-- (provider, provider_subject) is the stable lookup key: for DingTalk the
-- subject is the unionId, which is stable per-user across an organization.
CREATE TABLE IF NOT EXISTS user_identities (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    provider VARCHAR(32) NOT NULL,
    provider_subject VARCHAR(128) NOT NULL,
    provider_tenant VARCHAR(64),
    display_name VARCHAR(255),
    avatar_url VARCHAR(500),
    last_login_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    deleted_at DATETIME
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_identities_provider_subject
    ON user_identities(provider, provider_subject) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_identities_user_provider
    ON user_identities(user_id, provider) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_identities_deleted_at ON user_identities(deleted_at);
