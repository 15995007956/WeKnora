DROP INDEX IF EXISTS idx_user_identities_deleted_at;
DROP INDEX IF EXISTS uq_user_identities_user_provider;
DROP INDEX IF EXISTS uq_user_identities_provider_subject;
DROP TABLE IF EXISTS user_identities;
