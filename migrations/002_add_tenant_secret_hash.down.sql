DROP INDEX IF EXISTS idx_users_tenant_username;
ALTER TABLE tenants
    DROP COLUMN IF EXISTS enrollment_secret_hash;
