ALTER TABLE tenants
    ADD COLUMN enrollment_secret_hash VARCHAR(255) NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_username
    ON users(tenant_id, username);
