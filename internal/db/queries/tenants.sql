-- name: CreateTenant :one
INSERT INTO tenants (tenant_code, name)
VALUES ($1, $2)
RETURNING *;

-- name: GetTenantByCode :one
SELECT * FROM tenants
WHERE tenant_code = $1;

-- name: GetTenantByID :one
SELECT * FROM tenants
WHERE id = $1;

-- name: ListTenants :many
SELECT * FROM tenants
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: UpdateTenant :one
UPDATE tenants
SET name = $2, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteTenant :exec
DELETE FROM tenants
WHERE id = $1;
-- name: UpdateTenantSecret :one
UPDATE tenants
SET enrollment_secret_hash = $2, updated_at = NOW()
WHERE id = $1
RETURNING *;
