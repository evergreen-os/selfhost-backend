-- name: CreatePolicy :one
INSERT INTO policies (
    policy_id,
    tenant_id,
    name,
    version_timestamp,
    policy_bundle,
    signature,
    signing_key_id,
    created_by
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
) RETURNING *;

-- name: GetPolicyByID :one
SELECT * FROM policies
WHERE policy_id = $1;

-- name: GetLatestPolicyByTenant :one
SELECT * FROM policies
WHERE tenant_id = $1
ORDER BY version_timestamp DESC
LIMIT 1;

-- name: ListPoliciesByTenant :many
SELECT * FROM policies
WHERE tenant_id = $1
ORDER BY version_timestamp DESC
LIMIT $2 OFFSET $3;

-- name: UpdatePolicy :one
UPDATE policies
SET
    name = $2,
    version_timestamp = $3,
    policy_bundle = $4,
    signature = $5,
    signing_key_id = $6
WHERE policy_id = $1
RETURNING *;

-- name: DeletePolicy :exec
DELETE FROM policies
WHERE policy_id = $1;