-- name: CreateUser :one
INSERT INTO users (
    tenant_id,
    username,
    email,
    password_hash,
    role
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING *;

-- name: GetUserByUsername :one
SELECT * FROM users
WHERE username = $1;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1;

-- name: ListUsersByTenant :many
SELECT * FROM users
WHERE tenant_id = $1
ORDER BY created_at ASC
LIMIT $2 OFFSET $3;

-- name: UpdateUserLastLogin :one
UPDATE users
SET last_login_at = NOW(), updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpdateUserPassword :one
UPDATE users
SET password_hash = $2, updated_at = NOW()
WHERE id = $1
RETURNING *;
