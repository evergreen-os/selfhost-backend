-- name: CreateEvent :one
INSERT INTO events (
    event_id,
    device_id,
    event_type,
    event_level,
    message,
    metadata,
    user_id,
    app_id,
    policy_id,
    error_details,
    duration_ms,
    event_timestamp
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
) RETURNING *;

-- name: GetEventByID :one
SELECT * FROM events
WHERE event_id = $1;

-- name: ListEventsByDevice :many
SELECT * FROM events
WHERE device_id = $1
ORDER BY event_timestamp DESC
LIMIT $2 OFFSET $3;

-- name: ListEventsByTenant :many
SELECT e.* FROM events e
JOIN devices d ON e.device_id = d.id
WHERE d.tenant_id = $1
ORDER BY e.event_timestamp DESC
LIMIT $2 OFFSET $3;

-- name: ListEventsByType :many
SELECT e.* FROM events e
JOIN devices d ON e.device_id = d.id
WHERE d.tenant_id = $1 AND e.event_type = $2
ORDER BY e.event_timestamp DESC
LIMIT $3 OFFSET $4;

-- name: CountEventsByDevice :one
SELECT COUNT(*) FROM events
WHERE device_id = $1;

-- name: DeleteOldEvents :exec
DELETE FROM events
WHERE event_timestamp < $1;