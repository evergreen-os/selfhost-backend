-- name: UpsertDeviceState :one
INSERT INTO device_states (
    device_id,
    active_policy_id,
    policy_applied_at,
    installed_apps,
    update_status,
    health_metrics,
    last_error,
    reported_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
) ON CONFLICT (device_id) DO UPDATE SET
    active_policy_id = EXCLUDED.active_policy_id,
    policy_applied_at = EXCLUDED.policy_applied_at,
    installed_apps = EXCLUDED.installed_apps,
    update_status = EXCLUDED.update_status,
    health_metrics = EXCLUDED.health_metrics,
    last_error = EXCLUDED.last_error,
    reported_at = EXCLUDED.reported_at,
    updated_at = NOW()
RETURNING *;

-- name: GetDeviceState :one
SELECT * FROM device_states
WHERE device_id = $1;

-- name: ListDeviceStatesByTenant :many
SELECT ds.* FROM device_states ds
JOIN devices d ON ds.device_id = d.id
WHERE d.tenant_id = $1
ORDER BY ds.reported_at DESC
LIMIT $2 OFFSET $3;

-- name: DeleteDeviceState :exec
DELETE FROM device_states
WHERE device_id = $1;

-- name: GetStaleDeviceStates :many
SELECT ds.* FROM device_states ds
WHERE ds.reported_at < $1
ORDER BY ds.reported_at ASC
LIMIT $2;