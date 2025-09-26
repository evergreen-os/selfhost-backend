-- name: CreateDevice :one
INSERT INTO devices (
    device_id,
    tenant_id,
    device_token_hash,
    status,
    hardware_model,
    hardware_manufacturer,
    hardware_serial_number,
    hardware_architecture,
    hardware_total_memory_bytes,
    hardware_total_storage_bytes,
    hardware_tpm_enabled,
    hardware_tpm_version,
    os_name,
    os_version,
    os_kernel_version,
    os_build_id,
    network_hostname,
    network_primary_mac,
    agent_version,
    agent_commit,
    enrolled_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
) RETURNING *;

-- name: GetDeviceByID :one
SELECT * FROM devices
WHERE device_id = $1;

-- name: GetDeviceByUUID :one
SELECT * FROM devices
WHERE id = $1;

-- name: ListDevicesByTenant :many
SELECT * FROM devices
WHERE tenant_id = $1
ORDER BY last_seen_at DESC NULLS LAST, created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListDevicesByStatus :many
SELECT * FROM devices
WHERE tenant_id = $1 AND status = $2
ORDER BY last_seen_at DESC NULLS LAST, created_at DESC
LIMIT $3 OFFSET $4;

-- name: UpdateDeviceStatus :one
UPDATE devices
SET status = $2, updated_at = NOW()
WHERE device_id = $1
RETURNING *;

-- name: UpdateDeviceLastSeen :one
UPDATE devices
SET last_seen_at = $2, updated_at = NOW()
WHERE device_id = $1
RETURNING *;

-- name: DeleteDevice :exec
DELETE FROM devices
WHERE device_id = $1;