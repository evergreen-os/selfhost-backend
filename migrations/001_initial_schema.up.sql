-- EvergreenOS Selfhost Backend Initial Schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenants table
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_code VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Users table for admin accounts
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL CHECK (role IN ('owner', 'admin', 'auditor')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

-- Devices table
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id VARCHAR(128) UNIQUE NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_token_hash VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL CHECK (status IN ('pending', 'enrolled', 'suspended', 'decommissioned')),

    -- Hardware information
    hardware_model VARCHAR(255),
    hardware_manufacturer VARCHAR(255),
    hardware_serial_number VARCHAR(255),
    hardware_architecture VARCHAR(32),
    hardware_total_memory_bytes BIGINT,
    hardware_total_storage_bytes BIGINT,
    hardware_tpm_enabled BOOLEAN DEFAULT FALSE,
    hardware_tpm_version VARCHAR(16),

    -- OS information
    os_name VARCHAR(128),
    os_version VARCHAR(64),
    os_kernel_version VARCHAR(128),
    os_build_id VARCHAR(128),

    -- Network information
    network_hostname VARCHAR(255),
    network_primary_mac VARCHAR(17),

    -- Agent information
    agent_version VARCHAR(64),
    agent_commit VARCHAR(40),

    -- Timestamps
    enrolled_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Policies table
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id VARCHAR(128) UNIQUE NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version_timestamp TIMESTAMPTZ NOT NULL,
    policy_bundle JSONB NOT NULL,
    signature TEXT,
    signing_key_id VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

-- Events table
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id VARCHAR(128) UNIQUE NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    event_level VARCHAR(16) NOT NULL CHECK (event_level IN ('info', 'warn', 'error')),
    message TEXT NOT NULL,
    metadata JSONB,
    user_id VARCHAR(128),
    app_id VARCHAR(128),
    policy_id VARCHAR(128),
    error_details TEXT,
    duration_ms BIGINT,
    event_timestamp TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit logs table (immutable)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    correlation_id UUID,
    actor_type VARCHAR(32) NOT NULL CHECK (actor_type IN ('user', 'device', 'system')),
    actor_id VARCHAR(128) NOT NULL,
    tenant_id UUID REFERENCES tenants(id),
    action VARCHAR(128) NOT NULL,
    resource_type VARCHAR(64),
    resource_id VARCHAR(128),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Device state snapshots (latest state per device)
CREATE TABLE device_states (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    active_policy_id VARCHAR(128),
    policy_applied_at TIMESTAMPTZ,
    installed_apps JSONB,
    update_status JSONB,
    health_metrics JSONB,
    last_error TEXT,
    reported_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_tenants_tenant_code ON tenants(tenant_code);
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_devices_tenant_id ON devices(tenant_id);
CREATE INDEX idx_devices_device_id ON devices(device_id);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_last_seen_at ON devices(last_seen_at);
CREATE INDEX idx_policies_tenant_id ON policies(tenant_id);
CREATE INDEX idx_policies_policy_id ON policies(policy_id);
CREATE INDEX idx_policies_version_timestamp ON policies(version_timestamp);
CREATE INDEX idx_events_device_id ON events(device_id);
CREATE INDEX idx_events_event_type ON events(event_type);
CREATE INDEX idx_events_event_timestamp ON events(event_timestamp);
CREATE INDEX idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_actor_id ON audit_logs(actor_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_device_states_reported_at ON device_states(reported_at);