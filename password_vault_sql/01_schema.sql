CREATE SCHEMA IF NOT EXISTS password_vault;
SET search_path TO password_vault;

CREATE TABLE IF NOT EXISTS users (
    user_id BIGSERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name VARCHAR(150),
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    account_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_users_account_status CHECK (account_status IN ('pending', 'active', 'locked', 'suspended', 'archived'))
);

CREATE TABLE IF NOT EXISTS roles (
    role_id BIGSERIAL PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS permissions (
    permission_id BIGSERIAL PRIMARY KEY,
    permission_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS categories (
    category_id BIGSERIAL PRIMARY KEY,
    category_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS vaults (
    vault_id BIGSERIAL PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    vault_name VARCHAR(120) NOT NULL,
    vault_type VARCHAR(20) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_vaults_vault_type CHECK (vault_type IN ('personal', 'shared', 'work', 'archive')),
    CONSTRAINT uq_vault_owner_name UNIQUE (owner_user_id, vault_name)
);

CREATE TABLE IF NOT EXISTS devices (
    device_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_name VARCHAR(150) NOT NULL,
    device_type VARCHAR(30) NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL UNIQUE,
    operating_system VARCHAR(100),
    browser_hint VARCHAR(100),
    is_trusted BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_devices_device_type CHECK (device_type IN ('windows_laptop', 'android_phone', 'macbook', 'linux_desktop', 'ios_phone', 'tablet', 'other'))
);

CREATE TABLE IF NOT EXISTS password_entries (
    password_entry_id BIGSERIAL PRIMARY KEY,
    vault_id BIGINT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
    category_id BIGINT REFERENCES categories(category_id) ON DELETE SET NULL,
    created_by_user_id BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    website_name VARCHAR(150) NOT NULL,
    username VARCHAR(150) NOT NULL,
    encrypted_password TEXT NOT NULL,
    password_fingerprint VARCHAR(255) NOT NULL,
    url TEXT,
    notes TEXT,
    password_strength VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ,
    is_favorite BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT chk_password_strength CHECK (password_strength IN ('weak', 'medium', 'strong', 'very_strong')),
    CONSTRAINT uq_vault_site_username UNIQUE (vault_id, website_name, username)
);

CREATE TABLE IF NOT EXISTS password_history (
    history_id BIGSERIAL PRIMARY KEY,
    password_entry_id BIGINT NOT NULL REFERENCES password_entries(password_entry_id) ON DELETE CASCADE,
    changed_by_user_id BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    encrypted_password TEXT NOT NULL,
    password_fingerprint VARCHAR(255) NOT NULL,
    version_number INTEGER NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    change_reason TEXT,
    CONSTRAINT uq_password_history_version UNIQUE (password_entry_id, version_number)
);

CREATE TABLE IF NOT EXISTS login_sessions (
    session_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id BIGINT REFERENCES devices(device_id) ON DELETE SET NULL,
    ip_address INET,
    browser_name VARCHAR(150),
    login_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    logout_time TIMESTAMPTZ,
    login_status VARCHAR(20) NOT NULL,
    failure_reason TEXT,
    CONSTRAINT chk_login_status CHECK (login_status IN ('success', 'failure'))
);

CREATE TABLE IF NOT EXISTS shared_passwords (
    shared_password_id BIGSERIAL PRIMARY KEY,
    password_entry_id BIGINT NOT NULL REFERENCES password_entries(password_entry_id) ON DELETE CASCADE,
    shared_by_user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    shared_with_user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    access_level VARCHAR(20) NOT NULL,
    shared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT chk_shared_access_level CHECK (access_level IN ('read_only', 'edit', 'temporary')),
    CONSTRAINT chk_distinct_share_users CHECK (shared_by_user_id <> shared_with_user_id),
    CONSTRAINT uq_shared_password UNIQUE (password_entry_id, shared_with_user_id)
);

CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    password_entry_id BIGINT REFERENCES password_entries(password_entry_id) ON DELETE CASCADE,
    login_session_id BIGINT REFERENCES login_sessions(session_id) ON DELETE CASCADE,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    alert_status VARCHAR(20) NOT NULL DEFAULT 'open',
    alert_message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    CONSTRAINT chk_alert_type CHECK (alert_type IN ('weak_password', 'reused_password', 'expired_password', 'new_device_login', 'multiple_failed_logins', 'suspicious_activity')),
    CONSTRAINT chk_alert_severity CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT chk_alert_status CHECK (alert_status IN ('open', 'acknowledged', 'resolved'))
);

CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    vault_id BIGINT REFERENCES vaults(vault_id) ON DELETE SET NULL,
    password_entry_id BIGINT REFERENCES password_entries(password_entry_id) ON DELETE SET NULL,
    action_type VARCHAR(50) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id BIGINT,
    action_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id BIGINT NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);
