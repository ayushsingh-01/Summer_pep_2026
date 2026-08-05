SET search_path TO password_vault;

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_account_status ON users(account_status);
CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users(last_login_at);

CREATE INDEX IF NOT EXISTS idx_vaults_owner_user_id ON vaults(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_vaults_vault_type ON vaults(vault_type);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen_at ON devices(last_seen_at);

CREATE INDEX IF NOT EXISTS idx_password_entries_vault_id ON password_entries(vault_id);
CREATE INDEX IF NOT EXISTS idx_password_entries_category_id ON password_entries(category_id);
CREATE INDEX IF NOT EXISTS idx_password_entries_created_by_user_id ON password_entries(created_by_user_id);
CREATE INDEX IF NOT EXISTS idx_password_entries_password_fingerprint ON password_entries(password_fingerprint);
CREATE INDEX IF NOT EXISTS idx_password_entries_expires_at ON password_entries(expires_at);
CREATE INDEX IF NOT EXISTS idx_password_entries_strength ON password_entries(password_strength);

CREATE INDEX IF NOT EXISTS idx_password_history_password_entry_id ON password_history(password_entry_id);
CREATE INDEX IF NOT EXISTS idx_password_history_changed_at ON password_history(changed_at);

CREATE INDEX IF NOT EXISTS idx_login_sessions_user_id ON login_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_login_sessions_device_id ON login_sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_login_sessions_login_time ON login_sessions(login_time);
CREATE INDEX IF NOT EXISTS idx_login_sessions_status ON login_sessions(login_status);

CREATE INDEX IF NOT EXISTS idx_shared_passwords_password_entry_id ON shared_passwords(password_entry_id);
CREATE INDEX IF NOT EXISTS idx_shared_passwords_shared_by_user_id ON shared_passwords(shared_by_user_id);
CREATE INDEX IF NOT EXISTS idx_shared_passwords_shared_with_user_id ON shared_passwords(shared_with_user_id);
CREATE INDEX IF NOT EXISTS idx_shared_passwords_expires_at ON shared_passwords(expires_at);

CREATE INDEX IF NOT EXISTS idx_security_alerts_user_id ON security_alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_security_alerts_alert_type ON security_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_security_alerts_created_at ON security_alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_security_alerts_open_only ON security_alerts(created_at) WHERE alert_status = 'open';

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_type ON audit_logs(action_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);
