SET search_path TO password_vault;

INSERT INTO roles (role_name, description)
VALUES
    ('admin', 'Full administrative access'),
    ('analyst', 'Can review reports and metrics'),
    ('user', 'Standard vault access'),
    ('auditor', 'Read-only compliance and audit access')
ON CONFLICT (role_name) DO NOTHING;

INSERT INTO permissions (permission_name, description)
VALUES
    ('manage_users', 'Create, update, and suspend users'),
    ('manage_vaults', 'Create and manage vaults'),
    ('share_passwords', 'Share password entries with other users'),
    ('view_reports', 'Access dashboards and analytics'),
    ('audit_logs', 'View audit log records')
ON CONFLICT (permission_name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
JOIN permissions p ON (
    (r.role_name = 'admin')
    OR (r.role_name = 'analyst' AND p.permission_name IN ('view_reports', 'audit_logs'))
    OR (r.role_name = 'user' AND p.permission_name = 'share_passwords')
    OR (r.role_name = 'auditor' AND p.permission_name IN ('view_reports', 'audit_logs'))
)
ON CONFLICT DO NOTHING;

INSERT INTO users (username, email, password_hash, full_name, email_verified, mfa_enabled, account_status, last_login_at)
VALUES
    ('john_doe', 'john@example.com', 'hash::john', 'John Doe', TRUE, TRUE, 'active', NOW() - INTERVAL '1 day'),
    ('alice_w', 'alice@example.com', 'hash::alice', 'Alice Walker', TRUE, FALSE, 'active', NOW() - INTERVAL '3 hours'),
    ('bob_admin', 'bob@example.com', 'hash::bob', 'Bob Admin', TRUE, TRUE, 'active', NOW() - INTERVAL '2 hours')
ON CONFLICT (username) DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.user_id, r.role_id
FROM users u
JOIN roles r ON (
    (u.username = 'john_doe' AND r.role_name = 'user')
    OR (u.username = 'alice_w' AND r.role_name = 'analyst')
    OR (u.username = 'bob_admin' AND r.role_name = 'admin')
)
ON CONFLICT DO NOTHING;

INSERT INTO categories (category_name, description)
VALUES
    ('Social', 'Social media accounts'),
    ('Banking', 'Financial services and banking'),
    ('Education', 'Learning and education platforms'),
    ('Entertainment', 'Streaming and media accounts'),
    ('Email', 'Email providers'),
    ('Shopping', 'Retail and ecommerce sites'),
    ('Gaming', 'Games and game launchers'),
    ('Development', 'Developer tools and repos'),
    ('Work', 'Work-related accounts')
ON CONFLICT (category_name) DO NOTHING;

INSERT INTO vaults (owner_user_id, vault_name, vault_type, description)
SELECT u.user_id, v.vault_name, v.vault_type, v.description
FROM users u
JOIN (
    VALUES
        ('john_doe', 'Personal Vault', 'personal', 'John private vault'),
        ('john_doe', 'Work Vault', 'work', 'John work accounts'),
        ('alice_w', 'Shared Vault', 'shared', 'Team shared vault'),
        ('bob_admin', 'Archive Vault', 'archive', 'Archived credentials')
) AS v(username, vault_name, vault_type, description)
ON v.username = u.username
ON CONFLICT (owner_user_id, vault_name) DO NOTHING;

INSERT INTO devices (user_id, device_name, device_type, device_fingerprint, operating_system, browser_hint, is_trusted, first_seen_at, last_seen_at)
SELECT u.user_id, d.device_name, d.device_type, d.device_fingerprint, d.operating_system, d.browser_hint, d.is_trusted, d.first_seen_at, d.last_seen_at
FROM users u
JOIN (
    VALUES
        ('john_doe', 'Windows Laptop', 'windows_laptop', 'fp::john-win', 'Windows 11', 'Chrome', TRUE, NOW() - INTERVAL '10 days', NOW() - INTERVAL '1 day'),
        ('john_doe', 'Android Phone', 'android_phone', 'fp::john-android', 'Android', 'Chrome Mobile', FALSE, NOW() - INTERVAL '4 days', NOW() - INTERVAL '4 hours'),
        ('alice_w', 'MacBook', 'macbook', 'fp::alice-mac', 'macOS', 'Safari', TRUE, NOW() - INTERVAL '12 days', NOW() - INTERVAL '3 hours'),
        ('bob_admin', 'Linux Desktop', 'linux_desktop', 'fp::bob-linux', 'Ubuntu', 'Firefox', TRUE, NOW() - INTERVAL '8 days', NOW() - INTERVAL '2 hours')
) AS d(username, device_name, device_type, device_fingerprint, operating_system, browser_hint, is_trusted, first_seen_at, last_seen_at)
ON d.username = u.username
ON CONFLICT (device_fingerprint) DO NOTHING;

WITH password_specs AS (
    SELECT *
    FROM (
        VALUES
            ('john_doe', 'Personal Vault', 'Email', 'Gmail', 'john.gmail', 'enc::john-gmail', 'fp::reuse-001', 'https://mail.google.com', 'Personal email account', 'weak', NOW() - INTERVAL '45 days', NOW() - INTERVAL '10 days', NOW() - INTERVAL '5 days', NOW() - INTERVAL '40 days', TRUE),
            ('john_doe', 'Personal Vault', 'Social', 'Twitter', 'john.social', 'enc::john-twitter', 'fp::reuse-001', 'https://x.com', 'Social account with reused fingerprint', 'medium', NOW() - INTERVAL '30 days', NOW() - INTERVAL '12 days', NOW() + INTERVAL '30 days', NOW() - INTERVAL '20 days', FALSE),
            ('john_doe', 'Work Vault', 'Development', 'GitHub', 'john.dev', 'enc::john-github', 'fp::john-github', 'https://github.com', 'Developer account', 'strong', NOW() - INTERVAL '20 days', NOW() - INTERVAL '5 days', NOW() + INTERVAL '60 days', NOW() - INTERVAL '5 days', TRUE),
            ('alice_w', 'Shared Vault', 'Work', 'Notion', 'alice.work', 'enc::alice-notion', 'fp::alice-notion', 'https://notion.so', 'Shared team workspace', 'very_strong', NOW() - INTERVAL '25 days', NOW() - INTERVAL '2 days', NOW() + INTERVAL '90 days', NOW() - INTERVAL '2 days', FALSE),
            ('alice_w', 'Shared Vault', 'Banking', 'Bank Portal', 'alice.bank', 'enc::alice-bank', 'fp::alice-bank', 'https://bank.example.com', 'Banking portal', 'strong', NOW() - INTERVAL '40 days', NOW() - INTERVAL '6 days', NOW() + INTERVAL '15 days', NOW() - INTERVAL '6 days', TRUE),
            ('bob_admin', 'Archive Vault', 'Email', 'Old Mail', 'bob.archive', 'enc::bob-oldmail', 'fp::bob-oldmail', 'https://mail.example.com', 'Archived email', 'medium', NOW() - INTERVAL '120 days', NOW() - INTERVAL '40 days', NOW() - INTERVAL '1 day', NOW() - INTERVAL '100 days', FALSE)
    ) AS p(username, vault_name, category_name, website_name, entry_username, encrypted_password, password_fingerprint, url, notes, password_strength, created_at, updated_at, expires_at, last_rotated_at, is_favorite)
)
INSERT INTO password_entries (
    vault_id,
    category_id,
    created_by_user_id,
    website_name,
    username,
    encrypted_password,
    password_fingerprint,
    url,
    notes,
    password_strength,
    created_at,
    updated_at,
    expires_at,
    last_rotated_at,
    is_favorite
)
SELECT
    v.vault_id,
    c.category_id,
    u.user_id,
    p.website_name,
    p.entry_username,
    p.encrypted_password,
    p.password_fingerprint,
    p.url,
    p.notes,
    p.password_strength,
    p.created_at,
    p.updated_at,
    p.expires_at,
    p.last_rotated_at,
    p.is_favorite
FROM password_specs p
JOIN users u ON u.username = p.username
JOIN vaults v ON v.owner_user_id = u.user_id AND v.vault_name = p.vault_name
JOIN categories c ON c.category_name = p.category_name
ON CONFLICT (vault_id, website_name, username) DO NOTHING;

INSERT INTO password_history (
    password_entry_id,
    changed_by_user_id,
    encrypted_password,
    password_fingerprint,
    version_number,
    changed_at,
    change_reason
)
SELECT
    pe.password_entry_id,
    pe.created_by_user_id,
    pe.encrypted_password,
    pe.password_fingerprint,
    1,
    pe.created_at,
    'initial_load'
FROM password_entries pe
WHERE NOT EXISTS (
    SELECT 1
    FROM password_history ph
    WHERE ph.password_entry_id = pe.password_entry_id
      AND ph.version_number = 1
);

WITH login_specs AS (
    SELECT *
    FROM (
        VALUES
            ('john_doe', 'fp::john-win', '10.0.0.10'::inet, 'Chrome', NOW() - INTERVAL '1 day 2 hours', NOW() - INTERVAL '1 day 1 hour', 'success', NULL),
            ('john_doe', 'fp::john-android', '10.0.0.14'::inet, 'Chrome Mobile', NOW() - INTERVAL '4 hours', NULL, 'failure', 'Invalid password'),
            ('john_doe', 'fp::john-android', '10.0.0.14'::inet, 'Chrome Mobile', NOW() - INTERVAL '3 hours 50 minutes', NULL, 'failure', 'Invalid password'),
            ('john_doe', 'fp::john-android', '10.0.0.14'::inet, 'Chrome Mobile', NOW() - INTERVAL '3 hours 45 minutes', NULL, 'failure', 'Invalid password'),
            ('alice_w', 'fp::alice-mac', '10.0.0.20'::inet, 'Safari', NOW() - INTERVAL '3 hours', NULL, 'success', NULL),
            ('bob_admin', 'fp::bob-linux', '10.0.0.30'::inet, 'Firefox', NOW() - INTERVAL '2 hours', NULL, 'success', NULL)
    ) AS l(username, device_fingerprint, ip_address, browser_name, login_time, logout_time, login_status, failure_reason)
)
INSERT INTO login_sessions (
    user_id,
    device_id,
    ip_address,
    browser_name,
    login_time,
    logout_time,
    login_status,
    failure_reason
)
SELECT
    u.user_id,
    d.device_id,
    l.ip_address,
    l.browser_name,
    l.login_time,
    l.logout_time,
    l.login_status,
    l.failure_reason
FROM login_specs l
JOIN users u ON u.username = l.username
JOIN devices d ON d.user_id = u.user_id AND d.device_fingerprint = l.device_fingerprint
ON CONFLICT DO NOTHING;

WITH share_specs AS (
    SELECT *
    FROM (
        VALUES
            ('john_doe', 'alice_w', 'read_only', NOW() - INTERVAL '5 days', NOW() + INTERVAL '10 days', NULL::timestamptz),
            ('alice_w', 'john_doe', 'temporary', NOW() - INTERVAL '2 days', NOW() + INTERVAL '2 days', NULL::timestamptz)
    ) AS s(shared_by_username, shared_with_username, access_level, shared_at, expires_at, revoked_at)
)
INSERT INTO shared_passwords (
    password_entry_id,
    shared_by_user_id,
    shared_with_user_id,
    access_level,
    shared_at,
    expires_at,
    revoked_at
)
SELECT
    pe.password_entry_id,
    sender.user_id,
    receiver.user_id,
    s.access_level,
    s.shared_at,
    s.expires_at,
    s.revoked_at
FROM share_specs s
JOIN users sender ON sender.username = s.shared_by_username
JOIN users receiver ON receiver.username = s.shared_with_username
JOIN password_entries pe ON (
    sender.username = 'john_doe'
    AND receiver.username = 'alice_w'
    AND pe.website_name = 'Gmail'
    AND pe.created_by_user_id = sender.user_id
) OR (
    sender.username = 'alice_w'
    AND receiver.username = 'john_doe'
    AND pe.website_name = 'Notion'
    AND pe.created_by_user_id = sender.user_id
)
ON CONFLICT (password_entry_id, shared_with_user_id) DO NOTHING;
