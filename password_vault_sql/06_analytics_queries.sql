SET search_path TO password_vault;

-- 1. Executive dashboard summary
WITH totals AS (
    SELECT
        (SELECT COUNT(*) FROM users) AS total_users,
        (SELECT COUNT(*) FROM vaults) AS total_vaults,
        (SELECT COUNT(*) FROM password_entries) AS total_passwords,
        (SELECT COUNT(*) FROM shared_passwords WHERE revoked_at IS NULL) AS shared_passwords,
        (SELECT COUNT(*) FROM password_entries WHERE expires_at IS NOT NULL AND expires_at <= NOW()) AS expired_passwords,
        (SELECT COUNT(*) FROM password_entries WHERE password_strength = 'weak') AS weak_passwords,
        (SELECT ROUND(100.0 * COUNT(*) FILTER (WHERE mfa_enabled) / NULLIF(COUNT(*), 0), 2) FROM users) AS mfa_adoption_rate,
        (SELECT COUNT(*) FROM login_sessions WHERE logout_time IS NULL AND login_status = 'success') AS active_sessions
)
SELECT * FROM totals;

-- 2. Password strength distribution
SELECT
    password_strength,
    COUNT(*) AS password_count,
    ROUND(100.0 * COUNT(*) / NULLIF(SUM(COUNT(*)) OVER (), 0), 2) AS percentage_of_total
FROM password_entries
GROUP BY password_strength
ORDER BY password_count DESC;

-- 3. Security score leaderboard
SELECT
    user_id,
    username,
    security_score,
    vault_count,
    password_count,
    open_alert_count,
    mfa_enabled
FROM vw_user_security_summary
ORDER BY security_score DESC, password_count DESC;

-- 4. Login analytics by hour and day
SELECT
    EXTRACT(DOW FROM login_time) AS day_of_week,
    EXTRACT(HOUR FROM login_time) AS hour_of_day,
    COUNT(*) AS login_count,
    COUNT(*) FILTER (WHERE login_status = 'success') AS successful_logins,
    COUNT(*) FILTER (WHERE login_status = 'failure') AS failed_logins
FROM login_sessions
GROUP BY EXTRACT(DOW FROM login_time), EXTRACT(HOUR FROM login_time)
ORDER BY day_of_week, hour_of_day;

-- 5. Device distribution
SELECT
    d.device_type,
    COUNT(*) AS device_count,
    COUNT(DISTINCT d.user_id) AS user_count,
    COUNT(*) FILTER (WHERE d.is_trusted) AS trusted_device_count
FROM devices d
GROUP BY d.device_type
ORDER BY device_count DESC;

-- 6. Vault usage analysis
SELECT
    vault_type,
    COUNT(*) AS vault_count,
    SUM(password_count) AS total_passwords,
    ROUND(AVG(password_count), 2) AS average_passwords_per_vault
FROM vw_vault_summary
GROUP BY vault_type
ORDER BY vault_count DESC;

-- 7. Security alert trend over time
SELECT
    DATE_TRUNC('day', created_at) AS alert_day,
    alert_type,
    COUNT(*) AS alert_count,
    SUM(COUNT(*)) OVER (PARTITION BY alert_type ORDER BY DATE_TRUNC('day', created_at)) AS running_total
FROM security_alerts
GROUP BY DATE_TRUNC('day', created_at), alert_type
ORDER BY alert_day, alert_type;

-- 8. Risk-ranked users with window function
WITH ranked_users AS (
    SELECT
        user_id,
        username,
        risk_score,
        risk_rank,
        weak_password_count,
        expired_password_count,
        failed_login_count,
        no_mfa_flag
    FROM vw_risk_ranking
)
SELECT
    *,
    CASE
        WHEN risk_score >= 40 THEN 'high'
        WHEN risk_score >= 20 THEN 'medium'
        ELSE 'low'
    END AS risk_band
FROM ranked_users
ORDER BY risk_score DESC, username;

-- 9. Audit action summary
SELECT
    action_type,
    COUNT(*) AS action_count,
    COUNT(DISTINCT user_id) AS affected_users,
    MAX(created_at) AS last_action_at
FROM audit_logs
GROUP BY action_type
ORDER BY action_count DESC, action_type;
