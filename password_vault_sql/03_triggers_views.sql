SET search_path TO password_vault;

CREATE OR REPLACE FUNCTION fn_capture_password_history()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_next_version INTEGER;
BEGIN
    IF NEW.encrypted_password IS DISTINCT FROM OLD.encrypted_password
       OR NEW.password_fingerprint IS DISTINCT FROM OLD.password_fingerprint THEN
        SELECT COALESCE(MAX(version_number), 0) + 1
        INTO v_next_version
        FROM password_history
        WHERE password_entry_id = OLD.password_entry_id;

        INSERT INTO password_history (
            password_entry_id,
            changed_by_user_id,
            encrypted_password,
            password_fingerprint,
            version_number,
            change_reason
        )
        VALUES (
            OLD.password_entry_id,
            COALESCE(NEW.created_by_user_id, OLD.created_by_user_id),
            OLD.encrypted_password,
            OLD.password_fingerprint,
            v_next_version,
            'password_updated'
        );

        NEW.last_rotated_at := NOW();
    END IF;

    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION fn_password_entry_security_checks()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_owner_user_id BIGINT;
BEGIN
    SELECT v.owner_user_id
    INTO v_owner_user_id
    FROM vaults v
    WHERE v.vault_id = NEW.vault_id;

    IF NEW.password_strength = 'weak' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM security_alerts
            WHERE password_entry_id = NEW.password_entry_id
              AND alert_type = 'weak_password'
              AND alert_status = 'open'
        ) THEN
            INSERT INTO security_alerts (
                user_id,
                password_entry_id,
                alert_type,
                severity,
                alert_message
            )
            VALUES (
                COALESCE(NEW.created_by_user_id, v_owner_user_id),
                NEW.password_entry_id,
                'weak_password',
                'medium',
                'Password strength is weak and should be improved.'
            );
        END IF;
    END IF;

    IF NEW.expires_at IS NOT NULL AND NEW.expires_at <= NOW() THEN
        IF NOT EXISTS (
            SELECT 1
            FROM security_alerts
            WHERE password_entry_id = NEW.password_entry_id
              AND alert_type = 'expired_password'
              AND alert_status = 'open'
        ) THEN
            INSERT INTO security_alerts (
                user_id,
                password_entry_id,
                alert_type,
                severity,
                alert_message
            )
            VALUES (
                COALESCE(NEW.created_by_user_id, v_owner_user_id),
                NEW.password_entry_id,
                'expired_password',
                'high',
                'Password has expired and should be rotated.'
            );
        END IF;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM password_entries pe
        JOIN vaults v ON v.vault_id = pe.vault_id
        WHERE pe.password_fingerprint = NEW.password_fingerprint
          AND pe.password_entry_id <> NEW.password_entry_id
          AND v.owner_user_id = v_owner_user_id
    ) THEN
        IF NOT EXISTS (
            SELECT 1
            FROM security_alerts
            WHERE password_entry_id = NEW.password_entry_id
              AND alert_type = 'reused_password'
              AND alert_status = 'open'
        ) THEN
            INSERT INTO security_alerts (
                user_id,
                password_entry_id,
                alert_type,
                severity,
                alert_message
            )
            VALUES (
                COALESCE(NEW.created_by_user_id, v_owner_user_id),
                NEW.password_entry_id,
                'reused_password',
                'high',
                'Password fingerprint matches another stored password.'
            );
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION fn_login_session_security_checks()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_failed_count INTEGER;
BEGIN
    IF NEW.login_status = 'success' AND NEW.device_id IS NOT NULL THEN
        UPDATE devices
        SET last_seen_at = NEW.login_time,
            updated_at = NOW()
        WHERE device_id = NEW.device_id;

        IF EXISTS (
            SELECT 1
            FROM devices d
            WHERE d.device_id = NEW.device_id
              AND d.is_trusted = FALSE
        ) THEN
            IF NOT EXISTS (
                SELECT 1
                FROM security_alerts
                WHERE login_session_id = NEW.session_id
                  AND alert_type = 'new_device_login'
            ) THEN
                INSERT INTO security_alerts (
                    user_id,
                    login_session_id,
                    alert_type,
                    severity,
                    alert_message
                )
                VALUES (
                    NEW.user_id,
                    NEW.session_id,
                    'new_device_login',
                    'medium',
                    'Login occurred from a device that is not yet trusted.'
                );
            END IF;
        END IF;
    END IF;

    IF NEW.login_status = 'failure' THEN
        SELECT COUNT(*)
        INTO v_failed_count
        FROM login_sessions ls
        WHERE ls.user_id = NEW.user_id
          AND ls.login_status = 'failure'
          AND ls.login_time >= NOW() - INTERVAL '15 minutes';

                IF v_failed_count >= 3 AND NOT EXISTS (
                        SELECT 1
                        FROM security_alerts
                        WHERE user_id = NEW.user_id
                            AND alert_type = 'multiple_failed_logins'
                            AND created_at >= NOW() - INTERVAL '15 minutes'
                ) THEN
            INSERT INTO security_alerts (
                user_id,
                login_session_id,
                alert_type,
                severity,
                alert_message
            )
            VALUES (
                NEW.user_id,
                NEW.session_id,
                'multiple_failed_logins',
                'high',
                'Multiple failed login attempts were detected in a short time window.'
            );
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION fn_audit_password_entries()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_entity_id BIGINT;
    v_actor_user_id BIGINT;
    v_vault_id BIGINT;
    v_payload JSONB;
BEGIN
    v_entity_id := COALESCE(NEW.password_entry_id, OLD.password_entry_id);
    v_actor_user_id := COALESCE(NEW.created_by_user_id, OLD.created_by_user_id);
    v_vault_id := COALESCE(NEW.vault_id, OLD.vault_id);
    v_payload := CASE
        WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD)
        ELSE to_jsonb(NEW)
    END;

    PERFORM fn_log_audit_event(
        v_actor_user_id,
        v_vault_id,
        v_entity_id,
        LOWER(TG_OP) || '_password_entry',
        'password_entries',
        v_entity_id,
        v_payload
    );

    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE OR REPLACE FUNCTION fn_audit_shared_passwords()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_entity_id BIGINT;
    v_payload JSONB;
BEGIN
    v_entity_id := COALESCE(NEW.shared_password_id, OLD.shared_password_id);
    v_payload := CASE
        WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD)
        ELSE to_jsonb(NEW)
    END;

    PERFORM fn_log_audit_event(
        COALESCE(NEW.shared_by_user_id, OLD.shared_by_user_id),
        NULL,
        COALESCE(NEW.password_entry_id, OLD.password_entry_id),
        LOWER(TG_OP) || '_shared_password',
        'shared_passwords',
        v_entity_id,
        v_payload
    );

    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE OR REPLACE FUNCTION fn_audit_vaults()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_entity_id BIGINT;
    v_payload JSONB;
BEGIN
    v_entity_id := COALESCE(NEW.vault_id, OLD.vault_id);
    v_payload := CASE
        WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD)
        ELSE to_jsonb(NEW)
    END;

    PERFORM fn_log_audit_event(
        COALESCE(NEW.owner_user_id, OLD.owner_user_id),
        v_entity_id,
        NULL,
        LOWER(TG_OP) || '_vault',
        'vaults',
        v_entity_id,
        v_payload
    );

    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE OR REPLACE FUNCTION fn_audit_users()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_entity_id BIGINT;
    v_payload JSONB;
BEGIN
    v_entity_id := COALESCE(NEW.user_id, OLD.user_id);
    v_payload := CASE
        WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD)
        ELSE to_jsonb(NEW)
    END;

    PERFORM fn_log_audit_event(
        v_entity_id,
        NULL,
        NULL,
        LOWER(TG_OP) || '_user',
        'users',
        v_entity_id,
        v_payload
    );

    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE OR REPLACE FUNCTION fn_audit_login_sessions()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_entity_id BIGINT;
    v_payload JSONB;
BEGIN
    v_entity_id := COALESCE(NEW.session_id, OLD.session_id);
    v_payload := CASE
        WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD)
        ELSE to_jsonb(NEW)
    END;

    PERFORM fn_log_audit_event(
        COALESCE(NEW.user_id, OLD.user_id),
        NULL,
        NULL,
        LOWER(TG_OP) || '_login_session',
        'login_sessions',
        v_entity_id,
        v_payload,
        COALESCE(NEW.ip_address, OLD.ip_address)
    );

    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE OR REPLACE VIEW vw_user_security_summary AS
SELECT
    u.user_id,
    u.username,
    u.email,
    u.account_status,
    u.email_verified,
    u.mfa_enabled,
    u.last_login_at,
    COUNT(DISTINCT v.vault_id) AS vault_count,
    COUNT(DISTINCT pe.password_entry_id) AS password_count,
    COUNT(DISTINCT sp.shared_password_id) FILTER (WHERE sp.revoked_at IS NULL) AS active_shared_password_count,
    COUNT(DISTINCT sa.alert_id) FILTER (WHERE sa.alert_status = 'open') AS open_alert_count,
    COUNT(DISTINCT pe.password_entry_id) FILTER (WHERE pe.password_strength IN ('strong', 'very_strong')) AS strong_password_count,
    ROUND(
        GREATEST(
            0,
            100
            - (COUNT(DISTINCT sa.alert_id) FILTER (WHERE sa.alert_status = 'open') * 8)
            - (COUNT(DISTINCT pe.password_entry_id) FILTER (WHERE pe.password_strength = 'weak') * 4)
            + CASE WHEN u.mfa_enabled THEN 12 ELSE 0 END
            + CASE WHEN u.email_verified THEN 5 ELSE 0 END
        )::NUMERIC,
        2
    ) AS security_score
FROM users u
LEFT JOIN vaults v ON v.owner_user_id = u.user_id
LEFT JOIN password_entries pe ON pe.vault_id = v.vault_id
LEFT JOIN shared_passwords sp ON sp.shared_by_user_id = u.user_id OR sp.shared_with_user_id = u.user_id
LEFT JOIN security_alerts sa ON sa.user_id = u.user_id
GROUP BY u.user_id, u.username, u.email, u.account_status, u.email_verified, u.mfa_enabled, u.last_login_at;

CREATE OR REPLACE VIEW vw_password_health AS
SELECT
    COUNT(*) AS total_passwords,
    COUNT(*) FILTER (WHERE password_strength = 'weak') AS weak_passwords,
    COUNT(*) FILTER (WHERE password_strength = 'medium') AS medium_passwords,
    COUNT(*) FILTER (WHERE password_strength = 'strong') AS strong_passwords,
    COUNT(*) FILTER (WHERE password_strength = 'very_strong') AS very_strong_passwords,
    ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400.0), 2) AS average_password_age_days,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE password_strength IN ('weak', 'medium')) / NULLIF(COUNT(*), 0),
        2
    ) AS percentage_not_strong
FROM password_entries;

CREATE OR REPLACE VIEW vw_vault_summary AS
SELECT
    v.vault_id,
    v.owner_user_id,
    u.username AS owner_username,
    v.vault_name,
    v.vault_type,
    COUNT(pe.password_entry_id) AS password_count,
    COUNT(DISTINCT pe.category_id) AS category_count,
    ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - pe.created_at)) / 86400.0), 2) AS average_password_age_days
FROM vaults v
JOIN users u ON u.user_id = v.owner_user_id
LEFT JOIN password_entries pe ON pe.vault_id = v.vault_id
GROUP BY v.vault_id, v.owner_user_id, u.username, v.vault_name, v.vault_type;

CREATE OR REPLACE VIEW vw_login_activity AS
SELECT
    ls.user_id,
    u.username,
    DATE_TRUNC('day', ls.login_time) AS login_day,
    COUNT(*) AS total_logins,
    COUNT(*) FILTER (WHERE ls.login_status = 'success') AS successful_logins,
    COUNT(*) FILTER (WHERE ls.login_status = 'failure') AS failed_logins,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE ls.login_status = 'success') / NULLIF(COUNT(*), 0),
        2
    ) AS success_rate
FROM login_sessions ls
JOIN users u ON u.user_id = ls.user_id
GROUP BY ls.user_id, u.username, DATE_TRUNC('day', ls.login_time);

CREATE OR REPLACE VIEW vw_risk_ranking AS
WITH user_counts AS (
    SELECT
        u.user_id,
        u.username,
        COUNT(DISTINCT pe.password_entry_id) FILTER (WHERE pe.password_strength = 'weak') AS weak_password_count,
        COUNT(DISTINCT pe.password_entry_id) FILTER (WHERE pe.expires_at IS NOT NULL AND pe.expires_at <= NOW()) AS expired_password_count,
        COUNT(DISTINCT ls.session_id) FILTER (WHERE ls.login_status = 'failure' AND ls.login_time >= NOW() - INTERVAL '30 days') AS failed_login_count,
        MAX(CASE WHEN u.mfa_enabled THEN 0 ELSE 1 END) AS no_mfa_flag
    FROM users u
    LEFT JOIN vaults v ON v.owner_user_id = u.user_id
    LEFT JOIN password_entries pe ON pe.vault_id = v.vault_id
    LEFT JOIN login_sessions ls ON ls.user_id = u.user_id
    GROUP BY u.user_id, u.username
)
SELECT
    user_id,
    username,
    weak_password_count,
    expired_password_count,
    failed_login_count,
    no_mfa_flag,
    (weak_password_count * 10 + expired_password_count * 8 + failed_login_count * 2 + no_mfa_flag * 12) AS risk_score,
    DENSE_RANK() OVER (
        ORDER BY (weak_password_count * 10 + expired_password_count * 8 + failed_login_count * 2 + no_mfa_flag * 12) DESC
    ) AS risk_rank
FROM user_counts;

CREATE OR REPLACE VIEW vw_security_alert_summary AS
SELECT
    alert_type,
    severity,
    alert_status,
    COUNT(*) AS alert_count,
    MAX(created_at) AS latest_alert_at
FROM security_alerts
GROUP BY alert_type, severity, alert_status;

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_vaults_updated_at ON vaults;
CREATE TRIGGER trg_vaults_updated_at
BEFORE UPDATE ON vaults
FOR EACH ROW
EXECUTE FUNCTION fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_devices_updated_at ON devices;
CREATE TRIGGER trg_devices_updated_at
BEFORE UPDATE ON devices
FOR EACH ROW
EXECUTE FUNCTION fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_password_entries_updated_at ON password_entries;
CREATE TRIGGER trg_password_entries_updated_at
BEFORE UPDATE ON password_entries
FOR EACH ROW
EXECUTE FUNCTION fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_password_entries_history ON password_entries;
CREATE TRIGGER trg_password_entries_history
BEFORE UPDATE ON password_entries
FOR EACH ROW
EXECUTE FUNCTION fn_capture_password_history();

DROP TRIGGER IF EXISTS trg_password_entries_security ON password_entries;
CREATE TRIGGER trg_password_entries_security
AFTER INSERT OR UPDATE ON password_entries
FOR EACH ROW
EXECUTE FUNCTION fn_password_entry_security_checks();

DROP TRIGGER IF EXISTS trg_login_sessions_security ON login_sessions;
CREATE TRIGGER trg_login_sessions_security
AFTER INSERT ON login_sessions
FOR EACH ROW
EXECUTE FUNCTION fn_login_session_security_checks();

DROP TRIGGER IF EXISTS trg_audit_password_entries ON password_entries;
CREATE TRIGGER trg_audit_password_entries
AFTER INSERT OR UPDATE OR DELETE ON password_entries
FOR EACH ROW
EXECUTE FUNCTION fn_audit_password_entries();

DROP TRIGGER IF EXISTS trg_audit_shared_passwords ON shared_passwords;
CREATE TRIGGER trg_audit_shared_passwords
AFTER INSERT OR UPDATE OR DELETE ON shared_passwords
FOR EACH ROW
EXECUTE FUNCTION fn_audit_shared_passwords();

DROP TRIGGER IF EXISTS trg_audit_vaults ON vaults;
CREATE TRIGGER trg_audit_vaults
AFTER INSERT OR UPDATE OR DELETE ON vaults
FOR EACH ROW
EXECUTE FUNCTION fn_audit_vaults();

DROP TRIGGER IF EXISTS trg_audit_users ON users;
CREATE TRIGGER trg_audit_users
AFTER INSERT OR UPDATE OR DELETE ON users
FOR EACH ROW
EXECUTE FUNCTION fn_audit_users();

DROP TRIGGER IF EXISTS trg_audit_login_sessions ON login_sessions;
CREATE TRIGGER trg_audit_login_sessions
AFTER INSERT OR UPDATE OR DELETE ON login_sessions
FOR EACH ROW
EXECUTE FUNCTION fn_audit_login_sessions();

