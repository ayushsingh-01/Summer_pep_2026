SET search_path TO password_vault;

CREATE OR REPLACE FUNCTION fn_set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION fn_password_strength_estimate(p_password TEXT)
RETURNS VARCHAR(20)
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    length_score INTEGER;
    class_score INTEGER := 0;
BEGIN
    IF p_password IS NULL THEN
        RETURN 'weak';
    END IF;

    length_score := LENGTH(p_password);

    IF p_password ~ '[a-z]' THEN
        class_score := class_score + 1;
    END IF;
    IF p_password ~ '[A-Z]' THEN
        class_score := class_score + 1;
    END IF;
    IF p_password ~ '[0-9]' THEN
        class_score := class_score + 1;
    END IF;
    IF p_password ~ '[^a-zA-Z0-9]' THEN
        class_score := class_score + 1;
    END IF;

    IF length_score < 8 OR class_score <= 1 THEN
        RETURN 'weak';
    ELSIF length_score < 12 OR class_score = 2 THEN
        RETURN 'medium';
    ELSIF length_score < 16 OR class_score = 3 THEN
        RETURN 'strong';
    END IF;

    RETURN 'very_strong';
END;
$$;

CREATE OR REPLACE FUNCTION fn_log_audit_event(
    p_user_id BIGINT,
    p_vault_id BIGINT,
    p_password_entry_id BIGINT,
    p_action_type VARCHAR,
    p_entity_type VARCHAR,
    p_entity_id BIGINT,
    p_action_details JSONB DEFAULT '{}'::jsonb,
    p_ip_address INET DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_audit_id BIGINT;
BEGIN
    INSERT INTO audit_logs (
        user_id,
        vault_id,
        password_entry_id,
        action_type,
        entity_type,
        entity_id,
        action_details,
        ip_address
    )
    VALUES (
        p_user_id,
        p_vault_id,
        p_password_entry_id,
        p_action_type,
        p_entity_type,
        p_entity_id,
        COALESCE(p_action_details, '{}'::jsonb),
        p_ip_address
    )
    RETURNING audit_id INTO v_audit_id;

    RETURN v_audit_id;
END;
$$;

CREATE OR REPLACE PROCEDURE sp_record_login_session(
    IN p_user_id BIGINT,
    IN p_device_id BIGINT DEFAULT NULL,
    IN p_ip_address INET DEFAULT NULL,
    IN p_browser_name VARCHAR DEFAULT NULL,
    IN p_login_status VARCHAR DEFAULT 'success',
    IN p_failure_reason TEXT DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_session_id BIGINT;
BEGIN
    INSERT INTO login_sessions (
        user_id,
        device_id,
        ip_address,
        browser_name,
        login_status,
        failure_reason
    )
    VALUES (
        p_user_id,
        p_device_id,
        p_ip_address,
        p_browser_name,
        p_login_status,
        p_failure_reason
    )
    RETURNING session_id INTO v_session_id;

    IF p_login_status = 'success' THEN
        UPDATE users
        SET last_login_at = NOW(),
            account_status = CASE WHEN account_status = 'pending' THEN 'active' ELSE account_status END
        WHERE user_id = p_user_id;
    END IF;

END;
$$;

CREATE OR REPLACE PROCEDURE sp_share_password(
    IN p_password_entry_id BIGINT,
    IN p_shared_by_user_id BIGINT,
    IN p_shared_with_user_id BIGINT,
    IN p_access_level VARCHAR,
    IN p_expires_at TIMESTAMPTZ DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_shared_id BIGINT;
    v_vault_id BIGINT;
BEGIN
    SELECT vault_id
    INTO v_vault_id
    FROM password_entries
    WHERE password_entry_id = p_password_entry_id;

    INSERT INTO shared_passwords (
        password_entry_id,
        shared_by_user_id,
        shared_with_user_id,
        access_level,
        expires_at
    )
    VALUES (
        p_password_entry_id,
        p_shared_by_user_id,
        p_shared_with_user_id,
        p_access_level,
        p_expires_at
    )
    RETURNING shared_password_id INTO v_shared_id;

END;
$$;

CREATE OR REPLACE PROCEDURE sp_change_mfa_status(
    IN p_user_id BIGINT,
    IN p_enabled BOOLEAN
)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE users
    SET mfa_enabled = p_enabled
    WHERE user_id = p_user_id;

END;
$$;
