import os
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv
from sqlalchemy import text

from utils.db import get_engine


# Load .env from repo root if present
ROOT = Path(__file__).resolve().parents[1]
dotenv_path = ROOT / ".env"
if dotenv_path.exists():
    load_dotenv(dotenv_path)


st.set_page_config(page_title="Password Vault Analytics", layout="wide")
st.title("Password Vault — Analytics Dashboard")


def resolve_database_url() -> str:
    """Prefer a single hosted DATABASE_URL, then fall back to separate Postgres env vars."""
    direct_url = os.getenv("DATABASE_URL", "").strip()
    if direct_url:
        return direct_url

    user = os.getenv("POSTGRES_USER", "pguser")
    password = os.getenv("POSTGRES_PASSWORD", "pgpass")
    host = os.getenv("POSTGRES_HOST", "127.0.0.1")
    port = os.getenv("POSTGRES_PORT", "55432")
    database = os.getenv("POSTGRES_DB", "password_vault")
    return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"


@st.cache_data(ttl=60)
def run_query(_engine, sql: str) -> pd.DataFrame:
    """Run SQL and return a DataFrame. Prefix engine param with underscore
    so Streamlit does not attempt to hash the SQLAlchemy Engine object."""
    return pd.read_sql(sql, _engine)


@st.cache_resource
def get_engine_cached(database_url: str):
    return get_engine(database_url)


def relation_exists(_engine, relation_name: str) -> bool:
    with _engine.connect() as connection:
        result = connection.execute(
            text("SELECT to_regclass(:relation_name) IS NOT NULL"),
            {"relation_name": relation_name},
        )
        return bool(result.scalar_one())


QUERY_SPECS = {
    "User Security Summary": {
        "relation": "password_vault.vw_user_security_summary",
        "sql": "SELECT * FROM password_vault.vw_user_security_summary ORDER BY security_score DESC;",
        "fallback_sql": """
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
            FROM password_vault.users u
            LEFT JOIN password_vault.vaults v ON v.owner_user_id = u.user_id
            LEFT JOIN password_vault.password_entries pe ON pe.vault_id = v.vault_id
            LEFT JOIN password_vault.shared_passwords sp ON sp.shared_by_user_id = u.user_id OR sp.shared_with_user_id = u.user_id
            LEFT JOIN password_vault.security_alerts sa ON sa.user_id = u.user_id
            GROUP BY u.user_id, u.username, u.email, u.account_status, u.email_verified, u.mfa_enabled, u.last_login_at
            ORDER BY security_score DESC;
        """,
    },
    "Password Health": {
        "relation": "password_vault.vw_password_health",
        "sql": "SELECT * FROM password_vault.vw_password_health;",
        "fallback_sql": """
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
            FROM password_vault.password_entries;
        """,
    },
    "Vault Summary": {
        "relation": "password_vault.vw_vault_summary",
        "sql": "SELECT * FROM password_vault.vw_vault_summary ORDER BY password_count DESC;",
        "fallback_sql": """
            SELECT
                v.vault_id,
                v.owner_user_id,
                u.username AS owner_username,
                v.vault_name,
                v.vault_type,
                COUNT(pe.password_entry_id) AS password_count,
                COUNT(DISTINCT pe.category_id) AS category_count,
                ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - pe.created_at)) / 86400.0), 2) AS average_password_age_days
            FROM password_vault.vaults v
            JOIN password_vault.users u ON u.user_id = v.owner_user_id
            LEFT JOIN password_vault.password_entries pe ON pe.vault_id = v.vault_id
            GROUP BY v.vault_id, v.owner_user_id, u.username, v.vault_name, v.vault_type
            ORDER BY password_count DESC;
        """,
    },
    "Login Activity": {
        "relation": "password_vault.vw_login_activity",
        "sql": "SELECT * FROM password_vault.vw_login_activity ORDER BY login_day DESC LIMIT 200;",
        "fallback_sql": """
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
            FROM password_vault.login_sessions ls
            JOIN password_vault.users u ON u.user_id = ls.user_id
            GROUP BY ls.user_id, u.username, DATE_TRUNC('day', ls.login_time)
            ORDER BY login_day DESC
            LIMIT 200;
        """,
    },
    "Risk Ranking": {
        "relation": "password_vault.vw_risk_ranking",
        "sql": "SELECT * FROM password_vault.vw_risk_ranking ORDER BY risk_score DESC LIMIT 100;",
        "fallback_sql": """
            WITH user_counts AS (
                SELECT
                    u.user_id,
                    u.username,
                    COUNT(DISTINCT pe.password_entry_id) FILTER (WHERE pe.password_strength = 'weak') AS weak_password_count,
                    COUNT(DISTINCT pe.password_entry_id) FILTER (WHERE pe.expires_at IS NOT NULL AND pe.expires_at <= NOW()) AS expired_password_count,
                    COUNT(DISTINCT ls.session_id) FILTER (WHERE ls.login_status = 'failure' AND ls.login_time >= NOW() - INTERVAL '30 days') AS failed_login_count,
                    MAX(CASE WHEN u.mfa_enabled THEN 0 ELSE 1 END) AS no_mfa_flag
                FROM password_vault.users u
                LEFT JOIN password_vault.vaults v ON v.owner_user_id = u.user_id
                LEFT JOIN password_vault.password_entries pe ON pe.vault_id = v.vault_id
                LEFT JOIN password_vault.login_sessions ls ON ls.user_id = u.user_id
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
            FROM user_counts
            ORDER BY risk_score DESC, username
            LIMIT 100;
        """,
    },
}

REQUIRED_TABLES = [
    "password_vault.users",
    "password_vault.vaults",
    "password_vault.password_entries",
    "password_vault.login_sessions",
    "password_vault.shared_passwords",
    "password_vault.security_alerts",
]


database_url = resolve_database_url()

st.sidebar.header("Connection")
st.sidebar.caption("The dashboard connects automatically from `DATABASE_URL` or the `POSTGRES_*` variables in `.env`.")
st.sidebar.code(database_url.replace(os.getenv("POSTGRES_PASSWORD", "pgpass"), "***"), language="text")

try:
    engine = get_engine_cached(database_url)
    with engine.connect() as connection:
        connection.exec_driver_sql("SELECT 1")
    st.sidebar.success("Connected")
except Exception as e:
    st.sidebar.error(f"Connection failed: {e}")
    st.stop()


missing_relations = [
    spec["relation"] for spec in QUERY_SPECS.values() if not relation_exists(engine, spec["relation"])
]

missing_tables = [table for table in REQUIRED_TABLES if not relation_exists(engine, table)]

if missing_tables:
    st.error(
        "The database is connected, but the password vault schema is not initialized. "
        "Run `password_vault_sql/00_setup.sql` against this database URL first, then restart Streamlit."
    )
    st.code("\n".join(missing_tables), language="text")
    st.stop()

if missing_relations:
    st.warning(
        "The database connection works, but some dashboard views are missing. "
        "The app will use fallback SQL against the base tables where possible. "
        "If the database is empty, run `password_vault_sql/00_setup.sql` on that database first."
    )


selected = st.selectbox("View", list(QUERY_SPECS.keys()))
st.markdown("---")

query_spec = QUERY_SPECS[selected]
sql = query_spec["sql"] if relation_exists(engine, query_spec["relation"]) else query_spec["fallback_sql"]
try:
    df = run_query(engine, sql)
    st.write(df)

    if selected == "User Security Summary":
        fig = px.bar(df, x="username", y="security_score", color="username", text="security_score")
        st.plotly_chart(fig, use_container_width=True)

    if selected == "Password Health" and "risk_score" in df.columns:
        fig = px.histogram(df, x="risk_score", nbins=20, title="Password risk score distribution")
        st.plotly_chart(fig, use_container_width=True)

except Exception as e:
    st.error(
        "Query failed. If this database is a fresh hosted instance, initialize it first by running "
        "`password_vault_sql/00_setup.sql` against the same database URL."
    )
    st.exception(e)
