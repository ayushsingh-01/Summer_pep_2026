import os
import hashlib
import base64
import secrets
import string
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import text

from utils.db import get_engine


# Load .env from repo root if present
ROOT = Path(__file__).resolve().parents[1]
dotenv_path = ROOT / ".env"
if dotenv_path.exists():
    load_dotenv(dotenv_path)


st.set_page_config(page_title="Password Vault Analytics", layout="wide")
st.markdown(
    """
    <style>
        :root {
            --pv-ink: #102A43;
            --pv-teal: #2A9D8F;
            --pv-coral: #E76F51;
            --pv-gold: #E9C46A;
            --pv-surface: rgba(255, 255, 255, 0.78);
            --pv-border: rgba(16, 42, 67, 0.10);
        }

        .stApp {
            background:
                radial-gradient(circle at top left, rgba(42, 157, 143, 0.18), transparent 30%),
                radial-gradient(circle at top right, rgba(231, 111, 81, 0.16), transparent 28%),
                linear-gradient(180deg, #F7FAFC 0%, #EEF5FF 48%, #FBFCFF 100%);
            color: var(--pv-ink);
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, rgba(16, 42, 67, 0.96), rgba(31, 68, 94, 0.96));
            color: white;
        }

        [data-testid="stSidebar"] * {
            color: white !important;
        }

        .pv-hero {
            padding: 1.4rem 1.5rem;
            border-radius: 24px;
            background: linear-gradient(135deg, rgba(16,42,67,0.96), rgba(42,157,143,0.88));
            color: white;
            box-shadow: 0 18px 50px rgba(16, 42, 67, 0.18);
            border: 1px solid rgba(255,255,255,0.16);
            margin-bottom: 1.1rem;
        }

        .pv-hero h1 {
            margin: 0;
            font-size: 2.2rem;
            letter-spacing: -0.03em;
        }

        .pv-hero p {
            margin: 0.35rem 0 0;
            font-size: 1rem;
            opacity: 0.94;
        }

        .pv-pill {
            display: inline-block;
            padding: 0.3rem 0.7rem;
            margin-right: 0.45rem;
            margin-top: 0.45rem;
            border-radius: 999px;
            background: rgba(255,255,255,0.14);
            border: 1px solid rgba(255,255,255,0.16);
            font-size: 0.78rem;
            font-weight: 600;
        }

        .pv-panel {
            background: var(--pv-surface);
            backdrop-filter: blur(14px);
            border: 1px solid var(--pv-border);
            border-radius: 22px;
            padding: 1rem 1.05rem;
            box-shadow: 0 14px 35px rgba(16, 42, 67, 0.07);
            margin-bottom: 1rem;
        }

        .pv-section-title {
            font-weight: 700;
            color: var(--pv-ink);
            margin-bottom: 0.45rem;
            letter-spacing: -0.02em;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="pv-hero">
        <h1>Password Vault</h1>
        <p>Security analytics, saved credentials, and password generation in one interactive workspace.</p>
        <span class="pv-pill">Analytics</span>
        <span class="pv-pill">Credentials</span>
        <span class="pv-pill">Password tools</span>
    </div>
    """,
    unsafe_allow_html=True,
)


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


@st.cache_data(ttl=30)
def fetch_dataframe(_engine, sql: str, params: dict | None = None) -> pd.DataFrame:
    return pd.read_sql(text(sql), _engine, params=params or {})


@st.cache_resource
def get_fernet_key() -> Fernet | None:
    key = os.getenv("APP_ENCRYPTION_KEY", "").strip()
    if not key:
        derived_seed = resolve_database_url().encode("utf-8")
        key = base64.urlsafe_b64encode(hashlib.sha256(derived_seed).digest()).decode("utf-8")
    return Fernet(key.encode("utf-8"))


def _build_fernet_from_seed(seed: str) -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(seed.encode("utf-8")).digest()).decode("utf-8")
    return Fernet(key.encode("utf-8"))


def get_decryption_candidates() -> list[Fernet]:
    candidates: list[Fernet] = []

    explicit_key = os.getenv("APP_ENCRYPTION_KEY", "").strip()
    if explicit_key:
        candidates.append(Fernet(explicit_key.encode("utf-8")))

    candidates.append(_build_fernet_from_seed(resolve_database_url()))

    legacy_seed = (
        f"postgresql+psycopg2://{os.getenv('POSTGRES_USER', 'pguser')}:{os.getenv('POSTGRES_PASSWORD', 'pgpass')}"
        f"@{os.getenv('POSTGRES_HOST', '127.0.0.1')}:{os.getenv('POSTGRES_PORT', '55432')}/{os.getenv('POSTGRES_DB', 'password_vault')}"
    )
    candidates.append(_build_fernet_from_seed(legacy_seed))

    deduped: list[Fernet] = []
    seen: set[str] = set()
    for candidate in candidates:
        token = candidate._signing_key + candidate._encryption_key
        token_id = token.hex()
        if token_id not in seen:
            seen.add(token_id)
            deduped.append(candidate)
    return deduped


def encrypt_credential(plain_text: str) -> tuple[str, str]:
    fernet = get_fernet_key()
    if fernet is None:
        raise ValueError("Set APP_ENCRYPTION_KEY in your .env before adding credentials.")

    encrypted_password = fernet.encrypt(plain_text.encode("utf-8")).decode("utf-8")
    fingerprint = hashlib.sha256(plain_text.encode("utf-8")).hexdigest()
    return encrypted_password, fingerprint


def decrypt_credential(encrypted_text: str) -> str:
    token = encrypted_text.encode("utf-8")
    last_error: Exception | None = None

    for fernet in get_decryption_candidates():
        try:
            return fernet.decrypt(token).decode("utf-8")
        except InvalidToken as exc:
            last_error = exc

    if last_error is not None:
        raise InvalidToken("Unable to decrypt credential with any available key.") from last_error

    raise InvalidToken("Unable to decrypt credential with any available key.")


def save_credential(
    _engine,
    *,
    vault_id: int,
    category_id: int | None,
    created_by_user_id: int,
    website_name: str,
    username: str,
    password: str,
    url: str | None,
    notes: str | None,
    password_strength: str,
    expires_at,
    is_favorite: bool,
) -> int:
    encrypted_password, fingerprint = encrypt_credential(password)
    insert_sql = text(
        """
        INSERT INTO password_vault.password_entries (
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
            expires_at,
            last_rotated_at,
            is_favorite
        )
        VALUES (
            :vault_id,
            :category_id,
            :created_by_user_id,
            :website_name,
            :username,
            :encrypted_password,
            :password_fingerprint,
            :url,
            :notes,
            :password_strength,
            :expires_at,
            NOW(),
            :is_favorite
        )
        RETURNING password_entry_id
        """
    )

    with _engine.begin() as connection:
        result = connection.execute(
            insert_sql,
            {
                "vault_id": vault_id,
                "category_id": category_id,
                "created_by_user_id": created_by_user_id,
                "website_name": website_name,
                "username": username,
                "encrypted_password": encrypted_password,
                "password_fingerprint": fingerprint,
                "url": url or None,
                "notes": notes or None,
                "password_strength": password_strength,
                "expires_at": expires_at,
                "is_favorite": is_favorite,
            },
        )
        return int(result.scalar_one())


def update_credential(
    _engine,
    *,
    password_entry_id: int,
    vault_id: int,
    category_id: int | None,
    created_by_user_id: int,
    website_name: str,
    username: str,
    password: str,
    url: str | None,
    notes: str | None,
    password_strength: str,
    expires_at,
    is_favorite: bool,
) -> None:
    encrypted_password, fingerprint = encrypt_credential(password)
    update_sql = text(
        """
        UPDATE password_vault.password_entries
        SET
            vault_id = :vault_id,
            category_id = :category_id,
            created_by_user_id = :created_by_user_id,
            website_name = :website_name,
            username = :username,
            encrypted_password = :encrypted_password,
            password_fingerprint = :password_fingerprint,
            url = :url,
            notes = :notes,
            password_strength = :password_strength,
            expires_at = :expires_at,
            last_rotated_at = NOW(),
            is_favorite = :is_favorite
        WHERE password_entry_id = :password_entry_id
          AND created_by_user_id = :created_by_user_id
        """
    )

    with _engine.begin() as connection:
        connection.execute(
            update_sql,
            {
                "password_entry_id": password_entry_id,
                "vault_id": vault_id,
                "category_id": category_id,
                "created_by_user_id": created_by_user_id,
                "website_name": website_name,
                "username": username,
                "encrypted_password": encrypted_password,
                "password_fingerprint": fingerprint,
                "url": url or None,
                "notes": notes or None,
                "password_strength": password_strength,
                "expires_at": expires_at,
                "is_favorite": is_favorite,
            },
        )


def delete_credential(_engine, *, password_entry_id: int, created_by_user_id: int) -> None:
    delete_sql = text(
        """
        DELETE FROM password_vault.password_entries
        WHERE password_entry_id = :password_entry_id
          AND created_by_user_id = :created_by_user_id
        """
    )
    with _engine.begin() as connection:
        connection.execute(
            delete_sql,
            {
                "password_entry_id": password_entry_id,
                "created_by_user_id": created_by_user_id,
            },
        )


def load_users(_engine) -> pd.DataFrame:
    return fetch_dataframe(
        _engine,
        """
        SELECT user_id, username, email
        FROM password_vault.users
        ORDER BY username;
        """,
    )


def load_vaults(_engine, user_id: int) -> pd.DataFrame:
    return fetch_dataframe(
        _engine,
        """
        SELECT vault_id, vault_name, vault_type
        FROM password_vault.vaults
        WHERE owner_user_id = :user_id
        ORDER BY vault_name;
        """,
        {"user_id": user_id},
    )


def load_categories(_engine) -> pd.DataFrame:
    return fetch_dataframe(
        _engine,
        """
        SELECT category_id, category_name
        FROM password_vault.categories
        ORDER BY category_name;
        """,
    )


def load_credentials(_engine, user_id: int) -> pd.DataFrame:
    return fetch_dataframe(
        _engine,
        """
        SELECT
            pe.password_entry_id,
            pe.vault_id,
            pe.category_id,
            pe.created_by_user_id,
            pe.website_name,
            pe.username,
            pe.encrypted_password,
            pe.url,
            pe.notes,
            pe.password_strength,
            pe.is_favorite,
            pe.created_at,
            pe.expires_at,
            v.vault_name,
            c.category_name
        FROM password_vault.password_entries pe
        JOIN password_vault.vaults v ON v.vault_id = pe.vault_id
        LEFT JOIN password_vault.categories c ON c.category_id = pe.category_id
        WHERE pe.created_by_user_id = :user_id
        ORDER BY pe.created_at DESC, pe.password_entry_id DESC;
        """,
        {"user_id": user_id},
    )


def local_strength_label(password: str) -> str:
    length_score = len(password)
    class_score = 0

    if any(ch.islower() for ch in password):
        class_score += 1
    if any(ch.isupper() for ch in password):
        class_score += 1
    if any(ch.isdigit() for ch in password):
        class_score += 1
    if any(ch in string.punctuation for ch in password):
        class_score += 1

    if length_score < 8 or class_score <= 1:
        return "weak"
    if length_score < 12 or class_score == 2:
        return "medium"
    if length_score < 16 or class_score == 3:
        return "strong"
    return "very_strong"


def generate_password_suggestion(*, length: int, include_symbols: bool) -> str:
    alphabet = string.ascii_letters + string.digits + (string.punctuation if include_symbols else "")
    password_chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if include_symbols:
        password_chars.append(secrets.choice(string.punctuation))

    while len(password_chars) < length:
        password_chars.append(secrets.choice(alphabet))

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars[:length])


def render_strength_meter(password: str) -> None:
    strength = local_strength_label(password)
    score_map = {"weak": 25, "medium": 50, "strong": 75, "very_strong": 100}
    color_map = {"weak": "#D1495B", "medium": "#E09F3E", "strong": "#2A9D8F", "very_strong": "#1D7874"}
    st.progress(score_map[strength] / 100.0)
    st.markdown(
        f"<div style='font-weight:600;color:{color_map[strength]};text-transform:uppercase;'>{strength.replace('_', ' ')}</div>",
        unsafe_allow_html=True,
    )


def render_analytics_visuals(selected: str, df: pd.DataFrame, _engine) -> None:
    if df.empty:
        st.info("No rows returned for this report.")
        return

    if selected == "User Security Summary":
        summary_cols = st.columns(4)
        summary_cols[0].metric("Average score", f"{df['security_score'].mean():.1f}")
        summary_cols[1].metric("MFA enabled", f"{int(df['mfa_enabled'].sum())}/{len(df)}")
        summary_cols[2].metric("Open alerts", f"{int(df['open_alert_count'].sum())}")
        summary_cols[3].metric("Strong passwords", f"{int(df['strong_password_count'].sum())}")

        chart_cols = st.columns(2)
        with chart_cols[0]:
            fig = px.bar(
                df.sort_values("security_score", ascending=True),
                x="security_score",
                y="username",
                orientation="h",
                color="mfa_enabled",
                color_discrete_map={True: "#2E86AB", False: "#D1495B"},
                title="Security score by user",
            )
            st.plotly_chart(fig, use_container_width=True)

        with chart_cols[1]:
            scatter_fig = px.scatter(
                df,
                x="password_count",
                y="open_alert_count",
                size="active_shared_password_count",
                color="security_score",
                hover_name="username",
                size_max=35,
                title="Password volume vs open alerts",
            )
            st.plotly_chart(scatter_fig, use_container_width=True)

    elif selected == "Password Health":
        summary_cols = st.columns(4)
        row = df.iloc[0]
        summary_cols[0].metric("Total passwords", f"{int(row['total_passwords'])}")
        summary_cols[1].metric("Weak / medium", f"{int(row['weak_passwords'] + row['medium_passwords'])}")
        summary_cols[2].metric("Average age", f"{row['average_password_age_days']:.1f} days")
        summary_cols[3].metric("Not strong", f"{row['percentage_not_strong']:.1f}%")

        strength_df = fetch_dataframe(
            _engine,
            """
            SELECT
                password_strength,
                COUNT(*) AS password_count
            FROM password_vault.password_entries
            GROUP BY password_strength
            ORDER BY password_count DESC;
            """,
        )
        age_df = fetch_dataframe(
            _engine,
            """
            SELECT
                password_strength,
                EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400.0 AS age_days
            FROM password_vault.password_entries;
            """,
        )

        chart_cols = st.columns(2)
        with chart_cols[0]:
            fig = px.pie(
                strength_df,
                names="password_strength",
                values="password_count",
                hole=0.45,
                title="Password strength mix",
            )
            st.plotly_chart(fig, use_container_width=True)

        with chart_cols[1]:
            hist = px.histogram(
                age_df,
                x="age_days",
                color="password_strength",
                nbins=20,
                title="Password age distribution",
            )
            st.plotly_chart(hist, use_container_width=True)

    elif selected == "Vault Summary":
        summary_cols = st.columns(3)
        summary_cols[0].metric("Vaults", f"{len(df)}")
        summary_cols[1].metric("Passwords", f"{int(df['password_count'].sum())}")
        summary_cols[2].metric("Avg age", f"{df['average_password_age_days'].mean():.1f} days")

        chart_cols = st.columns(2)
        with chart_cols[0]:
            fig = px.bar(
                df.sort_values("password_count", ascending=False),
                x="vault_name",
                y="password_count",
                color="vault_type",
                title="Passwords per vault",
            )
            st.plotly_chart(fig, use_container_width=True)

        with chart_cols[1]:
            treemap = px.treemap(
                df,
                path=["vault_type", "owner_username", "vault_name"],
                values="password_count",
                color="category_count",
                title="Vault composition",
            )
            st.plotly_chart(treemap, use_container_width=True)

    elif selected == "Login Activity":
        summary_cols = st.columns(4)
        summary_cols[0].metric("Login rows", f"{len(df)}")
        summary_cols[1].metric("Successful logins", f"{int(df['successful_logins'].sum())}")
        summary_cols[2].metric("Failed logins", f"{int(df['failed_logins'].sum())}")
        summary_cols[3].metric("Avg success rate", f"{df['success_rate'].mean():.1f}%")

        trend_df = df.groupby("login_day", as_index=False)[["total_logins", "successful_logins", "failed_logins"]].sum()
        user_success_df = df.groupby("username", as_index=False)["success_rate"].mean().sort_values("success_rate", ascending=False)
        heatmap_df = fetch_dataframe(
            _engine,
            """
            SELECT
                EXTRACT(DOW FROM login_time) AS day_of_week,
                EXTRACT(HOUR FROM login_time) AS hour_of_day,
                COUNT(*) AS login_count
            FROM password_vault.login_sessions
            GROUP BY EXTRACT(DOW FROM login_time), EXTRACT(HOUR FROM login_time)
            ORDER BY day_of_week, hour_of_day;
            """,
        )

        chart_cols = st.columns(2)
        with chart_cols[0]:
            line_fig = px.line(
                trend_df,
                x="login_day",
                y=["total_logins", "successful_logins", "failed_logins"],
                markers=True,
                title="Login trend over time",
            )
            st.plotly_chart(line_fig, use_container_width=True)

        with chart_cols[1]:
            bar_fig = px.bar(user_success_df, x="username", y="success_rate", color="username", title="Average success rate by user")
            st.plotly_chart(bar_fig, use_container_width=True)

        heatmap = px.density_heatmap(
            heatmap_df,
            x="hour_of_day",
            y="day_of_week",
            z="login_count",
            nbinsx=24,
            nbinsy=7,
            color_continuous_scale="Blues",
            title="Login hot spots by day and hour",
        )
        st.plotly_chart(heatmap, use_container_width=True)

    elif selected == "Risk Ranking":
        summary_cols = st.columns(4)
        summary_cols[0].metric("Top risk", f"{df['risk_score'].max():.0f}")
        summary_cols[1].metric("Average risk", f"{df['risk_score'].mean():.1f}")
        summary_cols[2].metric("High-risk users", f"{int((df['risk_score'] >= 40).sum())}")
        summary_cols[3].metric("Low-risk users", f"{int((df['risk_score'] < 20).sum())}")

        chart_cols = st.columns(2)
        with chart_cols[0]:
            bar_fig = px.bar(
                df.sort_values("risk_score", ascending=True),
                x="risk_score",
                y="username",
                orientation="h",
                color="risk_score",
                title="Risk score leaderboard",
            )
            st.plotly_chart(bar_fig, use_container_width=True)

        with chart_cols[1]:
            bubble = px.scatter(
                df,
                x="weak_password_count",
                y="failed_login_count",
                size="expired_password_count",
                color="no_mfa_flag",
                hover_name="username",
                size_max=40,
                title="Risk drivers by user",
            )
            st.plotly_chart(bubble, use_container_width=True)

        if "risk_rank" in df.columns:
            rank_fig = px.bar(df.sort_values("risk_rank"), x="username", y="risk_rank", color="risk_rank", title="Risk rank order")
            st.plotly_chart(rank_fig, use_container_width=True)


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

users_df = load_users(engine)
if users_df.empty:
    st.warning("No users were found in this database. Initialize the schema and seed data first.")
    st.stop()

st.sidebar.title("Workspace")
st.sidebar.caption("Use the sidebar to move between sections.")
page = st.sidebar.radio("Sections", ["Analytics", "Credentials", "Password"], index=0)

st.sidebar.markdown("---")
st.sidebar.markdown("### Quick Glance")
st.sidebar.metric("Users", len(users_df))
st.sidebar.metric("Database", os.getenv("POSTGRES_DB", "password_vault"))

if page == "Analytics":
    st.markdown('<div class="pv-panel">', unsafe_allow_html=True)
    st.markdown('<div class="pv-section-title">Analytics</div>', unsafe_allow_html=True)
    selected = st.selectbox("View", list(QUERY_SPECS.keys()))
    st.markdown("---")

    query_spec = QUERY_SPECS[selected]
    sql = query_spec["sql"] if relation_exists(engine, query_spec["relation"]) else query_spec["fallback_sql"]
    try:
        df = run_query(engine, sql)
        render_analytics_visuals(selected, df, engine)
        st.markdown("#### Raw data")
        st.dataframe(df, use_container_width=True, hide_index=True)

    except Exception as e:
        st.error(
            "Query failed. If this database is a fresh hosted instance, initialize it first by running "
            "`password_vault_sql/00_setup.sql` against the same database URL."
        )
        st.exception(e)
    st.markdown('</div>', unsafe_allow_html=True)

elif page == "Credentials":
    st.markdown('<div class="pv-panel">', unsafe_allow_html=True)
    st.markdown('<div class="pv-section-title">Credentials</div>', unsafe_allow_html=True)
    st.subheader("Add or remove your own credentials")
    st.caption("Choose a user, then create or delete credentials in that user's vaults.")

    user_labels = {f"{row.username} ({row.email})": int(row.user_id) for row in users_df.itertuples(index=False)}
    selected_user_label = st.selectbox("Credential owner", list(user_labels.keys()))
    selected_user_id = user_labels[selected_user_label]

    vaults_df = load_vaults(engine, selected_user_id)
    categories_df = load_categories(engine)
    credentials_df = load_credentials(engine, selected_user_id)

    left_col, right_col = st.columns(2)

    with left_col:
        st.markdown("#### Add credential")
        if vaults_df.empty:
            st.info("This user has no vaults yet. Create a vault in the database before adding a credential.")
        else:
            if os.getenv("APP_ENCRYPTION_KEY", "").strip() == "":
                st.info("Using a key derived from `DATABASE_URL` for credential encryption. Set `APP_ENCRYPTION_KEY` if you want a dedicated key.")

            with st.form("add_credential_form", clear_on_submit=True):
                vault_label_map = {
                    f"{row.vault_name} ({row.vault_type})": int(row.vault_id)
                    for row in vaults_df.itertuples(index=False)
                }
                category_options = ["(none)"] + [row.category_name for row in categories_df.itertuples(index=False)]

                vault_label = st.selectbox("Vault", list(vault_label_map.keys()))
                category_label = st.selectbox("Category", category_options)
                website_name = st.text_input("Website / service name")
                credential_username = st.text_input("Username / email")
                show_add_password = st.checkbox("Show password while typing", key="show_add_password")
                credential_password = st.text_input("Password", type="default" if show_add_password else "password")
                url = st.text_input("URL", placeholder="https://example.com")
                notes = st.text_area("Notes", height=100)
                has_expiry = st.checkbox("Set expiry date")
                expiry_date = st.date_input("Expiry date", disabled=not has_expiry)
                is_favorite = st.checkbox("Mark as favorite")
                submit_add = st.form_submit_button("Save credential")

            if submit_add:
                if not website_name or not credential_username or not credential_password:
                    st.error("Website, username, and password are required.")
                else:
                    try:
                        strength_df = fetch_dataframe(
                            engine,
                            "SELECT password_vault.fn_password_strength_estimate(:plain_password) AS strength",
                            {"plain_password": credential_password},
                        )
                        password_strength = str(strength_df.iloc[0]["strength"])
                        category_id = None
                        if category_label != "(none)":
                            category_id = int(categories_df.loc[categories_df["category_name"] == category_label, "category_id"].iloc[0])

                        inserted_id = save_credential(
                            engine,
                            vault_id=vault_label_map[vault_label],
                            category_id=category_id,
                            created_by_user_id=selected_user_id,
                            website_name=website_name.strip(),
                            username=credential_username.strip(),
                            password=credential_password,
                            url=url.strip() or None,
                            notes=notes.strip() or None,
                            password_strength=password_strength,
                            expires_at=pd.Timestamp(expiry_date).to_pydatetime() if has_expiry else None,
                            is_favorite=is_favorite,
                        )
                        fetch_dataframe.clear()
                        run_query.clear()
                        st.success(f"Credential saved with ID {inserted_id}.")
                        st.rerun()
                    except (ValueError, InvalidToken) as e:
                        st.error(str(e))
                    except Exception as e:
                        st.exception(e)

    st.markdown("---")
    st.markdown("#### Edit credential")
    if credentials_df.empty:
        st.info("No credentials are available to edit for this user.")
    else:
        editable_map = {
            f"{row.website_name} | {row.username} | {row.vault_name} | {row.password_entry_id}": int(row.password_entry_id)
            for row in credentials_df.itertuples(index=False)
        }
        selected_edit_label = st.selectbox("Credential to edit", list(editable_map.keys()), key="edit_credential_select")
        selected_row = credentials_df.loc[credentials_df["password_entry_id"] == editable_map[selected_edit_label]].iloc[0]

        selected_vault_id = int(selected_row["vault_id"])
        selected_category_id = None if pd.isna(selected_row["category_id"]) else int(selected_row["category_id"])
        try:
            current_password = decrypt_credential(str(selected_row["encrypted_password"]))
        except InvalidToken:
            current_password = ""
            st.warning("The current password could not be decrypted with the active key. You can still overwrite it with a new password.")

        edit_vault_options = {
            f"{row.vault_name} ({row.vault_type})": int(row.vault_id)
            for row in vaults_df.itertuples(index=False)
        }
        edit_category_options = ["(none)"] + [row.category_name for row in categories_df.itertuples(index=False)]
        default_vault_label = next((label for label, vault_id in edit_vault_options.items() if vault_id == selected_vault_id), list(edit_vault_options.keys())[0])
        default_category_label = "(none)"
        if selected_category_id is not None:
            category_match = categories_df.loc[categories_df["category_id"] == selected_category_id, "category_name"]
            if not category_match.empty:
                default_category_label = str(category_match.iloc[0])

        with st.form("edit_credential_form"):
            edit_vault_label = st.selectbox("Vault", list(edit_vault_options.keys()), index=list(edit_vault_options.keys()).index(default_vault_label), key="edit_vault")
            edit_category_label = st.selectbox("Category", edit_category_options, index=edit_category_options.index(default_category_label), key="edit_category")
            edit_website_name = st.text_input("Website / service name", value=str(selected_row["website_name"]))
            edit_credential_username = st.text_input("Username / email", value=str(selected_row["username"]))
            show_edit_password = st.checkbox("Show password while typing", key="show_edit_password")
            edit_credential_password = st.text_input("Password", value=current_password, type="default" if show_edit_password else "password")
            edit_url = st.text_input("URL", value="" if pd.isna(selected_row["url"]) else str(selected_row["url"]))
            edit_notes = st.text_area("Notes", value="" if pd.isna(selected_row["notes"]) else str(selected_row["notes"]), height=100)
            edit_is_favorite = st.checkbox("Mark as favorite", value=bool(selected_row["is_favorite"]))
            edit_has_expiry = st.checkbox("Set expiry date", value=not pd.isna(selected_row["expires_at"]))
            if edit_has_expiry and not pd.isna(selected_row["expires_at"]):
                expiry_value = pd.Timestamp(selected_row["expires_at"]).date()
            else:
                expiry_value = pd.Timestamp.now().date()
            edit_expiry_date = st.date_input("Expiry date", value=expiry_value, disabled=not edit_has_expiry)
            submit_edit = st.form_submit_button("Save changes")

        if submit_edit:
            if not edit_website_name or not edit_credential_username or not edit_credential_password:
                st.error("Website, username, and password are required.")
            else:
                try:
                    strength_df = fetch_dataframe(
                        engine,
                        "SELECT password_vault.fn_password_strength_estimate(:plain_password) AS strength",
                        {"plain_password": edit_credential_password},
                    )
                    password_strength = str(strength_df.iloc[0]["strength"])
                    edit_category_id = None
                    if edit_category_label != "(none)":
                        edit_category_id = int(categories_df.loc[categories_df["category_name"] == edit_category_label, "category_id"].iloc[0])

                    update_credential(
                        engine,
                        password_entry_id=int(selected_row["password_entry_id"]),
                        vault_id=edit_vault_options[edit_vault_label],
                        category_id=edit_category_id,
                        created_by_user_id=selected_user_id,
                        website_name=edit_website_name.strip(),
                        username=edit_credential_username.strip(),
                        password=edit_credential_password,
                        url=edit_url.strip() or None,
                        notes=edit_notes.strip() or None,
                        password_strength=password_strength,
                        expires_at=pd.Timestamp(edit_expiry_date).to_pydatetime() if edit_has_expiry else None,
                        is_favorite=edit_is_favorite,
                    )
                    fetch_dataframe.clear()
                    run_query.clear()
                    st.success("Credential updated.")
                    st.rerun()
                except (ValueError, InvalidToken) as e:
                    st.error(str(e))
                except Exception as e:
                    st.exception(e)

    with right_col:
        st.markdown("#### Delete credential")
        if credentials_df.empty:
            st.info("No credentials were found for this user.")
        else:
            credential_map = {
                f"{row.website_name} | {row.username} | {row.vault_name} | {row.password_entry_id}": int(row.password_entry_id)
                for row in credentials_df.itertuples(index=False)
            }
            selected_credential_label = st.selectbox("Credential to delete", list(credential_map.keys()))
            confirm_delete = st.checkbox("I understand this will permanently delete the credential")

            if st.button("Delete selected credential", type="primary", disabled=not confirm_delete):
                try:
                    delete_credential(
                        engine,
                        password_entry_id=credential_map[selected_credential_label],
                        created_by_user_id=selected_user_id,
                    )
                    fetch_dataframe.clear()
                    run_query.clear()
                    st.success("Credential deleted.")
                    st.rerun()
                except Exception as e:
                    st.exception(e)

        st.markdown("#### View saved password")
        if credentials_df.empty:
            st.info("No credentials were found for this user.")
        else:
            view_map = {
                f"{row.website_name} | {row.username} | {row.vault_name} | {row.password_entry_id}": int(row.password_entry_id)
                for row in credentials_df.itertuples(index=False)
            }
            selected_view_label = st.selectbox("Credential to reveal", list(view_map.keys()), key="view_credential_select")
            reveal_password = st.checkbox("Reveal decrypted password", key="reveal_saved_password")

            if reveal_password:
                selected_view_row = credentials_df.loc[credentials_df["password_entry_id"] == view_map[selected_view_label]].iloc[0]
                try:
                    decrypted_password = decrypt_credential(str(selected_view_row["encrypted_password"]))
                    st.code(decrypted_password, language="text")
                    st.caption("Use this only for credentials you own or are authorized to inspect.")
                except InvalidToken:
                    st.error("This password could not be decrypted with the active key.")

        st.markdown("#### Your credentials")
        st.dataframe(credentials_df, use_container_width=True, hide_index=True)

    st.markdown('</div>', unsafe_allow_html=True)

else:
    st.markdown('<div class="pv-panel">', unsafe_allow_html=True)
    st.markdown('<div class="pv-section-title">Password</div>', unsafe_allow_html=True)
    st.subheader("Password suggestion and strength checker")
    st.caption("Type a website name and the app suggests a password, shows its strength, and can save it as a credential.")

    password_user_label = st.selectbox(
        "Credential owner",
        list(user_labels.keys()),
        key="password_owner_select",
    )
    password_user_id = user_labels[password_user_label]

    password_vaults_df = load_vaults(engine, password_user_id)
    password_categories_df = load_categories(engine)

    if password_vaults_df.empty:
        st.info("This user has no vaults yet. Create a vault before generating and saving credentials.")
    else:
        password_vault_labels = {
            f"{row.vault_name} ({row.vault_type})": int(row.vault_id)
            for row in password_vaults_df.itertuples(index=False)
        }
        password_category_options = ["(none)"] + [row.category_name for row in password_categories_df.itertuples(index=False)]

        suggestion_col, action_col = st.columns([3, 1])
        with suggestion_col:
            suggestion_vault_label = st.selectbox("Vault", list(password_vault_labels.keys()))
            suggestion_category_label = st.selectbox("Category", password_category_options)
            suggestion_website_name = st.text_input("Website name")
            suggestion_username = st.text_input("Username / email")
            suggestion_length = st.slider("Password length", min_value=12, max_value=32, value=18)
            suggestion_include_symbols = st.checkbox("Include symbols", value=True)

        suggestion_key = (
            f"password_suggestion_{password_user_id}_"
            f"{suggestion_website_name.strip().lower()}_{suggestion_username.strip().lower()}_"
            f"{suggestion_length}_{int(suggestion_include_symbols)}"
        )

        with action_col:
            st.markdown("#### Suggested password")
            if st.button("Refresh suggestion", use_container_width=True):
                st.session_state.pop(suggestion_key, None)

            if suggestion_website_name.strip():
                if suggestion_key not in st.session_state:
                    st.session_state[suggestion_key] = generate_password_suggestion(
                        length=suggestion_length,
                        include_symbols=suggestion_include_symbols,
                    )

                suggested_password = st.session_state[suggestion_key]
                st.code(suggested_password, language="text")
                render_strength_meter(suggested_password)

                accept_suggestion = st.checkbox("I accept this password and want to save the credential", key=f"accept_password_suggestion_{suggestion_key}")
                if accept_suggestion:
                    password_url = st.text_input("URL for this credential", placeholder="https://example.com")
                    password_notes = st.text_area("Notes", height=90)
                    password_is_favorite = st.checkbox("Mark as favorite", key=f"password_suggestion_favorite_{suggestion_key}")
                    expiry_toggle = st.checkbox("Set expiry date", key=f"password_suggestion_expiry_toggle_{suggestion_key}")
                    expiry_date_value = st.date_input("Expiry date", disabled=not expiry_toggle, key=f"password_suggestion_expiry_date_{suggestion_key}")

                    if st.button("Save suggested credential"):
                        try:
                            password_strength = local_strength_label(suggested_password)
                            category_id = None
                            if suggestion_category_label != "(none)":
                                category_id = int(
                                    password_categories_df.loc[
                                        password_categories_df["category_name"] == suggestion_category_label, "category_id"
                                    ].iloc[0]
                                )

                            inserted_id = save_credential(
                                engine,
                                vault_id=password_vault_labels[suggestion_vault_label],
                                category_id=category_id,
                                created_by_user_id=password_user_id,
                                website_name=suggestion_website_name.strip(),
                                username=suggestion_username.strip(),
                                password=suggested_password,
                                url=password_url.strip() or None,
                                notes=password_notes.strip() or None,
                                password_strength=password_strength,
                                expires_at=pd.Timestamp(expiry_date_value).to_pydatetime() if expiry_toggle else None,
                                is_favorite=password_is_favorite,
                            )
                            fetch_dataframe.clear()
                            run_query.clear()
                            st.success(f"Suggested credential saved with ID {inserted_id}.")
                            st.rerun()
                        except Exception as e:
                            st.exception(e)

                st.markdown("#### Password checker")
                custom_password = st.text_input("Test a password", type="password", key="password_strength_tester")
                if custom_password:
                    render_strength_meter(custom_password)
                    st.caption(f"Estimated strength: {local_strength_label(custom_password)}")

    st.markdown('</div>', unsafe_allow_html=True)
