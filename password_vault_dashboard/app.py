import os
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv

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


QUERIES = {
    "User Security Summary": "SELECT * FROM password_vault.vw_user_security_summary ORDER BY security_score DESC;",
    "Password Health": "SELECT * FROM password_vault.vw_password_health ORDER BY risk_score DESC;",
    "Vault Summary": "SELECT * FROM password_vault.vw_vault_summary ORDER BY total_entries DESC;",
    "Login Activity": "SELECT * FROM password_vault.vw_login_activity ORDER BY last_login DESC LIMIT 200;",
    "Risk Ranking": "SELECT * FROM password_vault.vw_risk_ranking ORDER BY risk_score DESC LIMIT 100;",
}


selected = st.selectbox("View", list(QUERIES.keys()))
st.markdown("---")

sql = QUERIES[selected]
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
    st.error(f"Query failed: {e}")
