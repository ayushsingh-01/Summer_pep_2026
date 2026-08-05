import os
from pathlib import Path

import pandas as pd
import streamlit as st
import plotly.express as px
from dotenv import load_dotenv

from utils.db import get_engine


# Load .env from repo root if present
ROOT = Path(__file__).resolve().parents[1]
dotenv_path = ROOT / ".env"
if dotenv_path.exists():
    load_dotenv(dotenv_path)


st.set_page_config(page_title="Password Vault Analytics", layout="wide")
st.title("Password Vault — Analytics Dashboard")


def get_conn_params():
    return {
        "host": st.sidebar.text_input("Host", os.getenv("POSTGRES_HOST", "localhost")),
        "port": st.sidebar.text_input("Port", os.getenv("POSTGRES_PORT", "5432")),
        "user": st.sidebar.text_input("User", os.getenv("POSTGRES_USER", "pguser")),
        "password": st.sidebar.text_input("Password", os.getenv("POSTGRES_PASSWORD", ""), type="password"),
        "db": st.sidebar.text_input("Database", os.getenv("POSTGRES_DB", "password_vault")),
    }


@st.cache_data(ttl=60)
def run_query(_engine, sql: str) -> pd.DataFrame:
    """Run SQL and return a DataFrame. Prefix engine param with underscore
    so Streamlit does not attempt to hash the SQLAlchemy Engine object."""
    return pd.read_sql(sql, _engine)


params = get_conn_params()
connect = st.sidebar.button("Connect")

engine = None
if connect:
    try:
        engine = get_engine(params["user"], params["password"], params["host"], params["port"], params["db"])
        st.sidebar.success("Connected (engine created).")
    except Exception as e:
        st.sidebar.error(f"Connection failed: {e}")


QUERIES = {
    "User Security Summary": "SELECT * FROM password_vault.vw_user_security_summary ORDER BY security_score DESC;",
    "Password Health": "SELECT * FROM password_vault.vw_password_health ORDER BY risk_score DESC;",
    "Vault Summary": "SELECT * FROM password_vault.vw_vault_summary ORDER BY total_entries DESC;",
    "Login Activity": "SELECT * FROM password_vault.vw_login_activity ORDER BY last_login DESC LIMIT 200;",
    "Risk Ranking": "SELECT * FROM password_vault.vw_risk_ranking ORDER BY risk_score DESC LIMIT 100;",
}


selected = st.selectbox("View", list(QUERIES.keys()))
st.markdown("---")

if engine is None:
    st.info("Click 'Connect' in the sidebar to create a DB connection (or set env vars in .env).")
else:
    sql = QUERIES[selected]
    try:
        df = run_query(engine, sql)
        st.write(df)

        if selected == "User Security Summary":
            fig = px.bar(df, x="username", y="security_score", color="username", text="security_score")
            st.plotly_chart(fig, use_container_width=True)

        if selected == "Password Health":
            if "risk_score" in df.columns:
                fig = px.histogram(df, x="risk_score", nbins=20, title="Password risk score distribution")
                st.plotly_chart(fig, use_container_width=True)

    except Exception as e:
        st.error(f"Query failed: {e}")
