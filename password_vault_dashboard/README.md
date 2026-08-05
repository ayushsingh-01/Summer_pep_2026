# Password Vault — Analytics Dashboard

Minimal Streamlit dashboard that connects to the local Postgres instance created by the SQL project.

Prerequisites
- Docker Compose up for the database (see repository root `docker-compose.yml`).
- Python 3.10+ and pip.

Setup

```bash
python -m venv .venv
source .venv/bin/activate   # or `.venv\Scripts\activate` on Windows
pip install -r password_vault_dashboard/requirements.txt
```

Run

```bash
streamlit run password_vault_dashboard/app.py
```

By default the app will load DB connection values from the repository `.env` file. You can also enter connection details in the sidebar.
