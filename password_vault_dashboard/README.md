# Password Vault — Analytics Dashboard

Streamlit dashboard that auto-connects to Postgres using `DATABASE_URL` first, then falls back to `POSTGRES_*` variables from `.env`.

## What changed

- No more manual Connect button.
- The app connects as soon as it starts.
- It works with a hosted Postgres instance once you set the environment variables.
- If the hosted database is empty, the app will warn you and tell you to run the SQL setup files first.
- You can add and delete your own credentials from the new Credentials tab.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r password_vault_dashboard/requirements.txt
```

## Configure the database

Use one of these options:

```bash
# Option 1: one hosted database URL
DATABASE_URL=postgresql+psycopg2://USER:PASSWORD@HOST:PORT/DBNAME

# Option 2: separate variables
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=55432
POSTGRES_USER=pguser
POSTGRES_PASSWORD=pgpass
POSTGRES_DB=password_vault
```

For an online database, create a hosted Postgres instance on a service like Neon, Supabase, or Render, then paste its connection string into `DATABASE_URL`.

If that database is brand new, run `password_vault_sql/00_setup.sql` against the same database once so the schema, views, seed data, and analytics objects are created.

Credential storage is encrypted before it is saved. By default the app derives an encryption key from `DATABASE_URL`, but you can set `APP_ENCRYPTION_KEY` in `.env` if you want to provide your own key.

## Run

```bash
streamlit run password_vault_dashboard/app.py
```

## After you write the code

1. Put your hosted DB connection string in `.env` as `DATABASE_URL`, or keep the `POSTGRES_*` settings.
2. Start the app with the command above.
3. If you change the database, restart Streamlit so it reloads the env vars.
4. If you want to deploy online, move the app to Streamlit Community Cloud or another host and set the same env vars there.
5. If the dashboard shows a missing-view warning, initialize the database with `password_vault_sql/00_setup.sql` before trying again.
6. Open the Credentials tab to add or delete entries for the selected user.
