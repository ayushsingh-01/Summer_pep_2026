from dotenv import load_dotenv
import os
load_dotenv()
from sqlalchemy import create_engine, text

direct_url = os.getenv('DATABASE_URL', '').strip()
if direct_url:
    url = direct_url
else:
    u = os.getenv('POSTGRES_USER', 'pguser')
    p = os.getenv('POSTGRES_PASSWORD', 'pgpass')
    h = os.getenv('POSTGRES_HOST', '127.0.0.1')
    port = os.getenv('POSTGRES_PORT', '55432')
    db = os.getenv('POSTGRES_DB', 'password_vault')
    url = f"postgresql+psycopg2://{u}:{p}@{h}:{port}/{db}"

print('Connecting to', url)
engine = create_engine(url)
with engine.connect() as conn:
    r = conn.execute(text(
        "select user_id, username, security_score from password_vault.vw_user_security_summary order by security_score desc"
    ))
    rows = r.fetchall()
    for row in rows:
        print(row)

print('Done')
