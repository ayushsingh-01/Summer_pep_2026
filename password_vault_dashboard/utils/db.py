from sqlalchemy import create_engine

def get_engine(user: str, password: str, host: str, port: str, db: str):
    """Return a SQLAlchemy engine for Postgres using psycopg2."""
    url = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{db}"
    return create_engine(url)
