from sqlalchemy import create_engine


def get_engine(database_url: str):
    """Return a SQLAlchemy engine for Postgres using a full SQLAlchemy URL."""
    return create_engine(database_url, pool_pre_ping=True)
