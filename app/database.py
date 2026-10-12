"""Database connection (MySQL/MariaDB).

T64.1.7 (2026-06-11): all credentials come from /opt/logsoc-web/config.yaml
via app.config_loader. No more env var indirection, no more .env file.

Resolution: app.config_loader.CFG (loaded once at import from config.yaml).
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config_loader import require, get

# Single source of truth: config.yaml
MYSQL_HOST = require("database.host")
MYSQL_PORT = int(require("database.port"))
MYSQL_USER = require("database.user")
MYSQL_PASSWORD = require("database.password")
MYSQL_DATABASE = require("database.database")

_url = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}"
engine = create_engine(_url, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
