"""
Docstring for app.config
"""

import os
from dotenv import load_dotenv

load_dotenv()

_secret_key = os.getenv("SECRET_KEY")
_algorithm = os.getenv("ALGORITHM")
_database_url = os.getenv("DATABASE_URL")
_migrations_url = os.getenv("MIGRATIONS_DB_URL")

if not _secret_key:
    raise ValueError("SECRET_KEY not found in .env")

if not _algorithm:
    raise ValueError("ALGORITHM not found in .env")

if not _database_url:
    raise ValueError("DATABASE_URL not found in .env")

if not _migrations_url:
    raise ValueError("MIGRATIONS_DB_URL not found in .env")


SECRET_KEY: str = _secret_key
ALGORITHM: str = _algorithm
DATABASE_URL: str = _database_url
MIGRATIONS_DB_URL: str = _migrations_url
