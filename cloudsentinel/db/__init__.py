"""
CloudSentinel persistence layer (standard-library sqlite3).

Used only by the API layer; the scanner engine and services have no
dependency on it.
"""

from .database import ENV_DB_PATH, PersistenceError, get_db_path, init_db
from .repository import ScanRepository

__all__ = ["ScanRepository", "PersistenceError", "get_db_path", "init_db", "ENV_DB_PATH"]
