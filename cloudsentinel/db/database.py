"""
SQLite database setup for CloudSentinel scan history.

Uses only the standard-library sqlite3 module. The database file, its parent
directory and the schema are created automatically on first use.

    CLOUDSENTINEL_DB_PATH   path to the SQLite file
                            (default: <project root>/data/cloudsentinel.db)

Only scanner output (reports, findings) and validated AI explanations are
stored. Raw IAM data, LLM API keys and other secrets are never stored.
"""

import os
import sqlite3
from pathlib import Path
from typing import Mapping, Optional

ENV_DB_PATH = "CLOUDSENTINEL_DB_PATH"
DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "cloudsentinel.db"
SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id                      TEXT PRIMARY KEY,
    created_at                   TEXT NOT NULL,
    account_id                   TEXT NOT NULL,
    scan_time                    TEXT NOT NULL,
    min_severity                 TEXT,
    entity_type                  TEXT,
    total_findings_before_filter INTEGER NOT NULL,
    total_findings               INTEGER NOT NULL,
    critical                     INTEGER NOT NULL,
    high                         INTEGER NOT NULL,
    medium                       INTEGER NOT NULL,
    low                          INTEGER NOT NULL,
    scan_metadata_json           TEXT NOT NULL,
    mitre_attack_summary_json    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at);

CREATE TABLE IF NOT EXISTS findings (
    scan_id         TEXT NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
    position        INTEGER NOT NULL,
    finding_id      TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    rule_name       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    cvss_score      REAL NOT NULL,
    entity_type     TEXT NOT NULL,
    affected_entity TEXT NOT NULL,
    finding_json    TEXT NOT NULL,
    PRIMARY KEY (scan_id, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_finding_id ON findings (finding_id);

CREATE TABLE IF NOT EXISTS explanations (
    explanation_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at            TEXT NOT NULL,
    finding_id            TEXT NOT NULL,
    rule_id               TEXT NOT NULL,
    severity              TEXT NOT NULL,
    cvss_score            REAL NOT NULL,
    finding_json          TEXT NOT NULL,
    summary               TEXT NOT NULL,
    why_it_matters        TEXT NOT NULL,
    attack_scenario       TEXT NOT NULL,
    remediation_explained TEXT NOT NULL,
    provider              TEXT NOT NULL,
    model                 TEXT,
    generated_at          TEXT NOT NULL,
    disclaimer            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_explanations_finding_id ON explanations (finding_id);

PRAGMA user_version = 1;
"""


class PersistenceError(Exception):
    """The scan history database could not be read or written."""


def get_db_path(environ: Optional[Mapping[str, str]] = None) -> Path:
    """Return the configured database path (CLOUDSENTINEL_DB_PATH or the default)."""
    env = os.environ if environ is None else environ
    value = env.get(ENV_DB_PATH, "").strip()
    return Path(value).expanduser() if value else DEFAULT_DB_PATH


def connect(db_path: Path) -> sqlite3.Connection:
    """Open a connection with dict-like rows and foreign keys enforced."""
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables and indexes if they don't exist. Safe to run repeatedly."""
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise PersistenceError(f"Database schema version {version} is newer than supported ({SCHEMA_VERSION})")
    conn.executescript(SCHEMA)
