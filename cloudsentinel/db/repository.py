"""
Scan history repository.

Stores and retrieves scanner reports, findings and AI explanations. All SQL
is parameterized. Stored findings are the scanner's output verbatim; the
deterministic scanner remains the source of truth and this layer never
changes or re-derives any finding.
"""

import json
import sqlite3
import threading
import uuid
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

from .database import PersistenceError, connect, init_db

SCAN_ID_PREFIX = "scn_"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _dumps(value: Any) -> str:
    return json.dumps(value, default=str)


class ScanRepository:
    """SQLite-backed history of scans and AI explanations."""

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        self._schema_ready = False
        self._lock = threading.Lock()

    def _ensure_schema(self) -> None:
        if self._schema_ready:
            return
        with self._lock:
            if not self._schema_ready:
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
                with closing(connect(self.db_path)) as conn:
                    init_db(conn)
                self._schema_ready = True

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """One connection per operation; commits on success, rolls back on error."""
        try:
            self._ensure_schema()
            with closing(connect(self.db_path)) as conn:
                with conn:
                    yield conn
        except (sqlite3.Error, OSError) as exc:
            raise PersistenceError(f"Scan history database error: {type(exc).__name__}: {exc}") from exc

    # ------------------------------------------------------------------
    # Scans and findings
    # ------------------------------------------------------------------

    def save_scan(self, report: Dict[str, Any]) -> str:
        """Store a ScanService report (as returned to the client) and its findings. Returns scan_id."""
        scan_id = SCAN_ID_PREFIX + uuid.uuid4().hex
        meta = report["scan_metadata"]
        filters = report["filters"]
        summary = report["summary"]

        scan_row = (
            scan_id, _now(), str(meta.get("account_id")), str(meta.get("scan_time")),
            filters.get("min_severity"), filters.get("entity_type"),
            filters.get("total_findings_before_filter", 0), summary.get("total_findings", 0),
            summary.get("critical", 0), summary.get("high", 0), summary.get("medium", 0), summary.get("low", 0),
            _dumps(meta), _dumps(report.get("mitre_attack_summary", {})),
        )
        finding_rows = [
            (
                scan_id, position, f["finding_id"], f["rule_id"], f["rule_name"], f["severity"],
                float(f["cvss_score"]), f["entity_type"], f["affected_entity"], _dumps(f),
            )
            for position, f in enumerate(report["findings"])
        ]

        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO scans (scan_id, created_at, account_id, scan_time, min_severity, entity_type, "
                "total_findings_before_filter, total_findings, critical, high, medium, low, "
                "scan_metadata_json, mitre_attack_summary_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                scan_row,
            )
            conn.executemany(
                "INSERT INTO findings (scan_id, position, finding_id, rule_id, rule_name, severity, "
                "cvss_score, entity_type, affected_entity, finding_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                finding_rows,
            )
        return scan_id

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Return the stored report (same shape as POST /scans) plus scan_id/created_at, or None."""
        with self._transaction() as conn:
            row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            findings = conn.execute(
                "SELECT finding_json FROM findings WHERE scan_id = ? ORDER BY position",
                (scan_id,),
            ).fetchall()

        return {
            "scan_id": row["scan_id"],
            "created_at": row["created_at"],
            "scan_metadata": json.loads(row["scan_metadata_json"]),
            "filters": self._filters(row),
            "summary": self._summary(row),
            "mitre_attack_summary": json.loads(row["mitre_attack_summary_json"]),
            "findings": [json.loads(f["finding_json"]) for f in findings],
        }

    def list_scans(self, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
        """Return stored scan summaries, newest first."""
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [
            {
                "scan_id": row["scan_id"],
                "created_at": row["created_at"],
                "account_id": row["account_id"],
                "scan_time": row["scan_time"],
                "filters": self._filters(row),
                "summary": self._summary(row),
            }
            for row in rows
        ]

    @staticmethod
    def _filters(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "min_severity": row["min_severity"],
            "entity_type": row["entity_type"],
            "total_findings_before_filter": row["total_findings_before_filter"],
        }

    @staticmethod
    def _summary(row: sqlite3.Row) -> Dict[str, int]:
        return {key: row[key] for key in ("total_findings", "critical", "high", "medium", "low")}

    # ------------------------------------------------------------------
    # AI explanations
    # ------------------------------------------------------------------

    def save_explanation(self, result: Dict[str, Any]) -> int:
        """Store a successful ExplanationService result. Returns explanation_id."""
        finding = result["finding"]
        explanation = result["explanation"]
        ai = result["ai"]

        with self._transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO explanations (created_at, finding_id, rule_id, severity, cvss_score, finding_json, "
                "summary, why_it_matters, attack_scenario, remediation_explained, "
                "provider, model, generated_at, disclaimer) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    _now(), result["finding_id"], finding["rule_id"], finding["severity"],
                    float(finding["cvss_score"]), _dumps(finding),
                    explanation["summary"], explanation["why_it_matters"],
                    explanation["attack_scenario"], explanation["remediation_explained"],
                    ai["provider"], ai.get("model"), ai["generated_at"], ai["disclaimer"],
                ),
            )
            return cursor.lastrowid

    def list_explanations(self, finding_id: str) -> List[Dict[str, Any]]:
        """Return stored explanations for a finding_id, newest first."""
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM explanations WHERE finding_id = ? ORDER BY explanation_id DESC",
                (finding_id,),
            ).fetchall()
        return [
            {
                "explanation_id": row["explanation_id"],
                "created_at": row["created_at"],
                "finding_id": row["finding_id"],
                "finding": json.loads(row["finding_json"]),
                "explanation": {
                    "summary": row["summary"],
                    "why_it_matters": row["why_it_matters"],
                    "attack_scenario": row["attack_scenario"],
                    "remediation_explained": row["remediation_explained"],
                },
                "ai": {
                    "provider": row["provider"],
                    "model": row["model"],
                    "generated_at": row["generated_at"],
                    "disclaimer": row["disclaimer"],
                },
            }
            for row in rows
        ]
