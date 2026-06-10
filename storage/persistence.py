"""
SQLite persistence for security events, trust, responses, and blocked IPs.
"""

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional


def _default_db_path() -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(root, "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "cyber_defense.db")


class SecurityStore:
    """Thread-safe SQLite store for audit and operational state."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("CDS_DB_PATH", _default_db_path())
        self._lock = threading.RLock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS security_events (
                        event_id TEXT PRIMARY KEY,
                        timestamp REAL NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        source_ip TEXT,
                        target_entity TEXT,
                        description TEXT,
                        action_taken TEXT,
                        status TEXT DEFAULT 'active'
                    );
                    CREATE TABLE IF NOT EXISTS trust_records (
                        entity_id TEXT PRIMARY KEY,
                        trust_score REAL NOT NULL,
                        last_updated REAL NOT NULL,
                        behavior_history TEXT,
                        trust_trend TEXT,
                        risk_level TEXT,
                        risk_score REAL DEFAULT 0,
                        asset_type TEXT DEFAULT 'employee_device',
                        asset_criticality REAL DEFAULT 1,
                        last_incident_type TEXT DEFAULT 'behavior_anomaly',
                        last_incident_severity TEXT DEFAULT 'low'
                    );
                    CREATE TABLE IF NOT EXISTS response_actions (
                        action_id TEXT PRIMARY KEY,
                        entity_id TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        status TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        completion_time REAL,
                        details TEXT
                    );
                    CREATE TABLE IF NOT EXISTS blocked_ips (
                        ip_address TEXT PRIMARY KEY,
                        reason TEXT,
                        blocked_at REAL NOT NULL,
                        status TEXT DEFAULT 'active',
                        firewall_applied INTEGER DEFAULT 0
                    );
                    CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_responses_status ON response_actions(status);
                    """
                )
                self._ensure_column_exists(conn, "trust_records", "risk_score", "REAL DEFAULT 0")
                self._ensure_column_exists(
                    conn, "trust_records", "asset_type", "TEXT DEFAULT 'employee_device'"
                )
                self._ensure_column_exists(
                    conn, "trust_records", "asset_criticality", "REAL DEFAULT 1"
                )
                self._ensure_column_exists(
                    conn,
                    "trust_records",
                    "last_incident_type",
                    "TEXT DEFAULT 'behavior_anomaly'",
                )
                self._ensure_column_exists(
                    conn,
                    "trust_records",
                    "last_incident_severity",
                    "TEXT DEFAULT 'low'",
                )
                conn.commit()
            finally:
                conn.close()

    def _ensure_column_exists(
        self, conn: sqlite3.Connection, table_name: str, column_name: str, column_def: str
    ) -> None:
        columns = {
            row["name"]
            for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        if column_name not in columns:
            conn.execute(
                f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}"
            )

    def save_security_event(self, event: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO security_events
                    (event_id, timestamp, event_type, severity, source_ip,
                     target_entity, description, action_taken, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event["event_id"],
                        event["timestamp"],
                        event["event_type"],
                        event["severity"],
                        event.get("source_ip", ""),
                        event.get("target_entity", ""),
                        event.get("description", ""),
                        event.get("action_taken", ""),
                        event.get("status", "active"),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def list_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM security_events
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def count_events_since(self, since_ts: float, severity: Optional[str] = None) -> int:
        with self._lock:
            conn = self._connect()
            try:
                if severity:
                    row = conn.execute(
                        """
                        SELECT COUNT(*) AS c FROM security_events
                        WHERE timestamp >= ? AND severity = ?
                        """,
                        (since_ts, severity),
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT COUNT(*) AS c FROM security_events WHERE timestamp >= ?",
                        (since_ts,),
                    ).fetchone()
                return int(row["c"])
            finally:
                conn.close()

    def save_trust_record(self, record: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO trust_records
                    (entity_id, trust_score, last_updated, behavior_history,
                     trust_trend, risk_level, risk_score, asset_type, asset_criticality,
                     last_incident_type, last_incident_severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["entity_id"],
                        record["trust_score"],
                        record["last_updated"],
                        json.dumps(record.get("behavior_history", [])),
                        record.get("trust_trend", "stable"),
                        record.get("risk_level", "low"),
                        record.get("risk_score", 0.0),
                        record.get("asset_type", "employee_device"),
                        record.get("asset_criticality", 1.0),
                        record.get("last_incident_type", "behavior_anomaly"),
                        record.get("last_incident_severity", "low"),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def load_all_trust_records(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT * FROM trust_records").fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    d["behavior_history"] = json.loads(d.get("behavior_history") or "[]")
                    result.append(d)
                return result
            finally:
                conn.close()

    def save_response_action(self, action: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO response_actions
                    (action_id, entity_id, action_type, status, timestamp,
                     completion_time, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action["action_id"],
                        action["entity_id"],
                        action["action_type"],
                        action["status"],
                        action["timestamp"],
                        action.get("completion_time"),
                        json.dumps(action.get("details", {})),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def list_responses_by_status(self, statuses: List[str], limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                placeholders = ",".join("?" * len(statuses))
                rows = conn.execute(
                    f"""
                    SELECT * FROM response_actions
                    WHERE status IN ({placeholders})
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (*statuses, limit),
                ).fetchall()
                out = []
                for r in rows:
                    d = dict(r)
                    d["details"] = json.loads(d.get("details") or "{}")
                    out.append(d)
                return out
            finally:
                conn.close()

    def count_responses_since(self, since_ts: float, action_type: Optional[str] = None) -> int:
        with self._lock:
            conn = self._connect()
            try:
                if action_type:
                    row = conn.execute(
                        """
                        SELECT COUNT(*) AS c FROM response_actions
                        WHERE timestamp >= ? AND action_type = ?
                        """,
                        (since_ts, action_type),
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT COUNT(*) AS c FROM response_actions WHERE timestamp >= ?",
                        (since_ts,),
                    ).fetchone()
                return int(row["c"])
            finally:
                conn.close()

    def save_blocked_ip(
        self, ip_address: str, reason: str, firewall_applied: bool
    ) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO blocked_ips
                    (ip_address, reason, blocked_at, status, firewall_applied)
                    VALUES (?, ?, ?, 'active', ?)
                    """,
                    (ip_address, reason, time.time(), 1 if firewall_applied else 0),
                )
                conn.commit()
            finally:
                conn.close()

    def list_blocked_ips(self, active_only: bool = True) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                if active_only:
                    rows = conn.execute(
                        "SELECT * FROM blocked_ips WHERE status = 'active' ORDER BY blocked_at DESC"
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM blocked_ips ORDER BY blocked_at DESC"
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def unblock_ip(self, ip_address: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "UPDATE blocked_ips SET status = 'released' WHERE ip_address = ? AND status = 'active'",
                    (ip_address,),
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def count_blocked_ips(self) -> int:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM blocked_ips WHERE status = 'active'"
                ).fetchone()
                return int(row["c"])
            finally:
                conn.close()


_store = None
_store_lock = threading.Lock()


def get_store():
    """Return SQLite store (CDS_DB_PATH) or PostgreSQL store (CDS_DATABASE_URL)."""
    global _store
    with _store_lock:
        if _store is None:
            db_url = os.environ.get("CDS_DATABASE_URL", "").strip()
            if db_url:
                from storage.postgres_store import PostgresSecurityStore

                _store = PostgresSecurityStore(db_url)
            else:
                _store = SecurityStore()
        return _store


def reset_store() -> None:
    """Clear cached store (for tests)."""
    global _store
    with _store_lock:
        _store = None
