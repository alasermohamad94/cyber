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
                        firewall_applied INTEGER DEFAULT 0,
                        provider TEXT DEFAULT 'local_os',
                        ttl_seconds INTEGER DEFAULT 3600,
                        expires_at REAL
                    );
                    CREATE TABLE IF NOT EXISTS security_incidents (
                        incident_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        incident_type TEXT,
                        severity TEXT NOT NULL,
                        status TEXT DEFAULT 'open',
                        source_ip TEXT,
                        target_entity TEXT,
                        assigned_to TEXT,
                        notes TEXT,
                        event_ids TEXT,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        resolved_at REAL
                    );
                    CREATE TABLE IF NOT EXISTS security_cases (
                        case_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        description TEXT,
                        status TEXT DEFAULT 'open',
                        created_by TEXT,
                        assigned_to TEXT,
                        incident_ids TEXT,
                        entity_ids TEXT,
                        ip_addresses TEXT,
                        investigator_notes TEXT,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS audit_log_chain (
                        record_id TEXT PRIMARY KEY,
                        record_type TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        details TEXT,
                        prev_hash TEXT NOT NULL,
                        record_hash TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS pending_approvals (
                        approval_id TEXT PRIMARY KEY,
                        action_type TEXT NOT NULL,
                        target_entity TEXT,
                        target_ip TEXT,
                        requested_by TEXT NOT NULL,
                        approved_by TEXT,
                        second_approved_by TEXT,
                        status TEXT DEFAULT 'pending',
                        details TEXT,
                        created_at REAL NOT NULL,
                        resolved_at REAL
                    );
                    CREATE TABLE IF NOT EXISTS quarantine_records (
                        quarantine_id TEXT PRIMARY KEY,
                        entity_id TEXT NOT NULL,
                        quarantine_type TEXT,
                        status TEXT DEFAULT 'active',
                        created_at REAL NOT NULL,
                        released_at REAL,
                        details TEXT
                    );
                    CREATE TABLE IF NOT EXISTS active_sessions (
                        session_id TEXT PRIMARY KEY,
                        username TEXT NOT NULL,
                        role TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        session_token TEXT UNIQUE,
                        created_at REAL NOT NULL,
                        last_activity REAL NOT NULL,
                        status TEXT DEFAULT 'active',
                        revoked_by TEXT,
                        revoked_at REAL
                    );
                    CREATE TABLE IF NOT EXISTS escalation_watches (
                        watch_id TEXT PRIMARY KEY,
                        entity_id TEXT NOT NULL,
                        incident_id TEXT NOT NULL,
                        original_action TEXT,
                        created_at REAL NOT NULL,
                        escalate_at REAL NOT NULL,
                        status TEXT DEFAULT 'watching',
                        resolved_by TEXT,
                        resolved_at REAL
                    );
                    CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_responses_status ON response_actions(status);
                    CREATE INDEX IF NOT EXISTS idx_incidents_status ON security_incidents(status);
                    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log_chain(timestamp);
                    """
                )
                self._ensure_column_exists(conn, "blocked_ips", "provider", "TEXT DEFAULT 'local_os'")
                self._ensure_column_exists(conn, "blocked_ips", "ttl_seconds", "INTEGER DEFAULT 3600")
                self._ensure_column_exists(conn, "blocked_ips", "expires_at", "REAL")
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
        self,
        ip_address: str,
        reason: str,
        firewall_applied: bool,
        provider: str = "local_os",
        ttl_seconds: int = 3600,
        expires_at: Optional[float] = None,
    ) -> None:
        with self._lock:
            conn = self._connect()
            try:
                exp = expires_at if expires_at is not None else time.time() + ttl_seconds
                conn.execute(
                    """
                    INSERT OR REPLACE INTO blocked_ips
                    (ip_address, reason, blocked_at, status, firewall_applied,
                     provider, ttl_seconds, expires_at)
                    VALUES (?, ?, ?, 'active', ?, ?, ?, ?)
                    """,
                    (
                        ip_address,
                        reason,
                        time.time(),
                        1 if firewall_applied else 0,
                        provider,
                        ttl_seconds,
                        exp,
                    ),
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

    def list_expired_blocked_ips(self, now_ts: float) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM blocked_ips
                    WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?
                    """,
                    (now_ts,),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_security_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM security_events WHERE event_id = ?", (event_id,)
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def get_trust_record(self, entity_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM trust_records WHERE entity_id = ?", (entity_id,)
                ).fetchone()
                if not row:
                    return None
                d = dict(row)
                d["behavior_history"] = json.loads(d.get("behavior_history") or "[]")
                return d
            finally:
                conn.close()

    def save_incident(self, incident: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO security_incidents
                    (incident_id, title, incident_type, severity, status, source_ip,
                     target_entity, assigned_to, notes, event_ids, created_at, updated_at, resolved_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident["incident_id"],
                        incident["title"],
                        incident.get("incident_type", ""),
                        incident["severity"],
                        incident.get("status", "open"),
                        incident.get("source_ip", ""),
                        incident.get("target_entity", ""),
                        incident.get("assigned_to", ""),
                        incident.get("notes", ""),
                        json.dumps(incident.get("event_ids", [])),
                        incident["created_at"],
                        incident["updated_at"],
                        incident.get("resolved_at"),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM security_incidents WHERE incident_id = ?", (incident_id,)
                ).fetchone()
                if not row:
                    return None
                d = dict(row)
                d["event_ids"] = json.loads(d.get("event_ids") or "[]")
                return d
            finally:
                conn.close()

    def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                current = self.get_incident(incident_id)
                if not current:
                    return
                merged = {**current, **updates}
                if "event_ids" in updates and isinstance(updates["event_ids"], list):
                    merged["event_ids"] = updates["event_ids"]
                conn.execute(
                    """
                    UPDATE security_incidents SET
                    title=?, incident_type=?, severity=?, status=?, source_ip=?,
                    target_entity=?, assigned_to=?, notes=?, event_ids=?,
                    updated_at=?, resolved_at=?
                    WHERE incident_id=?
                    """,
                    (
                        merged.get("title", ""),
                        merged.get("incident_type", ""),
                        merged.get("severity", "medium"),
                        merged.get("status", "open"),
                        merged.get("source_ip", ""),
                        merged.get("target_entity", ""),
                        merged.get("assigned_to", ""),
                        merged.get("notes", ""),
                        json.dumps(merged.get("event_ids", [])),
                        merged.get("updated_at", time.time()),
                        merged.get("resolved_at"),
                        incident_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assigned_to: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                query = "SELECT * FROM security_incidents WHERE 1=1"
                params: List[Any] = []
                if status:
                    query += " AND status = ?"
                    params.append(status)
                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                if assigned_to:
                    query += " AND assigned_to = ?"
                    params.append(assigned_to)
                query += " ORDER BY updated_at DESC LIMIT ?"
                params.append(limit)
                rows = conn.execute(query, params).fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    d["event_ids"] = json.loads(d.get("event_ids") or "[]")
                    result.append(d)
                return result
            finally:
                conn.close()

    def save_case(self, case: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO security_cases
                    (case_id, title, description, status, created_by, assigned_to,
                     incident_ids, entity_ids, ip_addresses, investigator_notes,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case["case_id"],
                        case["title"],
                        case.get("description", ""),
                        case.get("status", "open"),
                        case.get("created_by", ""),
                        case.get("assigned_to", ""),
                        json.dumps(case.get("incident_ids", [])),
                        json.dumps(case.get("entity_ids", [])),
                        json.dumps(case.get("ip_addresses", [])),
                        case.get("investigator_notes", ""),
                        case["created_at"],
                        case["updated_at"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM security_cases WHERE case_id = ?", (case_id,)
                ).fetchone()
                if not row:
                    return None
                d = dict(row)
                d["incident_ids"] = json.loads(d.get("incident_ids") or "[]")
                d["entity_ids"] = json.loads(d.get("entity_ids") or "[]")
                d["ip_addresses"] = json.loads(d.get("ip_addresses") or "[]")
                return d
            finally:
                conn.close()

    def update_case(self, case_id: str, updates: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                current = self.get_case(case_id)
                if not current:
                    return
                merged = {**current, **updates}
                conn.execute(
                    """
                    UPDATE security_cases SET
                    title=?, description=?, status=?, assigned_to=?,
                    incident_ids=?, entity_ids=?, ip_addresses=?,
                    investigator_notes=?, updated_at=?
                    WHERE case_id=?
                    """,
                    (
                        merged.get("title", ""),
                        merged.get("description", ""),
                        merged.get("status", "open"),
                        merged.get("assigned_to", ""),
                        json.dumps(merged.get("incident_ids", [])),
                        json.dumps(merged.get("entity_ids", [])),
                        json.dumps(merged.get("ip_addresses", [])),
                        merged.get("investigator_notes", ""),
                        merged.get("updated_at", time.time()),
                        case_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def list_cases(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM security_cases ORDER BY updated_at DESC LIMIT ?", (limit,)
                ).fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    d["incident_ids"] = json.loads(d.get("incident_ids") or "[]")
                    d["entity_ids"] = json.loads(d.get("entity_ids") or "[]")
                    d["ip_addresses"] = json.loads(d.get("ip_addresses") or "[]")
                    result.append(d)
                return result
            finally:
                conn.close()

    def save_audit_record(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO audit_log_chain
                    (record_id, record_type, actor, timestamp, details, prev_hash, record_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["record_id"],
                        entry["record_type"],
                        entry["actor"],
                        entry["timestamp"],
                        json.dumps(entry.get("details", {}), ensure_ascii=False),
                        entry["prev_hash"],
                        entry["record_hash"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def get_last_audit_hash(self) -> Optional[str]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT record_hash FROM audit_log_chain ORDER BY timestamp DESC LIMIT 1"
                ).fetchone()
                return row["record_hash"] if row else None
            finally:
                conn.close()

    def list_audit_records(
        self, limit: int = 100, chronological: bool = False
    ) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                order = "ASC" if chronological else "DESC"
                rows = conn.execute(
                    f"SELECT * FROM audit_log_chain ORDER BY timestamp {order} LIMIT ?",
                    (limit,),
                ).fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    d["details"] = json.loads(d.get("details") or "{}")
                    result.append(d)
                return result
            finally:
                conn.close()

    def query_audit_records(
        self,
        record_type: Optional[str] = None,
        actor: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                query = "SELECT * FROM audit_log_chain WHERE 1=1"
                params: List[Any] = []
                if record_type:
                    query += " AND record_type = ?"
                    params.append(record_type)
                if actor:
                    query += " AND actor = ?"
                    params.append(actor)
                if since:
                    query += " AND timestamp >= ?"
                    params.append(since)
                if until:
                    query += " AND timestamp <= ?"
                    params.append(until)
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                rows = conn.execute(query, params).fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    d["details"] = json.loads(d.get("details") or "{}")
                    result.append(d)
                return result
            finally:
                conn.close()

    def save_pending_approval(self, approval: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO pending_approvals
                    (approval_id, action_type, target_entity, target_ip, requested_by,
                     approved_by, second_approved_by, status, details, created_at, resolved_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval["approval_id"],
                        approval["action_type"],
                        approval.get("target_entity", ""),
                        approval.get("target_ip", ""),
                        approval["requested_by"],
                        approval.get("approved_by", ""),
                        approval.get("second_approved_by", ""),
                        approval.get("status", "pending"),
                        json.dumps(approval.get("details", {})),
                        approval["created_at"],
                        approval.get("resolved_at"),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def list_pending_approvals(self, status: str = "pending") -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM pending_approvals WHERE status = ? ORDER BY created_at DESC",
                    (status,),
                ).fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    d["details"] = json.loads(d.get("details") or "{}")
                    result.append(d)
                return result
            finally:
                conn.close()

    def approve_action(
        self, approval_id: str, approver: str, is_second: bool = False
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM pending_approvals WHERE approval_id = ?", (approval_id,)
                ).fetchone()
                if not row:
                    return None
                d = dict(row)
                d["details"] = json.loads(d.get("details") or "{}")
                if is_second:
                    conn.execute(
                        """
                        UPDATE pending_approvals SET second_approved_by=?, status='approved',
                        resolved_at=? WHERE approval_id=?
                        """,
                        (approver, time.time(), approval_id),
                    )
                else:
                    conn.execute(
                        "UPDATE pending_approvals SET approved_by=? WHERE approval_id=?",
                        (approver, approval_id),
                    )
                conn.commit()
                if is_second:
                    d["status"] = "approved"
                    d["second_approved_by"] = approver
                else:
                    d["approved_by"] = approver
                return d
            finally:
                conn.close()

    def save_quarantine(self, record: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO quarantine_records
                    (quarantine_id, entity_id, quarantine_type, status, created_at, released_at, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["quarantine_id"],
                        record["entity_id"],
                        record.get("quarantine_type", "virtual_quarantine"),
                        record.get("status", "active"),
                        record["created_at"],
                        record.get("released_at"),
                        json.dumps(record.get("details", {})),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def list_quarantine(self, active_only: bool = True) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                if active_only:
                    rows = conn.execute(
                        "SELECT * FROM quarantine_records WHERE status = 'active' ORDER BY created_at DESC"
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM quarantine_records ORDER BY created_at DESC"
                    ).fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    d["details"] = json.loads(d.get("details") or "{}")
                    result.append(d)
                return result
            finally:
                conn.close()

    def release_quarantine(self, quarantine_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    """
                    UPDATE quarantine_records SET status='released', released_at=?
                    WHERE quarantine_id=? AND status='active'
                    """,
                    (time.time(), quarantine_id),
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def save_active_session(self, record: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO active_sessions
                    (session_id, username, role, ip_address, user_agent, session_token,
                     created_at, last_activity, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["session_id"],
                        record["username"],
                        record.get("role", ""),
                        record.get("ip_address", ""),
                        record.get("user_agent", ""),
                        record["session_token"],
                        record["created_at"],
                        record["last_activity"],
                        record.get("status", "active"),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def update_session_activity(self, session_token: str, ts: float) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE active_sessions SET last_activity=? WHERE session_token=? AND status='active'",
                    (ts, session_token),
                )
                conn.commit()
            finally:
                conn.close()

    def list_active_sessions(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM active_sessions WHERE status='active' ORDER BY last_activity DESC"
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def revoke_session(self, session_id: str, revoked_by: str, ts: float) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    """
                    UPDATE active_sessions SET status='revoked', revoked_by=?, revoked_at=?
                    WHERE session_id=? AND status='active'
                    """,
                    (revoked_by, ts, session_id),
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def is_session_revoked(self, session_token: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT status FROM active_sessions WHERE session_token=?", (session_token,)
                ).fetchone()
                return bool(row and row["status"] == "revoked")
            finally:
                conn.close()

    def save_escalation_watch(self, watch: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO escalation_watches
                    (watch_id, entity_id, incident_id, original_action, created_at,
                     escalate_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        watch["watch_id"],
                        watch["entity_id"],
                        watch["incident_id"],
                        watch.get("original_action", "alert"),
                        watch["created_at"],
                        watch["escalate_at"],
                        watch.get("status", "watching"),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def list_due_escalations(self, now_ts: float) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM escalation_watches
                    WHERE status='watching' AND escalate_at <= ?
                    """,
                    (now_ts,),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def mark_escalation_triggered(self, watch_id: str, ts: float) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE escalation_watches SET status='escalated', resolved_at=? WHERE watch_id=?",
                    (ts, watch_id),
                )
                conn.commit()
            finally:
                conn.close()

    def resolve_escalation_watch(self, incident_id: str, analyst: str, ts: float) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    """
                    UPDATE escalation_watches SET status='acknowledged', resolved_by=?, resolved_at=?
                    WHERE incident_id=? AND status='watching'
                    """,
                    (analyst, ts, incident_id),
                )
                conn.commit()
                return cur.rowcount > 0
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
    """Clear cached store and related singletons (for tests)."""
    global _store
    with _store_lock:
        _store = None
    try:
        from security import audit_chain as ac

        ac._audit_chain = None
    except ImportError:
        pass
    try:
        from security import session_registry as sr

        sr._registry = None
    except ImportError:
        pass
    try:
        from decision_engine import escalation as esc

        esc._manager = None
    except ImportError:
        pass
    try:
        from soc import incident_manager as im

        im._manager = None
    except ImportError:
        pass
    try:
        from soc import case_manager as cm

        cm._manager = None
    except ImportError:
        pass
    try:
        from response import playbooks as pb

        pb._executor = None
    except ImportError:
        pass
