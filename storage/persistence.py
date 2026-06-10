"""
SQLite persistence for security events, trust, responses, and blocked IPs.
"""

import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

GENESIS_HASH = "0" * 64

INCIDENT_STATUSES = ("open", "investigating", "pending_approval", "resolved")
CASE_STATUSES = ("open", "investigating", "closed")

QUERY_FIELDS = {
    "event_id": "TEXT",
    "timestamp": "REAL",
    "event_type": "TEXT",
    "severity": "TEXT",
    "source_ip": "TEXT",
    "target_entity": "TEXT",
    "description": "TEXT",
    "action_taken": "TEXT",
    "status": "TEXT",
}

QUERY_OPERATORS = {
    "eq": "=",
    "neq": "!=",
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
    "contains": "LIKE",
    "in": "IN",
}


def compute_audit_hash(log_id: int, timestamp: float, actor: str, action: str, details: Dict[str, Any], prev_hash: str) -> str:
    payload = json.dumps(
        {
            "log_id": log_id,
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "details": details,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_event_query(filters: List[Dict[str, Any]], logic: str, limit: int, placeholder: str = "?") -> Tuple[str, list]:
    """Build a WHERE clause + params for security_events from a whitelist of fields/operators."""
    logic = (logic or "AND").upper()
    if logic not in ("AND", "OR"):
        logic = "AND"

    clauses = []
    params: list = []
    for f in filters:
        field = f.get("field")
        op = f.get("op")
        value = f.get("value")
        if field not in QUERY_FIELDS or op not in QUERY_OPERATORS:
            continue
        sql_op = QUERY_OPERATORS[op]
        if op == "contains":
            clauses.append(f"{field} LIKE {placeholder}")
            params.append(f"%{value}%")
        elif op == "in":
            values = value if isinstance(value, list) else [value]
            if not values:
                continue
            in_placeholders = ",".join(placeholder for _ in values)
            clauses.append(f"{field} IN ({in_placeholders})")
            params.extend(values)
        else:
            clauses.append(f"{field} {sql_op} {placeholder}")
            params.append(value)

    where_sql = f" WHERE {f' {logic} '.join(clauses)}" if clauses else ""
    sql = f"SELECT * FROM security_events{where_sql} ORDER BY timestamp DESC LIMIT {placeholder}"
    params.append(limit)
    return sql, params


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
                        risk_level TEXT
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
                    CREATE TABLE IF NOT EXISTS security_incidents (
                        incident_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        description TEXT,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'open',
                        assigned_to TEXT,
                        case_id TEXT,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        notes TEXT
                    );
                    CREATE TABLE IF NOT EXISTS incident_events (
                        incident_id TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        linked_at REAL NOT NULL,
                        PRIMARY KEY (incident_id, event_id)
                    );
                    CREATE TABLE IF NOT EXISTS security_cases (
                        case_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        description TEXT,
                        status TEXT NOT NULL DEFAULT 'open',
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        notes TEXT
                    );
                    CREATE TABLE IF NOT EXISTS case_incidents (
                        case_id TEXT NOT NULL,
                        incident_id TEXT NOT NULL,
                        linked_at REAL NOT NULL,
                        PRIMARY KEY (case_id, incident_id)
                    );
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        actor TEXT NOT NULL,
                        action TEXT NOT NULL,
                        details TEXT,
                        prev_hash TEXT NOT NULL,
                        hash TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_responses_status ON response_actions(status);
                    CREATE INDEX IF NOT EXISTS idx_incidents_status ON security_incidents(status);
                    CREATE INDEX IF NOT EXISTS idx_incidents_case ON security_incidents(case_id);
                    CREATE INDEX IF NOT EXISTS idx_cases_status ON security_cases(status);
                    """
                )
                conn.commit()
            finally:
                conn.close()

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
                     trust_trend, risk_level)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["entity_id"],
                        record["trust_score"],
                        record["last_updated"],
                        json.dumps(record.get("behavior_history", [])),
                        record.get("trust_trend", "stable"),
                        record.get("risk_level", "low"),
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

    # ------------------------------------------------------------------
    # Security incidents
    # ------------------------------------------------------------------

    def create_incident(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        assigned_to: Optional[str] = None,
        event_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        incident_id = f"inc_{uuid.uuid4().hex[:12]}"
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO security_incidents
                    (incident_id, title, description, severity, status, assigned_to,
                     case_id, created_at, updated_at, notes)
                    VALUES (?, ?, ?, ?, 'open', ?, NULL, ?, ?, '')
                    """,
                    (incident_id, title, description, severity, assigned_to, now, now),
                )
                for event_id in event_ids or []:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO incident_events (incident_id, event_id, linked_at)
                        VALUES (?, ?, ?)
                        """,
                        (incident_id, event_id, now),
                    )
                conn.commit()
            finally:
                conn.close()
        return self.get_incident(incident_id)

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM security_incidents WHERE incident_id = ?", (incident_id,)
                ).fetchone()
                if not row:
                    return None
                incident = dict(row)
                incident["event_ids"] = [
                    r["event_id"]
                    for r in conn.execute(
                        "SELECT event_id FROM incident_events WHERE incident_id = ? ORDER BY linked_at",
                        (incident_id,),
                    ).fetchall()
                ]
                return incident
            finally:
                conn.close()

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assigned_to: Optional[str] = None,
        case_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        clauses = []
        params: list = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if assigned_to:
            clauses.append("assigned_to = ?")
            params.append(assigned_to)
        if case_id:
            clauses.append("case_id = ?")
            params.append(case_id)
        where_sql = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    f"SELECT * FROM security_incidents{where_sql} ORDER BY updated_at DESC LIMIT ?",
                    params,
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def update_incident(self, incident_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
        allowed = {"title", "description", "severity", "status", "assigned_to", "notes", "case_id"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return self.get_incident(incident_id)
        if "status" in updates and updates["status"] not in INCIDENT_STATUSES:
            raise ValueError(f"Invalid incident status: {updates['status']}")
        updates["updated_at"] = time.time()
        set_sql = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [incident_id]
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    f"UPDATE security_incidents SET {set_sql} WHERE incident_id = ?", params
                )
                conn.commit()
            finally:
                conn.close()
        return self.get_incident(incident_id)

    def link_event_to_incident(self, incident_id: str, event_id: str) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO incident_events (incident_id, event_id, linked_at)
                    VALUES (?, ?, ?)
                    """,
                    (incident_id, event_id, time.time()),
                )
                conn.execute(
                    "UPDATE security_incidents SET updated_at = ? WHERE incident_id = ?",
                    (time.time(), incident_id),
                )
                conn.commit()
            finally:
                conn.close()

    def list_incident_events(self, incident_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT se.* FROM security_events se
                    JOIN incident_events ie ON ie.event_id = se.event_id
                    WHERE ie.incident_id = ?
                    ORDER BY se.timestamp ASC
                    """,
                    (incident_id,),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Security cases
    # ------------------------------------------------------------------

    def create_case(self, title: str, description: str = "", incident_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        case_id = f"case_{uuid.uuid4().hex[:12]}"
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO security_cases
                    (case_id, title, description, status, created_at, updated_at, notes)
                    VALUES (?, ?, ?, 'open', ?, ?, '')
                    """,
                    (case_id, title, description, now, now),
                )
                for incident_id in incident_ids or []:
                    conn.execute(
                        "INSERT OR IGNORE INTO case_incidents (case_id, incident_id, linked_at) VALUES (?, ?, ?)",
                        (case_id, incident_id, now),
                    )
                    conn.execute(
                        "UPDATE security_incidents SET case_id = ?, updated_at = ? WHERE incident_id = ?",
                        (case_id, now, incident_id),
                    )
                conn.commit()
            finally:
                conn.close()
        return self.get_case(case_id)

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM security_cases WHERE case_id = ?", (case_id,)).fetchone()
                if not row:
                    return None
                case = dict(row)
                case["incident_ids"] = [
                    r["incident_id"]
                    for r in conn.execute(
                        "SELECT incident_id FROM case_incidents WHERE case_id = ? ORDER BY linked_at",
                        (case_id,),
                    ).fetchall()
                ]
                return case
            finally:
                conn.close()

    def list_cases(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        clauses = []
        params: list = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        where_sql = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    f"SELECT * FROM security_cases{where_sql} ORDER BY updated_at DESC LIMIT ?", params
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def update_case(self, case_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
        allowed = {"title", "description", "status", "notes"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return self.get_case(case_id)
        if "status" in updates and updates["status"] not in CASE_STATUSES:
            raise ValueError(f"Invalid case status: {updates['status']}")
        updates["updated_at"] = time.time()
        set_sql = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [case_id]
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(f"UPDATE security_cases SET {set_sql} WHERE case_id = ?", params)
                conn.commit()
            finally:
                conn.close()
        return self.get_case(case_id)

    def link_incident_to_case(self, case_id: str, incident_id: str) -> None:
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO case_incidents (case_id, incident_id, linked_at) VALUES (?, ?, ?)",
                    (case_id, incident_id, now),
                )
                conn.execute(
                    "UPDATE security_incidents SET case_id = ?, updated_at = ? WHERE incident_id = ?",
                    (case_id, now, incident_id),
                )
                conn.execute("UPDATE security_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Immutable audit log (SHA-256 hash chain)
    # ------------------------------------------------------------------

    def append_audit_log(self, actor: str, action: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        details = details or {}
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT hash FROM audit_logs ORDER BY log_id DESC LIMIT 1").fetchone()
                prev_hash = row["hash"] if row else GENESIS_HASH
                timestamp = time.time()
                cur = conn.execute(
                    """
                    INSERT INTO audit_logs (timestamp, actor, action, details, prev_hash, hash)
                    VALUES (?, ?, ?, ?, ?, '')
                    """,
                    (timestamp, actor, action, json.dumps(details, default=str), prev_hash),
                )
                log_id = cur.lastrowid
                entry_hash = compute_audit_hash(log_id, timestamp, actor, action, details, prev_hash)
                conn.execute("UPDATE audit_logs SET hash = ? WHERE log_id = ?", (entry_hash, log_id))
                conn.commit()
            finally:
                conn.close()
        return {
            "log_id": log_id,
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "details": details,
            "prev_hash": prev_hash,
            "hash": entry_hash,
        }

    def list_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM audit_logs ORDER BY log_id DESC LIMIT ?", (limit,)
                ).fetchall()
                out = []
                for r in rows:
                    d = dict(r)
                    d["details"] = json.loads(d.get("details") or "{}")
                    out.append(d)
                return out
            finally:
                conn.close()

    def verify_audit_chain(self) -> Dict[str, Any]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT * FROM audit_logs ORDER BY log_id ASC").fetchall()
            finally:
                conn.close()
        expected_prev = GENESIS_HASH
        for r in rows:
            d = dict(r)
            details = json.loads(d.get("details") or "{}")
            if d["prev_hash"] != expected_prev:
                return {"valid": False, "total": len(rows), "broken_at": d["log_id"]}
            recomputed = compute_audit_hash(d["log_id"], d["timestamp"], d["actor"], d["action"], details, d["prev_hash"])
            if recomputed != d["hash"]:
                return {"valid": False, "total": len(rows), "broken_at": d["log_id"]}
            expected_prev = d["hash"]
        return {"valid": True, "total": len(rows), "broken_at": None}

    # ------------------------------------------------------------------
    # Advanced query engine
    # ------------------------------------------------------------------

    def query_events(self, filters: List[Dict[str, Any]], logic: str = "AND", limit: int = 100) -> List[Dict[str, Any]]:
        sql, params = build_event_query(filters, logic, limit, placeholder="?")
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(sql, params).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Event replay engine
    # ------------------------------------------------------------------

    def replay_events(
        self,
        target_entity: Optional[str] = None,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        clauses = []
        params: list = []
        if target_entity:
            clauses.append("target_entity = ?")
            params.append(target_entity)
        if start_ts is not None:
            clauses.append("timestamp >= ?")
            params.append(start_ts)
        if end_ts is not None:
            clauses.append("timestamp <= ?")
            params.append(end_ts)
        where_sql = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    f"SELECT * FROM security_events{where_sql} ORDER BY timestamp ASC LIMIT ?", params
                ).fetchall()
                return [dict(r) for r in rows]
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
