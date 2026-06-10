"""
PostgreSQL persistence for security events, trust, responses, and blocked IPs.
"""

import json
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras

from storage.persistence import (
    CASE_STATUSES,
    GENESIS_HASH,
    INCIDENT_STATUSES,
    build_event_query,
    compute_audit_hash,
)


class PostgresSecurityStore:
    """Thread-safe PostgreSQL store for audit and operational state."""

    def __init__(self, database_url: str):
        self.database_url = database_url
        self._lock = threading.RLock()
        self._init_schema()

    def _connect(self):
        conn = psycopg2.connect(self.database_url)
        conn.autocommit = False
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS security_events (
                            event_id TEXT PRIMARY KEY,
                            timestamp DOUBLE PRECISION NOT NULL,
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
                            trust_score DOUBLE PRECISION NOT NULL,
                            last_updated DOUBLE PRECISION NOT NULL,
                            behavior_history TEXT,
                            trust_trend TEXT,
                            risk_level TEXT
                        );
                        CREATE TABLE IF NOT EXISTS response_actions (
                            action_id TEXT PRIMARY KEY,
                            entity_id TEXT NOT NULL,
                            action_type TEXT NOT NULL,
                            status TEXT NOT NULL,
                            timestamp DOUBLE PRECISION NOT NULL,
                            completion_time DOUBLE PRECISION,
                            details TEXT
                        );
                        CREATE TABLE IF NOT EXISTS blocked_ips (
                            ip_address TEXT PRIMARY KEY,
                            reason TEXT,
                            blocked_at DOUBLE PRECISION NOT NULL,
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
                            created_at DOUBLE PRECISION NOT NULL,
                            updated_at DOUBLE PRECISION NOT NULL,
                            notes TEXT
                        );
                        CREATE TABLE IF NOT EXISTS incident_events (
                            incident_id TEXT NOT NULL,
                            event_id TEXT NOT NULL,
                            linked_at DOUBLE PRECISION NOT NULL,
                            PRIMARY KEY (incident_id, event_id)
                        );
                        CREATE TABLE IF NOT EXISTS security_cases (
                            case_id TEXT PRIMARY KEY,
                            title TEXT NOT NULL,
                            description TEXT,
                            status TEXT NOT NULL DEFAULT 'open',
                            created_at DOUBLE PRECISION NOT NULL,
                            updated_at DOUBLE PRECISION NOT NULL,
                            notes TEXT
                        );
                        CREATE TABLE IF NOT EXISTS case_incidents (
                            case_id TEXT NOT NULL,
                            incident_id TEXT NOT NULL,
                            linked_at DOUBLE PRECISION NOT NULL,
                            PRIMARY KEY (case_id, incident_id)
                        );
                        CREATE TABLE IF NOT EXISTS audit_logs (
                            log_id SERIAL PRIMARY KEY,
                            timestamp DOUBLE PRECISION NOT NULL,
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
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO security_events
                        (event_id, timestamp, event_type, severity, source_ip,
                         target_entity, description, action_taken, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (event_id) DO UPDATE SET
                            timestamp = EXCLUDED.timestamp,
                            event_type = EXCLUDED.event_type,
                            severity = EXCLUDED.severity,
                            source_ip = EXCLUDED.source_ip,
                            target_entity = EXCLUDED.target_entity,
                            description = EXCLUDED.description,
                            action_taken = EXCLUDED.action_taken,
                            status = EXCLUDED.status
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
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT * FROM security_events
                        ORDER BY timestamp DESC LIMIT %s
                        """,
                        (limit,),
                    )
                    return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def count_events_since(self, since_ts: float, severity: Optional[str] = None) -> int:
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    if severity:
                        cur.execute(
                            """
                            SELECT COUNT(*) FROM security_events
                            WHERE timestamp >= %s AND severity = %s
                            """,
                            (since_ts, severity),
                        )
                    else:
                        cur.execute(
                            "SELECT COUNT(*) FROM security_events WHERE timestamp >= %s",
                            (since_ts,),
                        )
                    return int(cur.fetchone()[0])
            finally:
                conn.close()

    def save_trust_record(self, record: Dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO trust_records
                        (entity_id, trust_score, last_updated, behavior_history,
                         trust_trend, risk_level)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (entity_id) DO UPDATE SET
                            trust_score = EXCLUDED.trust_score,
                            last_updated = EXCLUDED.last_updated,
                            behavior_history = EXCLUDED.behavior_history,
                            trust_trend = EXCLUDED.trust_trend,
                            risk_level = EXCLUDED.risk_level
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
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("SELECT * FROM trust_records")
                    result = []
                    for r in cur.fetchall():
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
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO response_actions
                        (action_id, entity_id, action_type, status, timestamp,
                         completion_time, details)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (action_id) DO UPDATE SET
                            entity_id = EXCLUDED.entity_id,
                            action_type = EXCLUDED.action_type,
                            status = EXCLUDED.status,
                            timestamp = EXCLUDED.timestamp,
                            completion_time = EXCLUDED.completion_time,
                            details = EXCLUDED.details
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
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        f"""
                        SELECT * FROM response_actions
                        WHERE status = ANY(%s)
                        ORDER BY timestamp DESC LIMIT %s
                        """,
                        (statuses, limit),
                    )
                    out = []
                    for r in cur.fetchall():
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
                with conn.cursor() as cur:
                    if action_type:
                        cur.execute(
                            """
                            SELECT COUNT(*) FROM response_actions
                            WHERE timestamp >= %s AND action_type = %s
                            """,
                            (since_ts, action_type),
                        )
                    else:
                        cur.execute(
                            "SELECT COUNT(*) FROM response_actions WHERE timestamp >= %s",
                            (since_ts,),
                        )
                    return int(cur.fetchone()[0])
            finally:
                conn.close()

    def save_blocked_ip(self, ip_address: str, reason: str, firewall_applied: bool) -> None:
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO blocked_ips
                        (ip_address, reason, blocked_at, status, firewall_applied)
                        VALUES (%s, %s, %s, 'active', %s)
                        ON CONFLICT (ip_address) DO UPDATE SET
                            reason = EXCLUDED.reason,
                            blocked_at = EXCLUDED.blocked_at,
                            status = 'active',
                            firewall_applied = EXCLUDED.firewall_applied
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
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    if active_only:
                        cur.execute(
                            "SELECT * FROM blocked_ips WHERE status = 'active' ORDER BY blocked_at DESC"
                        )
                    else:
                        cur.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
                    return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def unblock_ip(self, ip_address: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE blocked_ips SET status = 'released'
                        WHERE ip_address = %s AND status = 'active'
                        """,
                        (ip_address,),
                    )
                    updated = cur.rowcount > 0
                conn.commit()
                return updated
            finally:
                conn.close()

    def count_blocked_ips(self) -> int:
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT COUNT(*) FROM blocked_ips WHERE status = 'active'"
                    )
                    return int(cur.fetchone()[0])
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
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO security_incidents
                        (incident_id, title, description, severity, status, assigned_to,
                         case_id, created_at, updated_at, notes)
                        VALUES (%s, %s, %s, %s, 'open', %s, NULL, %s, %s, '')
                        """,
                        (incident_id, title, description, severity, assigned_to, now, now),
                    )
                    for event_id in event_ids or []:
                        cur.execute(
                            """
                            INSERT INTO incident_events (incident_id, event_id, linked_at)
                            VALUES (%s, %s, %s) ON CONFLICT DO NOTHING
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
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("SELECT * FROM security_incidents WHERE incident_id = %s", (incident_id,))
                    row = cur.fetchone()
                    if not row:
                        return None
                    incident = dict(row)
                    cur.execute(
                        "SELECT event_id FROM incident_events WHERE incident_id = %s ORDER BY linked_at",
                        (incident_id,),
                    )
                    incident["event_ids"] = [r["event_id"] for r in cur.fetchall()]
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
            clauses.append("status = %s")
            params.append(status)
        if severity:
            clauses.append("severity = %s")
            params.append(severity)
        if assigned_to:
            clauses.append("assigned_to = %s")
            params.append(assigned_to)
        if case_id:
            clauses.append("case_id = %s")
            params.append(case_id)
        where_sql = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        f"SELECT * FROM security_incidents{where_sql} ORDER BY updated_at DESC LIMIT %s", params
                    )
                    return [dict(r) for r in cur.fetchall()]
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
        set_sql = ", ".join(f"{k} = %s" for k in updates)
        params = list(updates.values()) + [incident_id]
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(f"UPDATE security_incidents SET {set_sql} WHERE incident_id = %s", params)
                conn.commit()
            finally:
                conn.close()
        return self.get_incident(incident_id)

    def link_event_to_incident(self, incident_id: str, event_id: str) -> None:
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO incident_events (incident_id, event_id, linked_at)
                        VALUES (%s, %s, %s) ON CONFLICT DO NOTHING
                        """,
                        (incident_id, event_id, now),
                    )
                    cur.execute(
                        "UPDATE security_incidents SET updated_at = %s WHERE incident_id = %s",
                        (now, incident_id),
                    )
                conn.commit()
            finally:
                conn.close()

    def list_incident_events(self, incident_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT se.* FROM security_events se
                        JOIN incident_events ie ON ie.event_id = se.event_id
                        WHERE ie.incident_id = %s
                        ORDER BY se.timestamp ASC
                        """,
                        (incident_id,),
                    )
                    return [dict(r) for r in cur.fetchall()]
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
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO security_cases
                        (case_id, title, description, status, created_at, updated_at, notes)
                        VALUES (%s, %s, %s, 'open', %s, %s, '')
                        """,
                        (case_id, title, description, now, now),
                    )
                    for incident_id in incident_ids or []:
                        cur.execute(
                            """
                            INSERT INTO case_incidents (case_id, incident_id, linked_at)
                            VALUES (%s, %s, %s) ON CONFLICT DO NOTHING
                            """,
                            (case_id, incident_id, now),
                        )
                        cur.execute(
                            "UPDATE security_incidents SET case_id = %s, updated_at = %s WHERE incident_id = %s",
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
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("SELECT * FROM security_cases WHERE case_id = %s", (case_id,))
                    row = cur.fetchone()
                    if not row:
                        return None
                    case = dict(row)
                    cur.execute(
                        "SELECT incident_id FROM case_incidents WHERE case_id = %s ORDER BY linked_at",
                        (case_id,),
                    )
                    case["incident_ids"] = [r["incident_id"] for r in cur.fetchall()]
                    return case
            finally:
                conn.close()

    def list_cases(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        clauses = []
        params: list = []
        if status:
            clauses.append("status = %s")
            params.append(status)
        where_sql = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(f"SELECT * FROM security_cases{where_sql} ORDER BY updated_at DESC LIMIT %s", params)
                    return [dict(r) for r in cur.fetchall()]
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
        set_sql = ", ".join(f"{k} = %s" for k in updates)
        params = list(updates.values()) + [case_id]
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(f"UPDATE security_cases SET {set_sql} WHERE case_id = %s", params)
                conn.commit()
            finally:
                conn.close()
        return self.get_case(case_id)

    def link_incident_to_case(self, case_id: str, incident_id: str) -> None:
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO case_incidents (case_id, incident_id, linked_at)
                        VALUES (%s, %s, %s) ON CONFLICT DO NOTHING
                        """,
                        (case_id, incident_id, now),
                    )
                    cur.execute(
                        "UPDATE security_incidents SET case_id = %s, updated_at = %s WHERE incident_id = %s",
                        (case_id, now, incident_id),
                    )
                    cur.execute("UPDATE security_cases SET updated_at = %s WHERE case_id = %s", (now, case_id))
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
                with conn.cursor() as cur:
                    cur.execute("SELECT hash FROM audit_logs ORDER BY log_id DESC LIMIT 1")
                    row = cur.fetchone()
                    prev_hash = row[0] if row else GENESIS_HASH
                    timestamp = time.time()
                    cur.execute(
                        """
                        INSERT INTO audit_logs (timestamp, actor, action, details, prev_hash, hash)
                        VALUES (%s, %s, %s, %s, %s, '') RETURNING log_id
                        """,
                        (timestamp, actor, action, json.dumps(details, default=str), prev_hash),
                    )
                    log_id = cur.fetchone()[0]
                    entry_hash = compute_audit_hash(log_id, timestamp, actor, action, details, prev_hash)
                    cur.execute("UPDATE audit_logs SET hash = %s WHERE log_id = %s", (entry_hash, log_id))
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
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("SELECT * FROM audit_logs ORDER BY log_id DESC LIMIT %s", (limit,))
                    out = []
                    for r in cur.fetchall():
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
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("SELECT * FROM audit_logs ORDER BY log_id ASC")
                    rows = cur.fetchall()
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
        sql, params = build_event_query(filters, logic, limit, placeholder="%s")
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(sql, params)
                    return [dict(r) for r in cur.fetchall()]
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
            clauses.append("target_entity = %s")
            params.append(target_entity)
        if start_ts is not None:
            clauses.append("timestamp >= %s")
            params.append(start_ts)
        if end_ts is not None:
            clauses.append("timestamp <= %s")
            params.append(end_ts)
        where_sql = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._lock:
            conn = self._connect()
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        f"SELECT * FROM security_events{where_sql} ORDER BY timestamp ASC LIMIT %s", params
                    )
                    return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()
