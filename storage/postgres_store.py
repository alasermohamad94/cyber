"""
PostgreSQL persistence for security events, trust, responses, and blocked IPs.
"""

import json
import threading
import time
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras


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
                        CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(timestamp);
                        CREATE INDEX IF NOT EXISTS idx_responses_status ON response_actions(status);
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
