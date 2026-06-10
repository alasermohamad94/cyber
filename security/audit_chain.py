"""
Immutable audit log chain using SHA-256 hash-chaining.
"""

import hashlib
import json
import threading
import time
from typing import Any, Dict, List, Optional

from storage.persistence import get_store

GENESIS_HASH = "0" * 64


class AuditChain:
    """Append-only audit log with hash-chaining for tamper detection."""

    def __init__(self):
        self._lock = threading.RLock()

    @property
    def _store(self):
        return get_store()

    def _compute_hash(self, payload: Dict[str, Any], prev_hash: str) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        digest_input = f"{prev_hash}|{canonical}"
        return hashlib.sha256(digest_input.encode("utf-8")).hexdigest()

    def append(self, record_type: str, actor: str, details: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            prev_hash = self._store.get_last_audit_hash() or GENESIS_HASH
            timestamp = time.time()
            payload = {
                "record_type": record_type,
                "actor": actor,
                "timestamp": timestamp,
                "details": details,
            }
            record_hash = self._compute_hash(payload, prev_hash)
            entry = {
                "record_id": f"audit_{int(timestamp)}_{record_hash[:8]}",
                "record_type": record_type,
                "actor": actor,
                "timestamp": timestamp,
                "details": details,
                "prev_hash": prev_hash,
                "record_hash": record_hash,
            }
            self._store.save_audit_record(entry)
            return entry

    def verify_chain(self, limit: int = 500) -> Dict[str, Any]:
        with self._lock:
            records = self._store.list_audit_records(limit=limit, chronological=True)
            if not records:
                return {"valid": True, "checked": 0, "broken_at": None}

            expected_prev = GENESIS_HASH
            for idx, record in enumerate(records):
                if record["prev_hash"] != expected_prev:
                    return {
                        "valid": False,
                        "checked": idx,
                        "broken_at": record["record_id"],
                        "reason": "prev_hash mismatch",
                    }
                payload = {
                    "record_type": record["record_type"],
                    "actor": record["actor"],
                    "timestamp": record["timestamp"],
                    "details": record.get("details", {}),
                }
                computed = self._compute_hash(payload, expected_prev)
                if computed != record["record_hash"]:
                    return {
                        "valid": False,
                        "checked": idx,
                        "broken_at": record["record_id"],
                        "reason": "record_hash mismatch",
                    }
                expected_prev = record["record_hash"]

            return {"valid": True, "checked": len(records), "broken_at": None}

    def query(
        self,
        record_type: Optional[str] = None,
        actor: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        return self._store.query_audit_records(
            record_type=record_type,
            actor=actor,
            since=since,
            until=until,
            limit=limit,
        )


_audit_chain: Optional[AuditChain] = None
_chain_lock = threading.Lock()


def get_audit_chain() -> AuditChain:
    global _audit_chain
    with _chain_lock:
        if _audit_chain is None:
            _audit_chain = AuditChain()
        return _audit_chain


__all__ = ["AuditChain", "get_audit_chain", "GENESIS_HASH"]
