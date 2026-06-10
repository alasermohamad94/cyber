"""
Trust System Module

This module manages trust scores and risk scores for entities in the cyber
defense system.
"""

import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from storage.persistence import get_store


RISK_SEVERITY_BONUS = {
    "low": 0.0,
    "medium": 7.0,
    "high": 15.0,
    "critical": 24.0,
}

SEVERITY_DECAY_FACTORS = {
    "low": 0.6,
    "medium": 1.0,
    "high": 1.4,
    "critical": 1.8,
}

ASSET_CRITICALITY_FACTORS = {
    "employee_device": 1.0,
    "web_server": 2.0,
    "database_server": 5.0,
}

ASSET_TYPE_ALIASES = {
    "employee": "employee_device",
    "employee_device": "employee_device",
    "endpoint": "employee_device",
    "generic": "employee_device",
    "user_device": "employee_device",
    "user_workstation": "employee_device",
    "workstation": "employee_device",
    "app_server": "web_server",
    "application_server": "web_server",
    "server_web": "web_server",
    "web": "web_server",
    "web_server": "web_server",
    "control_server": "database_server",
    "database": "database_server",
    "database_server": "database_server",
    "db": "database_server",
    "db_server": "database_server",
}

INCIDENT_TYPE_DECAY_FACTORS = {
    "behavior_anomaly": 1.0,
    "distributed_scan": 1.1,
    "targeted_brute_force": 1.3,
    "credential_abuse": 1.4,
    "lateral_movement": 1.5,
    "malware_activity": 1.6,
    "data_exfiltration": 1.8,
}

INCIDENT_TYPE_ALIASES = {
    "anomaly": "behavior_anomaly",
    "behavior_anomaly": "behavior_anomaly",
    "brute_force": "targeted_brute_force",
    "credential_abuse": "credential_abuse",
    "data_exfiltration": "data_exfiltration",
    "distributed_scan": "distributed_scan",
    "exfiltration": "data_exfiltration",
    "lateral_movement": "lateral_movement",
    "malware": "malware_activity",
    "malware_activity": "malware_activity",
    "port_scan": "distributed_scan",
    "scan": "distributed_scan",
    "targeted_brute_force": "targeted_brute_force",
}


@dataclass(frozen=True)
class TrustRecord:
    """
    Trust record for an entity.

    Attributes
    ----------
    entity_id:
        Unique identifier for the entity
    trust_score:
        Current trust score [0, 100]
    last_updated:
        Timestamp of last update
    behavior_history:
        List of recent behavior scores
    trust_trend:
        Trend direction: 'improving', 'declining', 'stable'
    risk_level:
        Current risk level based on the computed risk score
    risk_score:
        Current risk score [0, 100]
    asset_type:
        Asset type used in risk scoring
    asset_criticality:
        Asset criticality factor applied to the base risk
    last_incident_type:
        Last incident type that affected trust decay
    last_incident_severity:
        Last severity used in rule-based trust decay
    """

    entity_id: str
    trust_score: float
    last_updated: float
    behavior_history: List[float]
    trust_trend: str
    risk_level: str
    risk_score: float = 0.0
    asset_type: str = "employee_device"
    asset_criticality: float = 1.0
    last_incident_type: str = "behavior_anomaly"
    last_incident_severity: str = "low"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "entity_id": self.entity_id,
            "trust_score": self.trust_score,
            "last_updated": self.last_updated,
            "behavior_history": self.behavior_history,
            "trust_trend": self.trust_trend,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "asset_type": self.asset_type,
            "asset_criticality": self.asset_criticality,
            "last_incident_type": self.last_incident_type,
            "last_incident_severity": self.last_incident_severity,
        }


TRUST_RECOVERY_CLEAN_HOURS = 24


class TrustManager:
    """
    Manages trust scores and risk-related operations for entities.

    The trust system now tracks:
    - Current behavior analysis
    - Historical behavior patterns
    - Dynamic risk scoring
    - Positive reinforcement for healthy behavior
    """

    def __init__(self):
        self.trust_records: Dict[str, TrustRecord] = {}
        self._lock = threading.RLock()
        self._store = get_store()
        self.max_history_length = 20
        self.positive_boost = 2.0
        self.negative_penalty = 5.0
        self._load_from_store()

    def _load_from_store(self) -> None:
        for record in self._store.load_all_trust_records():
            self.trust_records[record["entity_id"]] = TrustRecord(
                entity_id=record["entity_id"],
                trust_score=float(record["trust_score"]),
                last_updated=float(record["last_updated"]),
                behavior_history=record.get("behavior_history", []),
                trust_trend=record.get("trust_trend", "stable"),
                risk_level=record.get("risk_level", "low"),
                risk_score=float(record.get("risk_score", 0.0)),
                asset_type=record.get("asset_type", "employee_device"),
                asset_criticality=float(record.get("asset_criticality", 1.0)),
                last_incident_type=record.get("last_incident_type", "behavior_anomaly"),
                last_incident_severity=record.get("last_incident_severity", "low"),
            )

    def _normalize_asset_type(self, asset_type: str) -> str:
        """Normalize incoming asset labels into the supported canonical types."""
        key = (asset_type or "").strip().lower()
        return ASSET_TYPE_ALIASES.get(key, "employee_device")

    def _infer_asset_type(
        self, entity_id: str, asset_context: Optional[Mapping[str, Any]]
    ) -> str:
        """Infer the asset type from explicit metadata first, then from the entity id."""
        if asset_context:
            for key in ("asset_type", "entity_type", "asset_category"):
                raw_value = asset_context.get(key)
                if isinstance(raw_value, str) and raw_value.strip():
                    return self._normalize_asset_type(raw_value)

        entity_key = entity_id.lower()
        if "db" in entity_key or "database" in entity_key:
            return "database_server"
        if "web" in entity_key or "server" in entity_key:
            return "web_server"
        return "employee_device"

    def _resolve_asset_profile(
        self, entity_id: str, asset_context: Optional[Mapping[str, Any]]
    ) -> Tuple[str, float]:
        """
        Resolve the asset type and criticality factor used in the risk engine.

        تعليق: نسمح بتمرير عامل مباشر عند الحاجة، لكن المسار الطبيعي يعتمد
        على نوع الأصل المعياري حتى يبقى السلوك قابلاً للتوقع والاختبار.
        """
        asset_type = self._infer_asset_type(entity_id, asset_context)
        asset_factor = ASSET_CRITICALITY_FACTORS.get(asset_type, 1.0)

        if asset_context:
            for key in ("asset_criticality", "criticality_factor"):
                raw_value = asset_context.get(key)
                try:
                    if raw_value is not None:
                        asset_factor = max(0.1, float(raw_value))
                        break
                except (TypeError, ValueError):
                    continue

        return asset_type, asset_factor

    def _normalize_incident_type(self, incident_type: str) -> str:
        """Normalize incoming incident labels into supported rule keys."""
        key = (incident_type or "").strip().lower()
        return INCIDENT_TYPE_ALIASES.get(key, "behavior_anomaly")

    def _resolve_incident_profile(
        self, entity_context: Optional[Mapping[str, Any]], behavior_score: float
    ) -> Tuple[str, str]:
        """
        Resolve the incident type and severity used in trust decay.

        تعليق: هذه الطبقة تجعل انخفاض الثقة مرتبطًا بالسياق الأمني الفعلي
        بدل أن يكون مجرد انخفاض زمني عام.
        """
        incident_type = "behavior_anomaly"
        incident_severity = self._severity_from_behavior_score(behavior_score)

        if not entity_context:
            return incident_type, incident_severity

        for key in ("incident_type", "detection_type", "event_type"):
            raw_value = entity_context.get(key)
            if isinstance(raw_value, str) and raw_value.strip():
                incident_type = self._normalize_incident_type(raw_value)
                break

        for key in ("incident_severity", "severity"):
            raw_value = entity_context.get(key)
            if isinstance(raw_value, str) and raw_value.strip():
                candidate = raw_value.strip().lower()
                if candidate in SEVERITY_DECAY_FACTORS:
                    incident_severity = candidate
                    break

        return incident_type, incident_severity

    def _severity_from_behavior_score(self, behavior_score: float) -> str:
        """Map the behavior score to a coarse severity label."""
        if behavior_score < 25:
            return "low"
        if behavior_score < 50:
            return "medium"
        if behavior_score < 75:
            return "high"
        return "critical"

    def _calculate_risk_level(self, risk_score: float) -> str:
        """Translate a numeric risk score into a dashboard-friendly level."""
        if risk_score < 25:
            return "low"
        if risk_score < 50:
            return "medium"
        if risk_score < 75:
            return "high"
        return "critical"

    def _calculate_trust_trend(self, behavior_history: List[float]) -> str:
        """Calculate the behavior trend from the latest samples."""
        if len(behavior_history) < 3:
            return "stable"

        recent_scores = behavior_history[-5:]
        if len(recent_scores) < 3:
            return "stable"

        split_index = len(recent_scores) // 2
        avg_first_half = sum(recent_scores[:split_index]) / split_index
        avg_second_half = sum(recent_scores[split_index:]) / (
            len(recent_scores) - split_index
        )
        difference = avg_second_half - avg_first_half

        if difference > 5:
            return "improving"
        if difference < -5:
            return "declining"
        return "stable"

    def _calculate_history_pressure(self, behavior_history: List[float]) -> float:
        """
        Calculate a pressure bonus from repeated suspicious behavior.

        تعليق: هذا الجزء هو أساس محرك المخاطر، لأنه يجعل السلوك المتكرر
        أخطر من الحدث المنفرد حتى لو كانت الدرجة اللحظية متقاربة.
        """
        if not behavior_history:
            return 0.0

        recent_scores = behavior_history[-4:]
        recent_average = sum(recent_scores) / len(recent_scores)
        pressure = max(0.0, recent_average - 25.0) * 0.25
        suspicious_streak = sum(1 for score in recent_scores if score >= 40.0)
        pressure += max(0, suspicious_streak - 1) * 2.0

        if len(recent_scores) >= 2 and recent_scores[-1] - recent_scores[-2] > 20:
            pressure += 4.0

        return min(15.0, pressure)

    def _calculate_risk_score(
        self,
        behavior_score: float,
        behavior_history: List[float],
        asset_criticality: float,
    ) -> float:
        """
        Build a normalized risk score [0, 100].

        تعليق: نحافظ هنا على معادلة واضحة وبسيطة:
        - السلوك الحالي هو الأساس
        - خطورة المستوى تضيف وزناً ثابتاً
        - التكرار التاريخي يرفع الخطر تدريجياً
        """
        severity = self._severity_from_behavior_score(behavior_score)
        severity_bonus = RISK_SEVERITY_BONUS[severity]
        history_pressure = self._calculate_history_pressure(behavior_history)

        # تعليق: هذه هي الدرجة الأساسية قبل أخذ حساسية الأصل بالحسبان.
        base_risk = behavior_score * 0.7 + severity_bonus + history_pressure
        risk_score = base_risk * asset_criticality
        return max(0.0, min(100.0, risk_score))

    def _calculate_trust_adjustment(
        self,
        risk_score: float,
        current_trust: float,
        incident_type: str,
        incident_severity: str,
        entity_id: str = "",
        behavior_history: Optional[List[float]] = None,
    ) -> float:
        """
        Adjust trust according to the current risk score.

        تعليق: هنا ننفذ Rule-based Score Decay عبر مضاعفات مستقلة
        لخطورة الحادث ونوعه، بحيث تصبح خسارة الثقة متناسبة مع طبيعة التهديد.
        """
        if risk_score < 20:
            adjustment = self.positive_boost
            if entity_id and self._can_auto_recover(entity_id, behavior_history or []):
                adjustment = self.positive_boost * 1.5
        elif risk_score < 35:
            adjustment = self.positive_boost * 0.5
        elif risk_score < 55:
            adjustment = -self.negative_penalty * 0.35
        elif risk_score < 75:
            adjustment = -self.negative_penalty * 0.7
        else:
            adjustment = -self.negative_penalty * 1.2

        if adjustment > 0:
            trust_multiplier = 1.0 + (current_trust / 100.0) * 0.5
        else:
            trust_multiplier = 1.0 + ((100.0 - current_trust) / 100.0) * 0.5

        final_adjustment = adjustment * trust_multiplier
        if final_adjustment < 0:
            incident_factor = INCIDENT_TYPE_DECAY_FACTORS.get(incident_type, 1.0)
            severity_factor = SEVERITY_DECAY_FACTORS.get(incident_severity, 1.0)
            final_adjustment *= incident_factor * severity_factor

        return final_adjustment

    def _can_auto_recover(self, entity_id: str, behavior_history: List[float]) -> bool:
        """Trust recovery: 24h clean period with no suspicious behavior."""
        if not behavior_history:
            return True
        clean_threshold = 40.0
        if any(score >= clean_threshold for score in behavior_history[-5:]):
            return False
        record = self.trust_records.get(entity_id)
        if not record:
            return True
        hours_since = (time.time() - record.last_updated) / 3600.0
        return hours_since >= TRUST_RECOVERY_CLEAN_HOURS and record.risk_score < 30.0

    def manual_trust_recovery(self, entity_id: str, analyst: str, note: str = "") -> bool:
        """Documented analyst-driven trust recovery."""
        with self._lock:
            if entity_id not in self.trust_records:
                return False
            rec = self.trust_records[entity_id]
            updated = TrustRecord(
                entity_id=entity_id,
                trust_score=min(100.0, rec.trust_score + 20.0),
                last_updated=time.time(),
                behavior_history=[],
                trust_trend="improving",
                risk_level="low",
                risk_score=max(0.0, rec.risk_score - 30.0),
                asset_type=rec.asset_type,
                asset_criticality=rec.asset_criticality,
                last_incident_type="behavior_anomaly",
                last_incident_severity="low",
            )
            self.trust_records[entity_id] = updated
            self._store.save_trust_record(updated.to_dict())
            try:
                from security.audit_chain import get_audit_chain

                get_audit_chain().append(
                    "trust_recovery_manual",
                    analyst,
                    {"entity_id": entity_id, "note": note},
                )
            except ImportError:
                pass
            return True

    def update_trust_score(
        self,
        entity_id: str,
        behavior_score: float,
        current_trust: Optional[float] = None,
        asset_context: Optional[Mapping[str, Any]] = None,
    ) -> float:
        """Update trust score for an entity based on the computed risk."""
        with self._lock:
            return self._update_trust_score_locked(
                entity_id, behavior_score, current_trust, asset_context
            )

    def _update_trust_score_locked(
        self,
        entity_id: str,
        behavior_score: float,
        current_trust: Optional[float] = None,
        asset_context: Optional[Mapping[str, Any]] = None,
    ) -> float:
        current_time = time.time()
        behavior_score = max(0.0, min(100.0, float(behavior_score)))
        asset_type, asset_criticality = self._resolve_asset_profile(
            entity_id, asset_context
        )
        incident_type, incident_severity = self._resolve_incident_profile(
            asset_context, behavior_score
        )

        if current_trust is None:
            if entity_id in self.trust_records:
                current_trust = self.trust_records[entity_id].trust_score
            else:
                current_trust = 100.0

        if entity_id in self.trust_records:
            behavior_history = self.trust_records[entity_id].behavior_history.copy()
        else:
            behavior_history = []

        behavior_history.append(behavior_score)
        if len(behavior_history) > self.max_history_length:
            behavior_history = behavior_history[-self.max_history_length:]

        risk_score = self._calculate_risk_score(
            behavior_score, behavior_history, asset_criticality
        )
        adjustment = self._calculate_trust_adjustment(
            risk_score,
            current_trust,
            incident_type,
            incident_severity,
            entity_id=entity_id,
            behavior_history=behavior_history,
        )
        new_trust = max(0.0, min(100.0, current_trust + adjustment))

        trust_trend = self._calculate_trust_trend(behavior_history)
        risk_level = self._calculate_risk_level(risk_score)

        trust_record = TrustRecord(
            entity_id=entity_id,
            trust_score=new_trust,
            last_updated=current_time,
            behavior_history=behavior_history,
            trust_trend=trust_trend,
            risk_level=risk_level,
            risk_score=risk_score,
            asset_type=asset_type,
            asset_criticality=asset_criticality,
            last_incident_type=incident_type,
            last_incident_severity=incident_severity,
        )

        self.trust_records[entity_id] = trust_record
        self._store.save_trust_record(trust_record.to_dict())
        return new_trust

    def get_trust_record(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Get trust record for an entity."""
        with self._lock:
            if entity_id not in self.trust_records:
                return None
            return self.trust_records[entity_id].to_dict()

    def get_all_trust_records(self) -> List[Dict[str, Any]]:
        """Get all trust records."""
        with self._lock:
            return [record.to_dict() for record in self.trust_records.values()]

    def get_entities_by_risk_level(self, risk_level: str) -> List[str]:
        """Get entities filtered by risk level."""
        with self._lock:
            return [
                entity_id
                for entity_id, record in self.trust_records.items()
                if record.risk_level == risk_level
            ]

    def reset_trust_score(self, entity_id: str, new_score: float = 100.0) -> bool:
        """Reset trust score for an entity."""
        with self._lock:
            if entity_id not in self.trust_records:
                return False

            new_score = max(0.0, min(100.0, new_score))
            updated_record = TrustRecord(
                entity_id=entity_id,
                trust_score=new_score,
                last_updated=time.time(),
                behavior_history=[],
                trust_trend="stable",
                risk_level="low",
                risk_score=0.0,
                asset_type=self.trust_records[entity_id].asset_type,
                asset_criticality=self.trust_records[entity_id].asset_criticality,
                last_incident_type="behavior_anomaly",
                last_incident_severity="low",
            )
            self.trust_records[entity_id] = updated_record
            self._store.save_trust_record(updated_record.to_dict())
            return True

    def get_trust_statistics(self) -> Dict[str, Any]:
        """Get overall trust system statistics."""
        with self._lock:
            return self._get_trust_statistics_locked()

    def _get_trust_statistics_locked(self) -> Dict[str, Any]:
        if not self.trust_records:
            return {
                "total_entities": 0,
                "average_trust_score": 0.0,
                "average_risk_score": 0.0,
                "risk_distribution": {},
                "trend_distribution": {},
            }

        trust_scores = [record.trust_score for record in self.trust_records.values()]
        risk_scores = [record.risk_score for record in self.trust_records.values()]
        risk_levels = [record.risk_level for record in self.trust_records.values()]
        trends = [record.trust_trend for record in self.trust_records.values()]

        risk_distribution = {}
        for level in ["low", "medium", "high", "critical"]:
            risk_distribution[level] = risk_levels.count(level)

        trend_distribution = {}
        for trend in ["improving", "declining", "stable"]:
            trend_distribution[trend] = trends.count(trend)

        return {
            "total_entities": len(self.trust_records),
            "average_trust_score": sum(trust_scores) / len(trust_scores),
            "average_risk_score": sum(risk_scores) / len(risk_scores),
            "min_trust_score": min(trust_scores),
            "max_trust_score": max(trust_scores),
            "risk_distribution": risk_distribution,
            "trend_distribution": trend_distribution,
        }


# Global trust manager instance
_trust_manager = TrustManager()


def update_trust_score(
    entity_id: str,
    behavior_score: float,
    current_trust: Optional[float] = None,
    asset_context: Optional[Mapping[str, Any]] = None,
) -> float:
    """
    Update trust score for an entity.
    
    This is the main entry point for the trust system.
    
    Args:
        entity_id: Entity identifier
        behavior_score: Current behavior score [0, 100]
        current_trust: Current trust score (optional)
        asset_context: Optional asset metadata used in risk scoring
        
    Returns:
        Updated trust score
    """
    return _trust_manager.update_trust_score(
        entity_id, behavior_score, current_trust, asset_context
    )


def get_trust_record(entity_id: str) -> Optional[Dict[str, Any]]:
    """Get trust record for an entity."""
    return _trust_manager.get_trust_record(entity_id)


def get_all_trust_records() -> List[Dict[str, Any]]:
    """Get all trust records."""
    return _trust_manager.get_all_trust_records()


def get_entities_by_risk_level(risk_level: str) -> List[str]:
    """Get entities filtered by risk level."""
    return _trust_manager.get_entities_by_risk_level(risk_level)


def reset_trust_score(entity_id: str, new_score: float = 100.0) -> bool:
    """Reset trust score for an entity."""
    return _trust_manager.reset_trust_score(entity_id, new_score)


def get_trust_statistics() -> Dict[str, Any]:
    """Get trust system statistics."""
    return _trust_manager.get_trust_statistics()


def reset_trust_manager() -> None:
    """Reset the cached global trust manager (for tests and controlled reloads)."""
    global _trust_manager
    _trust_manager = TrustManager()


__all__ = [
    "TrustRecord", "TrustManager",
    "update_trust_score", "get_trust_record", "get_all_trust_records",
    "get_entities_by_risk_level", "reset_trust_score", "get_trust_statistics",
    "reset_trust_manager",
]
