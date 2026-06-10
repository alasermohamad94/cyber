"""
Trust System Module

This module manages trust scores and risk scores for entities in the cyber
defense system.
"""

import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from storage.persistence import get_store


RISK_SEVERITY_BONUS = {
    "low": 0.0,
    "medium": 7.0,
    "high": 15.0,
    "critical": 24.0,
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
    """

    entity_id: str
    trust_score: float
    last_updated: float
    behavior_history: List[float]
    trust_trend: str
    risk_level: str
    risk_score: float = 0.0

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
        }


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
        self.decay_rate = 0.95
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
            )

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

    def _apply_time_decay(self, trust_score: float, last_updated: float) -> float:
        """Apply a mild time-based decay to the trust score."""
        current_time = time.time()
        days_since_update = (current_time - last_updated) / (24 * 3600)

        if days_since_update < 1:
            return trust_score

        decayed_score = trust_score * (self.decay_rate ** days_since_update)
        return max(0.0, min(100.0, decayed_score))

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
        self, behavior_score: float, behavior_history: List[float]
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

        risk_score = behavior_score * 0.7 + severity_bonus + history_pressure
        return max(0.0, min(100.0, risk_score))

    def _calculate_trust_adjustment(
        self, risk_score: float, current_trust: float
    ) -> float:
        """
        Adjust trust according to the current risk score.

        This is intentionally simple in the first task; later tasks can inject
        asset criticality and rule-based incident decay without changing callers.
        """
        if risk_score < 20:
            adjustment = self.positive_boost
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

        return adjustment * trust_multiplier

    def update_trust_score(
        self,
        entity_id: str,
        behavior_score: float,
        current_trust: Optional[float] = None,
    ) -> float:
        """Update trust score for an entity based on the computed risk."""
        with self._lock:
            return self._update_trust_score_locked(
                entity_id, behavior_score, current_trust
            )

    def _update_trust_score_locked(
        self,
        entity_id: str,
        behavior_score: float,
        current_trust: Optional[float] = None,
    ) -> float:
        current_time = time.time()
        behavior_score = max(0.0, min(100.0, float(behavior_score)))

        if current_trust is None:
            if entity_id in self.trust_records:
                current_trust = self.trust_records[entity_id].trust_score
            else:
                current_trust = 100.0

        if entity_id in self.trust_records:
            current_trust = self._apply_time_decay(
                current_trust,
                self.trust_records[entity_id].last_updated,
            )
            behavior_history = self.trust_records[entity_id].behavior_history.copy()
        else:
            behavior_history = []

        behavior_history.append(behavior_score)
        if len(behavior_history) > self.max_history_length:
            behavior_history = behavior_history[-self.max_history_length:]

        risk_score = self._calculate_risk_score(behavior_score, behavior_history)
        adjustment = self._calculate_trust_adjustment(risk_score, current_trust)
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
) -> float:
    """
    Update trust score for an entity.
    
    This is the main entry point for the trust system.
    
    Args:
        entity_id: Entity identifier
        behavior_score: Current behavior score [0, 100]
        current_trust: Current trust score (optional)
        
    Returns:
        Updated trust score
    """
    return _trust_manager.update_trust_score(entity_id, behavior_score, current_trust)


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
