"""
Trust System Module

This module manages trust scores for entities in the cyber defense system.
Trust scores are updated based on behavior analysis and historical patterns.
"""

import threading
import time
from typing import Dict, Any, List
from dataclasses import dataclass

from storage.persistence import get_store


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
        Current risk level based on trust score
    """
    entity_id: str
    trust_score: float
    last_updated: float
    behavior_history: List[float]
    trust_trend: str
    risk_level: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'entity_id': self.entity_id,
            'trust_score': self.trust_score,
            'last_updated': self.last_updated,
            'behavior_history': self.behavior_history,
            'trust_trend': self.trust_trend,
            'risk_level': self.risk_level
        }


class TrustManager:
    """
    Manages trust scores and trust-related operations for entities.
    
    The trust system uses a combination of:
    - Current behavior analysis
    - Historical behavior patterns
    - Time-based decay
    - Positive reinforcement for good behavior
    """
    
    def __init__(self):
        self.trust_records: Dict[str, TrustRecord] = {}
        self._lock = threading.RLock()
        self._store = get_store()
        self.max_history_length = 20
        self.decay_rate = 0.95  # Daily decay factor
        self.positive_boost = 2.0  # Trust boost for good behavior
        self.negative_penalty = 5.0  # Trust penalty for bad behavior
        self._load_from_store()

    def _load_from_store(self) -> None:
        for record in self._store.load_all_trust_records():
            self.trust_records[record["entity_id"]] = TrustRecord(
                entity_id=record["entity_id"],
                trust_score=record["trust_score"],
                last_updated=record["last_updated"],
                behavior_history=record.get("behavior_history", []),
                trust_trend=record.get("trust_trend", "stable"),
                risk_level=record.get("risk_level", "low"),
            )
        
    def _calculate_risk_level(self, trust_score: float) -> str:
        """
        Calculate risk level based on trust score.
        
        Args:
            trust_score: Trust score [0, 100]
            
        Returns:
            Risk level string
        """
        if trust_score >= 80:
            return 'low'
        elif trust_score >= 60:
            return 'medium'
        elif trust_score >= 40:
            return 'high'
        else:
            return 'critical'
    
    def _calculate_trust_trend(self, behavior_history: List[float]) -> str:
        """
        Calculate trust trend based on behavior history.
        
        Args:
            behavior_history: List of recent behavior scores
            
        Returns:
            Trend string: 'improving', 'declining', 'stable'
        """
        if len(behavior_history) < 3:
            return 'stable'
        
        # Calculate trend using linear regression on recent scores
        recent_scores = behavior_history[-5:]  # Last 5 scores
        if len(recent_scores) < 3:
            return 'stable'
        
        # Simple trend calculation
        avg_first_half = sum(recent_scores[:len(recent_scores)//2]) / (len(recent_scores)//2)
        avg_second_half = sum(recent_scores[len(recent_scores)//2:]) / (len(recent_scores) - len(recent_scores)//2)
        
        difference = avg_second_half - avg_first_half
        
        if difference > 5:
            return 'improving'
        elif difference < -5:
            return 'declining'
        else:
            return 'stable'
    
    def _apply_time_decay(self, trust_score: float, last_updated: float) -> float:
        """
        Apply time-based decay to trust score.
        
        Args:
            trust_score: Current trust score
            last_updated: Last update timestamp
            
        Returns:
            Decayed trust score
        """
        current_time = time.time()
        days_since_update = (current_time - last_updated) / (24 * 3600)
        
        if days_since_update < 1:
            return trust_score
        
        # Apply exponential decay
        decayed_score = trust_score * (self.decay_rate ** days_since_update)
        return max(0.0, min(100.0, decayed_score))
    
    def _calculate_trust_adjustment(self, behavior_score: float, current_trust: float) -> float:
        """
        Calculate trust score adjustment based on behavior.
        
        Args:
            behavior_score: Current behavior score [0, 100]
            current_trust: Current trust score [0, 100]
            
        Returns:
            Trust adjustment amount (positive or negative)
        """
        # Convert behavior score to trust impact
        # Lower behavior scores are better (less suspicious)
        if behavior_score < 20:
            # Very good behavior - positive reinforcement
            adjustment = self.positive_boost
        elif behavior_score < 40:
            # Good behavior - small positive
            adjustment = self.positive_boost * 0.5
        elif behavior_score < 60:
            # Suspicious behavior - small negative
            adjustment = -self.negative_penalty * 0.3
        elif behavior_score < 80:
            # Very suspicious behavior - moderate negative
            adjustment = -self.negative_penalty * 0.7
        else:
            # Extremely suspicious behavior - strong negative
            adjustment = -self.negative_penalty
        
        # Scale adjustment based on current trust level
        # High-trust entities get more benefit from good behavior
        # Low-trust entities get penalized more for bad behavior
        if adjustment > 0:  # Positive adjustment
            trust_multiplier = 1.0 + (current_trust / 100.0) * 0.5
        else:  # Negative adjustment
            trust_multiplier = 1.0 + ((100 - current_trust) / 100.0) * 0.5
        
        return adjustment * trust_multiplier
    
    def update_trust_score(self, entity_id: str, behavior_score: float, 
                          current_trust: float = None) -> float:
        """
        Update trust score for an entity based on behavior analysis.
        
        Args:
            entity_id: Entity identifier
            behavior_score: Current behavior score [0, 100]
            current_trust: Current trust score (if None, will fetch from records)
            
        Returns:
            Updated trust score
        """
        with self._lock:
            return self._update_trust_score_locked(
                entity_id, behavior_score, current_trust
            )

    def _update_trust_score_locked(
        self, entity_id: str, behavior_score: float, current_trust: float = None
    ) -> float:
        current_time = time.time()
        
        # Get current trust score
        if current_trust is None:
            if entity_id in self.trust_records:
                current_trust = self.trust_records[entity_id].trust_score
            else:
                current_trust = 100.0  # Default to full trust for new entities
        
        # Apply time decay if this is an existing entity
        if entity_id in self.trust_records:
            current_trust = self._apply_time_decay(
                current_trust, 
                self.trust_records[entity_id].last_updated
            )
        
        # Calculate trust adjustment
        adjustment = self._calculate_trust_adjustment(behavior_score, current_trust)
        
        # Apply adjustment
        new_trust = current_trust + adjustment
        
        # Clamp to valid range
        new_trust = max(0.0, min(100.0, new_trust))
        
        # Update behavior history
        if entity_id in self.trust_records:
            behavior_history = self.trust_records[entity_id].behavior_history.copy()
        else:
            behavior_history = []
        
        behavior_history.append(behavior_score)
        
        # Limit history length
        if len(behavior_history) > self.max_history_length:
            behavior_history = behavior_history[-self.max_history_length:]
        
        # Calculate trend and risk level
        trust_trend = self._calculate_trust_trend(behavior_history)
        risk_level = self._calculate_risk_level(new_trust)
        
        # Create and store trust record
        trust_record = TrustRecord(
            entity_id=entity_id,
            trust_score=new_trust,
            last_updated=current_time,
            behavior_history=behavior_history,
            trust_trend=trust_trend,
            risk_level=risk_level
        )
        
        self.trust_records[entity_id] = trust_record
        self._store.save_trust_record(trust_record.to_dict())

        return new_trust

    def get_trust_record(self, entity_id: str) -> Dict[str, Any]:
        """
        Get trust record for an entity.
        
        Args:
            entity_id: Entity identifier
            
        Returns:
            Trust record dictionary or None if not found
        """
        with self._lock:
            if entity_id not in self.trust_records:
                return None
            return self.trust_records[entity_id].to_dict()

    def get_all_trust_records(self) -> List[Dict[str, Any]]:
        """Get all trust records."""
        with self._lock:
            return [record.to_dict() for record in self.trust_records.values()]
    
    def get_entities_by_risk_level(self, risk_level: str) -> List[str]:
        """
        Get entities filtered by risk level.
        
        Args:
            risk_level: Risk level to filter by
            
        Returns:
            List of entity IDs with the specified risk level
        """
        with self._lock:
            return [
                entity_id for entity_id, record in self.trust_records.items()
                if record.risk_level == risk_level
            ]
    
    def reset_trust_score(self, entity_id: str, new_score: float = 100.0) -> bool:
        """
        Reset trust score for an entity.
        
        Args:
            entity_id: Entity identifier
            new_score: New trust score [0, 100]
            
        Returns:
            True if successful, False if entity not found
        """
        with self._lock:
            if entity_id not in self.trust_records:
                return False

            new_score = max(0.0, min(100.0, new_score))
            updated_record = TrustRecord(
                entity_id=entity_id,
                trust_score=new_score,
                last_updated=time.time(),
                behavior_history=[],
                trust_trend='stable',
                risk_level=self._calculate_risk_level(new_score)
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
                'total_entities': 0,
                'average_trust_score': 0.0,
                'risk_distribution': {},
                'trend_distribution': {}
            }
        
        trust_scores = [record.trust_score for record in self.trust_records.values()]
        risk_levels = [record.risk_level for record in self.trust_records.values()]
        trends = [record.trust_trend for record in self.trust_records.values()]
        
        # Calculate distributions
        risk_distribution = {}
        for level in ['low', 'medium', 'high', 'critical']:
            risk_distribution[level] = risk_levels.count(level)
        
        trend_distribution = {}
        for trend in ['improving', 'declining', 'stable']:
            trend_distribution[trend] = trends.count(trend)
        
        return {
            'total_entities': len(self.trust_records),
            'average_trust_score': sum(trust_scores) / len(trust_scores),
            'min_trust_score': min(trust_scores),
            'max_trust_score': max(trust_scores),
            'risk_distribution': risk_distribution,
            'trend_distribution': trend_distribution
        }


# Global trust manager instance
_trust_manager = TrustManager()


def update_trust_score(entity_id: str, behavior_score: float, current_trust: float = None) -> float:
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


def get_trust_record(entity_id: str) -> Dict[str, Any]:
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


__all__ = [
    "TrustRecord", "TrustManager",
    "update_trust_score", "get_trust_record", "get_all_trust_records",
    "get_entities_by_risk_level", "reset_trust_score", "get_trust_statistics"
]