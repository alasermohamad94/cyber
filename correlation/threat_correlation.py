"""Threat correlation engine for linking related detections into one incident."""

from __future__ import annotations

import hashlib
import time
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional

CORRELATION_WINDOW_SECONDS = 15 * 60

SEVERITY_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


@dataclass(frozen=True)
class ThreatObservation:
    """Single suspicious observation captured from the analysis pipeline."""

    timestamp: float
    entity_id: str
    source_ip: str
    event_type: str
    severity: str
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CorrelatedIncident:
    """Multi-step incident produced by linking multiple observations."""

    correlated: bool
    incident_id: Optional[str]
    incident_type: Optional[str]
    severity: str
    confidence: float
    source_ip: str
    matched_event_types: List[str]
    related_entities: List[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    time_window_seconds: int
    reasoning: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _safe_get_text(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key, "")
    if value is None:
        return ""
    return str(value).strip()


def _safe_get_number(data: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    value = data.get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _extract_behavior_score(behavior_profile: Mapping[str, Any]) -> float:
    """Extract the behavior score from a dict-like object or dataclass."""
    if hasattr(behavior_profile, "behavior_score"):
        value = getattr(behavior_profile, "behavior_score")
    else:
        value = behavior_profile.get("behavior_score", 0.0)
    try:
        return max(0.0, min(100.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _extract_behavior_features(behavior_profile: Mapping[str, Any]) -> Mapping[str, Any]:
    """Extract normalized perception features from a behavior profile."""
    if hasattr(behavior_profile, "features"):
        features = getattr(behavior_profile, "features")
    else:
        features = behavior_profile.get("features", {})
    if isinstance(features, Mapping):
        return features
    return {}


def _extract_anomaly_level(behavior_profile: Mapping[str, Any]) -> str:
    """Extract the anomaly level from a profile."""
    if hasattr(behavior_profile, "anomaly_level"):
        return str(getattr(behavior_profile, "anomaly_level") or "low")
    return str(behavior_profile.get("anomaly_level", "low") or "low")


class ThreatCorrelationEngine:
    """Stateful rule engine that links related detections into one incident."""

    def __init__(
        self,
        correlation_window_seconds: int = CORRELATION_WINDOW_SECONDS,
        max_observations: int = 1000,
    ) -> None:
        self.correlation_window_seconds = int(max(60, correlation_window_seconds))
        self._observations: Deque[ThreatObservation] = deque(maxlen=max_observations)

    def analyze(
        self,
        entity_id: str,
        entity_data: Mapping[str, Any],
        behavior_profile: Mapping[str, Any],
        analysis_timestamp: Optional[float] = None,
    ) -> CorrelatedIncident:
        """
        Record the current suspicious observation and try to correlate it.

        The core rule implemented for this project is:
        distributed scan -> targeted brute force from the same IP within 15 minutes
        which produces one combined incident automatically.
        """

        timestamp = float(analysis_timestamp or time.time())
        source_ip = _safe_get_text(entity_data, "source_ip")
        event_type = self._resolve_event_type(entity_data, behavior_profile)
        severity = self._resolve_severity(entity_data, behavior_profile, event_type)
        confidence = self._resolve_confidence(entity_data, behavior_profile, event_type)

        observation = ThreatObservation(
            timestamp=timestamp,
            entity_id=entity_id,
            source_ip=source_ip,
            event_type=event_type,
            severity=severity,
            confidence=confidence,
        )

        related_observations = self._find_related_observations(source_ip, timestamp)
        correlated_incident = self._build_correlated_incident(observation, related_observations)

        self._observations.append(observation)
        self._prune_old_observations(timestamp)
        return correlated_incident

    def _prune_old_observations(self, now: float) -> None:
        cutoff = now - self.correlation_window_seconds
        while self._observations and self._observations[0].timestamp < cutoff:
            self._observations.popleft()

    def _find_related_observations(
        self, source_ip: str, now: float
    ) -> List[ThreatObservation]:
        if not source_ip:
            return []

        cutoff = now - self.correlation_window_seconds
        return [
            observation
            for observation in self._observations
            if observation.source_ip == source_ip and observation.timestamp >= cutoff
        ]

    def _resolve_event_type(
        self,
        entity_data: Mapping[str, Any],
        behavior_profile: Mapping[str, Any],
    ) -> str:
        explicit_incident_type = _safe_get_text(entity_data, "incident_type").lower()
        if explicit_incident_type in {
            "distributed_scan",
            "targeted_brute_force",
            "data_exfiltration",
        }:
            return explicit_incident_type

        features = _extract_behavior_features(behavior_profile)
        distributed_scan_signal = _safe_get_number(features, "distributed_scan_signal")
        targeted_brute_force_signal = _safe_get_number(
            features, "targeted_brute_force_signal"
        )
        exfiltration_signal = _safe_get_number(features, "exfiltration_signal")

        if exfiltration_signal >= 0.75:
            return "data_exfiltration"
        if targeted_brute_force_signal >= 0.75:
            return "targeted_brute_force"
        if distributed_scan_signal >= 0.70:
            return "distributed_scan"
        return "behavior_anomaly"

    def _resolve_severity(
        self,
        entity_data: Mapping[str, Any],
        behavior_profile: Mapping[str, Any],
        event_type: str,
    ) -> str:
        explicit_severity = _safe_get_text(entity_data, "incident_severity").lower()
        if explicit_severity in SEVERITY_ORDER:
            return explicit_severity

        anomaly_level = _extract_anomaly_level(behavior_profile).lower()
        if anomaly_level in SEVERITY_ORDER:
            return anomaly_level

        if event_type == "data_exfiltration":
            return "critical"
        if event_type == "targeted_brute_force":
            return "high"
        if event_type == "distributed_scan":
            return "medium"
        return "low"

    def _resolve_confidence(
        self,
        entity_data: Mapping[str, Any],
        behavior_profile: Mapping[str, Any],
        event_type: str,
    ) -> float:
        features = _extract_behavior_features(behavior_profile)
        behavior_score = _extract_behavior_score(behavior_profile)

        signal_by_event = {
            "distributed_scan": _safe_get_number(features, "distributed_scan_signal"),
            "targeted_brute_force": _safe_get_number(
                features, "targeted_brute_force_signal"
            ),
            "data_exfiltration": _safe_get_number(features, "exfiltration_signal"),
        }

        explicit_confidence = _safe_get_number(entity_data, "detection_confidence", -1.0)
        if explicit_confidence >= 0.0:
            return max(0.0, min(1.0, explicit_confidence))

        signal_confidence = signal_by_event.get(event_type, behavior_score / 100.0)
        return max(0.0, min(1.0, signal_confidence))

    def _build_correlated_incident(
        self,
        observation: ThreatObservation,
        related_observations: Iterable[ThreatObservation],
    ) -> CorrelatedIncident:
        all_observations = list(related_observations) + [observation]
        matched_event_types = self._ordered_event_types(all_observations)
        related_entities = self._ordered_entities(all_observations)

        if not observation.source_ip:
            return CorrelatedIncident(
                correlated=False,
                incident_id=None,
                incident_type=None,
                severity=observation.severity,
                confidence=observation.confidence,
                source_ip="",
                matched_event_types=matched_event_types,
                related_entities=related_entities,
                first_seen=None,
                last_seen=observation.timestamp,
                time_window_seconds=self.correlation_window_seconds,
                reasoning="No correlation was created because the source IP is missing.",
            )

        if self._has_sequence(
            all_observations,
            ["distributed_scan", "targeted_brute_force", "data_exfiltration"],
        ):
            return self._create_incident(
                all_observations,
                incident_type="multi_stage_attack",
                severity="critical",
                reasoning=(
                    "Correlated distributed scan, targeted brute force, and data exfiltration "
                    "from the same source IP within the active window."
                ),
            )

        if self._has_sequence(
            all_observations,
            ["distributed_scan", "targeted_brute_force"],
        ):
            return self._create_incident(
                all_observations,
                incident_type="recon_to_initial_access",
                severity="high",
                reasoning=(
                    "Correlated distributed scan followed by targeted brute force "
                    "from the same source IP within 15 minutes."
                ),
            )

        if self._has_sequence(
            all_observations,
            ["targeted_brute_force", "data_exfiltration"],
        ):
            return self._create_incident(
                all_observations,
                incident_type="credential_compromise_exfiltration",
                severity="critical",
                reasoning=(
                    "Correlated targeted brute force followed by data exfiltration "
                    "from the same source IP within the active window."
                ),
            )

        return CorrelatedIncident(
            correlated=False,
            incident_id=None,
            incident_type=None,
            severity=observation.severity,
            confidence=observation.confidence,
            source_ip=observation.source_ip,
            matched_event_types=matched_event_types,
            related_entities=related_entities,
            first_seen=all_observations[0].timestamp if all_observations else None,
            last_seen=observation.timestamp,
            time_window_seconds=self.correlation_window_seconds,
            reasoning="No matching multi-stage threat pattern was found in the active window.",
        )

    def _ordered_event_types(
        self, observations: Iterable[ThreatObservation]
    ) -> List[str]:
        ordered_types: List[str] = []
        for observation in sorted(observations, key=lambda item: item.timestamp):
            if observation.event_type not in ordered_types:
                ordered_types.append(observation.event_type)
        return ordered_types

    def _ordered_entities(self, observations: Iterable[ThreatObservation]) -> List[str]:
        ordered_entities: List[str] = []
        for observation in sorted(observations, key=lambda item: item.timestamp):
            if observation.entity_id not in ordered_entities:
                ordered_entities.append(observation.entity_id)
        return ordered_entities

    def _has_sequence(
        self, observations: Iterable[ThreatObservation], expected_sequence: List[str]
    ) -> bool:
        sorted_events = sorted(observations, key=lambda item: item.timestamp)
        cursor = 0
        for observation in sorted_events:
            if observation.event_type == expected_sequence[cursor]:
                cursor += 1
                if cursor == len(expected_sequence):
                    return True
        return False

    def _create_incident(
        self,
        observations: List[ThreatObservation],
        incident_type: str,
        severity: str,
        reasoning: str,
    ) -> CorrelatedIncident:
        ordered_observations = sorted(observations, key=lambda item: item.timestamp)
        matched_event_types = self._ordered_event_types(ordered_observations)
        related_entities = self._ordered_entities(ordered_observations)
        confidence = max(
            0.0,
            min(
                1.0,
                sum(item.confidence for item in ordered_observations)
                / max(1, len(ordered_observations)),
            ),
        )
        confidence = round(max(confidence, 0.75), 2)
        first_seen = ordered_observations[0].timestamp
        last_seen = ordered_observations[-1].timestamp
        incident_id = self._build_incident_id(
            incident_type,
            ordered_observations[0].source_ip,
            first_seen,
            last_seen,
            matched_event_types,
        )

        # نجمع عدة أحداث مترابطة في incident واحدة قابلة للعرض في الواجهة لاحقاً.
        return CorrelatedIncident(
            correlated=True,
            incident_id=incident_id,
            incident_type=incident_type,
            severity=self._max_severity(severity, ordered_observations),
            confidence=confidence,
            source_ip=ordered_observations[0].source_ip,
            matched_event_types=matched_event_types,
            related_entities=related_entities,
            first_seen=first_seen,
            last_seen=last_seen,
            time_window_seconds=self.correlation_window_seconds,
            reasoning=reasoning,
        )

    def _max_severity(
        self, base_severity: str, observations: Iterable[ThreatObservation]
    ) -> str:
        severity = base_severity if base_severity in SEVERITY_ORDER else "low"
        highest_rank = SEVERITY_ORDER[severity]
        for observation in observations:
            rank = SEVERITY_ORDER.get(observation.severity, 0)
            if rank > highest_rank:
                highest_rank = rank
                severity = observation.severity
        return severity

    def _build_incident_id(
        self,
        incident_type: str,
        source_ip: str,
        first_seen: float,
        last_seen: float,
        matched_event_types: List[str],
    ) -> str:
        raw_value = (
            f"{incident_type}|{source_ip}|{int(first_seen)}|{int(last_seen)}|"
            f"{','.join(matched_event_types)}"
        )
        digest = hashlib.sha1(raw_value.encode("utf-8")).hexdigest()[:12]
        return f"corr_{digest}"


__all__ = [
    "CORRELATION_WINDOW_SECONDS",
    "CorrelatedIncident",
    "ThreatCorrelationEngine",
    "ThreatObservation",
]
