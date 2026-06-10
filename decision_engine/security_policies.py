"""
Configurable security policies with time, asset, and identity conditions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Mapping, Optional


@dataclass(frozen=True)
class SecurityPolicy:
    policy_id: str
    name: str
    action_override: str
    severity: str
    priority: int
    description: str
    conditions: Dict[str, Any]


def _in_business_hours() -> bool:
    now = datetime.now()
    return 8 <= now.hour < 18 and now.weekday() < 5


def _after_hours() -> bool:
    return not _in_business_hours()


POLICY_CONDITION_CHECKS: Dict[str, Callable[[Mapping[str, Any]], bool]] = {
    "after_hours": lambda _ctx: _after_hours(),
    "business_hours": lambda _ctx: _in_business_hours(),
    "sensitive_asset": lambda ctx: ctx.get("asset_type") in {"database_server", "web_server"}
    and ctx.get("asset_criticality", 1.0) >= 2.0,
    "database_server": lambda ctx: ctx.get("asset_type") == "database_server",
    "external_connection_attempt": lambda ctx: bool(ctx.get("external_connection")),
}


SECURITY_POLICIES: List[SecurityPolicy] = [
    SecurityPolicy(
        policy_id="after_hours_sensitive_block",
        name="حظر الاتصال الخارجي بعد ساعات العمل",
        action_override="block",
        severity="high",
        priority=85,
        description="Sensitive servers must not accept external connections after business hours.",
        conditions={"after_hours": True, "sensitive_asset": True, "external_connection_attempt": True},
    ),
    SecurityPolicy(
        policy_id="database_isolate_guard",
        name="حماية خوادم قواعد البيانات",
        action_override="isolate",
        severity="critical",
        priority=95,
        description="Database servers require isolation on critical correlated attacks.",
        conditions={"database_server": True},
    ),
]


def evaluate_security_policies(context: Mapping[str, Any]) -> List[SecurityPolicy]:
    """Return policies whose conditions all match the given context."""
    matched: List[SecurityPolicy] = []
    for policy in SECURITY_POLICIES:
        if all(
            POLICY_CONDITION_CHECKS.get(key, lambda _c: False)(context)
            for key in policy.conditions
            if policy.conditions.get(key)
        ):
            matched.append(policy)
    return sorted(matched, key=lambda p: p.priority, reverse=True)


def apply_policy_overrides(
    base_action: str,
    base_severity: str,
    context: Mapping[str, Any],
) -> Dict[str, Any]:
    """Apply highest-priority matching policy override to base decision."""
    matched = evaluate_security_policies(context)
    if not matched:
        return {
            "action": base_action,
            "severity": base_severity,
            "policy_applied": None,
            "matched_policies": [],
        }
    top = matched[0]
    action_rank = {"monitor": 0, "alert": 1, "block": 2, "isolate": 3}
    final_action = base_action
    if action_rank.get(top.action_override, 0) > action_rank.get(base_action, 0):
        final_action = top.action_override
    return {
        "action": final_action,
        "severity": top.severity if top.severity else base_severity,
        "policy_applied": top.policy_id,
        "matched_policies": [p.policy_id for p in matched],
        "policy_description": top.description,
    }


CRITICAL_ASSET_TYPES = {"database_server"}


def requires_two_man_approval(action: str, asset_type: str) -> bool:
    """Critical assets require dual admin approval for isolate/block."""
    return action in {"isolate", "block"} and asset_type in CRITICAL_ASSET_TYPES


__all__ = [
    "SecurityPolicy",
    "SECURITY_POLICIES",
    "evaluate_security_policies",
    "apply_policy_overrides",
    "requires_two_man_approval",
]
