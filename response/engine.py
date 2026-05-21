"""
Response Engine Module

This module implements automated response actions for the cyber defense system.
It executes security decisions made by the decision engine.
"""

import threading
import time
import random
from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum

from storage.persistence import get_store


class ResponseStatus(Enum):
    """Response execution status."""
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ResponseAction:
    """
    Response action data structure.
    
    Attributes
    ----------
    action_id:
        Unique identifier for the response action
    entity_id:
        Target entity identifier
    action_type:
        Type of response action
    status:
        Current execution status
    timestamp:
        When the action was initiated
    completion_time:
        When the action was completed (None if not completed)
    details:
        Additional details about the response
    """
    action_id: str
    entity_id: str
    action_type: str
    status: ResponseStatus
    timestamp: float
    completion_time: float
    details: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'action_id': self.action_id,
            'entity_id': self.entity_id,
            'action_type': self.action_type,
            'status': self.status.value,
            'timestamp': self.timestamp,
            'completion_time': self.completion_time,
            'details': self.details
        }


class ResponseExecutor:
    """
    Handles the execution of security response actions.
    
    In a real system, this would interface with actual security infrastructure
    like firewalls, IDS/IPS, endpoint detection systems, etc.
    """
    
    def __init__(self):
        self.active_responses: Dict[str, ResponseAction] = {}
        self.response_history: List[ResponseAction] = []
        self._lock = threading.RLock()
        self._store = get_store()
        self._load_from_store()

    def _load_from_store(self) -> None:
        for row in self._store.list_responses_by_status(
            [s.value for s in ResponseStatus], limit=500
        ):
            action = ResponseAction(
                action_id=row["action_id"],
                entity_id=row["entity_id"],
                action_type=row["action_type"],
                status=ResponseStatus(row["status"]),
                timestamp=row["timestamp"],
                completion_time=row.get("completion_time") or 0.0,
                details=row.get("details", {}),
            )
            self.response_history.append(action)
            if action.status in (ResponseStatus.PENDING, ResponseStatus.EXECUTING):
                self.active_responses[action.action_id] = action

    def _persist_action(self, action: ResponseAction) -> None:
        self._store.save_response_action(action.to_dict())
        
    def _generate_action_id(self) -> str:
        """Generate a unique action ID."""
        return f"resp_{int(time.time())}_{random.randint(1000, 9999)}"
    
    def _execute_monitor_action(self, entity_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a monitoring action."""
        # In a real system, this would adjust monitoring levels, logging, etc.
        return {
            'status': 'completed',
            'message': f"Enhanced monitoring activated for {entity_id}",
            'monitoring_level': 'elevated',
            'log_retention': 'extended'
        }
    
    def _execute_alert_action(self, entity_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an alert action."""
        # In a real system, this would send alerts to SOC, email, SIEM, etc.
        alert_id = f"alert_{int(time.time())}"
        return {
            'status': 'completed',
            'message': f"Security alert generated for {entity_id}",
            'alert_id': alert_id,
            'recipients': ['soc_team', 'security_analysts'],
            'priority': details.get('severity', 'medium')
        }
    
    def _execute_block_action(self, entity_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a blocking action."""
        # In a real system, this would update firewall rules, ACLs, etc.
        block_id = f"block_{int(time.time())}"
        return {
            'status': 'completed',
            'message': f"Blocking action applied to {entity_id}",
            'block_id': block_id,
            'block_type': 'network_access',
            'duration': '3600',  # 1 hour in seconds
            'auto_release': True
        }
    
    def _execute_isolate_action(self, entity_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an isolation action."""
        # In a real system, this would quarantine the endpoint, disable accounts, etc.
        isolate_id = f"isolate_{int(time.time())}"
        return {
            'status': 'completed',
            'message': f"Isolation protocol activated for {entity_id}",
            'isolate_id': isolate_id,
            'isolation_type': 'full_quarantine',
            'affected_systems': ['network', 'applications', 'data_access'],
            'requires_manual_review': True
        }
    
    def execute_action(self, entity_id: str, decision: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a security response action based on the decision.
        
        Args:
            entity_id: Target entity identifier
            decision: Security decision from decision engine
            
        Returns:
            Response result dictionary
        """
        with self._lock:
            return self._execute_action_locked(entity_id, decision)

    def _execute_action_locked(self, entity_id: str, decision: Dict[str, Any]) -> Dict[str, Any]:
        action_type = decision.get('action', 'monitor')
        severity = decision.get('severity', 'low')
        
        # Create response action record
        action_id = self._generate_action_id()
        current_time = time.time()
        
        response_action = ResponseAction(
            action_id=action_id,
            entity_id=entity_id,
            action_type=action_type,
            status=ResponseStatus.EXECUTING,
            timestamp=current_time,
            completion_time=0.0,
            details=decision.copy()
        )
        
        self.active_responses[action_id] = response_action
        self._persist_action(response_action)

        try:
            # Execute the appropriate action
            if action_type == 'monitor':
                result = self._execute_monitor_action(entity_id, decision)
            elif action_type == 'alert':
                result = self._execute_alert_action(entity_id, decision)
            elif action_type == 'block':
                result = self._execute_block_action(entity_id, decision)
            elif action_type == 'isolate':
                result = self._execute_isolate_action(entity_id, decision)
            else:
                raise ValueError(f"Unknown action type: {action_type}")
            
            # Update action status to completed
            completion_time = time.time()
            completed_action = ResponseAction(
                action_id=action_id,
                entity_id=entity_id,
                action_type=action_type,
                status=ResponseStatus.COMPLETED,
                timestamp=current_time,
                completion_time=completion_time,
                details=decision.copy()
            )
            
            self.response_history.append(completed_action)
            self.active_responses.pop(action_id, None)
            self._persist_action(completed_action)
            
            # Add execution details to result
            result.update({
                'action_id': action_id,
                'entity_id': entity_id,
                'action_type': action_type,
                'execution_time': completion_time - current_time,
                'status': 'completed'
            })
            
            return result
            
        except Exception as e:
            # Handle execution failure
            failed_action = ResponseAction(
                action_id=action_id,
                entity_id=entity_id,
                action_type=action_type,
                status=ResponseStatus.FAILED,
                timestamp=current_time,
                completion_time=time.time(),
                details={**decision, 'error': str(e)}
            )
            
            self.active_responses.pop(action_id, None)
            self.response_history.append(failed_action)
            self._persist_action(failed_action)
            
            return {
                'action_id': action_id,
                'entity_id': entity_id,
                'action_type': action_type,
                'status': 'failed',
                'error': str(e),
                'message': f"Failed to execute {action_type} action for {entity_id}"
            }
    
    def get_active_responses(self) -> List[Dict[str, Any]]:
        """Get list of currently active responses."""
        with self._lock:
            return [
                action.to_dict() for action in self.active_responses.values()
                if action.status in [ResponseStatus.PENDING, ResponseStatus.EXECUTING]
            ]

    def get_recent_responses(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Recently completed or failed responses for dashboards."""
        with self._lock:
            recent = [
                a for a in self.response_history
                if a.status in (ResponseStatus.COMPLETED, ResponseStatus.FAILED, ResponseStatus.CANCELLED)
            ]
            return [action.to_dict() for action in recent[-limit:]]

    def get_response_summary(self) -> Dict[str, Any]:
        """Counts for threat/analytics views."""
        with self._lock:
            now = time.time()
            day_start = now - 86400
            active = len(self.active_responses)
            isolated = sum(
                1 for a in self.response_history
                if a.action_type == "isolate"
                and a.status == ResponseStatus.COMPLETED
                and a.timestamp >= day_start
            )
            resolved_today = sum(
                1 for a in self.response_history
                if a.status == ResponseStatus.COMPLETED and a.timestamp >= day_start
            )
            return {
                "active_responses": active,
                "isolated_systems": isolated,
                "resolved_today": resolved_today,
            }

    def get_response_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get response history."""
        with self._lock:
            return [action.to_dict() for action in self.response_history[-limit:]]
    
    def cancel_response(self, action_id: str) -> Dict[str, Any]:
        """Cancel an active response."""
        with self._lock:
            return self._cancel_response_locked(action_id)

    def _cancel_response_locked(self, action_id: str) -> Dict[str, Any]:
        if action_id not in self.active_responses:
            return {
                'status': 'failed',
                'message': f"Action {action_id} not found"
            }
        
        action = self.active_responses[action_id]
        if action.status in [ResponseStatus.COMPLETED, ResponseStatus.FAILED, ResponseStatus.CANCELLED]:
            return {
                'status': 'failed',
                'message': f"Action {action_id} cannot be cancelled (status: {action.status.value})"
            }
        
        # Update to cancelled
        cancelled_action = ResponseAction(
            action_id=action.action_id,
            entity_id=action.entity_id,
            action_type=action.action_type,
            status=ResponseStatus.CANCELLED,
            timestamp=action.timestamp,
            completion_time=time.time(),
            details=action.details
        )
        
        self.active_responses.pop(action_id, None)
        self.response_history.append(cancelled_action)
        self._persist_action(cancelled_action)

        return {
            'status': 'completed',
            'message': f"Action {action_id} cancelled successfully"
        }


# Global response executor instance
_response_executor = ResponseExecutor()


def execute_response(entity_id: str, decision: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a security response action.
    
    This is the main entry point for the response engine.
    
    Args:
        entity_id: Target entity identifier
        decision: Security decision from decision engine
        
    Returns:
        Response execution result
    """
    return _response_executor.execute_action(entity_id, decision)


def get_active_responses() -> List[Dict[str, Any]]:
    """Get currently active response actions."""
    return _response_executor.get_active_responses()


def get_response_history(limit: int = 100) -> List[Dict[str, Any]]:
    """Get response action history."""
    return _response_executor.get_response_history(limit)


def get_recent_responses(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recently finished response actions."""
    return _response_executor.get_recent_responses(limit)


def get_response_summary() -> Dict[str, Any]:
    """Get aggregated response counters."""
    return _response_executor.get_response_summary()


def cancel_response(action_id: str) -> Dict[str, Any]:
    """Cancel an active response action."""
    return _response_executor.cancel_response(action_id)


__all__ = [
    "ResponseAction", "ResponseStatus", "ResponseExecutor",
    "execute_response", "get_active_responses", "get_recent_responses",
    "get_response_summary", "get_response_history", "cancel_response"
]