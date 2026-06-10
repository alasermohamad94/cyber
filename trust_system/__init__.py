"""
Trust System Module
"""

from .trust_manager import (
    TrustRecord,
    TrustManager,
    update_trust_score,
    get_trust_record,
    get_all_trust_records,
    get_entities_by_risk_level,
    reset_trust_score,
    get_trust_statistics,
    reset_trust_manager,
)

__all__ = [
    "TrustRecord",
    "TrustManager", 
    "update_trust_score",
    "get_trust_record",
    "get_all_trust_records",
    "get_entities_by_risk_level",
    "reset_trust_score",
    "get_trust_statistics",
    "reset_trust_manager",
]

# Make functions available at package level
from .trust_manager import (
    update_trust_score as _update_trust_score,
    get_trust_record as _get_trust_record,
    get_all_trust_records as _get_all_trust_records,
    get_entities_by_risk_level as _get_entities_by_risk_level,
    reset_trust_score as _reset_trust_score,
    get_trust_statistics as _get_trust_statistics,
    reset_trust_manager as _reset_trust_manager,
)

# Expose functions at package level
get_trust_statistics = _get_trust_statistics
get_all_trust_records = _get_all_trust_records
get_trust_record = _get_trust_record
get_entities_by_risk_level = _get_entities_by_risk_level
reset_trust_score = _reset_trust_score
update_trust_score = _update_trust_score
reset_trust_manager = _reset_trust_manager
