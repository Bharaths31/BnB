"""Unified evidence representation (WS11)."""
from guard.evidence.models import (
    CONFIDENCE_WEIGHTS,
    SEVERITY_WEIGHTS,
    Evidence,
    EvidenceCategory,
    make_evidence_id,
    severity_from_score,
)
from guard.evidence.collector import EvidenceCollector

__all__ = [
    "Evidence",
    "EvidenceCategory",
    "EvidenceCollector",
    "SEVERITY_WEIGHTS",
    "CONFIDENCE_WEIGHTS",
    "make_evidence_id",
    "severity_from_score",
]
