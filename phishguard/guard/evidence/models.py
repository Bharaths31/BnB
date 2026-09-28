"""Unified evidence representation shared by all detection modules (WS11).

No detector communicates with the explainer or the dashboard through free text.
Every detector emits :class:`Evidence` objects; the fusion engine preserves them and the
explanation engine may only render facts that exist as evidence.

This module has **no dependency on the rest of the application** so it can be imported
from anywhere without creating import cycles.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Optional

from pydantic import BaseModel, Field


class EvidenceCategory(str, Enum):
    """The 13 evidence categories required by the specification."""

    HEADER = "HEADER"
    AUTHENTICATION = "AUTHENTICATION"
    TEXT = "TEXT"
    TACTIC = "TACTIC"
    URL = "URL"
    HTML = "HTML"
    ATTACHMENT = "ATTACHMENT"
    IMAGE = "IMAGE"
    QR = "QR"
    BEHAVIOR = "BEHAVIOR"
    GRAPH = "GRAPH"
    CAMPAIGN = "CAMPAIGN"
    CONSISTENCY = "CONSISTENCY"
    THREAT_INTEL = "THREAT_INTEL"


#: Relative weight of each severity bucket when ranking evidence.
SEVERITY_WEIGHTS = {
    "info": 0.0,
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}

#: How much we trust the emitting module's judgement.
CONFIDENCE_WEIGHTS = {
    "low": 0.4,
    "medium": 0.75,
    "high": 1.0,
}


def severity_from_score(score: float) -> str:
    """Map a normalised ``[0, 1]`` risk contribution to a severity label."""
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def make_evidence_id(category: str, feature: str, value: str, source_module: str) -> str:
    """Deterministic evidence id.

    Using a hash (instead of a random UUID) keeps the whole pipeline reproducible: the same
    email always produces the same evidence ids, which makes explanations auditable and
    snapshot-testable.
    """
    raw = f"{category}|{feature}|{value}|{source_module}"
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


class Evidence(BaseModel):
    """A single, atomic, machine-readable observation from one detector."""

    evidence_id: str = ""
    category: EvidenceCategory
    feature: str
    value: str
    normalized_score: float = 0.0
    severity: str = "info"
    confidence: str = "medium"
    source_module: str = ""
    timestamp: datetime = Field(default_factory=_utcnow)
    related_entity: Optional[str] = None
    explanation_key: str = ""

    def model_post_init(self, __context) -> None:  # type: ignore[override]
        if not self.evidence_id:
            self.evidence_id = make_evidence_id(
                self.category.value, self.feature, str(self.value), self.source_module
            )
        if not self.explanation_key:
            self.explanation_key = self.feature

    @property
    def rank_score(self) -> float:
        """Deterministic value used to rank evidence for the explanation."""
        sev = SEVERITY_WEIGHTS.get(self.severity, 0.0)
        conf = CONFIDENCE_WEIGHTS.get(self.confidence, 0.5)
        return round(float(self.normalized_score) * sev * conf, 6)

    @classmethod
    def of(
        cls,
        category: EvidenceCategory,
        feature: str,
        value,
        normalized_score: float,
        source_module: str,
        *,
        severity: Optional[str] = None,
        confidence: str = "medium",
        related_entity: Optional[str] = None,
        explanation_key: Optional[str] = None,
    ) -> "Evidence":
        """Convenience constructor used throughout the detectors."""
        score = max(0.0, min(1.0, float(normalized_score)))
        return cls(
            category=category,
            feature=feature,
            value=str(value),
            normalized_score=score,
            severity=severity or severity_from_score(score),
            confidence=confidence,
            source_module=source_module,
            related_entity=related_entity,
            explanation_key=explanation_key or feature,
        )
