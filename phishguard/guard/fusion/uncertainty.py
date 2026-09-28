"""Component-agreement / uncertainty estimation for fusion (WS7).

Distinguishes "many components strongly agree" from "one component fires and the rest are
quiet" — the two must not be treated identically. Agreeing components raise confidence;
disagreeing ones raise uncertainty and can route a high-risk prediction to REVIEW instead of
an automatic BLOCK.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean
from typing import Dict, List, Tuple

#: The eight logical components tracked for agreement.
COMPONENTS: List[str] = [
    "text", "url", "headers", "html", "behavioral", "attachment", "graph", "consistency",
]

BEHAVIORAL_FEATURES = {
    "sender_newness_score", "sender_frequency_anomaly", "sender_time_anomaly",
    "sender_domain_change_score", "sender_replyto_anomaly", "sender_url_behavior_anomaly",
    "sender_attachment_anomaly", "sender_authentication_anomaly",
    "recipient_relationship_newness", "recipient_relationship_anomaly",
    "display_name_history_anomaly", "communication_pattern_anomaly",
}
CONSISTENCY_FEATURES = {
    "display_href_mismatch", "display_domain_mismatch", "sender_identity_mismatch",
    "replyto_identity_mismatch", "brand_domain_mismatch", "text_url_semantic_mismatch",
    "ocr_url_mismatch", "qr_context_mismatch", "subject_body_mismatch",
    "attachment_context_mismatch", "brand_visual_domain_mismatch", "identity_history_mismatch",
}
INTENT_DERIVED = {
    "credential_harvesting_score", "financial_fraud_score", "account_takeover_score",
    "business_email_compromise_score", "malicious_attachment_score", "social_engineering_score",
}


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


@dataclass
class UncertaintyReport:
    uncertainty_score: float = 0.0
    prediction_confidence: float = 0.0
    decision_margin: float = 0.0
    component_agreement: float = 1.0
    component_disagreement: float = 0.0
    evidence_count: int = 0
    component_risks: Dict[str, float] = field(default_factory=dict)
    missing_components: List[str] = field(default_factory=list)


def extract_component_risks(component_scores: Dict[str, float]) -> Tuple[Dict[str, float], List[str]]:
    """Reduce a flat feature dict to one risk scalar per logical component."""
    risks: Dict[str, float] = {}

    def add(name: str, value: float) -> None:
        risks[name] = max(risks.get(name, 0.0), _clamp(value))

    if "text" in component_scores:
        add("text", component_scores["text"])
    if "headers_anomaly_count" in component_scores:
        add("headers", component_scores["headers_anomaly_count"] / 6.0)

    for key, value in component_scores.items():
        if key == "html.html_risk_score":
            add("html", value)
        elif key == "attachment.attachment_risk_score":
            add("attachment", value)
        elif key == "graph.graph_risk_score":
            add("graph", value)
        elif key == "campaign.campaign_membership_score":
            add("campaign", value)
        elif key.startswith("url.") and any(t in key for t in ("risk", "p_url", "prob", "suspicious")):
            add("url", value)
        elif key.startswith("behavioral.") and key.split(".", 1)[1] in BEHAVIORAL_FEATURES:
            add("behavioral", value)
        elif key.startswith("consistency.") and key.split(".", 1)[1] in CONSISTENCY_FEATURES:
            add("consistency", value)
        elif key.startswith("intent.") and key.split(".", 1)[1] in INTENT_DERIVED:
            add("intent", value)

    missing = [name for name in COMPONENTS if name not in risks]
    return risks, missing


def compute_uncertainty(
    risks: Dict[str, float],
    calibrated_probability: float,
    evidence_count: int = 0,
    missing: List[str] = None,
) -> UncertaintyReport:
    missing = list(missing or [])
    values = sorted(risks.values())

    if len(values) >= 2:
        centre = mean(values)
        mad = mean(abs(v - centre) for v in values)
        disagreement = _clamp(2.0 * mad)  # MAD of 0.5 (max) -> 1.0
    else:
        disagreement = 0.0

    missing_ratio = len(missing) / len(COMPONENTS)
    margin = _clamp(abs(calibrated_probability - 0.5) * 2.0)

    uncertainty = _clamp(0.70 * disagreement + 0.20 * missing_ratio + 0.10 * (1.0 - margin))
    confidence = _clamp(max(calibrated_probability, 1.0 - calibrated_probability) * (1.0 - 0.5 * uncertainty))

    return UncertaintyReport(
        uncertainty_score=round(uncertainty, 4),
        prediction_confidence=round(confidence, 4),
        decision_margin=round(margin, 4),
        component_agreement=round(1.0 - disagreement, 4),
        component_disagreement=round(disagreement, 4),
        evidence_count=int(evidence_count),
        component_risks={k: round(v, 4) for k, v in risks.items()},
        missing_components=missing,
    )


__all__ = [
    "COMPONENTS",
    "UncertaintyReport",
    "extract_component_risks",
    "compute_uncertainty",
]
