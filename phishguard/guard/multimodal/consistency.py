"""Cross-modal consistency engine (WS2).

Combines identity, link and semantic consistency into the 12 required features and a
contradiction score that grows with the number of *independent* modalities that disagree. No
generative model is involved: everything is deterministic string/statistical analysis.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from guard.component import AnalysisContext, ComponentResult
from guard.evidence import Evidence
from guard.multimodal.identity_consistency import identity_features
from guard.multimodal.link_consistency import link_features
from guard.multimodal.semantic_consistency import semantic_features

FEATURE_NAMES: List[str] = [
    "display_href_mismatch",
    "display_domain_mismatch",
    "sender_identity_mismatch",
    "replyto_identity_mismatch",
    "brand_domain_mismatch",
    "text_url_semantic_mismatch",
    "ocr_url_mismatch",
    "qr_context_mismatch",
    "subject_body_mismatch",
    "attachment_context_mismatch",
    "brand_visual_domain_mismatch",
    "identity_history_mismatch",
]


class ConsistencyResult(BaseModel):
    overall_consistency_score: float = 1.0
    contradiction_score: float = 0.0
    features: Dict[str, float] = Field(default_factory=dict)
    evidence: List[str] = Field(default_factory=list)


def compute_consistency(parsed, profile=None):
    f_identity, e_identity = identity_features(parsed, profile)
    f_link, e_link = link_features(parsed)
    f_semantic, e_semantic = semantic_features(parsed)
    features: Dict[str, float] = {**f_identity, **f_link, **f_semantic}
    for name in FEATURE_NAMES:
        features.setdefault(name, 0.0)
    return features, [*e_identity, *e_link, *e_semantic]


def build_result(features: Dict[str, float], evidence: List[Evidence]) -> ConsistencyResult:
    contradictions = sum(1 for name in FEATURE_NAMES if features.get(name, 0.0) >= 0.5)
    contradiction_score = min(1.0, contradictions / 4.0)
    strongest = max(features.values()) if features else 0.0
    lines = [
        f"{e.feature}={e.value}"
        for e in sorted(evidence, key=lambda x: -x.normalized_score)[:8]
    ]
    return ConsistencyResult(
        overall_consistency_score=round(1.0 - strongest, 4),
        contradiction_score=round(contradiction_score, 4),
        features=features,
        evidence=lines,
    )


class MultimodalComponent:
    name = "consistency"

    def run(self, parsed, ctx: AnalysisContext) -> ComponentResult:
        profile = getattr(ctx, "behavioral_profile", None) if ctx else None
        features, evidence = compute_consistency(parsed, profile)
        return ComponentResult(name=self.name, features=features, evidence=evidence)

    def fallback(self, parsed, ctx: AnalysisContext) -> ComponentResult:
        return ComponentResult(
            name=self.name,
            features={name: 0.0 for name in FEATURE_NAMES},
            evidence=[],
            degraded=True,
        )


__all__ = ["MultimodalComponent", "ConsistencyResult", "compute_consistency", "build_result", "FEATURE_NAMES"]
