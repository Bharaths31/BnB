# guard/explainer/engine.py
"""Deterministic, evidence-driven explanation engine.

Renders only facts that exist as evidence or as verdict fields — it never invents information
and never uses a generative model.
"""
from guard.config import policy
from guard.explainer.templates import EXPLANATION_TEMPLATES
from guard.models import Verdict

#: Maps a verdict reason substring to a template key.
_REASON_TEMPLATES = (
    ("urgency", "urgency"),
    ("authority", "authority"),
    ("credential", "credential_request"),
    ("financial", "financial"),
)


class ExplainerEngine:
    def explain(self, verdict: Verdict) -> str:
        max_reasons = policy.get("explainer", {}).get("max_reasons", 5)
        bullets = []

        if verdict.level == "ALLOW":
            bullets.append("No significant threats detected.")
        else:
            for reason in verdict.reasons:
                for needle, key in _REASON_TEMPLATES:
                    if needle in reason:
                        template = EXPLANATION_TEMPLATES[key]
                        bullets.append(f"{template['header']} {template['detail']}")
                        break
            if verdict.component_scores.get("headers_anomaly_count", 0) > 0:
                template = EXPLANATION_TEMPLATES["headers_anomaly"]
                bullets.append(f"{template['header']} {template['detail']}")
            if not bullets:
                template = EXPLANATION_TEMPLATES["general"]
                bullets.append(f"{template['header']} {template['detail']}")

        # Evidence summary (deterministic ranking by rank_score, then feature name).
        if verdict.evidence:
            top = sorted(
                verdict.evidence,
                key=lambda e: (-e.rank_score, -e.normalized_score, e.feature, e.evidence_id),
            )[:max_reasons]
            rendered = "; ".join(f"{e.category.value}:{e.feature}={e.value}" for e in top)
            bullets.append(f"Top evidence: {rendered}")

        if verdict.level != "ALLOW":
            bullets.append(
                f"Component agreement {verdict.component_agreement:.2f}, "
                f"disagreement {verdict.component_disagreement:.2f}."
            )

        if verdict.level == "REVIEW":
            bullets.append(
                f"Routed to REVIEW: risk {verdict.calibrated_probability:.2f} is high but "
                f"uncertainty {verdict.uncertainty:.2f} is high (components disagree), so a "
                f"human should review before an automatic block."
            )

        formatted = "### PhishGuard Explanation\n\n"
        for index, bullet in enumerate(bullets[: max_reasons + 3], start=1):
            formatted += f"{index}. {bullet}\n"
        return formatted


explainer_engine = ExplainerEngine()
