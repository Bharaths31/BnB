"""Fusion engine with a pluggable component registry.

The original heuristic (text probability + header anomaly bonus) is preserved as the
deterministic fallback so the live watcher keeps working with no trained meta-model. On top
of it, every Phase-1/2 detector can register itself and contribute:

* named features merged into ``Verdict.component_scores``;
* :class:`~guard.evidence.models.Evidence` objects preserved on the verdict;
* its own latency measurement.

Components run through :func:`guard.component.safe_run`, so a failing detector degrades
instead of breaking the pipeline.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional

import numpy as np
import structlog

from guard.component import AnalysisComponent, AnalysisContext, safe_run
from guard.config import policy
from guard.evidence.collector import EvidenceCollector
from guard.fusion.meta_model import meta_model
from guard.fusion.uncertainty import compute_uncertainty, extract_component_risks
from guard.headers.rules import get_header_features
from guard.models import ParsedEmail, Verdict
from guard.nlp.classifier import classifier
from guard.nlp.tactic_classifier import tactic_classifier

logger = structlog.get_logger()


class FusionEngine:
    def __init__(self) -> None:
        # In a trained deployment a LightGBM meta-classifier is loaded here.
        self.ready = True
        self._components: List[AnalysisComponent] = []

    # ------------------------------------------------------------------ registry
    def register(self, component: AnalysisComponent) -> None:
        """Register a detector. Re-registering the same name replaces it."""
        name = getattr(component, "name", component.__class__.__name__)
        self._components = [
            c for c in self._components if getattr(c, "name", c.__class__.__name__) != name
        ]
        self._components.append(component)

    def unregister(self, name: str) -> None:
        self._components = [c for c in self._components if getattr(c, "name", "") != name]

    @property
    def components(self) -> List[AnalysisComponent]:
        return list(self._components)

    def update_after_verdict(self, parsed: ParsedEmail, verdict: Verdict) -> Dict[str, bool]:
        """Run post-verdict hooks (profile/graph learning) for every willing component.

        Kept separate from ``evaluate`` so that learning always happens *after* a decision and
        can be gated by an update policy. A failing hook never affects the verdict.
        """
        updated: Dict[str, bool] = {}
        for component in self._components:
            hook = getattr(component, "update_after_verdict", None)
            if callable(hook):
                name = getattr(component, "name", component.__class__.__name__)
                try:
                    updated[name] = bool(hook(parsed, verdict))
                except Exception as exc:  # noqa: BLE001 - hooks must not break processing
                    logger.warning("post_verdict_hook_failed", component=name, error=str(exc))
                    updated[name] = False
        return updated

    # ------------------------------------------------------------------ evaluation
    def evaluate(
        self,
        uid: int,
        parsed: ParsedEmail,
        context: Optional[AnalysisContext] = None,
    ) -> Verdict:
        start = time.perf_counter()

        # 1. Core deterministic signals (unchanged behaviour).
        text_phish_prob = classifier.classify(parsed.normalized_body)
        tactics = tactic_classifier.classify(parsed.normalized_body)
        headers = get_header_features(parsed)

        reasons: List[str] = []
        threshold = policy.get("explainer", {}).get("confidence_threshold", 0.6)
        for tactic, prob in tactics.items():
            if prob > threshold:
                reasons.append(f"High {tactic} confidence: {prob:.2f}")

        ctx = context or AnalysisContext(
            uid=uid,
            sender_domain=parsed.sender_domain,
            replyto_domain=parsed.replyto_domain,
        )

        # 2. Registered detectors, each isolated and timed.
        collector = EvidenceCollector()
        component_features: Dict[str, float] = {}
        latencies: Dict[str, float] = {}
        degraded = False
        for component in self._components:
            result = safe_run(component, parsed, ctx)
            latencies[result.name] = round(result.latency_ms, 3)
            degraded = degraded or result.degraded
            component_features.update(result.merged_features(prefix=True))
            collector.extend(result.evidence)

        # 3. Deterministic fallback fusion (replaced by the trained meta-model later).
        score = text_phish_prob + (0.1 if float(headers.sum()) > 0 else 0.0)

        component_scores: Dict[str, float] = {
            "text": text_phish_prob,
            "headers_anomaly_count": float(headers.sum()),
            **{f"tactic.{k}": float(v) for k, v in tactics.items()},
            **component_features,
        }

        # 4. Calibration + component-agreement uncertainty + decision level.
        calibrated = meta_model.calibrate(score)
        risks, missing = extract_component_risks(component_scores)
        report = compute_uncertainty(risks, calibrated, evidence_count=len(collector), missing=missing)
        level = meta_model.decide(calibrated, report.uncertainty_score)

        total_latency = (time.perf_counter() - start) * 1000.0
        latencies["fusion"] = round(total_latency, 3)

        return Verdict(
            uid=uid,
            score=score,
            level=level,
            reasons=reasons,
            component_scores=component_scores,
            explanation=None,  # generated by the explainer
            evidence=collector.all(),
            degraded=degraded,
            latencies=latencies,
            total_latency_ms=round(total_latency, 3),
            calibrated_probability=round(calibrated, 4),
            uncertainty=report.uncertainty_score,
            confidence=report.prediction_confidence,
            component_agreement=report.component_agreement,
            component_disagreement=report.component_disagreement,
        )


fusion_engine = FusionEngine()
