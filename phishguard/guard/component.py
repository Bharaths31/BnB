"""Shared detector contract for every PhishGuard analysis capability.

Each detector implements :class:`AnalysisComponent` (a single ``run`` method returning a
:class:`ComponentResult`) and is executed through :func:`safe_run`, which enforces three of
the project-wide capability rules:

* **rule 6** – a deterministic fallback result when a dependency fails;
* **rule 8** – per-component latency measurement;
* **rule 9** – a failing component never prevents the rest of the pipeline from running.

Keeping this tiny and dependency-light means every new module (HTML, attachments,
behavioral, multimodal, graph, ...) integrates in exactly the same way.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

import structlog
from pydantic import BaseModel, Field

from guard.evidence.models import Evidence

logger = structlog.get_logger()


class AnalysisContext(BaseModel):
    """Cross-component inputs.

    Detectors such as the HTML module must not judge complexity in isolation; they consume
    reputation / authentication / intent context from here so that findings can be
    contextualised instead of treated as hard rules.
    """

    uid: int = 0
    mailbox: str = ""
    sender_domain: str = ""
    replyto_domain: str = ""
    sender_reputation: float = 0.0
    domain_reputation: float = 0.0
    auth_features: Dict[str, float] = Field(default_factory=dict)
    url_features: Dict[str, float] = Field(default_factory=dict)
    intent_scores: Dict[str, float] = Field(default_factory=dict)
    graph_features: Dict[str, float] = Field(default_factory=dict)
    behavioral_profile: Optional[Any] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class ComponentResult(BaseModel):
    """What every detector returns."""

    name: str = ""
    features: Dict[str, float] = Field(default_factory=dict)
    evidence: List[Evidence] = Field(default_factory=list)
    latency_ms: float = 0.0
    degraded: bool = False

    def merged_features(self, prefix: bool = True) -> Dict[str, float]:
        if not prefix or not self.name:
            return dict(self.features)
        return {f"{self.name}.{k}": v for k, v in self.features.items()}


@runtime_checkable
class AnalysisComponent(Protocol):
    """Minimal protocol every detector satisfies."""

    name: str

    def run(self, parsed: Any, ctx: AnalysisContext) -> ComponentResult:  # pragma: no cover
        ...


def safe_run(component: AnalysisComponent, parsed: Any, ctx: AnalysisContext) -> ComponentResult:
    """Run ``component`` in isolation, never raising.

    On failure the component's own ``fallback`` is used when provided, otherwise a neutral
    empty result is returned. Either way the result is flagged ``degraded`` and the latency
    is recorded so the caller can continue with the rest of the pipeline.
    """
    start = time.perf_counter()
    component_name = getattr(component, "name", component.__class__.__name__)
    result: Optional[ComponentResult] = None
    try:
        result = component.run(parsed, ctx)
        if result is None:
            result = ComponentResult(name=component_name)
        if not result.name:
            result.name = component_name
    except Exception as exc:  # noqa: BLE001 - isolation boundary by design
        logger.warning("component_failed", component=component_name, error=str(exc), exc_info=True)
        fallback = getattr(component, "fallback", None)
        if callable(fallback):
            try:
                result = fallback(parsed, ctx)
            except Exception:  # pragma: no cover - a fallback should never itself fail
                logger.error("component_fallback_failed", component=component_name)
                result = None
        if result is None:
            result = ComponentResult(name=component_name)
        result.degraded = True
        if not result.name:
            result.name = component_name
    if result.latency_ms == 0.0:
        result.latency_ms = (time.perf_counter() - start) * 1000.0
    return result


__all__ = ["AnalysisContext", "ComponentResult", "AnalysisComponent", "safe_run"]
