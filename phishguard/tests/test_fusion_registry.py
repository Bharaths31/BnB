"""Tests for the FusionEngine component registry (Phase 0 hook)."""
from guard.component import ComponentResult
from guard.evidence import Evidence, EvidenceCategory
from guard.fusion.fusion_engine import FusionEngine
from tests.factories import credential_phish


class _HtmlStub:
    name = "html"

    def run(self, parsed, ctx):
        return ComponentResult(
            name=self.name,
            features={"forms": 2.0, "password_inputs": 1.0},
            evidence=[Evidence.of(EvidenceCategory.HTML, "password_form", "true", 0.7, self.name)],
        )


class _BoomStub:
    name = "boom"

    def run(self, parsed, ctx):
        raise RuntimeError("no dependency")


def test_registered_component_features_reach_verdict():
    engine = FusionEngine()
    engine.register(_HtmlStub())
    verdict = engine.evaluate(1, credential_phish())
    assert verdict.component_scores["html.forms"] == 2.0
    assert verdict.component_scores["html.password_inputs"] == 1.0
    assert "html" in verdict.latencies
    assert verdict.total_latency_ms >= 0.0
    assert any(e.category == EvidenceCategory.HTML for e in verdict.evidence)


def test_failing_component_does_not_break_pipeline():
    engine = FusionEngine()
    engine.register(_BoomStub())
    verdict = engine.evaluate(2, credential_phish())
    assert verdict.degraded is True
    assert verdict.level in {"ALLOW", "FLAG", "REVIEW", "BLOCK"}
    # Core scoring still produced a verdict.
    assert "text" in verdict.component_scores


def test_register_replaces_component_with_same_name():
    engine = FusionEngine()

    class Alt(_HtmlStub):
        name = "html"

        def run(self, parsed, ctx):
            return ComponentResult(name="html", features={"forms": 99.0})

    engine.register(_HtmlStub())
    engine.register(Alt())
    assert len(engine.components) == 1
    verdict = engine.evaluate(3, credential_phish())
    assert verdict.component_scores["html.forms"] == 99.0


def test_unregister_component():
    engine = FusionEngine()
    engine.register(_HtmlStub())
    engine.unregister("html")
    assert engine.components == []
