"""Tests for the shared detector contract (safe_run / ComponentResult)."""
from guard.component import AnalysisContext, ComponentResult, safe_run
from guard.evidence import Evidence, EvidenceCategory
from tests.factories import make_email


class _GoodComponent:
    name = "good"

    def run(self, parsed, ctx):
        return ComponentResult(
            name=self.name,
            features={"signal": 0.5},
            evidence=[Evidence.of(EvidenceCategory.URL, "signal", "0.5", 0.5, self.name)],
        )


class _BoomComponent:
    name = "boom"

    def run(self, parsed, ctx):
        raise RuntimeError("dependency exploded")


class _BoomWithFallback:
    name = "boom-fb"

    def run(self, parsed, ctx):
        raise RuntimeError("dependency exploded")

    def fallback(self, parsed, ctx):
        return ComponentResult(name=self.name, features={"nominal": 0.0})


def test_safe_run_success_records_latency():
    result = safe_run(_GoodComponent(), make_email(), AnalysisContext())
    assert result.degraded is False
    assert result.features == {"signal": 0.5}
    assert len(result.evidence) == 1
    assert result.latency_ms >= 0.0


def test_safe_run_isolates_failure():
    result = safe_run(_BoomComponent(), make_email(), AnalysisContext())
    assert result.degraded is True
    assert result.features == {}
    assert result.name == "boom"


def test_safe_run_uses_deterministic_fallback():
    result = safe_run(_BoomWithFallback(), make_email(), AnalysisContext())
    assert result.degraded is True
    assert result.features == {"nominal": 0.0}


def test_component_result_merged_features_prefixes():
    result = ComponentResult(name="html", features={"forms": 3.0})
    assert result.merged_features() == {"html.forms": 3.0}
    assert result.merged_features(prefix=False) == {"forms": 3.0}
