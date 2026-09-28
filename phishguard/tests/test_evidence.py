"""Tests for the unified evidence representation (WS11)."""
from guard.evidence import Evidence, EvidenceCategory, EvidenceCollector
from guard.evidence.models import severity_from_score


def test_severity_mapping():
    assert severity_from_score(0.0) == "info"
    assert severity_from_score(0.1) == "low"
    assert severity_from_score(0.5) == "medium"
    assert severity_from_score(0.8) == "high"
    assert severity_from_score(0.95) == "critical"


def test_evidence_id_is_deterministic():
    a = Evidence.of(EvidenceCategory.URL, "domain_age", "2 days", 0.82, "url")
    b = Evidence.of(EvidenceCategory.URL, "domain_age", "2 days", 0.82, "url")
    assert a.evidence_id == b.evidence_id
    assert a.severity == "high"
    assert a.explanation_key == "domain_age"


def test_evidence_score_is_clamped():
    e = Evidence.of(EvidenceCategory.URL, "x", "v", 5.0, "url")
    assert e.normalized_score == 1.0


def test_collector_dedup_keeps_stronger_observation():
    collector = EvidenceCollector()
    collector.add(Evidence.of(EvidenceCategory.BEHAVIOR, "new_sender", "true", 0.2, "behavioral"))
    collector.add(Evidence.of(EvidenceCategory.BEHAVIOR, "new_sender", "true", 0.9, "behavioral"))
    assert len(collector) == 1
    assert collector.all()[0].normalized_score == 0.9


def test_top_ranking_is_deterministic_and_ordered():
    collector = EvidenceCollector()
    collector.add(Evidence.of(EvidenceCategory.URL, "domain_age", "2 days", 0.82, "url", severity="high"))
    collector.add(Evidence.of(EvidenceCategory.CONSISTENCY, "display_href_mismatch", "true", 0.94, "multimodal", severity="critical"))
    collector.add(Evidence.of(EvidenceCategory.BEHAVIOR, "new_relationship", "true", 0.61, "behavioral", severity="medium"))
    top = collector.top(2)
    assert [e.feature for e in top] == ["display_href_mismatch", "domain_age"]
    # Re-running yields an identical ordering.
    assert [e.evidence_id for e in collector.top(2)] == [e.evidence_id for e in top]


def test_category_scores_and_features():
    collector = EvidenceCollector()
    collector.add(Evidence.of(EvidenceCategory.GRAPH, "shared_infra", "7 domains", 0.89, "graph"))
    collector.add(Evidence.of(EvidenceCategory.GRAPH, "domain_age", "2 days", 0.3, "graph"))
    assert collector.category_scores()["GRAPH"] == 0.89
    assert collector.features()["graph.shared_infra"] == 0.89
