"""Fusion uncertainty / REVIEW tests (WS7) — the 6 required scenarios."""
from guard.component import ComponentResult
from guard.fusion.meta_model import MetaModel
from guard.fusion.uncertainty import compute_uncertainty, extract_component_risks
from guard.fusion.fusion_engine import FusionEngine
from guard.explainer.engine import explainer_engine
from tests.factories import credential_phish, make_email


def test_all_components_agree_is_confident():
    risks = {"text": 0.90, "url": 0.88, "headers": 0.92, "behavioral": 0.87}
    report = compute_uncertainty(risks, calibrated_probability=0.92, evidence_count=6)
    assert report.component_disagreement < 0.1
    assert report.uncertainty_score < 0.2
    assert report.prediction_confidence > 0.8
    assert MetaModel().decide(0.92, report.uncertainty_score) == "BLOCK"


def test_one_component_disagrees_triggers_review():
    risks = {"text": 0.95, "url": 0.08, "headers": 0.10, "behavioral": 0.12}
    report = compute_uncertainty(risks, calibrated_probability=0.95)
    assert report.component_disagreement > 0.5
    assert MetaModel().decide(0.95, report.uncertainty_score) == "REVIEW"


def test_only_one_component_fires():
    risks = {"text": 0.9, "url": 0.0, "headers": 0.0}
    report = compute_uncertainty(risks, calibrated_probability=0.9)
    assert report.component_agreement < 0.5
    assert report.uncertainty_score > 0.4


def test_missing_components_are_reported():
    risks, missing = extract_component_risks({"text": 0.9})
    assert "text" in risks
    assert "graph" in missing and "attachment" in missing
    report = compute_uncertainty(risks, calibrated_probability=0.9, missing=missing)
    assert report.missing_components
    assert report.uncertainty_score > 0.1


def test_extract_component_risks_maps_and_ignores_raw_counts():
    scores = {
        "text": 0.8,
        "headers_anomaly_count": 3.0,
        "html.html_risk_score": 0.7,
        "html.form_count": 9.0,  # raw count must NOT be used as risk
        "attachment.attachment_risk_score": 0.6,
        "behavioral.sender_newness_score": 1.0,
        "consistency.display_href_mismatch": 0.9,
        "intent.credential_harvesting_score": 0.5,
    }
    risks, missing = extract_component_risks(scores)
    assert risks["headers"] == 0.5
    assert risks["html"] == 0.7
    assert risks["attachment"] == 0.6
    assert risks["behavioral"] == 1.0
    assert risks["consistency"] == 0.9
    assert risks["intent"] == 0.5
    assert "graph" in missing


def test_model_failure_still_produces_verdict_with_uncertainty():
    class Boom:
        name = "attachment"

        def run(self, parsed, ctx):
            raise RuntimeError("attachment backend down")

    engine = FusionEngine()
    engine.register(Boom())
    verdict = engine.evaluate(1, credential_phish())
    assert verdict.degraded is True
    assert verdict.level in {"ALLOW", "FLAG", "REVIEW", "BLOCK"}
    assert 0.0 <= verdict.uncertainty <= 1.0
    assert verdict.calibrated_probability == verdict.score


def test_calibrated_edge_cases():
    model = MetaModel()
    assert model.calibrate(-1.0) == 0.0
    assert model.calibrate(2.0) == 1.0
    low, _ = extract_component_risks({"text": 0.0})
    high, _ = extract_component_risks({"text": 0.0})
    assert compute_uncertainty(low, 0.0).decision_margin == 1.0
    assert compute_uncertainty(high, 0.5).decision_margin == 0.0
    assert model.decide(0.1, 0.9) == "ALLOW"


def test_review_explanation_is_explicit():
    engine = FusionEngine()
    v = engine.evaluate(1, credential_phish())
    v.level = "REVIEW"
    v.uncertainty = 0.8
    v.calibrated_probability = 0.9
    v.component_agreement = 0.3
    v.component_disagreement = 0.7
    text = explainer_engine.explain(v)
    assert "REVIEW" in text
    assert "disagreement" in text or "agree" in text
