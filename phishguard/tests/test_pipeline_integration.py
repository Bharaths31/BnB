"""End-to-end pipeline integration test (Phase 1 wiring)."""
from guard.behavioral.profile_store import ProfileStore
from guard.pipeline import build_default_engine
from tests.factories import credential_phish, make_email, make_url


def test_pipeline_registers_all_components():
    engine = build_default_engine(ProfileStore(":memory:"))
    names = {getattr(c, "name", "") for c in engine.components}
    assert {"html", "attachment", "consistency", "behavioral"} <= names


def test_pipeline_evaluates_and_collects_features_and_evidence():
    engine = build_default_engine(ProfileStore(":memory:"))
    verdict = engine.evaluate(1, credential_phish())

    # Features from every detector reach the verdict.
    for prefix in ("html.", "consistency.", "behavioral.", "attachment."):
        assert any(k.startswith(prefix) for k in verdict.component_scores), prefix
    assert verdict.evidence, "evidence should be preserved on the verdict"
    assert verdict.total_latency_ms > 0


def test_post_verdict_learning_updates_profiles_only_after_analysis():
    store = ProfileStore(":memory:")
    engine = build_default_engine(store)
    email = make_email(
        from_addr="colleague@company.com",
        recipients=["bob@company.com"],
        subject="Lunch tomorrow?",
        body_plain="Want to grab lunch tomorrow?",
        urls=[make_url("https://company.com/x", "x")],
    )
    # Read path must not create a profile.
    engine.evaluate(1, email)
    assert store.get_sender("colleague@company.com") is None

    updated = engine.update_after_verdict(email, engine.evaluate(2, email))
    assert updated.get("behavioral") is True
    assert store.get_sender("colleague@company.com") is not None
