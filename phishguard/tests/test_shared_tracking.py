"""Tests for the optional shared multi-tester tracking store (no MongoDB required)."""
from guard.tracking.shared_store import SharedTracker


def test_tracker_disabled_without_uri(monkeypatch):
    monkeypatch.delenv("MONGODB_URI", raising=False)
    tracker = SharedTracker(uri="")
    assert tracker.enabled is False

    class _Verdict:
        uid = 1
        level = "ALLOW"
        score = 0.1

    # A no-op must never raise and must return False.
    assert tracker.record_verdict(_Verdict(), "victim@demo.local", "subject", "sender") is False
    assert tracker.record_feedback("victim@demo.local", 1, "subject", "not_phishing") is False
    assert tracker.latest() == []
    assert tracker.summary() == []


def test_tracker_enabled_flag_from_uri():
    tracker = SharedTracker(uri="mongodb+srv://example")
    assert tracker.enabled is True
