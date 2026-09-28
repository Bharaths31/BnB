"""Behavioral profiling tests (WS1) — the 10 required scenarios."""
from datetime import datetime, timedelta, timezone

import pytest

from guard.behavioral import (
    BehavioralComponent,
    compute_behavioral_features,
    resolve_profiles,
    summarize,
)
from guard.behavioral.profile_store import ProfileStore
from guard.models import Verdict
from tests.factories import FIXED_NOW, make_email, make_url

SENDER = "alice@example.com"
RECIPIENT = "bob@example.com"


def _feed(store, n=15, sender=SENDER, recipient=RECIPIENT, domain="example.com",
          subject="Weekly report", body="Please find the weekly report attached for review.",
          urls=None, attachments=None, spf="pass", start=None, step_days=1):
    component = BehavioralComponent(store)
    start = start or (FIXED_NOW - timedelta(days=n * step_days))
    for i in range(n):
        email = make_email(
            subject=subject,
            from_addr=sender,
            from_display="Alice",
            recipients=[recipient],
            body_plain=body,
            urls=urls if urls is not None else [make_url("https://example.com/report", "report")],
            attachments=attachments,
            received_at=start + timedelta(days=i * step_days),
            spf=spf,
            dkim=spf,
            dmarc=spf,
        )
        component.update_after_verdict(email, Verdict(uid=i, score=0.1, level="ALLOW"), recipient)


def _features(store, email):
    profile, rel = resolve_profiles(store, email)
    features = compute_behavioral_features(profile, rel, email)
    return features, summarize(features, profile, rel)


def test_normal_repeated_communication_is_not_anomalous():
    store = ProfileStore(":memory:")
    _feed(store, n=15)
    email = make_email(
        from_addr=SENDER, from_display="Alice", recipients=[RECIPIENT],
        subject="Weekly report", body_plain="Please find the weekly report attached for review.",
        urls=[make_url("https://example.com/report", "report")], received_at=FIXED_NOW,
    )
    features, result = _features(store, email)
    assert features["sender_domain_change_score"] == 0.0
    assert features["sender_attachment_anomaly"] == 0.0
    assert features["sender_url_behavior_anomaly"] == 0.0
    assert features["sender_time_anomaly"] < 0.2
    assert features["sender_frequency_anomaly"] < 0.5
    assert result.tri_state == "normal"


def test_new_sender_is_unknown_not_phishing():
    store = ProfileStore(":memory:")
    email = make_email(from_addr="stranger@nowhere.test", recipients=[RECIPIENT], subject="Hello")
    component = BehavioralComponent(store)
    result = component.run(email, None)
    features, summary = _features(store, email)
    assert features["sender_newness_score"] == 1.0
    assert summary.tri_state == "genuinely_unknown"
    # none of the "change/anomaly vs history" features can fire without history
    assert features["sender_domain_change_score"] == 0.0
    assert summary.sender_anomaly_score == 0.0
    # the read path must not create a profile
    assert store.get_sender("stranger@nowhere.test") is None
    assert "behavioral" in component.name


def test_new_recipient_relationship():
    store = ProfileStore(":memory:")
    _feed(store, n=10)
    email = make_email(from_addr=SENDER, recipients=["carol@example.com"],
                       subject="Weekly report", received_at=FIXED_NOW)
    features, summary = _features(store, email)
    assert features["recipient_relationship_newness"] == 1.0
    assert summary.relationship_anomaly_score == 0.0  # unknown, not anomalous


def test_abnormal_sending_time():
    store = ProfileStore(":memory:")
    _feed(store, n=12)
    odd_time = FIXED_NOW.replace(hour=3, minute=0)
    email = make_email(from_addr=SENDER, recipients=[RECIPIENT], subject="Weekly report",
                       urls=[make_url("https://example.com/report")], received_at=odd_time)
    features, _ = _features(store, email)
    assert features["sender_time_anomaly"] > 0.5


def test_abnormal_attachment_behavior():
    store = ProfileStore(":memory:")
    _feed(store, n=10)  # sender never sends attachments
    email = make_email(
        from_addr=SENDER, recipients=[RECIPIENT], subject="Invoice",
        attachments=[("invoice.zip", "application/zip", b"PK\x03\x04zip")],
        received_at=FIXED_NOW,
    )
    features, _ = _features(store, email)
    assert features["sender_attachment_anomaly"] == 1.0


def test_abnormal_url_behavior():
    store = ProfileStore(":memory:")
    _feed(store, n=10)
    email = make_email(
        from_addr=SENDER, recipients=[RECIPIENT], subject="Weekly report",
        urls=[make_url("http://evil.example.net/login", "login")], received_at=FIXED_NOW,
    )
    features, _ = _features(store, email)
    assert features["sender_url_behavior_anomaly"] == 1.0


def test_sender_domain_change():
    store = ProfileStore(":memory:")
    _feed(store, n=10)
    email = make_email(from_addr="alice@evil.example.net", recipients=[RECIPIENT],
                       subject="Weekly report", received_at=FIXED_NOW)
    features, _ = _features(store, email)
    assert features["sender_domain_change_score"] == 1.0


def test_display_name_change():
    store = ProfileStore(":memory:")
    _feed(store, n=10)
    email = make_email(from_addr=SENDER, from_display="IT Support", recipients=[RECIPIENT],
                       subject="Weekly report", received_at=FIXED_NOW)
    features, _ = _features(store, email)
    assert features["display_name_history_anomaly"] == 1.0


def test_profile_persistence(tmp_path):
    path = str(tmp_path / "profiles.db")
    store = ProfileStore(path)
    _feed(store, n=8)
    store.save_relationship(
        store.get_relationship(SENDER, RECIPIENT)
    )
    store.close()

    reopened = ProfileStore(path)
    profile = reopened.get_sender(SENDER)
    assert profile is not None
    assert profile.total_messages == 8
    rel = reopened.get_relationship(SENDER, RECIPIENT)
    assert rel is not None and rel.message_count == 8
    assert len(reopened.observations_for(SENDER)) == 8


def test_profile_poisoning_prevention():
    store = ProfileStore(":memory:")
    component = BehavioralComponent(store)
    malicious = make_email(from_addr="attacker@bad.test", recipients=[RECIPIENT],
                           subject="verify your account immediately")

    blocked = component.update_after_verdict(
        malicious, Verdict(uid=1, score=0.97, level="BLOCK"), RECIPIENT
    )
    assert blocked is False
    assert store.get_sender("attacker@bad.test") is None

    allowed = component.update_after_verdict(
        malicious, Verdict(uid=2, score=0.1, level="ALLOW"), RECIPIENT
    )
    assert allowed is True
    profile = store.get_sender("attacker@bad.test")
    assert profile is not None and profile.total_messages == 1
