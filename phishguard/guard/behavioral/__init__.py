"""Behavioral profiling subsystem (WS1).

Read path (during analysis): build historical sender / relationship profiles, compute the 12
deterministic anomaly features and emit evidence. This never writes to the store.

Write path (:meth:`BehavioralComponent.update_after_verdict`): fold the analysed email into
the profiles *after* a verdict, gated by a configurable policy so obviously malicious mail
does not poison the history.
"""
from __future__ import annotations

from datetime import datetime, timezone
from statistics import mean
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from guard.behavioral import anomaly as A
from guard.behavioral.profile_store import ProfileStore, get_profile_store
from guard.behavioral.recipient_profile import RelationshipProfile, update_relationship_profile
from guard.behavioral.sender_profile import SenderProfile, update_sender_profile
from guard.component import AnalysisContext, ComponentResult
from guard.config import policy
from guard.evidence import Evidence, EvidenceCategory

FEATURE_NAMES: List[str] = [
    "sender_newness_score",
    "sender_frequency_anomaly",
    "sender_time_anomaly",
    "sender_domain_change_score",
    "sender_replyto_anomaly",
    "sender_url_behavior_anomaly",
    "sender_attachment_anomaly",
    "sender_authentication_anomaly",
    "recipient_relationship_newness",
    "recipient_relationship_anomaly",
    "display_name_history_anomaly",
    "communication_pattern_anomaly",
]

_SENDER_FEATURES = [
    "sender_frequency_anomaly",
    "sender_domain_change_score",
    "sender_replyto_anomaly",
    "sender_url_behavior_anomaly",
    "sender_attachment_anomaly",
    "sender_authentication_anomaly",
    "display_name_history_anomaly",
]


class BehaviorProfileResult(BaseModel):
    sender_anomaly_score: float = 0.0
    relationship_anomaly_score: float = 0.0
    sender_newness_score: float = 0.0
    temporal_anomaly_score: float = 0.0
    communication_anomaly_score: float = 0.0
    tri_state: str = "genuinely_unknown"
    features: Dict[str, float] = Field(default_factory=dict)
    evidence: List[str] = Field(default_factory=list)


def resolve_profiles(store: ProfileStore, parsed):
    """Resolve the sender profile (with identity fallback) and relationship profile."""
    sender = (parsed.from_addr or "").lower()
    recipient = parsed.recipients[0].lower() if parsed.recipients else ""
    profile = store.get_sender(sender)
    if profile is None and parsed.from_display:
        # Identity fallback: same claimed identity from a new/unknown domain.
        profile = store.get_sender_by_display(parsed.from_display)
    rel = None
    if profile is not None and recipient:
        rel = store.get_relationship(profile.sender, recipient)
    return profile, rel


def compute_behavioral_features(
    profile: Optional[SenderProfile],
    rel: Optional[RelationshipProfile],
    parsed,
    now: Optional[datetime] = None,
) -> Dict[str, float]:
    now = now or parsed.received_at or datetime.now(timezone.utc)
    return {
        "sender_newness_score": A.sender_newness_score(profile),
        "sender_frequency_anomaly": A.sender_frequency_anomaly(profile, parsed, now),
        "sender_time_anomaly": A.sender_time_anomaly(profile, parsed, now),
        "sender_domain_change_score": A.sender_domain_change_score(profile, parsed),
        "sender_replyto_anomaly": A.sender_replyto_anomaly(profile, parsed),
        "sender_url_behavior_anomaly": A.sender_url_behavior_anomaly(profile, parsed),
        "sender_attachment_anomaly": A.sender_attachment_anomaly(profile, parsed),
        "sender_authentication_anomaly": A.sender_authentication_anomaly(profile, parsed),
        "recipient_relationship_newness": A.recipient_relationship_newness(rel),
        "recipient_relationship_anomaly": A.recipient_relationship_anomaly(rel, parsed, now),
        "display_name_history_anomaly": A.display_name_history_anomaly(profile, parsed),
        "communication_pattern_anomaly": A.communication_pattern_anomaly(profile, rel, parsed),
    }


def summarize(
    features: Dict[str, float],
    profile: Optional[SenderProfile],
    rel: Optional[RelationshipProfile],
) -> BehaviorProfileResult:
    sender_component = mean(features[f] for f in _SENDER_FEATURES) if features else 0.0
    has_history = bool(profile and profile.total_messages > 0)
    strongest = max(features.values()) if features else 0.0
    result = BehaviorProfileResult(
        sender_anomaly_score=round(sender_component, 4),
        relationship_anomaly_score=round(features.get("recipient_relationship_anomaly", 0.0), 4),
        sender_newness_score=round(features.get("sender_newness_score", 0.0), 4),
        temporal_anomaly_score=round(features.get("sender_time_anomaly", 0.0), 4),
        communication_anomaly_score=round(features.get("communication_pattern_anomaly", 0.0), 4),
        tri_state=A.tri_state(strongest, has_history),
        features=dict(features),
    )
    result.evidence = _evidence_lines(result)
    return result


def _evidence_lines(result: BehaviorProfileResult) -> List[str]:
    lines = [f"Behavioral state: {result.tri_state}"]
    if result.sender_newness_score > 0.5:
        lines.append("Sender is new to this mailbox")
    for name, value in sorted(result.features.items(), key=lambda kv: kv[1], reverse=True):
        if value >= 0.5:
            lines.append(f"{name}={value:.2f}")
    return lines


def _emit_evidence(features: Dict[str, float], entity: str) -> List[Evidence]:
    evidence: List[Evidence] = []
    for name, value in features.items():
        if value >= 0.35:
            evidence.append(
                Evidence.of(
                    EvidenceCategory.BEHAVIOR,
                    name,
                    f"{value:.2f}",
                    value,
                    "behavioral",
                    related_entity=entity,
                )
            )
    return evidence


def _should_update(verdict) -> bool:
    mode = policy.get("behavioral", {}).get("update_policy", "only_below_block")
    if mode == "always":
        return True
    if mode == "confirmed_only":
        return verdict.level == "ALLOW"
    # default: only_below_block — never learn from blocked mail
    return verdict.level != "BLOCK"


class BehavioralComponent:
    name = "behavioral"

    def __init__(self, store: Optional[ProfileStore] = None):
        self.store = store or get_profile_store()

    # ------------------------------------------------------------------ analysis (read)
    def run(self, parsed, ctx: AnalysisContext) -> ComponentResult:
        profile, rel = resolve_profiles(self.store, parsed)
        features = compute_behavioral_features(profile, rel, parsed)
        entity = (profile.sender if profile else (parsed.from_addr or "")).lower()
        return ComponentResult(
            name=self.name,
            features=features,
            evidence=_emit_evidence(features, entity),
        )

    def fallback(self, parsed, ctx: AnalysisContext) -> ComponentResult:
        # Neutral, non-informative features so the pipeline keeps running.
        return ComponentResult(
            name=self.name,
            features={name: 0.0 for name in FEATURE_NAMES},
            evidence=[],
            degraded=True,
        )

    # -------------------------------------------------------- learning (write, post-verdict)
    def update_after_verdict(self, parsed, verdict, recipient: str = "") -> bool:
        if not _should_update(verdict):
            return False
        now = parsed.received_at or datetime.now(timezone.utc)
        sender = (parsed.from_addr or "").lower()
        recipient = (recipient or (parsed.recipients[0] if parsed.recipients else "")).lower()

        profile = self.store.get_sender(sender) or SenderProfile(sender=sender)
        update_sender_profile(profile, parsed, now)
        self.store.save_sender(profile)

        if recipient:
            rel = self.store.get_relationship(sender, recipient) or RelationshipProfile(
                sender=sender, recipient=recipient
            )
            update_relationship_profile(rel, parsed, now, recipient)
            self.store.save_relationship(rel)

        self.store.record_observation(sender, recipient, verdict.level, now)
        return True


__all__ = [
    "BehavioralComponent",
    "BehaviorProfileResult",
    "compute_behavioral_features",
    "resolve_profiles",
    "summarize",
    "FEATURE_NAMES",
]
