"""Deterministic anomaly features for the behavioral profiler (WS1).

Numeric distributions use robust statistics (median + MAD); categorical distributions use
historical frequency. A genuinely new sender is reported as **unknown**, not phishing: every
function returns a ``[0, 1]`` score and the caller decides how much weight to give it.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Dict, Optional

from guard.behavioral.temporal_features import hour_anomaly, weekday_anomaly
from guard.config import policy

if False:  # pragma: no cover - typing only, avoids an import cycle
    from guard.behavioral.sender_profile import SenderProfile
    from guard.behavioral.recipient_profile import RelationshipProfile


# --------------------------------------------------------------------------- statistics
def median(values) -> float:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return 0.0
    n = len(vals)
    mid = n // 2
    if n % 2:
        return float(vals[mid])
    return float((vals[mid - 1] + vals[mid]) / 2.0)


def mad(values, m: Optional[float] = None) -> float:
    vals = [v for v in values if v is not None]
    if not vals:
        return 0.0
    med = median(vals) if m is None else float(m)
    return median(abs(v - med) for v in vals)


def robust_z(value: float, m: float, madv: float) -> float:
    """Median-absolute-deviation z-score (0.6745 scaling for normal consistency)."""
    if madv is None or abs(madv) <= 1e-9:
        scale = max(abs(m) * 0.1, 1e-6)
        return 0.6745 * (value - m) / scale
    return 0.6745 * (value - m) / float(madv)


def _z_threshold() -> float:
    return float(policy.get("behavioral", {}).get("anomaly_z_threshold", 3.5))


def score_from_z(z: float, threshold: Optional[float] = None) -> float:
    threshold = threshold or _z_threshold()
    return min(1.0, abs(z) / threshold)


def novelty(counter: Dict[str, int], key: str) -> float:
    """1.0 when ``key`` has never been seen; decreases with its historical frequency."""
    total = sum(counter.values())
    if total <= 0:
        return 1.0
    if key not in counter:
        return 1.0
    return max(0.0, 1.0 - counter[key] / total)


def jaccard(a: Dict[str, int], b: Dict[str, int]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def tri_state(score: float, has_history: bool) -> str:
    """Explicitly distinguish unknown / unusual / strongly anomalous."""
    if not has_history:
        return "genuinely_unknown"
    if score >= 0.75:
        return "strongly_anomalous"
    if score >= 0.4:
        return "unusual"
    return "normal"


# ----------------------------------------------------------------------------- features
def sender_newness_score(profile: "Optional[SenderProfile]") -> float:
    if profile is None or profile.total_messages == 0:
        return 1.0
    return 1.0 / (1.0 + profile.total_messages / 5.0)


def sender_frequency_anomaly(profile: "Optional[SenderProfile]", parsed, now: datetime) -> float:
    if profile is None or profile.median_interval_seconds is None or profile.last_seen is None:
        return 0.0
    interval = (now - profile.last_seen).total_seconds()
    if interval < 0:
        return 0.0
    z = robust_z(interval, profile.median_interval_seconds, profile.interval_mad or 0.0)
    burst = max(0.0, -z)  # only unusually *rapid* sending is a frequency anomaly
    return min(1.0, burst / _z_threshold())


def sender_time_anomaly(profile: "Optional[SenderProfile]", parsed, now: datetime) -> float:
    if profile is None:
        return 0.0
    hour = now.hour + now.minute / 60.0
    h_score = hour_anomaly(hour, profile.typical_sending_hour)
    w_score = weekday_anomaly(now.weekday(), profile.typical_sending_weekday)
    return max(h_score, w_score)


def sender_domain_change_score(profile: "Optional[SenderProfile]", parsed) -> float:
    if profile is None or profile.total_messages == 0:
        return 0.0
    domain = parsed.sender_domain
    if not domain:
        return 0.0
    return novelty(profile.sender_domains, domain)


def sender_replyto_anomaly(profile: "Optional[SenderProfile]", parsed) -> float:
    reply_to = parsed.replyto_domain
    if not reply_to:
        return 0.0
    score = novelty(profile.replyto_domains, reply_to) if profile else 0.0
    if reply_to != parsed.sender_domain:
        score = max(score, 0.6)
    return score


def sender_url_behavior_anomaly(profile: "Optional[SenderProfile]", parsed) -> float:
    if profile is None or profile.total_messages == 0:
        return 0.0
    count = len(parsed.urls)
    domain_novelty = 0.0
    if count:
        new = sum(1 for u in parsed.urls if not u.domain or u.domain not in profile.url_domains)
        domain_novelty = new / count
    count_score = 0.0
    if profile.url_count_samples:
        z = robust_z(count, profile.url_count_median, profile.url_count_mad)
        count_score = score_from_z(z)
    return min(1.0, max(domain_novelty, count_score))


def sender_attachment_anomaly(profile: "Optional[SenderProfile]", parsed) -> float:
    if profile is None or not parsed.attachments:
        return 0.0
    base = max(0.0, 1.0 - profile.attachment_frequency)
    novel = 0
    for att in parsed.attachments:
        if att.content_type and att.content_type not in profile.attachment_types:
            novel += 1
    novel_fraction = novel / len(parsed.attachments)
    return min(1.0, max(base, novel_fraction))


def _auth_failed(parsed) -> bool:
    return any(getattr(parsed, f"{name}_result", "none") == "fail" for name in ("spf", "dkim", "dmarc"))


def sender_authentication_anomaly(profile: "Optional[SenderProfile]", parsed) -> float:
    if profile is None or profile.total_messages == 0:
        return 0.0
    if not _auth_failed(parsed):
        return 0.0
    total = sum(profile.auth_outcomes.values())
    if total <= 0:
        return 0.5
    fail_rate = profile.auth_outcomes.get("fail", 0) / total
    return min(1.0, max(0.0, 1.0 - fail_rate))


def recipient_relationship_newness(rel: "Optional[RelationshipProfile]") -> float:
    if rel is None or rel.message_count == 0:
        return 1.0
    return 1.0 / (1.0 + rel.message_count / 3.0)


def recipient_relationship_anomaly(rel: "Optional[RelationshipProfile]", parsed, now: datetime) -> float:
    if rel is None or rel.message_count == 0:
        return 0.0
    scores = []
    # interval deviation (both directions are unusual for a known relationship)
    if rel.avg_interval_seconds is not None and rel.last_seen is not None:
        interval = (now - rel.last_seen).total_seconds()
        z = robust_z(interval, rel.avg_interval_seconds, rel.interval_mad or 0.0)
        scores.append(score_from_z(z))
    # subject divergence from the relationship's typical tokens
    if rel.subject_tokens:
        sim = jaccard(_tokens(parsed.subject), rel.subject_tokens)
        scores.append(max(0.0, 1.0 - sim))
    # url novelty
    if parsed.urls:
        new = sum(1 for u in parsed.urls if not u.domain or u.domain not in rel.url_domains)
        scores.append(new / len(parsed.urls))
    # attachment novelty
    if parsed.attachments:
        repo = max(0.0, 1.0 - rel.attachment_frequency)
        novel = sum(1 for a in parsed.attachments if a.content_type and a.content_type not in rel.attachment_types)
        scores.append(max(repo, novel / len(parsed.attachments)))
    return min(1.0, max(scores)) if scores else 0.0


def display_name_history_anomaly(profile: "Optional[SenderProfile]", parsed) -> float:
    if profile is None or profile.total_messages == 0:
        return 0.0
    display = (parsed.from_display or "").strip().lower()
    if not display:
        return 0.0
    return novelty(profile.display_names, display)


def communication_pattern_anomaly(
    profile: "Optional[SenderProfile]", rel: "Optional[RelationshipProfile]", parsed
) -> float:
    if profile is None or profile.total_messages == 0:
        return 0.0
    scores = []
    # subject divergence from the sender's typical vocabulary
    if profile.subject_tokens:
        scores.append(max(0.0, 1.0 - jaccard(_tokens(parsed.subject), profile.subject_tokens)))
    # message length deviation
    if profile.length_samples:
        z = robust_z(len(parsed.visible_text or parsed.normalized_body), profile.median_message_length, profile.length_mad)
        scores.append(score_from_z(z))
    # recipient novelty
    if parsed.recipients:
        scores.append(novelty(profile.recipient_addresses, parsed.recipients[0].lower()))
    return min(1.0, max(scores)) if scores else 0.0


# ------------------------------------------------------------------------------- tokens
_STOPWORDS = {
    "the", "a", "an", "to", "of", "and", "or", "for", "in", "on", "at", "is", "are", "your",
    "you", "we", "our", "this", "that", "with", "from", "re", "fw", "fwd", "please", "hello",
    "hi", "dear",
}


def _tokens(text: str) -> Dict[str, int]:
    counts: Counter = Counter()
    for raw in (text or "").lower().replace("_", " ").split():
        token = "".join(ch for ch in raw if ch.isalnum())
        if token and token not in _STOPWORDS and len(token) > 2:
            counts[token] += 1
    return dict(counts)


__all__ = [
    "median", "mad", "robust_z", "score_from_z", "novelty", "jaccard", "tri_state",
    "sender_newness_score", "sender_frequency_anomaly", "sender_time_anomaly",
    "sender_domain_change_score", "sender_replyto_anomaly", "sender_url_behavior_anomaly",
    "sender_attachment_anomaly", "sender_authentication_anomaly",
    "recipient_relationship_newness", "recipient_relationship_anomaly",
    "display_name_history_anomaly", "communication_pattern_anomaly",
]
