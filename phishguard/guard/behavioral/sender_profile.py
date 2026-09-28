"""Historical sender profiles (WS1).

A profile keeps a capped reservoir of numeric samples (for robust median/MAD statistics) and
frequency counters for categorical distributions. ``recompute`` derives the summary
statistics the anomaly engine reads.
"""
from __future__ import annotations

from datetime import datetime, timezone
from collections import Counter
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from guard.behavioral.anomaly import _tokens, mad, median
from guard.behavioral.temporal_features import circular_hour_mean, weekday_mode

MAX_SAMPLES = 500
MAX_COUNTER = 200


def _append_capped(samples: List[float], value: float) -> None:
    samples.append(float(value))
    if len(samples) > MAX_SAMPLES:
        del samples[: len(samples) - MAX_SAMPLES]


def _bump(counter: Dict[str, int], key: str, amount: int = 1) -> None:
    if not key:
        return
    counter[key] = counter.get(key, 0) + amount
    if len(counter) > MAX_COUNTER:
        keep = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:MAX_COUNTER]
        counter.clear()
        counter.update(dict(keep))


class SenderProfile(BaseModel):
    sender: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_messages: int = 0
    attachment_messages: int = 0

    # numeric reservoirs
    length_samples: List[float] = Field(default_factory=list)
    url_count_samples: List[float] = Field(default_factory=list)
    interval_samples: List[float] = Field(default_factory=list)
    hour_samples: List[float] = Field(default_factory=list)
    weekday_samples: List[float] = Field(default_factory=list)

    # categorical distributions
    recipient_domains: Dict[str, int] = Field(default_factory=dict)
    recipient_addresses: Dict[str, int] = Field(default_factory=dict)
    subject_tokens: Dict[str, int] = Field(default_factory=dict)
    sender_domains: Dict[str, int] = Field(default_factory=dict)
    replyto_domains: Dict[str, int] = Field(default_factory=dict)
    display_names: Dict[str, int] = Field(default_factory=dict)
    auth_outcomes: Dict[str, int] = Field(default_factory=dict)
    url_domains: Dict[str, int] = Field(default_factory=dict)
    attachment_types: Dict[str, int] = Field(default_factory=dict)
    campaigns: Dict[str, int] = Field(default_factory=dict)
    display_consistency_ok: int = 0
    display_consistency_total: int = 0

    # derived statistics (recomputed)
    messages_per_day: float = 0.0
    typical_sending_hour: Optional[float] = None
    typical_sending_weekday: Optional[int] = None
    median_message_length: float = 0.0
    length_mad: float = 0.0
    url_count_median: float = 0.0
    url_count_mad: float = 0.0
    median_interval_seconds: Optional[float] = None
    interval_mad: Optional[float] = None
    attachment_frequency: float = 0.0

    @property
    def display_key(self) -> str:
        """Most frequently observed display name for this sender identity."""
        if not self.display_names:
            return ""
        return max(self.display_names.items(), key=lambda kv: kv[1])[0]

    def recompute(self) -> "SenderProfile":
        if self.length_samples:
            self.median_message_length = median(self.length_samples)
            self.length_mad = mad(self.length_samples, self.median_message_length)
        if self.url_count_samples:
            self.url_count_median = median(self.url_count_samples)
            self.url_count_mad = mad(self.url_count_samples, self.url_count_median)
        if self.interval_samples:
            self.median_interval_seconds = median(self.interval_samples)
            self.interval_mad = mad(self.interval_samples, self.median_interval_seconds)
        self.typical_sending_hour = circular_hour_mean(self.hour_samples)
        # "Typical weekday" is only meaningful when the sender's weekday distribution is
        # concentrated; for a sender who mails every day it is noise, so we drop it.
        if self.weekday_samples:
            counts = Counter(self.weekday_samples)
            mode, count = counts.most_common(1)[0]
            concentration = count / len(self.weekday_samples)
            self.typical_sending_weekday = int(mode) if concentration >= 0.5 else None
        else:
            self.typical_sending_weekday = None
        if self.total_messages > 0:
            self.attachment_frequency = self.attachment_messages / self.total_messages
        if self.first_seen and self.last_seen:
            span_days = max((self.last_seen - self.first_seen).total_seconds() / 86400.0, 1.0 / 24.0)
            self.messages_per_day = self.total_messages / span_days
        return self


def _auth_outcome(parsed) -> str:
    return "fail" if any(
        getattr(parsed, f"{name}_result", "none") == "fail" for name in ("spf", "dkim", "dmarc")
    ) else "pass"


def update_sender_profile(
    profile: Optional[SenderProfile],
    parsed,
    now: Optional[datetime] = None,
    label: str = "unknown",
) -> SenderProfile:
    """Fold one analysed email into the sender's profile."""
    now = now or parsed.received_at or datetime.now(timezone.utc)
    if profile is None:
        profile = SenderProfile(sender=(parsed.from_addr or "").lower(), first_seen=now)
    if profile.first_seen is None:
        profile.first_seen = now

    if profile.last_seen is not None and now >= profile.last_seen:
        _append_capped(profile.interval_samples, (now - profile.last_seen).total_seconds())

    body_len = len(parsed.visible_text or parsed.normalized_body or "")
    _append_capped(profile.length_samples, float(body_len))
    _append_capped(profile.url_count_samples, float(len(parsed.urls)))
    _append_capped(profile.hour_samples, now.hour + now.minute / 60.0)
    _append_capped(profile.weekday_samples, now.weekday())

    for recipient in parsed.recipients:
        _bump(profile.recipient_addresses, recipient.lower())
        if "@" in recipient:
            _bump(profile.recipient_domains, recipient.split("@")[-1].lower())
    for token in _tokens(parsed.subject):
        _bump(profile.subject_tokens, token)
    if parsed.sender_domain:
        _bump(profile.sender_domains, parsed.sender_domain)
    if parsed.replyto_domain:
        _bump(profile.replyto_domains, parsed.replyto_domain)

    display = (parsed.from_display or "").strip().lower()
    if display:
        if profile.total_messages > 0:
            profile.display_consistency_total += 1
            if display in profile.display_names:
                profile.display_consistency_ok += 1
        _bump(profile.display_names, display)

    _bump(profile.auth_outcomes, _auth_outcome(parsed))
    for url in parsed.urls:
        if url.domain:
            _bump(profile.url_domains, url.domain)
    if parsed.attachments:
        profile.attachment_messages += 1
        for att in parsed.attachments:
            if att.content_type:
                _bump(profile.attachment_types, att.content_type)

    profile.total_messages += 1
    profile.last_seen = now
    return profile.recompute()
