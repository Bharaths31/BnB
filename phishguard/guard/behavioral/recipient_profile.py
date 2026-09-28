"""Historical sender-recipient relationship profiles (WS1)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from guard.behavioral.anomaly import _tokens, jaccard, mad, median
from guard.behavioral.sender_profile import _append_capped, _bump


class RelationshipProfile(BaseModel):
    sender: str = ""
    recipient: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    message_count: int = 0
    attachment_messages: int = 0

    interval_samples: List[float] = Field(default_factory=list)
    length_samples: List[float] = Field(default_factory=list)
    url_count_samples: List[float] = Field(default_factory=list)
    subject_sim_samples: List[float] = Field(default_factory=list)

    subject_tokens: Dict[str, int] = Field(default_factory=dict)
    url_domains: Dict[str, int] = Field(default_factory=dict)
    attachment_types: Dict[str, int] = Field(default_factory=dict)

    avg_interval_seconds: Optional[float] = None
    interval_mad: Optional[float] = None
    median_message_length: float = 0.0
    length_mad: float = 0.0
    url_count_median: float = 0.0
    url_count_mad: float = 0.0
    typical_subject_similarity: float = 0.0
    attachment_frequency: float = 0.0

    @property
    def is_new(self) -> bool:
        return self.message_count < 2

    def recompute(self) -> "RelationshipProfile":
        if self.interval_samples:
            self.avg_interval_seconds = median(self.interval_samples)
            self.interval_mad = mad(self.interval_samples, self.avg_interval_seconds)
        if self.length_samples:
            self.median_message_length = median(self.length_samples)
            self.length_mad = mad(self.length_samples, self.median_message_length)
        if self.url_count_samples:
            self.url_count_median = median(self.url_count_samples)
            self.url_count_mad = mad(self.url_count_samples, self.url_count_median)
        if self.subject_sim_samples:
            self.typical_subject_similarity = median(self.subject_sim_samples)
        if self.message_count > 0:
            self.attachment_frequency = self.attachment_messages / self.message_count
        return self


def update_relationship_profile(
    rel: Optional[RelationshipProfile],
    parsed,
    now: Optional[datetime] = None,
    recipient: str = "",
) -> RelationshipProfile:
    """Fold one analysed email into a sender->recipient relationship profile."""
    now = now or parsed.received_at or datetime.now(timezone.utc)
    recipient = (recipient or (parsed.recipients[0] if parsed.recipients else "")).lower()
    if rel is None:
        rel = RelationshipProfile(
            sender=(parsed.from_addr or "").lower(), recipient=recipient, first_seen=now
        )
    if rel.first_seen is None:
        rel.first_seen = now

    if rel.last_seen is not None and now >= rel.last_seen:
        _append_capped(rel.interval_samples, (now - rel.last_seen).total_seconds())

    tokens = _tokens(parsed.subject)
    if rel.subject_tokens:
        _append_capped(rel.subject_sim_samples, jaccard(tokens, rel.subject_tokens))
    for token in tokens:
        _bump(rel.subject_tokens, token)

    _append_capped(rel.length_samples, float(len(parsed.visible_text or parsed.normalized_body or "")))
    _append_capped(rel.url_count_samples, float(len(parsed.urls)))
    for url in parsed.urls:
        if url.domain:
            _bump(rel.url_domains, url.domain)
    if parsed.attachments:
        rel.attachment_messages += 1
        for att in parsed.attachments:
            if att.content_type:
                _bump(rel.attachment_types, att.content_type)

    rel.message_count += 1
    rel.last_seen = now
    return rel.recompute()
