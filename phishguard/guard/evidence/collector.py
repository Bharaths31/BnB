"""Deterministic evidence collection and ranking (WS11).

The collector is intentionally tiny: it de-duplicates by ``evidence_id`` (keeping the
strongest observation), preserves insertion order for ties, and exposes a deterministic
``top(n)`` ranking used by the explanation engine and the dashboard.
"""
from __future__ import annotations

from typing import Dict, Iterable, List

from guard.evidence.models import Evidence, EvidenceCategory


class EvidenceCollector:
    """Accumulates evidence from every detector and ranks it deterministically."""

    def __init__(self) -> None:
        self._items: Dict[str, Evidence] = {}

    # ------------------------------------------------------------------ mutation
    def add(self, evidence: Evidence) -> None:
        existing = self._items.get(evidence.evidence_id)
        if existing is None or evidence.rank_score > existing.rank_score:
            self._items[evidence.evidence_id] = evidence

    def extend(self, items: Iterable[Evidence]) -> None:
        for item in items:
            self.add(item)

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._items)

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return bool(self._items)

    # ------------------------------------------------------------------ queries
    def all(self) -> List[Evidence]:
        """All evidence in insertion order (stable)."""
        return list(self._items.values())

    def top(self, n: int = 5) -> List[Evidence]:
        """Highest-value evidence, deterministically ordered.

        Sort key: ``rank_score`` descending, then severity weight, then ``feature`` name.
        The secondary keys make the ordering total, so identical inputs always produce an
        identical explanation.
        """
        ordered = sorted(
            self._items.values(),
            key=lambda e: (-e.rank_score, -e.normalized_score, e.feature, e.evidence_id),
        )
        return ordered[:n]

    def by_category(self) -> Dict[str, List[Evidence]]:
        buckets: Dict[str, List[Evidence]] = {}
        for item in self._items.values():
            buckets.setdefault(item.category.value, []).append(item)
        return buckets

    def category_scores(self) -> Dict[str, float]:
        """Max normalised score per category (used as component inputs)."""
        scores: Dict[str, float] = {}
        for item in self._items.values():
            key = item.category.value
            scores[key] = max(scores.get(key, 0.0), item.normalized_score)
        return scores

    def features(self) -> Dict[str, float]:
        """Feature candidates for the fusion model, namespaced by category."""
        out: Dict[str, float] = {}
        for item in self._items.values():
            out[f"{item.category.value.lower()}.{item.feature}"] = item.normalized_score
        return out


__all__ = ["Evidence", "EvidenceCategory", "EvidenceCollector"]
