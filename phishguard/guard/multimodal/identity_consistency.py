"""Identity consistency: display name, sender domain, Reply-To, claimed brand (WS2).

Deterministic only — no generative model. Brand detection uses a configurable dictionary with
Unicode/punycode canonicalisation, edit distance, confusable distance and domain-token
similarity, and explicitly distinguishes exact legitimate domains from lookalikes.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Set, Tuple

from guard.config import policy
from guard.evidence import Evidence, EvidenceCategory
from guard.parse.normalizer import normalize_text

MODULE = "consistency.identity"

_DOMAIN_RE = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.IGNORECASE)


def load_brand_table() -> Dict[str, dict]:
    brands = policy.get("brands") or {}
    if brands:
        return {
            key.lower(): {
                "display": meta.get("display", key.title()),
                "legitimate_domains": [d.lower() for d in meta.get("legitimate_domains", [])],
            }
            for key, meta in brands.items()
        }
    protected = policy.get("protected_brands") or []
    return {
        b.lower(): {"display": b.title(), "legitimate_domains": [f"{b}.com"]} for b in protected
    }


BRANDS: Dict[str, dict] = load_brand_table()
MAILING_DOMAINS: Set[str] = {d.lower() for d in (policy.get("legitimate_mailing_domains") or [])}


# --------------------------------------------------------------------------- primitives
def edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def confusable_distance(a: str, b: str) -> int:
    return edit_distance(normalize_text(a).lower(), normalize_text(b).lower())


def token_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def is_mailing_domain(domain: str) -> bool:
    domain = (domain or "").lower()
    return any(domain == d or domain.endswith("." + d) for d in MAILING_DOMAINS)


def is_legitimate_domain(domain: str, brand_meta: dict) -> bool:
    domain = (domain or "").lower()
    return any(domain == d or domain.endswith("." + d) for d in brand_meta.get("legitimate_domains", []))


def is_lookalike(domain: str, brand_meta: dict) -> bool:
    """True when ``domain`` is NOT legitimate but visually resembles a legitimate domain."""
    domain = (domain or "").lower()
    if not domain:
        return False
    for legit in brand_meta.get("legitimate_domains", []):
        if domain == legit or domain.endswith("." + legit):
            return False
        if edit_distance(domain, legit) <= 2:
            return True
        if confusable_distance(domain, legit) <= 1:
            return True
        core = legit.split(".")[0]
        if core and core in domain:
            return True
    return False


def claimed_brands(text: str) -> Set[str]:
    lowered = (text or "").lower()
    claimed = set()
    for key, meta in BRANDS.items():
        if key in lowered or meta["display"].lower() in lowered:
            claimed.add(key)
    return claimed


def _is_any_legitimate(domain: str) -> bool:
    return any(is_legitimate_domain(domain, meta) for meta in BRANDS.values())


def _domain_in_text(text: str) -> str:
    match = _DOMAIN_RE.search(text or "")
    return match.group(1).lower() if match else ""


# ----------------------------------------------------------------------------- features
def identity_features(parsed, profile=None) -> Tuple[Dict[str, float], List[Evidence]]:
    features: Dict[str, float] = {
        "sender_identity_mismatch": 0.0,
        "replyto_identity_mismatch": 0.0,
        "brand_domain_mismatch": 0.0,
        "brand_visual_domain_mismatch": 0.0,
        "identity_history_mismatch": 0.0,
    }
    evidence: List[Evidence] = []

    sender_domain = getattr(parsed, "sender_domain", "") or ""
    display = getattr(parsed, "from_display", "") or ""
    subject = getattr(parsed, "subject", "") or ""
    reply_to_domain = getattr(parsed, "replyto_domain", "") or ""

    # 1. Display-name vs sender-domain: a domain or brand token in the display name must match.
    display_domain = _domain_in_text(display)
    if display_domain and sender_domain and display_domain != sender_domain:
        features["sender_identity_mismatch"] = max(features["sender_identity_mismatch"], 0.8)
        evidence.append(Evidence.of(EvidenceCategory.CONSISTENCY, "sender_identity_mismatch",
                                    f"{display_domain} vs {sender_domain}", 0.8, MODULE))

    # 2. Brand claim vs actual sender domain.
    claimed = claimed_brands(display + " " + subject)
    for brand in claimed:
        meta = BRANDS[brand]
        if is_legitimate_domain(sender_domain, meta) or is_mailing_domain(sender_domain):
            continue
        if is_lookalike(sender_domain, meta):
            features["brand_visual_domain_mismatch"] = max(features["brand_visual_domain_mismatch"], 0.9)
            features["brand_domain_mismatch"] = max(features["brand_domain_mismatch"], 0.9)
            evidence.append(Evidence.of(EvidenceCategory.CONSISTENCY, "brand_visual_domain_mismatch",
                                        f"claims {meta['display']} from {sender_domain}", 0.9, MODULE,
                                        severity="critical", confidence="high"))
        else:
            features["brand_domain_mismatch"] = max(features["brand_domain_mismatch"], 0.6)
            features["sender_identity_mismatch"] = max(features["sender_identity_mismatch"], 0.5)
            evidence.append(Evidence.of(EvidenceCategory.CONSISTENCY, "brand_domain_mismatch",
                                        f"claims {meta['display']} from {sender_domain}", 0.6, MODULE))

    # 3. Reply-To vs From.
    if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
        score = 0.15 if is_mailing_domain(reply_to_domain) else 0.7
        if _is_any_legitimate(reply_to_domain):
            score = 0.2
        features["replyto_identity_mismatch"] = score
        if score >= 0.5:
            evidence.append(Evidence.of(EvidenceCategory.CONSISTENCY, "replyto_identity_mismatch",
                                        f"reply-to {reply_to_domain}", score, MODULE))

    # 4. Claimed organisation vs historical sender identity (behavioral profile).
    if profile is not None:
        history_domains = getattr(profile, "sender_domains", {}) or {}
        history_names = getattr(profile, "display_names", {}) or {}
        if history_domains and sender_domain and sender_domain not in history_domains:
            features["identity_history_mismatch"] = max(features["identity_history_mismatch"], 0.6)
        if history_names and display and display.strip().lower() not in history_names:
            features["identity_history_mismatch"] = max(features["identity_history_mismatch"], 0.4)
        if features["identity_history_mismatch"] >= 0.5:
            evidence.append(Evidence.of(EvidenceCategory.CONSISTENCY, "identity_history_mismatch",
                                        "sender identity changed vs history",
                                        features["identity_history_mismatch"], MODULE))

    return features, evidence
