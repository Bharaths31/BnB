"""Structured phishing-intent features (WS10).

Extends the existing tactic classifier rather than replacing it. The existing labels are
preserved and exposed under canonical names, and derived intent scores are computed from
**conjunctions of language tactics and verified technical signals** — so no single language
feature is ever sufficient on its own.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from guard.component import AnalysisContext, ComponentResult
from guard.evidence import Evidence, EvidenceCategory
from guard.nlp.tactic_classifier import tactic_classifier

MODULE = "intent"

#: Canonical tactic labels required by the specification.
CANONICAL_TACTICS = [
    "urgency",
    "authority_impersonation",
    "credential_request",
    "payment_gift_card",
    "link_bait",
    "attachment_lure",
]

_LINK_TOKENS = ("click here", "click the link", "click below", "follow this link", "verify at",
                "login at", "sign in at", "http://", "https://")
_ATTACHMENT_TOKENS = ("attached", "attachment", "open the", "enable macros", "see the file",
                      "download the", "review the document", "open the document")
_QR_TOKENS = ("scan the qr", "scan this qr", "qr code", "scan the code")
_GIFT_TOKENS = ("gift card", "itunes card", "steam card", "google play card")


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


class IntentResult(BaseModel):
    tactics: Dict[str, float] = Field(default_factory=dict)
    tactic_confidence: Dict[str, float] = Field(default_factory=dict)
    derived_intent_scores: Dict[str, float] = Field(default_factory=dict)
    evidence: List[str] = Field(default_factory=list)


def canonical_tactics(text: str, base_tactics: Optional[Dict[str, float]] = None,
                      has_urls: bool = False, has_attachments: bool = False,
                      has_qr: bool = False) -> Dict[str, float]:
    base = base_tactics or {}
    lowered = (text or "").lower()

    urgency = float(base.get("urgency", 0.0))
    authority = float(base.get("authority", 0.0))
    credential = float(base.get("credential_request", 0.0))
    payment = float(base.get("financial", 0.0))

    if any(token in lowered for token in _GIFT_TOKENS):
        payment = max(payment, 0.7)
    if any(token in lowered for token in ("password", "sign in", "log in", "login", "2fa", "verify your identity")):
        credential = max(credential, 0.5)

    link_bait = 0.0
    if has_urls and any(token in lowered for token in _LINK_TOKENS):
        link_bait = 0.6
    elif has_urls and (urgency or credential):
        link_bait = 0.4

    attachment_lure = 0.0
    if has_attachments or any(token in lowered for token in _ATTACHMENT_TOKENS):
        attachment_lure = 0.6 if any(token in lowered for token in _ATTACHMENT_TOKENS) or has_attachments else 0.0

    if has_qr:
        link_bait = max(link_bait, 0.5)

    return {
        "urgency": _clamp(urgency),
        "authority_impersonation": _clamp(authority),
        "credential_request": _clamp(credential),
        "payment_gift_card": _clamp(payment),
        "link_bait": _clamp(link_bait),
        "attachment_lure": _clamp(attachment_lure),
    }


def derived_intent_scores(tactics: Dict[str, float], technical: Dict[str, float]) -> Dict[str, float]:
    urgency = tactics.get("urgency", 0.0)
    authority = tactics.get("authority_impersonation", 0.0)
    credential = tactics.get("credential_request", 0.0)
    payment = tactics.get("payment_gift_card", 0.0)
    link_bait = tactics.get("link_bait", 0.0)
    attachment_lure = tactics.get("attachment_lure", 0.0)

    url_suspicious = technical.get("url_suspicious", 0.0)
    brand_mismatch = technical.get("brand_domain_mismatch", 0.0)
    replyto_mismatch = technical.get("replyto_mismatch", 0.0)
    attachment_risk = technical.get("attachment_risk", 0.0)
    auth_fail = technical.get("auth_fail", 0.0)

    web = max(url_suspicious, brand_mismatch)

    return {
        "credential_harvesting_score": _clamp(credential * max(web, 0.0)),
        "financial_fraud_score": _clamp(payment * max(0.4, authority, replyto_mismatch, 0.9 * urgency)),
        "account_takeover_score": _clamp(credential * max(brand_mismatch, auth_fail, 0.3)),
        "business_email_compromise_score": _clamp(authority * payment * (0.6 + 0.4 * replyto_mismatch)),
        "malicious_attachment_score": _clamp(attachment_lure * max(attachment_risk, 0.3)),
        "social_engineering_score": _clamp(max(urgency, authority) * (0.5 + 0.5 * max(link_bait, attachment_lure))),
    }


def _technical_signals(parsed) -> Dict[str, float]:
    urls = list(getattr(parsed, "urls", []) or [])
    risky_tlds = {"zip", "mov", "xyz", "top", "club", "live", "click", "ru", "tk", "gq", "cf", "work"}
    url_suspicious = 0.0
    for url in urls:
        domain = (url.domain or "").lower()
        if url.is_punycode:
            url_suspicious = max(url_suspicious, 0.8)
        if url.domain and url.domain != "" and url.display_text_mismatch:
            url_suspicious = max(url_suspicious, 0.7)
        if "@" in url.raw_url:
            url_suspicious = max(url_suspicious, 0.7)
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        if tld in risky_tlds:
            url_suspicious = max(url_suspicious, 0.5)
        if domain and (any(ch.isdigit() for ch in domain.split(".")[0]) or "-" in domain.split(".")[0]):
            url_suspicious = max(url_suspicious, 0.4)

    # Brand mismatch from the consistency engine (deterministic, cheap).
    try:
        from guard.multimodal.identity_consistency import identity_features

        identity, _ = identity_features(parsed)
        brand_mismatch = max(identity.get("brand_domain_mismatch", 0.0),
                             identity.get("brand_visual_domain_mismatch", 0.0))
        replyto_mismatch = identity.get("replyto_identity_mismatch", 0.0)
    except Exception:
        brand_mismatch = 0.0
        replyto_mismatch = 0.0

    attachment_risk = 0.0
    for att in getattr(parsed, "attachments", []) or []:
        from guard.attachment.features import filename_risk

        attachment_risk = max(attachment_risk, filename_risk(att.filename))
        if att.has_macros:
            attachment_risk = max(attachment_risk, 0.8)

    auth_fail = 1.0 if any(
        getattr(parsed, f"{name}_result", "none") == "fail" for name in ("spf", "dkim", "dmarc")
    ) else 0.0

    return {
        "url_suspicious": _clamp(url_suspicious),
        "brand_domain_mismatch": _clamp(brand_mismatch),
        "replyto_mismatch": _clamp(replyto_mismatch),
        "attachment_risk": _clamp(attachment_risk),
        "auth_fail": auth_fail,
    }


def classify_intent(parsed) -> IntentResult:
    text = getattr(parsed, "normalized_body", "") or getattr(parsed, "visible_text", "") or ""
    base = tactic_classifier.classify(text)
    tactics = canonical_tactics(
        text,
        base,
        has_urls=bool(getattr(parsed, "urls", [])),
        has_attachments=bool(getattr(parsed, "attachments", [])),
        has_qr=bool(getattr(parsed, "extracted_qr_urls", [])),
    )
    technical = _technical_signals(parsed)
    derived = derived_intent_scores(tactics, technical)
    evidence = [
        f"{name}={value:.2f}"
        for name, value in sorted(derived.items(), key=lambda kv: kv[1], reverse=True)
        if value >= 0.5
    ]
    return IntentResult(
        tactics=tactics,
        tactic_confidence=dict(base),
        derived_intent_scores=derived,
        evidence=evidence,
    )


class IntentComponent:
    name = "intent"

    def run(self, parsed, ctx: AnalysisContext) -> ComponentResult:
        result = classify_intent(parsed)
        features: Dict[str, float] = {
            **{f"tactic.{k}": v for k, v in result.tactics.items()},
            **result.derived_intent_scores,
        }
        evidence = [
            Evidence.of(EvidenceCategory.TACTIC, name, f"{value:.2f}", value, MODULE)
            for name, value in result.derived_intent_scores.items()
            if value >= 0.5
        ]
        return ComponentResult(name=self.name, features=features, evidence=evidence)

    def fallback(self, parsed, ctx: AnalysisContext) -> ComponentResult:
        return ComponentResult(
            name=self.name,
            features={f"tactic.{k}": 0.0 for k in CANONICAL_TACTICS}
            | {k: 0.0 for k in (
                "credential_harvesting_score", "financial_fraud_score", "account_takeover_score",
                "business_email_compromise_score", "malicious_attachment_score",
                "social_engineering_score")},
            evidence=[],
            degraded=True,
        )


__all__ = [
    "IntentComponent",
    "IntentResult",
    "classify_intent",
    "canonical_tactics",
    "derived_intent_scores",
    "CANONICAL_TACTICS",
]
