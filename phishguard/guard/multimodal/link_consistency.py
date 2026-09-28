"""Link consistency: displayed URL text vs destination, OCR text, QR codes (WS2)."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from guard.evidence import Evidence, EvidenceCategory

MODULE = "consistency.link"

_DOMAIN_RE = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.IGNORECASE)


def _host(url: str) -> str:
    if not url:
        return ""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _domain_in_text(text: str) -> str:
    match = _DOMAIN_RE.search(text or "")
    return match.group(1).lower() if match else ""


def link_features(parsed) -> Tuple[Dict[str, float], List[Evidence]]:
    features: Dict[str, float] = {
        "display_href_mismatch": 0.0,
        "display_domain_mismatch": 0.0,
        "ocr_url_mismatch": 0.0,
        "qr_context_mismatch": 0.0,
    }
    evidence: List[Evidence] = []

    urls = list(getattr(parsed, "urls", []) or [])
    considered = 0
    display_mismatch = 0
    domain_mismatch = 0
    for url in urls:
        display = (url.display_text or "").strip()
        if not display:
            continue
        considered += 1
        if url.display_text_mismatch:
            display_mismatch += 1
        text_host = _domain_in_text(display)
        if text_host and url.domain and text_host != url.domain:
            domain_mismatch += 1

    if considered:
        features["display_href_mismatch"] = display_mismatch / considered
        features["display_domain_mismatch"] = domain_mismatch / considered
        if features["display_domain_mismatch"] >= 0.5:
            evidence.append(Evidence.of(EvidenceCategory.CONSISTENCY, "display_href_mismatch",
                                        f"{domain_mismatch}/{considered} links", 0.9, MODULE,
                                        severity="critical", confidence="high"))

    # OCR text vs actual link destinations.
    image_text = (getattr(parsed, "extracted_image_text", "") or "").lower()
    url_domains = {u.domain.lower() for u in urls if u.domain}
    ocr_domains = set(_DOMAIN_RE.findall(image_text))
    if ocr_domains and url_domains and not (ocr_domains & url_domains):
        features["ocr_url_mismatch"] = 0.8
        evidence.append(Evidence.of(EvidenceCategory.CONSISTENCY, "ocr_url_mismatch",
                                    f"OCR {sorted(ocr_domains)[:1]} vs {sorted(url_domains)[:1]}",
                                    0.8, MODULE))
    elif ocr_domains and not url_domains:
        features["ocr_url_mismatch"] = 0.5

    # QR destination vs surrounding message text.
    qr_urls = list(getattr(parsed, "extracted_qr_urls", []) or [])
    if qr_urls:
        qr_domains = {_host(u) for u in qr_urls if _host(u)}
        visible = (getattr(parsed, "visible_text", "") or "").lower()
        if qr_domains and not any(d in visible for d in qr_domains):
            features["qr_context_mismatch"] = 0.7
            evidence.append(Evidence.of(EvidenceCategory.CONSISTENCY, "qr_context_mismatch",
                                        f"QR -> {sorted(qr_domains)[:1]}", 0.7, MODULE))

    return features, evidence
