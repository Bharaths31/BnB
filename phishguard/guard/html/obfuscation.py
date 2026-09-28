"""Static obfuscation / hidden-content analysis (WS3)."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

from bs4 import BeautifulSoup

from guard.evidence import Evidence, EvidenceCategory
from guard.html.features import is_hidden, is_offscreen, is_transparent, is_zero_sized

MODULE = "html.obfuscation"

_REDIRECT_RE = re.compile(r"(window\.location|location\.href|location\.replace|location\.assign)", re.IGNORECASE)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


def analyze_obfuscation(html: str, sender_domain: str = "") -> Tuple[Dict[str, float], List[Evidence], float]:
    soup = BeautifulSoup(html or "", "html.parser")
    hidden = [t for t in soup.find_all() if is_hidden(t)]
    hidden_with_text = [t for t in hidden if t.get_text().strip()]
    hidden_text_length = sum(len(t.get_text().strip()) for t in hidden_with_text)
    zero_sized = [t for t in soup.find_all() if is_zero_sized(t)]
    transparent = [t for t in soup.find_all() if is_transparent(t)]
    offscreen = [t for t in soup.find_all() if is_offscreen(t)]

    style_attrs = [t.get("style", "") for t in soup.find_all(style=True)]
    suspicious_styles = sum(
        1 for s in style_attrs
        if any(token in s.replace(" ", "").lower() for token in
               ("display:none", "visibility:hidden", "opacity:0", "font-size:0", "left:-"))
    )

    script_text = " ".join(s.get_text() for s in soup.find_all("script"))
    js_redirect = len(_REDIRECT_RE.findall(script_text))
    meta_refresh = sum(
        1 for m in soup.find_all("meta", attrs={"http-equiv": True})
        if m.get("http-equiv", "").lower() == "refresh"
    )
    base64_blobs = len(_BASE64_RE.findall(html or ""))

    features: Dict[str, float] = {
        "hidden_text_length": float(hidden_text_length),
        "css_hiding_count": float(len(hidden) + suspicious_styles),
        "zero_sized_element_count": float(len(zero_sized)),
        "transparent_element_count": float(len(transparent)),
        "offscreen_element_count": float(len(offscreen)),
        "suspicious_redirect_count": float(meta_refresh + js_redirect),
        "base64_blob_count": float(base64_blobs),
    }

    evidence: List[Evidence] = []
    score = 0.0
    if hidden_text_length >= 10:
        score = max(score, min(1.0, 0.5 + hidden_text_length / 400.0))
        evidence.append(Evidence.of(EvidenceCategory.HTML, "hidden_text",
                                    f"{hidden_text_length} chars", score, MODULE))
    if suspicious_styles:
        style_score = min(1.0, 0.2 + 0.1 * suspicious_styles)
        score = max(score, style_score)
        evidence.append(Evidence.of(EvidenceCategory.HTML, "css_obfuscation",
                                    f"{suspicious_styles} style(s)", style_score, MODULE))
    if transparent or offscreen:
        score = max(score, 0.5)
        evidence.append(Evidence.of(EvidenceCategory.HTML, "hidden_positioning",
                                    f"{len(transparent) + len(offscreen)} element(s)", 0.5, MODULE))
    if meta_refresh or js_redirect:
        score = max(score, 0.5)
        evidence.append(Evidence.of(EvidenceCategory.HTML, "suspicious_redirect",
                                    f"{meta_refresh + js_redirect}", 0.5, MODULE))
    return features, evidence, score


def hidden_text_excerpt(html: str, limit: int = 200) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    parts = [t.get_text().strip() for t in soup.find_all() if is_hidden(t) and t.get_text().strip()]
    return " ".join(parts)[:limit]
