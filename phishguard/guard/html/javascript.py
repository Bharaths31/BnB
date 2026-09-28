"""Static JavaScript analysis (WS3). Scripts are inspected as text, never executed."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

from bs4 import BeautifulSoup

from guard.evidence import Evidence, EvidenceCategory
from guard.html.features import shannon_entropy

MODULE = "html.javascript"

SUSPICIOUS_TOKENS = (
    "eval(", "atob(", "btoa(", "unescape(", "string.fromcharcode", "fromcharcode",
    "document.write", "xmlhttprequest", "fetch(", "window.location", "location.href",
    "location.replace", "location.assign", "new function", "settimeout(", "decodeuri",
)

_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_UNICODE_ESCAPE_RE = re.compile(r"%u[0-9a-fA-F]{4}")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")


def analyze_scripts(html: str) -> Tuple[Dict[str, float], List[Evidence], float]:
    soup = BeautifulSoup(html or "", "html.parser")
    scripts = soup.find_all("script")
    inline = [s for s in scripts if not s.get("src")]
    combined = " ".join(s.get_text() for s in inline)

    lowered = combined.lower()
    token_count = sum(lowered.count(token) for token in SUSPICIOUS_TOKENS)
    hex_escapes = len(_HEX_ESCAPE_RE.findall(combined))
    unicode_escapes = len(_UNICODE_ESCAPE_RE.findall(combined))
    base64_blobs = len(_BASE64_RE.findall(combined))
    encoded_indicators = hex_escapes + unicode_escapes + base64_blobs
    entropy = shannon_entropy(combined)

    features: Dict[str, float] = {
        "javascript_size": float(len(combined)),
        "javascript_entropy": float(entropy),
        "suspicious_javascript_tokens": float(token_count),
        "encoded_javascript_indicators": float(encoded_indicators),
        "base64_script_blob_count": float(base64_blobs),
        "hex_escape_count": float(hex_escapes),
        "unicode_escape_count": float(unicode_escapes),
    }

    evidence: List[Evidence] = []
    score = 0.0
    if encoded_indicators:
        score = max(score, min(1.0, 0.4 + 0.1 * encoded_indicators))
        evidence.append(Evidence.of(EvidenceCategory.HTML, "encoded_javascript",
                                    f"{encoded_indicators} indicator(s)", score, MODULE))
    if token_count:
        token_score = min(1.0, 0.2 + 0.15 * token_count)
        score = max(score, token_score)
        evidence.append(Evidence.of(EvidenceCategory.HTML, "suspicious_js_tokens",
                                    f"{token_count} token(s)", token_score, MODULE))
    # Very high entropy in a script is a mild obfuscation signal.
    if entropy >= 5.0:
        score = max(score, 0.4)
        evidence.append(Evidence.of(EvidenceCategory.HTML, "js_entropy",
                                    f"{entropy:.2f}", min(1.0, entropy / 8.0), MODULE))
    return features, evidence, score
