"""Anti-evasion text / URL normalisation.

Uses the ``confusables`` package when available and otherwise falls back to a built-in
homoglyph folding table, so normalisation (and everything downstream that depends on it,
including the adversarial homoglyph tests) works on a bare CPU machine.
"""
from __future__ import annotations

import re
import unicodedata
import urllib.parse

from bs4 import BeautifulSoup

try:  # optional dependency
    import confusables as _confusables  # type: ignore
except Exception:  # pragma: no cover - exercised when the package is absent
    _confusables = None

# Zero-width / invisible characters used to split keywords.
_ZERO_WIDTH_RE = re.compile(r"[\u200B\u200C\u200D\uFEFF\u2060\u00AD]")
# Bidirectional override / isolate characters.
_BIDI_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")

#: Conservative homoglyph fold table (Cyrillic / Greek / common lookalikes).
_BUILTIN_CONFUSABLES = {
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0455": "s", "\u0458": "j",
    "\u0501": "d", "\u04bb": "h", "\u04cf": "l", "\u043c": "m", "\u043d": "h",
    "\u043a": "k", "\u0432": "b", "\u0442": "t", "\u0433": "r", "\u0437": "3",
    # Greek
    "\u03bf": "o", "\u03c1": "p", "\u03b1": "a", "\u03b5": "e", "\u03b9": "i",
    "\u03bd": "v", "\u03ba": "k", "\u03c4": "t", "\u03c5": "u", "\u03c7": "x",
    "\u03b2": "b", "\u03b7": "n", "\u03bc": "m", "\u03c3": "o",
    # Latin extended lookalikes
    "\u0131": "i", "\u0142": "l", "\u00f8": "o", "\u00e6": "ae", "\u0153": "oe",
    # Digits often substituted in domains
    "0": "o", "1": "l", "3": "e", "5": "s",
}


def _fold_confusables(text: str) -> str:
    if _confusables is not None:
        try:
            normalized = _confusables.normalize(text, prioritize_alpha=True)
            if normalized:
                return normalized[0]
        except Exception:
            pass
    return "".join(_BUILTIN_CONFUSABLES.get(ch, ch) for ch in text)


def normalize_text(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH_RE.sub("", text)
    text = _BIDI_RE.sub("", text)
    text = _fold_confusables(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def normalize_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    url = unicodedata.normalize("NFKC", url)
    url = _ZERO_WIDTH_RE.sub("", url)
    url = _BIDI_RE.sub("", url)
    url = urllib.parse.unquote(url)
    url = re.sub(r"hxxps?://", "http://", url, flags=re.IGNORECASE)
    url = url.replace("[.]", ".").replace("(.)", ".")
    return url


def visible_text_from_html(html: str) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.extract()
    return soup.get_text(separator=" ")
