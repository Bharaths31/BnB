"""Semantic consistency: subject/body, text/URL, attachment context (WS2).

Uses deterministic token overlap (Jaccard) — no generative model.
"""
from __future__ import annotations

from typing import Dict, List, Set, Tuple

from guard.evidence import Evidence, EvidenceCategory

MODULE = "consistency.semantic"

_STOPWORDS = {
    "the", "a", "an", "to", "of", "and", "or", "for", "in", "on", "at", "is", "are", "your",
    "you", "we", "our", "this", "that", "with", "from", "re", "fw", "fwd", "please", "hello",
    "hi", "dear", "here", "https", "http", "www", "com", "net", "org",
}

_EXT_MIME = {
    "pdf": ("application/pdf",),
    "doc": ("msword",),
    "docx": ("wordprocessingml",),
    "docm": ("wordprocessingml", "macroenabled"),
    "xls": ("ms-excel",),
    "xlsx": ("spreadsheetml",),
    "xlsm": ("spreadsheetml", "macroenabled"),
    "ppt": ("ms-powerpoint",),
    "pptx": ("presentationml",),
    "zip": ("zip",),
    "jpg": ("image/jpeg", "image/jpg"),
    "jpeg": ("image/jpeg", "image/jpg"),
    "png": ("image/png",),
    "gif": ("image/gif",),
    "svg": ("image/svg",),
    "html": ("text/html", "html"),
    "txt": ("text/plain",),
    "ics": ("calendar",),
}


def tokens(text: str) -> Set[str]:
    out: Set[str] = set()
    for raw in (text or "").lower().replace("_", " ").split():
        token = "".join(ch for ch in raw if ch.isalnum())
        if token and token not in _STOPWORDS and len(token) > 2:
            out.add(token)
    return out


def jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def containment(a: Set[str], b: Set[str]) -> float:
    """Fraction of ``a`` present in ``b`` (asymmetric — suited to short subjects/filenames)."""
    if not a:
        return 1.0
    if not b:
        return 0.0
    return len(a & b) / len(a)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def _filename_mime_mismatch(filename: str, content_type: str) -> float:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in (filename or "") else ""
    expected = _EXT_MIME.get(ext)
    if not expected or not content_type:
        return 0.0
    declared = content_type.lower()
    return 0.0 if any(token in declared for token in expected) else 0.6


def semantic_features(parsed) -> Tuple[Dict[str, float], List[Evidence]]:
    features: Dict[str, float] = {
        "text_url_semantic_mismatch": 0.0,
        "subject_body_mismatch": 0.0,
        "attachment_context_mismatch": 0.0,
        "attachment_filename_mime_mismatch": 0.0,
    }
    evidence: List[Evidence] = []

    body_tokens = tokens(getattr(parsed, "visible_text", "") or getattr(parsed, "body_plain", ""))
    subject_tokens = tokens(getattr(parsed, "subject", "") or "")

    if subject_tokens and body_tokens:
        features["subject_body_mismatch"] = _clamp(1.0 - containment(subject_tokens, body_tokens) - 0.2)

    urls = list(getattr(parsed, "urls", []) or [])
    if urls and body_tokens:
        best = 0.0
        for url in urls:
            url_tokens = tokens(url.domain.replace(".", " ").replace("-", " ")) | tokens(url.normalized)
            best = max(best, containment(url_tokens, body_tokens))
        features["text_url_semantic_mismatch"] = _clamp(1.0 - best - 0.3)

    attachments = list(getattr(parsed, "attachments", []) or [])
    if attachments:
        best_att = 0.0
        for att in attachments:
            best_att = max(best_att, containment(tokens(att.filename), body_tokens))
            features["attachment_filename_mime_mismatch"] = max(
                features["attachment_filename_mime_mismatch"],
                _filename_mime_mismatch(att.filename, att.content_type),
            )
        if body_tokens:
            features["attachment_context_mismatch"] = _clamp(1.0 - best_att - 0.3)

    for name, value in features.items():
        if value >= 0.6:
            evidence.append(Evidence.of(EvidenceCategory.CONSISTENCY, name, f"{value:.2f}", value, MODULE))

    return features, evidence
