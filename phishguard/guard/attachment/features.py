"""Attachment feature primitives (WS5)."""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Dict, Iterable, List, Set

from guard.attachment.magic import DANGEROUS_EXTENSIONS, extension_of

_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]\}]+", re.IGNORECASE)
_SCRIPT_TOKENS = (
    "<script", "javascript:", "vbscript:", "onload=", "onerror=", "onclick=",
    "powershell", "wscript", "cscript", "cmd.exe", "/bin/sh", "eval(", "document.write",
)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def file_entropy(data: bytes) -> float:
    """Normalised byte entropy in [0, 1] (8 bits/byte -> 1.0)."""
    return min(1.0, shannon_entropy(data) / 8.0)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data or b"").hexdigest()


def filename_risk(filename: str) -> float:
    name = (filename or "").strip()
    if not name:
        return 0.0
    score = 0.0
    lowered = name.lower()
    parts = lowered.split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    if ext in DANGEROUS_EXTENSIONS:
        score = max(score, 0.9)
    # double extension: something.pdf.exe
    if len(parts) >= 3 and parts[-1] in DANGEROUS_EXTENSIONS and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "zip"}:
        score = max(score, 0.8)
    if any(ch in name for ch in ("\u202e", "\u202d", "\u200f", "\u202a")):
        score = 1.0  # right-to-left override hides the real extension
    if len(name) > 120:
        score = max(score, 0.3)
    return min(1.0, score)


def looks_like_text(data: bytes, limit: int = 65536) -> bool:
    sample = data[:limit]
    if not sample or b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(sample) > 0.8


def extract_urls(data: bytes, limit: int = 200000) -> List[str]:
    if not data:
        return []
    text = data[:limit].decode("latin-1", "replace")
    text = re.sub(r"hxxps?://", "http://", text, flags=re.IGNORECASE)
    return list(dict.fromkeys(_URL_RE.findall(text)))


def extract_domains(urls: Iterable[str]) -> Set[str]:
    domains = set()
    for url in urls:
        try:
            after = url.split("://", 1)[1]
        except IndexError:
            continue
        host = after.split("/", 1)[0].split("?", 1)[0].split("@")[-1].split(":")[0].lower()
        if host:
            domains.add(host)
    return domains


def script_indicator(data: bytes) -> bool:
    if not looks_like_text(data):
        return False
    text = data[:65536].decode("latin-1", "replace").lower()
    return any(token in text for token in _SCRIPT_TOKENS)


def aggregate(per_attachment: List[Dict[str, float]]) -> Dict[str, float]:
    """Aggregate per-attachment features with max semantics (worst-case)."""
    if not per_attachment:
        return {
            "attachment_count": 0.0,
            "filename_risk": 0.0,
            "extension_mismatch_count": 0.0,
            "mime_magic_mismatch_count": 0.0,
            "max_file_entropy": 0.0,
            "max_archive_depth": 0.0,
            "nested_archive_count": 0.0,
            "embedded_url_count": 0.0,
            "embedded_domain_count": 0.0,
            "macro_indicator_count": 0.0,
            "external_relationship_count": 0.0,
            "script_indicator_count": 0.0,
            "suspicious_pdf_action_count": 0.0,
            "suspicious_office_relationship_count": 0.0,
            "attachment_size_anomaly": 0.0,
            "attachment_hash_reputation": 0.0,
            "attachment_risk_score": 0.0,
        }
    keys = set().union(*[set(d) for d in per_attachment])
    out: Dict[str, float] = {"attachment_count": float(len(per_attachment))}
    for key in keys:
        out[key] = max(d.get(key, 0.0) for d in per_attachment)
    out["attachment_risk_score"] = max(d.get("risk_score", 0.0) for d in per_attachment)
    return out
