"""Static PDF action/URL analysis (WS5).

Operates on the raw bytes — no PDF renderer, no JavaScript execution. Only the presence of
risky action keywords and embedded URLs is recorded.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Set

from guard.attachment.features import extract_domains

_URI_RE = re.compile(rb"/URI\s*\(([^)]*)\)")
_RAW_URL_RE = re.compile(rb"https?://[^\s\)\]\}>\"']+", re.IGNORECASE)

_JS_MARKERS = (b"/JavaScript", b"/JS", b"/S /JavaScript")
_OPEN_ACTION = (b"/OpenAction", b"/AA", b"/Launch", b"/SubmitForm", b"/ImportData")


@dataclass
class PdfFindings:
    embedded_urls: List[str] = field(default_factory=list)
    embedded_domains: Set[str] = field(default_factory=set)
    has_javascript: bool = False
    has_open_action: bool = False
    has_launch: bool = False
    has_forms: bool = False
    has_embedded_file: bool = False
    suspicious_action: bool = False


def analyze_pdf(data: bytes) -> PdfFindings:
    findings = PdfFindings()
    urls: List[str] = []

    for match in _URI_RE.finditer(data):
        url = match.group(1).decode("latin-1", "replace").strip()
        if url:
            urls.append(url)
    urls.extend(m.decode("latin-1", "replace") for m in _RAW_URL_RE.findall(data))
    findings.embedded_urls = list(dict.fromkeys(urls))
    findings.embedded_domains = extract_domains(findings.embedded_urls)

    findings.has_javascript = any(marker in data for marker in _JS_MARKERS)
    findings.has_open_action = any(marker in data for marker in _OPEN_ACTION)
    findings.has_launch = b"/Launch" in data
    findings.has_forms = b"/AcroForm" in data
    findings.has_embedded_file = b"/EmbeddedFile" in data
    findings.suspicious_action = (
        findings.has_javascript or findings.has_launch or findings.has_embedded_file
    )
    return findings
