"""Static Office document analysis (WS5).

OOXML documents are ZIP containers, so relationships/macros/URLs are read from the archive.
Legacy OLE (binary doc/xls/ppt) files are scanned for macro markers without a full parser.
Nothing is executed.
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import List, Set

from guard.attachment.features import extract_domains, extract_urls
from guard.attachment.magic import DOCX, OLE, PPTX, XLSX

_EXTERNAL_REL_RE = re.compile(rb'TargetMode\s*=\s*"External"')
_TARGET_RE = re.compile(rb'Target\s*=\s*"([^"]+)"')

_OLE_MACRO_MARKERS = (
    b"vbaProject", b"_VBA_PROJECT", b"VBAProject", b"AutoOpen", b"AutoExec", b"Macros",
    b"Attribute VB_",
)


@dataclass
class OfficeFindings:
    macro_indicator: bool = False
    external_relationship_count: int = 0
    remote_template: bool = False
    embedded_urls: List[str] = field(default_factory=list)
    embedded_domains: Set[str] = field(default_factory=set)


def analyze_office(data: bytes, magic_type: str) -> OfficeFindings:
    findings = OfficeFindings()
    if magic_type in (DOCX, XLSX, PPTX):
        _analyze_ooxml(data, findings)
    elif magic_type == OLE:
        lowered = data
        findings.macro_indicator = any(marker in lowered for marker in _OLE_MACRO_MARKERS)
    return findings


def _analyze_ooxml(data: bytes, findings: OfficeFindings) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except Exception:
        return

    lowered_names = [n.lower() for n in names]
    if any("vbaproject.bin" in n for n in lowered_names):
        findings.macro_indicator = True

    for name in names:
        low = name.lower()
        if not low.endswith(".rels"):
            continue
        try:
            content = zf.read(name)
        except Exception:
            continue
        if _EXTERNAL_REL_RE.search(content):
            for match in _TARGET_RE.finditer(content):
                target = match.group(1).decode("latin-1", "replace")
                if target.lower().startswith(("http://", "https://", "file://", "\\\\")):
                    findings.external_relationship_count += 1
                    findings.embedded_urls.extend(extract_urls(target.encode("latin-1", "replace")))
                    if "template" in target.lower() or "attachedtemplate" in low:
                        findings.remote_template = True
        # Scan XML parts for embedded URLs.
        if low.endswith(".xml") or low.endswith(".rels"):
            try:
                part = zf.read(name)
            except Exception:
                continue
            urls = extract_urls(part)
            if urls:
                findings.embedded_urls.extend(urls)

    findings.embedded_urls = list(dict.fromkeys(findings.embedded_urls))
    findings.embedded_domains |= extract_domains(findings.embedded_urls)
