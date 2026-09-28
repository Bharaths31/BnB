"""Recursive archive inspection with decompression-bomb protection (WS5)."""
from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional, Set

from guard.attachment.features import extract_domains, extract_urls
from guard.attachment.magic import DANGEROUS_EXTENSIONS, extension_of

_TEXT_MEMBER_EXTS = {
    "xml", "rels", "txt", "html", "htm", "js", "json", "csv", "vbs", "ps1", "url", "lnk",
    "bat", "cmd", "sh", "py",
}
_NESTED_ARCHIVE_EXTS = {"zip", "jar", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "gz", "tar"}


@dataclass
class ArchiveLimits:
    max_depth: int = 3
    max_files: int = 500
    max_total_bytes: int = 100 * 1024 * 1024
    max_compression_ratio: int = 100


@dataclass
class ArchiveFindings:
    nested_archive_count: int = 0
    file_count: int = 0
    total_uncompressed_bytes: int = 0
    max_depth: int = 0
    embedded_urls: List[str] = field(default_factory=list)
    embedded_domains: Set[str] = field(default_factory=set)
    dangerous_members: List[str] = field(default_factory=list)
    macro_indicator: bool = False
    bomb_suspected: bool = False
    truncated: bool = False


def inspect_archive(
    data: bytes,
    limits: Optional[ArchiveLimits] = None,
    depth: int = 0,
    findings: Optional[ArchiveFindings] = None,
) -> ArchiveFindings:
    limits = limits or ArchiveLimits()
    findings = findings or ArchiveFindings()
    if depth >= limits.max_depth:
        return findings
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except Exception:
        return findings

    findings.max_depth = max(findings.max_depth, depth + 1)
    for info in infos:
        if findings.file_count >= limits.max_files or findings.total_uncompressed_bytes >= limits.max_total_bytes:
            findings.truncated = True
            findings.bomb_suspected = True
            break

        name = info.filename
        findings.file_count += 1
        findings.total_uncompressed_bytes += info.file_size

        # Compression-ratio bomb heuristic.
        if info.file_size > 1024 * 1024 and info.compress_size > 0:
            if info.file_size / info.compress_size > limits.max_compression_ratio:
                findings.bomb_suspected = True

        ext = extension_of(name)
        lowered = name.lower()
        if ext in DANGEROUS_EXTENSIONS:
            findings.dangerous_members.append(name)
        if "vbaproject.bin" in lowered or "vba" in lowered or lowered.endswith(".docm"):
            findings.macro_indicator = True

        if ext in _NESTED_ARCHIVE_EXTS and depth + 1 < limits.max_depth:
            try:
                nested = zf.read(info) if info.file_size <= limits.max_total_bytes else b""
            except Exception:
                nested = b""
            if nested:
                findings.nested_archive_count += 1
                inspect_archive(nested, limits, depth + 1, findings)

        if ext in _TEXT_MEMBER_EXTS:
            try:
                content = zf.read(info)[:200000]
            except Exception:
                continue
            urls = extract_urls(content)
            findings.embedded_urls.extend(urls)
            findings.embedded_domains |= extract_domains(urls)

    findings.embedded_urls = list(dict.fromkeys(findings.embedded_urls))
    return findings
