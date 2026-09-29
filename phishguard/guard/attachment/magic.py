"""Magic-byte detection (WS5).

Declared MIME types and file extensions are attacker-controlled, so we sniff the actual bytes.
All parsing here is bounded and static.
"""
from __future__ import annotations

import io
import zipfile
from typing import Dict, Optional, Set

# Canonical sniffed types.
PDF = "pdf"
ZIP = "zip"
OLE = "ole"           # legacy doc/xls/ppt (Compound File Binary)
DOCX = "docx"
XLSX = "xlsx"
PPTX = "pptx"
PNG = "png"
JPEG = "jpeg"
GIF = "gif"
BMP = "bmp"
WEBP = "webp"
GZIP = "gzip"
RAR = "rar"
SEVENZIP = "7z"
SVG = "svg"
HTML = "html"
ICS = "ics"
EML = "eml"
TXT = "txt"
EXECUTABLE = "executable"
UNKNOWN = "unknown"

_SIGNATURES = [
    (b"%PDF-", PDF),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", OLE),
    (b"PK\x03\x04", ZIP),
    (b"PK\x05\x06", ZIP),
    (b"PK\x07\x08", ZIP),
    (b"\x89PNG\r\n\x1a\n", PNG),
    (b"\xff\xd8\xff", JPEG),
    (b"GIF87a", GIF),
    (b"GIF89a", GIF),
    (b"BM", BMP),
    (b"\x1f\x8b", GZIP),
    (b"Rar!\x1a\x07", RAR),
    (b"7z\xbc\xaf\x27\x1c", SEVENZIP),
]

#: Extensions (lower-case, no dot) that are consistent with a sniffed type.
EXTENSION_GROUPS: Dict[str, Set[str]] = {
    PDF: {"pdf"},
    ZIP: {"zip"},
    OLE: {"doc", "xls", "ppt", "msi"},
    DOCX: {"docx", "docm", "dotx"},
    XLSX: {"xlsx", "xlsm", "xltx"},
    PPTX: {"pptx", "pptm"},
    PNG: {"png"},
    JPEG: {"jpg", "jpeg", "jpe"},
    GIF: {"gif"},
    BMP: {"bmp"},
    WEBP: {"webp"},
    GZIP: {"gz", "tgz"},
    RAR: {"rar"},
    SEVENZIP: {"7z"},
    SVG: {"svg"},
    HTML: {"html", "htm"},
    ICS: {"ics"},
    EML: {"eml"},
    TXT: {"txt", "csv", "log"},
}

#: Executable / active-content extensions — high filename risk.
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "pif", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf",
    "wsh", "hta", "jar", "msi", "lnk", "iso", "img", "dll", "cpl", "reg", "application",
}

_MIME_EXPECTATIONS: Dict[str, tuple] = {
    PDF: ("application/pdf",),
    ZIP: ("application/zip", "application/x-zip", "application/octet-stream"),
    OLE: ("application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
          "application/x-ole-storage", "application/octet-stream"),
    DOCX: ("application/vnd.openxmlformats-officedocument.wordprocessingml.document",
           "application/vnd.ms-word.document.macroenabled.12"),
    XLSX: ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
           "application/vnd.ms-excel.sheet.macroenabled.12"),
    PPTX: ("application/vnd.openxmlformats-officedocument.presentationml.presentation",
           "application/vnd.ms-powerpoint.presentation.macroenabled.12"),
    PNG: ("image/png",),
    JPEG: ("image/jpeg", "image/jpg"),
    GIF: ("image/gif",),
    BMP: ("image/bmp",),
    WEBP: ("image/webp",),
    SVG: ("image/svg+xml", "image/svg"),
    HTML: ("text/html",),
    ICS: ("text/calendar",),
    EML: ("message/rfc822",),
    TXT: ("text/plain",),
}


def _looks_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(sample) > 0.9


def _is_ooxml(data: bytes) -> Optional[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except Exception:
        return None
    if "[Content_Types].xml" not in names:
        return ZIP
    joined = " ".join(names).lower()
    if "word/" in joined:
        return DOCX
    if "xl/" in joined:
        return XLSX
    if "ppt/" in joined:
        return PPTX
    return ZIP


def detect(data: bytes) -> str:
    """Return the canonical sniffed type for ``data``."""
    if isinstance(data, str):  # defensive: mailparser can hand back str payloads
        data = data.encode("utf-8", "replace")
    if not data:
        return UNKNOWN
    for signature, kind in _SIGNATURES:
        if data.startswith(signature):
            if kind == ZIP:
                return _is_ooxml(data) or ZIP
            return kind
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return WEBP
    # Text-based formats.
    head = data[:4096].lstrip()
    lowered = head.lower()
    if b"<svg" in lowered or lowered.startswith(b"<?xml") and b"<svg" in data[:4096].lower():
        return SVG
    if b"<!doctype html" in lowered or b"<html" in lowered:
        return HTML
    if b"begin:vcalendar" in lowered:
        return ICS
    if lowered.startswith(b"from:") or b"\nreceived:" in lowered or b"\nx-phishguard" in lowered:
        return EML
    if _looks_text(data):
        return TXT
    return UNKNOWN


def extension_of(filename: str) -> str:
    if not filename or "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].strip().lower()


def extension_mismatch(filename: str, magic_type: str) -> bool:
    ext = extension_of(filename)
    if not ext or magic_type in (UNKNOWN,):
        return False
    allowed = EXTENSION_GROUPS.get(magic_type)
    if allowed is None:
        return False
    return ext not in allowed


def mime_magic_mismatch(declared_mime: str, magic_type: str) -> bool:
    declared = (declared_mime or "").split(";")[0].strip().lower()
    if not declared or magic_type in (UNKNOWN,):
        return False
    expected = _MIME_EXPECTATIONS.get(magic_type)
    if not expected:
        return False
    return declared not in expected
