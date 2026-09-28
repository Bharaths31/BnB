"""Email parsing (Phase 0 extension).

Adds what the new subsystems need while keeping the existing ``ParsedEmail`` contract:

* envelope recipients (``To`` / ``Cc``) and the ``Date`` timestamp — behavioral profiling;
* per-URL display text and scheme — cross-modal consistency;
* raw attachment payloads (size-capped) — static attachment analysis.

``mailparser`` remains the preferred backend. Because it is an optional dependency, a
stdlib-``email`` fallback is provided so the whole pipeline stays locally executable and
degrades deterministically when a parser dependency is missing.
"""
from __future__ import annotations

import email
import email.policy
import email.utils
import os
import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from bs4 import BeautifulSoup

from guard.models import AttachmentInfo, ParsedEmail, URLInfo
from guard.parse.html_sanitizer import sanitize_html
from guard.parse.normalizer import normalize_text, normalize_url

MAX_ATTACHMENT_BYTES = int(os.environ.get("PHISHGUARD_MAX_ATTACHMENT_BYTES", 10 * 1024 * 1024))
MAX_BODY_BYTES = int(os.environ.get("PHISHGUARD_MAX_BODY_BYTES", 2 * 1024 * 1024))

#: Image-ish MIME types we run OCR / QR extraction on.
_IMAGE_TYPES = ("image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp", "image/bmp")

_URL_RE = re.compile(r"h?t?t?ps?://[^\s<>\"')]+", re.IGNORECASE)


def _domain_of(url: str) -> str:
    without_scheme = url.split("://", 1)[1] if "://" in url else url
    return without_scheme.split("/", 1)[0].split("?", 1)[0].split("@")[-1].strip()


def _scheme_of(url: str) -> str:
    return url.split("://", 1)[0].lower() if "://" in url else ""


def build_url_info(raw_url: str, display_text: str = "") -> URLInfo:
    """Build a :class:`URLInfo` from an href and its visible anchor text."""
    norm = normalize_url(raw_url)
    domain = _domain_of(norm)
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    display = (display_text or "").strip()
    mismatch = bool(display) and bool(domain) and domain not in display
    return URLInfo(
        raw_url=raw_url,
        normalized=norm,
        domain=domain,
        tld=tld,
        is_punycode="xn--" in domain.lower(),
        display_text_mismatch=mismatch,
        display_text=display,
        scheme=_scheme_of(raw_url),
    )


def extract_urls_from_html(html: str) -> List[URLInfo]:
    """Collect anchors (with display text) and bare URLs from an HTML body."""
    infos: List[URLInfo] = []
    if not html:
        return infos
    seen = set()
    soup = BeautifulSoup(html, "html.parser")
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"]
        if href.strip().lower().startswith(("mailto:", "tel:", "#", "javascript:", "data:")):
            continue
        info = build_url_info(href, anchor.get_text())
        if info.normalized and info.normalized not in seen:
            seen.add(info.normalized)
            infos.append(info)
    # Bare URLs in the body text. Anchor text is removed first so that link *display* text
    # (already captured above) is not mistaken for a separate destination.
    text_soup = BeautifulSoup(html, "html.parser")
    for anchor in text_soup.find_all("a"):
        anchor.extract()
    for tag in text_soup(["script", "style"]):
        tag.extract()
    for match in _URL_RE.finditer(text_soup.get_text(" ")):
        url = match.group(0).rstrip(".,;)")
        info = build_url_info(url)
        if info.normalized and info.normalized not in seen:
            seen.add(info.normalized)
            infos.append(info)
    return infos


def extract_urls_from_text(text: str) -> List[URLInfo]:
    infos: List[URLInfo] = []
    if not text:
        return infos
    for match in _URL_RE.finditer(text):
        infos.append(build_url_info(match.group(0).rstrip(".,;)")))
    return infos


def _run_media_extraction(parsed: ParsedEmail, content_type: str, payload: bytes) -> None:
    """Best-effort OCR/QR on image parts; never raises."""
    if not payload or not content_type.lower().startswith("image/"):
        return
    try:
        from guard.parse.ocr import extract_qr_urls, extract_text_from_image

        text = extract_text_from_image(payload)
        if text:
            parsed.extracted_image_text += text + " "
        parsed.extracted_qr_urls.extend(extract_qr_urls(payload))
    except Exception:
        return


def _finalize_bodies(parsed: ParsedEmail) -> None:
    body_plain = (parsed.body_plain or "")[:MAX_BODY_BYTES]
    body_html = (parsed.body_html or "")[:MAX_BODY_BYTES]
    parsed.body_plain = body_plain
    parsed.body_html = body_html
    if body_html:
        parsed.visible_text = sanitize_html(body_html)
    else:
        parsed.visible_text = body_plain
    parsed.normalized_body = normalize_text(parsed.visible_text)
    if body_html:
        parsed.urls = extract_urls_from_html(body_html)
    else:
        parsed.urls = extract_urls_from_text(body_plain)


# --------------------------------------------------------------------------- mailparser
def _parse_with_mailparser(raw_bytes: bytes) -> ParsedEmail:
    import mailparser  # imported lazily so the module loads without the dependency

    mail = mailparser.parse_from_bytes(raw_bytes)
    parsed = ParsedEmail()
    parsed.subject = mail.subject or ""
    if mail.from_:
        parsed.from_display, parsed.from_addr = mail.from_[0]
    parsed.raw_headers = mail.headers or {}

    parsed.reply_to = (mail.headers or {}).get("Reply-To", "") or ""
    parsed.return_path = (mail.headers or {}).get("Return-Path", "") or ""
    parsed.received_chain = list(mail.received or [])

    parsed.recipients = [addr for _, addr in (mail.to or []) if addr]
    parsed.cc = [addr for _, addr in (mail.cc or []) if addr]
    parsed.received_at = _coerce_datetime(getattr(mail, "date", None))

    _apply_auth_results(parsed)

    parsed.body_plain = " ".join(mail.text_plain or [])
    parsed.body_html = " ".join(mail.text_html or [])

    for att in mail.attachments or []:
        payload = att.get("payload", b"") or b""
        content_type = att.get("mail_content_type", "") or ""
        filename = att.get("filename", "unknown") or "unknown"
        _append_attachment(parsed, filename, content_type, payload)
        _run_media_extraction(parsed, content_type, payload)

    _finalize_bodies(parsed)
    return parsed


# ------------------------------------------------------------------------------- stdlib
def _parse_with_stdlib(raw_bytes: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    parsed = ParsedEmail()
    parsed.subject = str(msg.get("Subject", "") or "")
    parsed.from_display, parsed.from_addr = email.utils.parseaddr(str(msg.get("From", "") or ""))
    parsed.reply_to = str(msg.get("Reply-To", "") or "")
    parsed.return_path = str(msg.get("Return-Path", "") or "")
    parsed.received_chain = [str(h) for h in (msg.get_all("Received") or [])]
    parsed.recipients = [
        addr for _, addr in email.utils.getaddresses([str(msg.get("To", "") or "")]) if addr
    ]
    parsed.cc = [
        addr for _, addr in email.utils.getaddresses([str(msg.get("Cc", "") or "")]) if addr
    ]
    parsed.received_at = _coerce_datetime(msg.get("Date"))
    parsed.raw_headers = {key: str(val) for key, val in msg.items()}

    _apply_auth_results(parsed)

    plain_parts: List[str] = []
    html_parts: List[str] = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        content_type = part.get_content_type()
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if disposition == "attachment" or filename or content_type not in ("text/plain", "text/html"):
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            _append_attachment(parsed, filename or "unknown", content_type, payload)
            _run_media_extraction(parsed, content_type, payload)
        elif content_type == "text/plain":
            plain_parts.append(_safe_get_content(part))
        elif content_type == "text/html":
            html_parts.append(_safe_get_content(part))

    parsed.body_plain = " ".join(plain_parts)
    parsed.body_html = " ".join(html_parts)

    _finalize_bodies(parsed)
    return parsed


def _safe_get_content(part) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else ""
    except Exception:
        try:
            return part.get_payload(decode=True).decode("utf-8", "replace")
        except Exception:
            return ""


# ------------------------------------------------------------------------------ helpers
def _append_attachment(parsed: ParsedEmail, filename: str, content_type: str, payload: bytes) -> None:
    if payload is None:
        payload = b""
    has_macros = filename.lower().endswith((".docm", ".xlsm", ".pptm"))
    parsed.attachments.append(
        AttachmentInfo(
            filename=filename,
            content_type=content_type or "",
            size=len(payload),
            has_macros=has_macros,
        )
    )
    # Retain a capped copy of the bytes for static analysis.
    parsed.attachment_payloads.append(payload[:MAX_ATTACHMENT_BYTES])


def _apply_auth_results(parsed: ParsedEmail) -> None:
    headers = parsed.raw_headers or {}
    auth = str(headers.get("Authentication-Results", "") or "").lower()
    parsed.spf_result = "fail" if "spf=fail" in auth else ("pass" if "spf=pass" in auth else "none")
    parsed.dkim_result = "fail" if "dkim=fail" in auth else ("pass" if "dkim=pass" in auth else "none")
    parsed.dmarc_result = "fail" if "dmarc=fail" in auth else ("pass" if "dmarc=pass" in auth else "none")


def _coerce_datetime(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = email.utils.parsedate_to_datetime(str(value))
        if dt is not None and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def parse_email(raw_bytes: bytes) -> ParsedEmail:
    """Parse raw MIME bytes into a :class:`ParsedEmail`.

    Tries ``mailparser`` first; falls back to the stdlib parser when it is unavailable or
    raises on malformed input.
    """
    if not os.environ.get("PHISHGUARD_FORCE_STDLIB_PARSER"):
        try:
            return _parse_with_mailparser(raw_bytes)
        except ImportError:
            pass
        except Exception:
            pass
    return _parse_with_stdlib(raw_bytes)
