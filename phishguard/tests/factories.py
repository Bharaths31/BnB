"""Deterministic email factories for the test suite.

These build :class:`ParsedEmail` objects (and raw MIME bytes) directly, so component tests do
not depend on the email parser or on OCR/ONNX runtimes. Everything is seeded/static, which
keeps the tests reproducible.
"""
from __future__ import annotations

from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr
from typing import Iterable, List, Optional, Sequence, Tuple

from guard.models import AttachmentInfo, ParsedEmail, URLInfo
from guard.parse.normalizer import normalize_text, normalize_url

FIXED_NOW = datetime(2026, 1, 15, 10, 30, tzinfo=timezone.utc)


def make_url(raw: str, display: str = "") -> URLInfo:
    norm = normalize_url(raw)
    without = norm.split("://", 1)[1] if "://" in norm else norm
    domain = without.split("/", 1)[0].split("?", 1)[0].split("@")[-1].strip()
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    return URLInfo(
        raw_url=raw,
        normalized=norm,
        domain=domain,
        tld=tld,
        is_punycode="xn--" in domain.lower(),
        display_text_mismatch=bool(display) and bool(domain) and domain not in display,
        display_text=display.strip(),
        scheme=raw.split("://", 1)[0].lower() if "://" in raw else "",
    )


def make_email(
    subject: str = "Meeting notes",
    from_addr: str = "alice@example.com",
    from_display: str = "Alice",
    reply_to: str = "",
    recipients: Optional[Iterable[str]] = None,
    cc: Optional[Iterable[str]] = None,
    body_plain: str = "",
    body_html: str = "",
    urls: Optional[Sequence[URLInfo]] = None,
    attachments: Optional[Sequence] = None,
    attachment_payloads: Optional[Sequence[bytes]] = None,
    reply_urls: Optional[Sequence[str]] = None,
    received_at: Optional[datetime] = FIXED_NOW,
    spf: str = "pass",
    dkim: str = "pass",
    dmarc: str = "pass",
    headers: Optional[dict] = None,
) -> ParsedEmail:
    parsed = ParsedEmail(
        subject=subject,
        from_addr=from_addr,
        from_display=from_display,
        reply_to=reply_to,
        recipients=list(recipients or []),
        cc=list(cc or []),
        body_plain=body_plain,
        body_html=body_html,
        visible_text=body_plain,
        normalized_body=normalize_text(body_plain),
        received_at=received_at,
        spf_result=spf,
        dkim_result=dkim,
        dmarc_result=dmarc,
    )
    parsed.urls = list(urls or [])
    for att in attachments or []:
        if isinstance(att, AttachmentInfo):
            parsed.attachments.append(att)
        else:
            filename, content_type, payload = att
            parsed.attachments.append(
                AttachmentInfo(
                    filename=filename,
                    content_type=content_type,
                    size=len(payload),
                    has_macros=filename.lower().endswith((".docm", ".xlsm", ".pptm")),
                )
            )
            parsed.attachment_payloads.append(payload)
    if attachment_payloads is not None:
        parsed.attachment_payloads = [bytes(p) for p in attachment_payloads]
    raw = dict(headers or {})
    raw.setdefault("Authentication-Results", f"spf={spf}; dkim={dkim}; dmarc={dmarc}")
    parsed.raw_headers = raw
    return parsed


# --------------------------------------------------------------------------- archetypes
def legit_newsletter() -> ParsedEmail:
    return make_email(
        subject="Your monthly product update",
        from_addr="newsletter@company.com",
        from_display="Company News",
        recipients=["bob@example.com"],
        body_plain=(
            "Hello Bob, here is your monthly newsletter with product tips and news. "
            "Visit https://company.com/blog to read more. Unsubscribe any time."
        ),
        urls=[make_url("https://company.com/blog", "Read the blog")],
    )


def credential_phish() -> ParsedEmail:
    return make_email(
        subject="Urgent: verify your identity immediately",
        from_addr="support@micros0ft-login.com",
        from_display="Microsoft Support",
        recipients=["bob@example.com"],
        body_plain=(
            "We detected unusual activity. Verify your identity immediately at your account "
            "to avoid suspension. Update your account now."
        ),
        urls=[make_url("http://micros0ft-login.com/verify", "https://microsoft.com/verify")],
    )


def bec_email() -> ParsedEmail:
    return make_email(
        subject="Re: wire transfer",
        from_addr="ceo@example-corp.com",
        from_display="CEO Jane Doe",
        reply_to="ceo.assistant@mail-other.net",
        recipients=["cfo@example-corp.com"],
        body_plain="Please process an urgent wire transfer today. Keep this confidential.",
        urls=[],
    )


def branded_phish() -> ParsedEmail:
    return make_email(
        subject="Your PayPal account has been limited",
        from_addr="service@paypal-secure-center.com",
        from_display="PayPal",
        recipients=["bob@example.com"],
        body_plain="Your PayPal account is limited. Confirm your password to restore access.",
        urls=[make_url("http://paypal-secure-center.com/login", "https://paypal.com/login")],
    )


def macro_document() -> ParsedEmail:
    payload = b"PK\x03\x04" + b"\x00" * 64 + b"vbaProject.bin" + b"\x00" * 32
    return make_email(
        subject="Invoice attached",
        from_addr="billing@vendor-payments.com",
        from_display="Vendor Billing",
        recipients=["bob@example.com"],
        body_plain="Please find the invoice attached and enable macros to view it.",
        attachments=[("invoice.docm", "application/vnd.ms-word.document.macroEnabled.12", payload)],
    )


def mailing_list_email() -> ParsedEmail:
    return make_email(
        subject="[dev-list] Weekly digest",
        from_addr="dev-list@lists.example.org",
        from_display="Dev List",
        recipients=["bob@example.com"],
        body_plain="Weekly digest of the developer mailing list. See https://lists.example.org/archive",
        urls=[make_url("https://lists.example.org/archive", "archive")],
        headers={"List-Id": "dev-list.lists.example.org", "List-Unsubscribe": "<mailto:leave@lists.example.org>"},
    )


# ------------------------------------------------------------------------- raw MIME bytes
def make_raw_mime(
    subject: str = "Hello",
    from_addr: str = "alice@example.com",
    from_display: str = "Alice",
    to: Sequence[str] = ("bob@example.com",),
    cc: Sequence[str] = (),
    reply_to: str = "",
    body_plain: str = "",
    body_html: str = "",
    attachments: Sequence[Tuple[str, str, bytes]] = (),
    date: Optional[datetime] = FIXED_NOW,
    headers: Optional[dict] = None,
) -> bytes:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((from_display, from_addr)) if from_display else from_addr
    if to:
        msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    if reply_to:
        msg["Reply-To"] = reply_to
    if date is not None:
        msg["Date"] = date.strftime("%a, %d %b %Y %H:%M:%S %z")
    for key, value in (headers or {}).items():
        msg[key] = value
    if body_html and body_plain:
        msg.set_content(body_plain)
        msg.add_alternative(body_html, subtype="html")
    elif body_html:
        msg.set_content(body_html, subtype="html")
    else:
        msg.set_content(body_plain or "")
    for filename, content_type, payload in attachments:
        maintype, subtype = content_type.split("/", 1)
        msg.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    return msg.as_bytes()
