"""Parser tests exercising the stdlib fallback (no mailparser dependency required)."""
import os

from guard.parse import parser
from tests.factories import make_raw_mime


def _parse(raw: bytes, monkeypatch):
    monkeypatch.setenv("PHISHGUARD_FORCE_STDLIB_PARSER", "1")
    return parser.parse_email(raw)


def test_stdlib_parser_extracts_envelope_and_auth(monkeypatch):
    raw = make_raw_mime(
        subject="Urgent: verify your identity",
        from_addr="support@micros0ft-login.com",
        from_display="Microsoft Support",
        to=["bob@example.com"],
        cc=["carol@example.com"],
        reply_to="reply@other-domain.net",
        body_plain="verify your identity immediately",
        headers={"Authentication-Results": "spf=fail; dkim=pass; dmarc=fail"},
    )
    parsed = _parse(raw, monkeypatch)
    assert parsed.subject == "Urgent: verify your identity"
    assert parsed.from_addr == "support@micros0ft-login.com"
    assert parsed.from_display == "Microsoft Support"
    assert parsed.recipients == ["bob@example.com"]
    assert parsed.cc == ["carol@example.com"]
    assert parsed.reply_to == "reply@other-domain.net"
    assert parsed.received_at is not None and parsed.received_at.year == 2026
    assert parsed.spf_result == "fail"
    assert parsed.dkim_result == "pass"
    assert parsed.dmarc_result == "fail"
    assert parsed.sender_domain == "micros0ft-login.com"
    assert parsed.replyto_domain == "other-domain.net"


def test_stdlib_parser_html_anchor_display_text(monkeypatch):
    html = (
        '<html><body><p>Please login</p>'
        '<a href="http://evil-login.com/verify">https://microsoft.com/verify</a>'
        "</body></html>"
    )
    raw = make_raw_mime(subject="Login", body_html=html)
    parsed = _parse(raw, monkeypatch)
    assert len(parsed.urls) == 1
    url = parsed.urls[0]
    assert url.domain == "evil-login.com"
    assert "microsoft.com" in url.display_text
    assert url.display_text_mismatch is True


def test_stdlib_parser_retains_attachment_payload(monkeypatch):
    payload = b"%PDF-1.4 fake pdf body"
    raw = make_raw_mime(
        subject="Invoice",
        body_plain="see attachment",
        attachments=[("invoice.pdf", "application/pdf", payload)],
    )
    parsed = _parse(raw, monkeypatch)
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "invoice.pdf"
    assert len(parsed.attachment_payloads) == 1
    assert parsed.attachment_payloads[0].startswith(b"%PDF")


def test_plain_text_url_extraction(monkeypatch):
    raw = make_raw_mime(body_plain="Visit hxxp://evil[.]com/now and http://ok.example.com/x")
    parsed = _parse(raw, monkeypatch)
    domains = {u.domain for u in parsed.urls}
    assert "evil.com" in domains
    assert "ok.example.com" in domains


def test_force_stdlib_env_defaults_off():
    # The switch must not be set unless a test/operator explicitly requests it.
    assert os.environ.get("PHISHGUARD_FORCE_STDLIB_PARSER") is None
