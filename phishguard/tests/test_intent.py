"""Structured intent tests (WS10) — the 8 required scenarios."""
from guard.nlp.intent import IntentComponent, classify_intent
from guard.component import AnalysisContext
from tests.factories import make_email, make_url


def _intent(email):
    return classify_intent(email)


def test_credential_phishing():
    email = make_email(
        from_addr="support@micros0ft-login.com",
        from_display="Microsoft Support",
        subject="Urgent: verify your identity",
        body_plain="We detected unusual activity. Verify your identity immediately to avoid suspension.",
        urls=[make_url("http://micros0ft-login.com/verify", "https://microsoft.com/verify")],
    )
    result = _intent(email)
    assert result.tactics["credential_request"] >= 0.5
    assert result.derived_intent_scores["credential_harvesting_score"] >= 0.4


def test_payment_fraud():
    email = make_email(
        from_addr="ceo@example-corp.com",
        from_display="CEO",
        subject="Urgent wire transfer",
        body_plain="Please process an urgent wire transfer for the acquisition today.",
    )
    result = _intent(email)
    assert result.derived_intent_scores["financial_fraud_score"] >= 0.4


def test_business_email_compromise():
    email = make_email(
        from_addr="ceo@example-corp.com",
        from_display="CEO Jane",
        reply_to="assistant@other-mail.net",
        subject="Re: wire transfer",
        body_plain="Urgent: process the wire transfer confidentially, I am the CEO.",
    )
    result = _intent(email)
    assert result.derived_intent_scores["business_email_compromise_score"] >= 0.3


def test_benign_password_reset_notification():
    email = make_email(
        from_addr="security@microsoft.com",
        from_display="Microsoft",
        subject="Password reset requested",
        body_plain="A password reset was requested. If this was you, sign in to your account.",
        urls=[make_url("https://microsoft.com/reset", "microsoft.com")],
    )
    result = _intent(email)
    # No verified technical signal -> the derived score stays low despite credential language.
    assert result.derived_intent_scores["credential_harvesting_score"] < 0.4


def test_legitimate_invoice():
    email = make_email(
        from_addr="billing@vendor.com",
        from_display="Vendor Billing",
        subject="Invoice INV-2026-001",
        body_plain="Please find your invoice for this month. Thank you for your business.",
        attachments=[("invoice.pdf", "application/pdf", b"%PDF-1.4 ok")],
    )
    result = _intent(email)
    assert result.derived_intent_scores["malicious_attachment_score"] < 0.4
    assert result.derived_intent_scores["credential_harvesting_score"] < 0.4


def test_ordinary_newsletter():
    email = make_email(
        from_addr="news@company.com",
        from_display="Company News",
        subject="Monthly product update",
        body_plain="Here is your monthly newsletter with tips. Read the blog for details.",
        urls=[make_url("https://company.com/blog", "blog")],
    )
    result = _intent(email)
    assert all(v < 0.4 for v in result.derived_intent_scores.values())


def test_attachment_lure():
    email = make_email(
        from_addr="billing@vendor-payments.com",
        from_display="Billing",
        subject="Invoice attached",
        body_plain="Open the attached document and enable macros to view the invoice.",
        attachments=[("invoice.docm", "application/vnd.ms-word.document.macroEnabled.12", b"PK\x03\x04macro")],
    )
    result = _intent(email)
    assert result.tactics["attachment_lure"] >= 0.5
    assert result.derived_intent_scores["malicious_attachment_score"] >= 0.4


def test_qr_lure():
    email = make_email(
        from_addr="rewards@example.com",
        subject="You won",
        body_plain="Scan the QR code to claim your reward immediately.",
    )
    email.extracted_qr_urls = ["http://evil-claim.net/x"]
    result = _intent(email)
    assert result.tactics["link_bait"] >= 0.4
    assert result.derived_intent_scores["social_engineering_score"] > 0.0


def test_component_emits_intent_features_and_evidence():
    email = make_email(
        from_addr="support@micros0ft-login.com",
        from_display="Microsoft Support",
        subject="Urgent verify",
        body_plain="Verify your identity immediately. Update your account now.",
        urls=[make_url("http://micros0ft-login.com/verify", "https://microsoft.com/verify")],
    )
    result = IntentComponent().run(email, AnalysisContext())
    assert "credential_harvesting_score" in result.features
    assert any(e.category.value == "TACTIC" for e in result.evidence)
