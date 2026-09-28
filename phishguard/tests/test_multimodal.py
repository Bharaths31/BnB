"""Cross-modal consistency tests (WS2) — the 8 required scenarios."""
from guard.component import AnalysisContext
from guard.multimodal import MultimodalComponent, compute_consistency
from tests.factories import make_email, make_url


def _features(email, profile=None):
    features, _ = compute_consistency(email, profile)
    return features


def test_legitimate_branded_email():
    email = make_email(
        from_addr="security@microsoft.com",
        from_display="Microsoft",
        subject="Your Microsoft account statement",
        recipients=["bob@example.com"],
        body_plain="Here is your Microsoft account statement for this month.",
        urls=[make_url("https://microsoft.com/account", "microsoft.com")],
    )
    features = _features(email)
    assert features["brand_domain_mismatch"] == 0.0
    assert features["brand_visual_domain_mismatch"] == 0.0
    assert features["display_domain_mismatch"] == 0.0


def test_display_href_mismatch():
    email = make_email(
        from_addr="support@evil-login.com",
        body_plain="Please login to your account",
        urls=[make_url("http://evil-login.com/verify", "https://microsoft.com/verify")],
    )
    features = _features(email)
    assert features["display_domain_mismatch"] == 1.0
    assert features["display_href_mismatch"] == 1.0


def test_replyto_mismatch():
    email = make_email(
        from_addr="boss@company.com",
        from_display="Boss",
        reply_to="boss.assistant@mail-other.net",
        body_plain="Please process this payment.",
    )
    features = _features(email)
    assert features["replyto_identity_mismatch"] >= 0.5


def test_homoglyph_brand():
    email = make_email(
        from_addr="support@micros0ft.com",  # digit zero
        from_display="Microsoft Support",
        subject="Your Microsoft account",
        body_plain="Verify your Microsoft account now.",
    )
    features = _features(email)
    assert features["brand_visual_domain_mismatch"] >= 0.8
    assert features["brand_domain_mismatch"] >= 0.8


def test_qr_url_conflicting_with_visible_text():
    email = make_email(
        from_addr="news@example.com",
        body_plain="Scan the code to claim your prize.",
    )
    email.extracted_qr_urls = ["http://evil-phish.net/claim"]
    features = _features(email)
    assert features["qr_context_mismatch"] >= 0.5


def test_benign_newsletter():
    email = make_email(
        from_addr="newsletter@company.com",
        from_display="Company News",
        subject="Your monthly product update",
        body_plain=(
            "Hello, here is your monthly newsletter with product tips and news. "
            "Visit company.com/blog to read more. Unsubscribe any time."
        ),
        urls=[make_url("https://company.com/blog", "Read the blog")],
    )
    features = _features(email)
    assert features["brand_domain_mismatch"] == 0.0
    assert features["display_domain_mismatch"] == 0.0
    assert features["qr_context_mismatch"] == 0.0
    assert features["subject_body_mismatch"] < 0.6


def test_legitimate_third_party_mailing_service():
    email = make_email(
        from_addr="bounce@sendgrid.net",
        from_display="PayPal",
        subject="Your PayPal receipt",
        reply_to="reply@sendgrid.net",
        body_plain="Your PayPal receipt is attached.",
    )
    features = _features(email)
    assert features["brand_domain_mismatch"] == 0.0  # mailing domain is legitimate
    assert features["replyto_identity_mismatch"] < 0.5


def test_forwarded_mailing_list_message():
    email = make_email(
        from_addr="dev-list@lists.example.org",
        from_display="Dev List",
        subject="[dev-list] Weekly digest",
        body_plain="Weekly digest from the developer mailing list. See lists.example.org/archive",
        urls=[make_url("https://lists.example.org/archive", "archive")],
        headers={"List-Id": "dev-list.lists.example.org"},
    )
    features = _features(email)
    assert features["brand_domain_mismatch"] == 0.0
    assert features["identity_history_mismatch"] == 0.0


def test_component_emits_consistency_evidence():
    email = make_email(
        from_addr="support@evil-login.com",
        from_display="Microsoft Support",
        subject="Verify your Microsoft account",
        urls=[make_url("http://evil-login.com/verify", "https://microsoft.com/verify")],
    )
    result = MultimodalComponent().run(email, AnalysisContext())
    assert set(result.features) >= {
        "display_href_mismatch", "brand_visual_domain_mismatch", "display_domain_mismatch"
    }
    assert any(e.category.value == "CONSISTENCY" for e in result.evidence)
