"""Form / credential-collection structural analysis (WS3). Static only."""
from __future__ import annotations

from typing import Dict, List, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from guard.evidence import Evidence, EvidenceCategory

MODULE = "html.forms"


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _is_external(host: str, sender_domain: str) -> bool:
    if not host or not sender_domain:
        return bool(host)
    sender_domain = sender_domain.lower()
    return not (host == sender_domain or host.endswith("." + sender_domain))


def analyze_forms(html: str, sender_domain: str = "") -> Tuple[Dict[str, float], List[Evidence], float]:
    soup = BeautifulSoup(html or "", "html.parser")
    forms = soup.find_all("form")
    external_actions = 0
    password_forms = 0
    credential_indicators = 0
    action_domains: List[str] = []

    for form in forms:
        action = (form.get("action") or "").strip()
        host = _host(action)
        has_password = form.find("input", attrs={"type": "password"}) is not None
        if host:
            action_domains.append(host)
        if has_password:
            password_forms += 1
        if host and _is_external(host, sender_domain):
            external_actions += 1
            if has_password:
                credential_indicators += 1

    iframe_count = len(soup.find_all("iframe"))
    password_inputs_total = len(soup.find_all("input", attrs={"type": "password"}))
    iframe_credential_indicator = 1 if iframe_count and (password_inputs_total or forms) else 0

    features: Dict[str, float] = {
        "form_external_action_count": float(external_actions),
        "password_form_count": float(password_forms),
        "credential_collection_indicator_count": float(credential_indicators),
        "iframe_credential_indicator": float(iframe_credential_indicator),
        "form_submission_domain_mismatch": 1.0 if external_actions else 0.0,
    }

    evidence: List[Evidence] = []
    if credential_indicators:
        evidence.append(Evidence.of(EvidenceCategory.HTML, "password_form_external_action",
                                    f"{credential_indicators} form(s)", 0.9, MODULE,
                                    severity="critical", confidence="high"))
    elif external_actions:
        evidence.append(Evidence.of(EvidenceCategory.HTML, "external_form_action",
                                    f"{external_actions} form(s)", 0.5, MODULE))
    if password_forms:
        evidence.append(Evidence.of(EvidenceCategory.HTML, "password_form",
                                    f"{password_forms} form(s)", 0.6, MODULE))

    score = 0.0
    if credential_indicators:
        score = 0.95
    elif external_actions and password_forms:
        score = 0.85
    elif external_actions:
        score = 0.4
    elif password_forms:
        score = 0.3
    if iframe_credential_indicator and (password_inputs_total or forms):
        score = max(score, 0.5)
    return features, evidence, score
