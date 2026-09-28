"""HTML structural phishing model + component (WS3).

Complexity is deliberately excluded from the risk score: a large, image-rich, external-CSS
marketing email scores zero on ``html_risk_score`` because it has no forms, no hidden text and
no obfuscation. The risk scores are further modulated by *context* (sender/domain reputation,
authentication, intent) before being handed to fusion.
"""
from __future__ import annotations

from typing import Dict, List

from pydantic import BaseModel, Field

from guard.component import AnalysisContext, ComponentResult
from guard.evidence import Evidence, EvidenceCategory
from guard.html.features import COMPLEXITY_ONLY, extract_features
from guard.html.forms import analyze_forms
from guard.html.javascript import analyze_scripts
from guard.html.obfuscation import analyze_obfuscation

MODULE = "html"


class HTMLRiskResult(BaseModel):
    html_risk_score: float = 0.0
    form_risk_score: float = 0.0
    obfuscation_score: float = 0.0
    external_resource_score: float = 0.0
    features: Dict[str, float] = Field(default_factory=dict)
    evidence: List[str] = Field(default_factory=list)


def _context_risk(ctx: AnalysisContext) -> float:
    """How untrusted is the surrounding context (1.0 = maximally suspicious)?"""
    risk = max(ctx.sender_reputation, ctx.domain_reputation)
    if any(ctx.auth_features.get(k, 0.0) for k in ("spf_fail", "dkim_fail", "dmarc_fail")):
        risk = max(risk, 0.5)
    risk = max(risk, ctx.intent_scores.get("credential_harvesting_score", 0.0))
    return min(1.0, max(0.0, risk))


class HtmlComponent:
    name = "html"

    def run(self, parsed, ctx: AnalysisContext) -> ComponentResult:
        html = getattr(parsed, "body_html", "") or ""
        if not html:
            return ComponentResult(name=self.name, features={"html_present": 0.0})

        ctx = ctx or AnalysisContext()
        sender_domain = getattr(parsed, "sender_domain", "") or ""

        structural = extract_features(html, sender_domain)
        form_features, form_evidence, form_score = analyze_forms(html, sender_domain)
        js_features, js_evidence, js_score = analyze_scripts(html)
        obf_features, obf_evidence, obf_score = analyze_obfuscation(html, sender_domain)

        external_score = min(1.0, structural["external_resource_count"] / 20.0)
        context = _context_risk(ctx)
        factor = 0.5 + 0.5 * context
        # Risk comes only from concrete collection/obfuscation signals — never from size,
        # DOM depth or benign external images/CSS. A remote-script dependency is a mild signal.
        if structural["external_script_count"] > 0:
            js_score = max(js_score, 0.3)
        base = max(form_score, obf_score, js_score)
        html_risk = min(1.0, base * factor)

        features: Dict[str, float] = {
            **structural,
            **form_features,
            **js_features,
            **obf_features,
            "html_present": 1.0,
            "form_risk_score": round(form_score, 4),
            "obfuscation_score": round(obf_score, 4),
            "external_resource_score": round(external_score, 4),
            "html_context_risk": round(context, 4),
            "html_risk_score": round(html_risk, 4),
        }

        evidence: List[Evidence] = [*form_evidence, *obf_evidence, *js_evidence]
        if external_score >= 0.5:
            evidence.append(
                Evidence.of(EvidenceCategory.HTML, "external_resources",
                            f"{int(structural['external_resource_count'])} resource(s)",
                            external_score, MODULE)
            )
        return ComponentResult(name=self.name, features=features, evidence=evidence)

    def fallback(self, parsed, ctx: AnalysisContext) -> ComponentResult:
        return ComponentResult(
            name=self.name,
            features={"html_present": 0.0, "html_risk_score": 0.0, "form_risk_score": 0.0,
                      "obfuscation_score": 0.0, "external_resource_score": 0.0},
            evidence=[],
            degraded=True,
        )


__all__ = ["HtmlComponent", "HTMLRiskResult", "COMPLEXITY_ONLY"]
