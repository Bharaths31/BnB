"""HTML structural phishing-analysis module (WS3)."""
from guard.html.features import (
    COMPLEXITY_ONLY,
    anchor_display_mismatch,
    extract_features,
    external_domains,
    hidden_text,
)
from guard.html.forms import analyze_forms
from guard.html.javascript import analyze_scripts
from guard.html.model import HTMLRiskResult, HtmlComponent
from guard.html.obfuscation import analyze_obfuscation

__all__ = [
    "HtmlComponent",
    "HTMLRiskResult",
    "extract_features",
    "analyze_forms",
    "analyze_scripts",
    "analyze_obfuscation",
    "anchor_display_mismatch",
    "hidden_text",
    "external_domains",
    "COMPLEXITY_ONLY",
]
