"""Static HTML structural feature extraction (WS3).

Everything here is deterministic and static: BeautifulSoup parses the markup, **JavaScript is
never executed**, and no network requests are made. Complexity alone is not treated as
malicious — these are raw features that downstream fusion contextualises.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_UNICODE_ESCAPE_RE = re.compile(r"%u[0-9a-fA-F]{4}")
_DOMAIN_RE = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.IGNORECASE)


def parse_style(tag) -> Dict[str, str]:
    style = (tag.get("style") or "") if hasattr(tag, "get") else ""
    out: Dict[str, str] = {}
    for part in style.split(";"):
        if ":" in part:
            key, value = part.split(":", 1)
            out[key.strip().lower()] = value.strip().lower()
    return out


def is_hidden(tag) -> bool:
    if tag.has_attr("hidden"):
        return True
    style = parse_style(tag)
    if style.get("display", "").startswith("none"):
        return True
    if style.get("visibility", "") in ("hidden", "collapse"):
        return True
    if style.get("opacity", "") in ("0", "0.0", "0%"):
        return True
    if style.get("font-size", "") in ("0", "0px", "0pt", "0em", "1px"):
        return True
    if style.get("height", "") in ("0", "0px") or style.get("width", "") in ("0", "0px"):
        return True
    return False


def is_zero_sized(tag) -> bool:
    style = parse_style(tag)
    return style.get("width", "") in ("0", "0px") and style.get("height", "") in ("0", "0px")


def is_transparent(tag) -> bool:
    style = parse_style(tag)
    if style.get("opacity", "") in ("0", "0.0", "0%"):
        return True
    color = style.get("color", "").replace(" ", "")
    background = style.get("background-color", style.get("background", "")).replace(" ", "")
    return bool(color) and color == background


def is_offscreen(tag) -> bool:
    style = parse_style(tag)
    if style.get("position", "") == "absolute":
        for key in ("left", "top"):
            value = style.get(key, "")
            if value.startswith("-") and value.rstrip("px").lstrip("-").isdigit():
                if abs(int(value.rstrip("px"))) >= 1000:
                    return True
    return False


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def is_external(url: str, sender_domain: str = "") -> bool:
    host = _host(url)
    if not host:
        return False
    if url.strip().lower().startswith("data:"):
        return False
    if not sender_domain:
        return True
    sender = sender_domain.lower()
    return not (host == sender or host.endswith("." + sender))


def display_text_looks_like_url(text: str) -> bool:
    text = (text or "").strip()
    if not text:
        return False
    if text.lower().startswith(("http://", "https://", "www.")):
        return True
    return bool(_DOMAIN_RE.fullmatch(text)) and "." in text


def anchor_display_mismatch(anchor, sender_domain: str = "") -> bool:
    href = anchor.get("href", "")
    if not href or href.strip().lower().startswith(("mailto:", "tel:", "#", "javascript:")):
        return False
    text = anchor.get_text().strip()
    if not display_text_looks_like_url(text):
        return False
    text_host = _extract_host_from_text(text)
    href_host = _host(href)
    return bool(text_host and href_host and text_host != href_host)


def _extract_host_from_text(text: str) -> str:
    text = text.strip()
    match = _DOMAIN_RE.search(text)
    return (match.group(1).lower() if match else "")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _dom_stats(soup: BeautifulSoup) -> Tuple[int, int]:
    node_count = len(soup.find_all())
    max_depth = 0

    def walk(tag, depth: int) -> None:
        nonlocal max_depth
        max_depth = max(max_depth, depth)
        for child in tag.children:
            if getattr(child, "name", None):
                walk(child, depth + 1)

    root = soup.body or soup
    walk(root, 0)
    return node_count, max_depth


def extract_features(html: str, sender_domain: str = "") -> Dict[str, float]:
    """Compute the full structural feature vector for an HTML body."""
    soup = BeautifulSoup(html or "", "html.parser")
    scripts = soup.find_all("script")
    external_scripts = [s for s in scripts if s.get("src")]
    inline_scripts = [s for s in scripts if not s.get("src")]

    images = soup.find_all("img")
    links = soup.find_all("link", href=True)
    resources = soup.find_all(src=True) + links

    external_image_domains = {_host(img.get("src", "")) for img in images if is_external(img.get("src", ""), sender_domain)}
    external_css_domains = {_host(l.get("href", "")) for l in links if is_external(l.get("href", ""), sender_domain)}
    external_resource_count = sum(
        1 for tag in resources if is_external(tag.get("src") or tag.get("href") or "", sender_domain)
    )

    anchors = soup.find_all("a", href=True)
    mismatched = sum(1 for a in anchors if anchor_display_mismatch(a, sender_domain))

    hidden = [t for t in soup.find_all() if is_hidden(t)]
    hidden_text_count = sum(1 for t in hidden if t.get_text().strip())
    zero_sized = [t for t in soup.find_all() if is_zero_sized(t)]
    transparent = [t for t in soup.find_all() if is_transparent(t)]
    offscreen = [t for t in soup.find_all() if is_offscreen(t)]

    style_attrs = [t.get("style", "") for t in soup.find_all(style=True)]
    suspicious_styles = sum(
        1 for s in style_attrs
        if any(token in s.replace(" ", "").lower() for token in
               ("display:none", "visibility:hidden", "opacity:0", "font-size:0", "left:-"))
    )

    node_count, depth = _dom_stats(soup)

    script_text = " ".join(s.get_text() for s in inline_scripts)
    data_uri_count = sum(
        1 for tag in soup.find_all(True)
        if str(tag.get("src", tag.get("href", ""))).strip().lower().startswith("data:")
    )
    base64_like = len(_BASE64_RE.findall(html or ""))
    redirects = sum(
        1 for m in soup.find_all("meta", attrs={"http-equiv": True})
        if (m.get("http-equiv", "").lower() == "refresh")
    )

    features = {
        "html_size": float(len(html or "")),
        "dom_node_count": float(node_count),
        "dom_depth": float(depth),
        "form_count": float(len(soup.find_all("form"))),
        "input_count": float(len(soup.find_all("input"))),
        "password_input_count": float(len(soup.find_all("input", attrs={"type": "password"}))),
        "iframe_count": float(len(soup.find_all("iframe"))),
        "script_count": float(len(scripts)),
        "inline_script_count": float(len(inline_scripts)),
        "external_script_count": float(len(external_scripts)),
        "hidden_element_count": float(len(hidden)),
        "hidden_text_count": float(hidden_text_count),
        "css_obfuscation_indicators": float(len(hidden) + suspicious_styles),
        "suspicious_style_attributes": float(suspicious_styles),
        "zero_sized_element_count": float(len(zero_sized)),
        "transparent_element_count": float(len(transparent)),
        "offscreen_element_count": float(len(offscreen)),
        "suspicious_redirect_count": float(redirects),
        "data_uri_count": float(data_uri_count),
        "base64_like_count": float(base64_like),
        "external_resource_count": float(external_resource_count),
        "external_image_domain_count": float(len(external_image_domains)),
        "external_css_domain_count": float(len(external_css_domains)),
        "anchor_count": float(len(anchors)),
        "mismatched_anchor_count": float(mismatched),
    }
    return features


#: Features that only represent complexity, never risk on their own.
COMPLEXITY_ONLY = {
    "html_size", "dom_node_count", "dom_depth", "script_count", "inline_script_count",
    "external_script_count", "external_resource_count", "anchor_count", "input_count",
    "external_image_domain_count", "external_css_domain_count", "data_uri_count",
}


def hidden_text(html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    return " ".join(t.get_text() for t in soup.find_all() if is_hidden(t) and t.get_text()).strip()


def external_domains(html: str, sender_domain: str = "") -> List[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    domains = set()
    for tag in soup.find_all(src=True) + soup.find_all(href=True):
        url = tag.get("src") or tag.get("href") or ""
        if is_external(url, sender_domain):
            domains.add(_host(url))
    return sorted(d for d in domains if d)
