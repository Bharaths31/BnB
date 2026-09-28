import unicodedata
import re
import urllib.parse
from bs4 import BeautifulSoup
import confusables

def normalize_text(text: str) -> str:
    if not text:
        return ""
    # NFKC normalization
    text = unicodedata.normalize('NFKC', text)
    # Strip zero-width chars
    text = re.sub(r'[\u200B\u200C\u200D\uFEFF\u2060]', '', text)
    # Strip bidirectional overrides
    text = re.sub(r'[\u202A-\u202E\u2066-\u2069]', '', text)
    # Homoglyph folding
    normalized = confusables.normalize(text, prioritize_alpha=True)
    if normalized:
        text = normalized[0]
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def normalize_url(url: str) -> str:
    if not url:
        return ""
    # Decode percent encoding
    url = urllib.parse.unquote(url)
    # De-obfuscate common tricks
    url = re.sub(r'hxxps?://', 'http://', url, flags=re.IGNORECASE)
    url = url.replace('[.]', '.')
    return url
