"""OCR + QR extraction with lazy, optional dependencies.

The original module created a ``RapidOCR`` engine at import time, which made
``import guard.parse.parser`` fail on any machine without the OCR runtime. Per the project's
"deterministic fallback when its dependency fails" rule, heavy dependencies are now loaded
lazily and any failure degrades to an empty result instead of breaking the pipeline.
"""
from __future__ import annotations

import io
import os
from typing import List

_ocr_engine = None
_ocr_load_failed = False


def _get_ocr_engine():
    """Lazily construct the RapidOCR engine. Returns ``None`` when unavailable."""
    global _ocr_engine, _ocr_load_failed
    if _ocr_engine is not None or _ocr_load_failed:
        return _ocr_engine
    if os.environ.get("PHISHGUARD_DISABLE_OCR"):
        _ocr_load_failed = True
        return None
    try:  # pragma: no cover - depends on optional native deps
        from rapidocr_onnxruntime import RapidOCR

        _ocr_engine = RapidOCR()
    except Exception:  # pragma: no cover
        _ocr_load_failed = True
        _ocr_engine = None
    return _ocr_engine


def extract_text_from_image(image_bytes: bytes) -> str:
    if not image_bytes:
        return ""
    engine = _get_ocr_engine()
    if engine is None:
        return ""
    try:  # pragma: no cover - requires OCR runtime
        result, _ = engine(image_bytes)
        if result:
            return " ".join(str(line[1]) for line in result)
    except Exception:
        return ""
    return ""


def extract_qr_urls(image_bytes: bytes) -> List[str]:
    if not image_bytes:
        return []
    urls: List[str] = []
    try:  # pragma: no cover - requires optional native deps
        from PIL import Image
        from pyzbar.pyzbar import decode

        img = Image.open(io.BytesIO(image_bytes))
        for obj in decode(img):
            data = obj.data.decode("utf-8", "replace")
            if data.startswith("http"):
                urls.append(data)
    except Exception:
        return urls
    return urls
