"""Pipeline assembly: register the detector components on a fusion engine.

Kept separate from ``fusion_engine`` so importing the engine has no side effects (no profile
database is opened unless the pipeline is actually built).

Usage in the watcher / API::

    engine = get_pipeline_engine()          # process-wide, lazily assembled
    verdict = engine.evaluate(uid, parsed)
    engine.update_after_verdict(parsed, verdict)
"""
from __future__ import annotations

import threading
from typing import Optional

from guard.attachment import AttachmentComponent
from guard.behavioral import BehavioralComponent
from guard.behavioral.profile_store import ProfileStore, get_profile_store
from guard.fusion.fusion_engine import FusionEngine
from guard.html import HtmlComponent
from guard.multimodal import MultimodalComponent
from guard.nlp.intent import IntentComponent


def build_default_engine(profile_store: Optional[ProfileStore] = None) -> FusionEngine:
    """Create a fusion engine with all currently-implemented detectors registered."""
    engine = FusionEngine()
    store = profile_store or get_profile_store()
    engine.register(HtmlComponent())
    engine.register(AttachmentComponent())
    engine.register(MultimodalComponent())
    engine.register(IntentComponent())
    engine.register(BehavioralComponent(store))
    return engine


_engine: Optional[FusionEngine] = None
_engine_lock = threading.Lock()


def get_pipeline_engine() -> FusionEngine:
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = build_default_engine()
    return _engine


__all__ = ["build_default_engine", "get_pipeline_engine"]
