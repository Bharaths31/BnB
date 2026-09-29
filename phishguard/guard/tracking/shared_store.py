"""Optional shared test-tracking store (MongoDB Atlas).

Enabled only when the ``MONGODB_URI`` environment variable is set. Everything is best-effort:
a missing ``pymongo`` install, a blank URI, or an unreachable database degrade to a silent
no-op, so the detection pipeline is never affected by the tracking layer.

Each event is attributed to a ``tester`` (from ``TESTER_ID``, falling back to the host name),
so several people running the stack locally can all record into one shared database.
"""
from __future__ import annotations

import os
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _default_uri() -> str:
    return os.environ.get("MONGODB_URI", "").strip()


class SharedTracker:
    def __init__(self, uri: Optional[str] = None):
        self.uri = uri if uri is not None else _default_uri()
        self._client = None
        self._import_failed = False

    # ------------------------------------------------------------------ plumbing
    @property
    def enabled(self) -> bool:
        return bool(self.uri)

    def _client_or_none(self):
        if not self.uri:
            return None
        if self._client is not None:
            return self._client
        if self._import_failed:
            return None
        try:
            from pymongo import MongoClient
        except Exception:
            self._import_failed = True
            return None
        try:
            self._client = MongoClient(self.uri, serverSelectionTimeoutMS=5000)
        except Exception:
            return None
        return self._client

    def _collection(self, name: str):
        client = self._client_or_none()
        if client is None:
            return None
        try:
            return client["phishguard_testing"][name]
        except Exception:
            return None

    def _tester(self) -> str:
        return os.environ.get("TESTER_ID", "").strip() or socket.gethostname()

    # ------------------------------------------------------------------ recording
    def record_verdict(self, verdict, mailbox: str = "", subject: str = "", sender: str = "") -> bool:
        if not self.enabled:
            return False
        collection = self._collection("test_events")
        if collection is None:
            return False
        try:
            collection.insert_one({
                "tester": self._tester(),
                "host": socket.gethostname(),
                "mailbox": mailbox,
                "uid": int(getattr(verdict, "uid", 0) or 0),
                "subject": subject or "",
                "sender": sender or "",
                "verdict": getattr(verdict, "level", "ALLOW"),
                "score": float(getattr(verdict, "score", 0.0) or 0.0),
                "created_at": datetime.now(timezone.utc),
            })
            return True
        except Exception:
            return False

    def record_feedback(self, mailbox: str, uid: int, subject: str, label: str) -> bool:
        if not self.enabled:
            return False
        collection = self._collection("test_feedback")
        if collection is None:
            return False
        try:
            collection.insert_one({
                "tester": self._tester(),
                "host": socket.gethostname(),
                "mailbox": mailbox,
                "uid": int(uid or 0),
                "subject": subject or "",
                "label": label,
                "created_at": datetime.now(timezone.utc),
            })
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ queries
    def latest(self, limit: int = 50) -> List[Dict[str, Any]]:
        collection = self._collection("test_events")
        if collection is None:
            return []
        try:
            return list(collection.find().sort("created_at", -1).limit(limit))
        except Exception:
            return []

    def summary(self) -> List[Dict[str, Any]]:
        collection = self._collection("test_events")
        if collection is None:
            return []
        try:
            return list(collection.aggregate([
                {"$group": {"_id": {"tester": "$tester", "verdict": "$verdict"}, "count": {"$sum": 1}}},
                {"$sort": {"_id.tester": 1, "_id.verdict": 1}},
            ]))
        except Exception:
            return []


#: Process-wide tracker. Reads ``MONGODB_URI`` / ``TESTER_ID`` from the environment once.
shared_tracker = SharedTracker()

__all__ = ["SharedTracker", "shared_tracker"]
