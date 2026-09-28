"""SQLite-backed persistence for behavioral profiles (WS1).

Restarting the service must not erase historical context, so profiles are stored as JSON
blobs alongside a raw observation log (which allows profiles to be rebuilt). Uses the stdlib
``sqlite3`` driver so it works without the async stack.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import List, Optional

from guard.behavioral.recipient_profile import RelationshipProfile
from guard.behavioral.sender_profile import SenderProfile
from guard.config import policy


def default_db_path() -> str:
    env = os.environ.get("PHISHGUARD_PROFILE_DB")
    if env:
        return env
    configured = policy.get("behavioral", {}).get("profile_db_path")
    if configured:
        return configured
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, "data", "profiles.db")


class ProfileStore:
    def __init__(self, path: Optional[str] = None):
        self.path = path or default_db_path()
        if self.path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sender_profiles (
                    sender TEXT PRIMARY KEY,
                    display_key TEXT,
                    total_messages INTEGER DEFAULT 0,
                    profile_json TEXT NOT NULL,
                    updated_at TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS relationship_profiles (
                    sender TEXT,
                    recipient TEXT,
                    profile_json TEXT NOT NULL,
                    updated_at TEXT,
                    PRIMARY KEY (sender, recipient)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS profile_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT,
                    recipient TEXT,
                    observed_at TEXT,
                    label TEXT,
                    created_at TEXT
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_obs_sender ON profile_observations(sender)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sender_display ON sender_profiles(display_key)")
            self._ensure_columns(
                "sender_profiles",
                {"display_key": "TEXT", "total_messages": "INTEGER DEFAULT 0"},
            )
            self._conn.commit()

    def _ensure_columns(self, table: str, columns: dict) -> None:
        existing = {row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in columns.items():
            if name not in existing:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    # --------------------------------------------------------------------- senders
    def get_sender(self, sender: str) -> Optional[SenderProfile]:
        if not sender:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT profile_json FROM sender_profiles WHERE sender = ?", (sender.lower(),)
            ).fetchone()
        return SenderProfile.model_validate_json(row["profile_json"]) if row else None

    def save_sender(self, profile: SenderProfile) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO sender_profiles"
                " (sender, display_key, total_messages, profile_json, updated_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    profile.sender.lower(),
                    profile.display_key,
                    profile.total_messages,
                    profile.model_dump_json(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()

    def get_sender_by_display(self, display: str) -> Optional[SenderProfile]:
        """Fallback identity lookup: the best-known sender using this display name.

        This is what makes sender-domain-change detection meaningful — the same claimed
        identity (e.g. "Microsoft Support") arriving from a lookalike domain is compared
        against that identity's history even though the address itself is new.
        """
        display = (display or "").strip().lower()
        if not display:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT profile_json FROM sender_profiles WHERE display_key = ?"
                " ORDER BY total_messages DESC LIMIT 1",
                (display,),
            ).fetchone()
        return SenderProfile.model_validate_json(row["profile_json"]) if row else None

    # ----------------------------------------------------------------- relationships
    def get_relationship(self, sender: str, recipient: str) -> Optional[RelationshipProfile]:
        if not sender or not recipient:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT profile_json FROM relationship_profiles WHERE sender = ? AND recipient = ?",
                (sender.lower(), recipient.lower()),
            ).fetchone()
        return RelationshipProfile.model_validate_json(row["profile_json"]) if row else None

    def save_relationship(self, profile: RelationshipProfile) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO relationship_profiles (sender, recipient, profile_json, updated_at)"
                " VALUES (?, ?, ?, ?)",
                (
                    profile.sender.lower(),
                    profile.recipient.lower(),
                    profile.model_dump_json(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()

    # ------------------------------------------------------------------ observations
    def record_observation(
        self, sender: str, recipient: str = "", label: str = "unknown", observed_at: Optional[datetime] = None
    ) -> None:
        observed_at = observed_at or datetime.now(timezone.utc)
        with self._lock:
            self._conn.execute(
                "INSERT INTO profile_observations (sender, recipient, observed_at, label, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (sender.lower(), (recipient or "").lower(), observed_at.isoformat(), label,
                 datetime.now(timezone.utc).isoformat()),
            )
            self._conn.commit()

    def observations_for(self, sender: str, limit: int = 1000) -> List[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT sender, recipient, observed_at, label FROM profile_observations"
                " WHERE sender = ? ORDER BY observed_at DESC LIMIT ?",
                (sender.lower(), limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


_default_store: Optional[ProfileStore] = None
_default_lock = threading.Lock()


def get_profile_store() -> ProfileStore:
    """Process-wide default store (lazy)."""
    global _default_store
    if _default_store is None:
        with _default_lock:
            if _default_store is None:
                _default_store = ProfileStore()
    return _default_store
