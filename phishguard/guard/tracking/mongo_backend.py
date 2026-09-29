"""MongoDB backend for the shared multi-tester system.

Provides schema creation, tester-account storage/authentication, and a lightweight
Mongo-backed message store so testers can send and receive test emails without the SMTP/IMAP
server. Everything degrades to a no-op when MongoDB is not configured or ``pymongo`` is absent,
so the detection pipeline is never affected.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from guard.tracking.credentials import database_name, resolve_uri

COLLECTIONS = ("users", "messages", "test_events", "test_feedback")


class MongoBackend:
    def __init__(self, uri: Optional[str] = None, db_name: Optional[str] = None):
        self._uri = uri
        self.db_name = db_name or database_name()
        self._client = None
        self._import_failed = False

    # ------------------------------------------------------------------ plumbing
    @property
    def uri(self) -> str:
        if self._uri is None:
            self._uri = resolve_uri()  # lazy: picks up creds/atlas-credentials.env
        return self._uri

    @uri.setter
    def uri(self, value: Optional[str]) -> None:
        self._uri = value

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

    def _db(self):
        client = self._client_or_none()
        if client is None:
            return None
        try:
            return client[self.db_name]
        except Exception:
            return None

    def ping(self) -> bool:
        db = self._db()
        if db is None:
            return False
        try:
            db.command("ping")
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ schema
    def ensure_schema(self) -> bool:
        """Create the collections and indexes if they do not exist (idempotent)."""
        db = self._db()
        if db is None:
            return False
        try:
            existing = set(db.list_collection_names())
            for name in COLLECTIONS:
                if name not in existing:
                    try:
                        db.create_collection(name)
                    except Exception:
                        pass  # already created by a concurrent process
            db.users.create_index("email", unique=True)
            db.messages.create_index("to")
            db.messages.create_index("from")
            db.messages.create_index("created_at")
            db.test_events.create_index("tester")
            db.test_events.create_index("created_at")
            db.test_feedback.create_index("tester")
            return True
        except Exception:
            return False

    def collection_names(self) -> List[str]:
        db = self._db()
        if db is None:
            return []
        try:
            return sorted(db.list_collection_names())
        except Exception:
            return []

    # ------------------------------------------------------------------ users
    @staticmethod
    def _hash_password(password: str, salt: Optional[str] = None):
        salt = salt or secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
        return digest.hex(), salt

    def upsert_user(
        self,
        email: str,
        password: Optional[str] = None,
        role: str = "tester",
        tester_id: str = "",
        display: str = "",
    ) -> bool:
        db = self._db()
        if db is None or not email:
            return False
        now = datetime.now(timezone.utc)
        update: Dict[str, Any] = {
            "email": email.lower(),
            "role": role,
            "tester_id": tester_id or "",
            "display": display or email,
            "active": True,
            "updated_at": now,
        }
        if password:
            digest, salt = self._hash_password(password)
            update["password_hash"] = digest
            update["salt"] = salt
        try:
            db.users.update_one(
                {"email": email.lower()},
                {"$set": update, "$setOnInsert": {"created_at": now}},
                upsert=True,
            )
            return True
        except Exception:
            return False

    def authenticate(self, email: str, password: str) -> bool:
        db = self._db()
        if db is None or not email:
            return False
        try:
            doc = db.users.find_one({"email": email.lower()})
        except Exception:
            return False
        if not doc or "password_hash" not in doc:
            return False
        digest, _ = self._hash_password(password, doc.get("salt"))
        return hmac.compare_digest(digest, doc["password_hash"])

    def list_users(self) -> List[Dict[str, Any]]:
        db = self._db()
        if db is None:
            return []
        try:
            return list(db.users.find(
                {}, {"_id": 0, "email": 1, "role": 1, "tester_id": 1, "active": 1, "created_at": 1}
            ))
        except Exception:
            return []

    # ------------------------------------------------------------------ messages
    def send_message(self, sender: str, to: str, subject: str = "", body: str = "") -> Optional[str]:
        db = self._db()
        if db is None or not sender or not to:
            return None
        doc = {
            "from": sender,
            "to": to,
            "subject": subject or "",
            "body": body or "",
            "read": False,
            "created_at": datetime.now(timezone.utc),
        }
        try:
            result = db.messages.insert_one(doc)
            return str(result.inserted_id)
        except Exception:
            return None

    def list_messages(self, mailbox: str, folder: str = "inbox", limit: int = 50) -> List[Dict[str, Any]]:
        db = self._db()
        if db is None or not mailbox:
            return []
        query = {"to": mailbox} if folder == "inbox" else {"from": mailbox}
        try:
            rows = list(db.messages.find(query).sort("created_at", -1).limit(limit))
        except Exception:
            return []
        for row in rows:
            row["_id"] = str(row.get("_id", ""))
        return rows

    def mark_read(self, message_id: str) -> bool:
        db = self._db()
        if db is None or not message_id:
            return False
        try:
            from bson import ObjectId

            db.messages.update_one({"_id": ObjectId(message_id)}, {"$set": {"read": True}})
            return True
        except Exception:
            return False


#: Process-wide backend (reads credentials lazily).
mongo_backend = MongoBackend()

__all__ = ["MongoBackend", "mongo_backend", "COLLECTIONS"]
