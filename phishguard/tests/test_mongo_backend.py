"""Tests for the optional MongoDB shared backend (no live cluster required)."""
import os

from guard.tracking.credentials import load_credentials, parse_env_file, resolve_uri
from guard.tracking.mongo_backend import MongoBackend


def test_parse_env_file(tmp_path):
    path = tmp_path / "atlas-credentials.env"
    path.write_text(
        "# comment\n"
        "MONGO_URL=mongodb+srv://cluster0.x.mongodb.net/?appName=Cluster0\n"
        "MONGO_USER=alice\n"
        "MONGO_PASSWORD=secret\n"
    )
    data = parse_env_file(path)
    assert data["MONGO_USER"] == "alice"
    assert data["MONGO_PASSWORD"] == "secret"


def test_resolve_uri_prefers_full_uri():
    uri = resolve_uri({"MONGODB_URI": "mongodb+srv://u:p@h/db", "MONGO_URL": "ignored"})
    assert uri == "mongodb+srv://u:p@h/db"


def test_resolve_uri_builds_from_parts_and_encodes_password():
    uri = resolve_uri({
        "MONGO_URL": "mongodb+srv://cluster0.x.mongodb.net/?appName=Cluster0",
        "MONGO_USER": "alice",
        "MONGO_PASSWORD": "p@ss",
    })
    assert uri.startswith("mongodb+srv://alice:")
    assert "cluster0.x.mongodb.net" in uri
    assert "p%40ss" in uri  # '@' URL-encoded


def test_resolve_uri_without_credentials_returns_url():
    uri = resolve_uri({"MONGO_URL": "mongodb+srv://cluster0.x.mongodb.net/"})
    assert uri == "mongodb+srv://cluster0.x.mongodb.net/"


def test_backend_disabled_without_uri():
    backend = MongoBackend(uri="")
    assert backend.enabled is False
    assert backend.ping() is False
    assert backend.ensure_schema() is False
    assert backend.upsert_user("a@b.c", "pw") is False
    assert backend.authenticate("a@b.c", "pw") is False
    assert backend.list_users() == []
    assert backend.send_message("a@b.c", "b@c.d", "s", "body") is None
    assert backend.list_messages("a@b.c") == []
    assert backend.mark_read("nope") is False
    assert backend.collection_names() == []


def test_password_hashing_roundtrip():
    digest, salt = MongoBackend._hash_password("hunter2")
    again, _ = MongoBackend._hash_password("hunter2", salt)
    wrong, _ = MongoBackend._hash_password("wrong", salt)
    assert digest == again
    assert digest != wrong


def test_load_credentials_populates_env(tmp_path):
    for key in ("MONGO_USER", "MONGO_PASSWORD"):
        os.environ.pop(key, None)
    path = tmp_path / "atlas-credentials.env"
    path.write_text("MONGO_USER=bob\nMONGO_PASSWORD=pw\n")
    loaded = load_credentials(str(path))
    assert loaded["MONGO_USER"] == "bob"
    assert os.environ.get("MONGO_USER") == "bob"
    os.environ.pop("MONGO_USER", None)
    os.environ.pop("MONGO_PASSWORD", None)
