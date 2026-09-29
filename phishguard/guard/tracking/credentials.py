"""Credential discovery for the shared MongoDB Atlas database.

Auto-detects ``creds/atlas-credentials.env`` (placed at deployment time) and resolves it into a
connection string. Accepts either a full URI or a cluster URL plus user/password. Nothing here
requires ``pymongo`` and no secret is ever returned in logs.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import quote_plus

_CRED_FILENAMES = ("atlas-credentials.env", "mongodb.env", "mongo.env")
_auto_loaded = False


def candidate_paths(explicit: Optional[str] = None):
    """Where credentials may live, in priority order."""
    if explicit:
        yield Path(explicit)
    root = Path(__file__).resolve().parents[2]  # phishguard/
    for name in _CRED_FILENAMES:
        yield root / "creds" / name
        yield Path.cwd() / "creds" / name


def parse_env_file(path) -> Dict[str, str]:
    data: Dict[str, str] = {}
    try:
        text = Path(path).read_text(encoding="utf-8")
    except Exception:
        return data
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def load_credentials(explicit: Optional[str] = None, override: bool = False) -> Dict[str, str]:
    """Load the first credentials file found into ``os.environ`` (without clobbering)."""
    for path in candidate_paths(explicit):
        if path and path.is_file():
            data = parse_env_file(path)
            for key, value in data.items():
                if override or key not in os.environ:
                    os.environ[key] = value
            return data
    return {}


def _first(env: Dict[str, str], names) -> str:
    for name in names:
        value = (env.get(name) or "").strip()
        if value:
            return value
    return ""


def resolve_uri(env: Optional[Dict[str, str]] = None) -> str:
    """Return a MongoDB connection string, or "" when not configured.

    Resolution order: a full URI (``MONGODB_URI``/aliases), else a cluster URL
    (``MONGO_URL``/aliases) combined with ``MONGO_USER``/``MONGO_PASSWORD``.
    """
    global _auto_loaded
    if env is None:
        if not _auto_loaded:
            load_credentials()
            _auto_loaded = True
        env = os.environ  # type: ignore[assignment]

    uri = _first(env, ("MONGODB_URI", "MONGO_URI", "ATLAS_URI", "MONGODB_URL"))
    if uri:
        return uri

    url = _first(env, ("MONGO_URL", "ATLAS_URL", "CLUSTER_URL", "MONGODB_HOST"))
    if not url:
        return ""
    user = _first(env, ("MONGO_USER", "ATLAS_USER", "DB_USERNAME", "MONGODB_USER"))
    password = _first(env, ("MONGO_PASSWORD", "ATLAS_PASSWORD", "DB_PASSWORD", "MONGODB_PASSWORD"))
    if not user or not password:
        return url
    if "://" not in url:
        url = "mongodb+srv://" + url
    scheme, rest = url.split("://", 1)
    host = rest.split("/", 1)[0]
    if "@" in host:  # credentials already embedded
        return url
    return f"{scheme}://{quote_plus(user)}:{quote_plus(password)}@{rest}"


def database_name(env: Optional[Dict[str, str]] = None) -> str:
    env = env or os.environ
    return (env.get("MONGODB_DB") or "phishguard").strip() or "phishguard"


__all__ = ["candidate_paths", "parse_env_file", "load_credentials", "resolve_uri", "database_name"]
