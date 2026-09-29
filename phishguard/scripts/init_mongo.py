#!/usr/bin/env python3
"""Create the shared MongoDB collections and indexes (idempotent).

Run once against a fresh Atlas cluster, or any time you add a new collection:

    python3 scripts/init_mongo.py
    python3 scripts/init_mongo.py --creds creds/atlas-credentials.env
    python3 scripts/init_mongo.py --uri "mongodb+srv://..."

The connection string is resolved from (in order) ``--uri``, ``MONGODB_URI``/aliases, or the
auto-detected ``creds/atlas-credentials.env``.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guard.tracking.credentials import load_credentials, resolve_uri
from guard.tracking.mongo_backend import COLLECTIONS, MongoBackend


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Initialise the shared MongoDB schema")
    parser.add_argument("--uri", default=None, help="override the connection string")
    parser.add_argument("--creds", default=None, help="path to a credentials env file")
    args = parser.parse_args(argv)

    if args.creds:
        load_credentials(args.creds)

    backend = MongoBackend(uri=args.uri)
    if not backend.enabled:
        print("No MongoDB connection string found (set MONGODB_URI or provide "
              "creds/atlas-credentials.env). Nothing to do.")
        return 1

    print(f"Connecting to MongoDB (database '{backend.db_name}')...")
    if not backend.ping():
        print("FAILED: could not reach MongoDB. Check the URI/user/password and network access.")
        return 2

    if not backend.ensure_schema():
        print("FAILED: could not create collections/indexes.")
        return 3

    print("Created/verified collections:", ", ".join(COLLECTIONS))
    print("Collections now present:", ", ".join(backend.collection_names()))
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
