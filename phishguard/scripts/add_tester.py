#!/usr/bin/env python3
"""Provision mail accounts for testers on the running mailserver **and** the shared MongoDB.

Examples:
    python3 scripts/add_tester.py alice@demo.local changeme
    python3 scripts/add_tester.py --from-file testers.txt
    python3 scripts/add_tester.py alice@demo.local changeme --no-mongo

``testers.txt`` format (one per line, ``email password``; the password defaults to
``changeme`` when omitted):

    alice@demo.local changeme
    bob@demo.local   changeme

Each tester is created on the mailserver (so they can use Roundcube / SMTP / IMAP) and, when
MongoDB is configured, upserted into the shared ``users`` collection so the Mongo-backed
webmail and reporting can authenticate them.
"""
import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guard.tracking.mongo_backend import MongoBackend


def add_mailserver_account(email: str, password: str) -> None:
    subprocess.check_call([
        "docker", "compose", "exec", "-T", "mailserver",
        "setup", "email", "add", email, password,
    ])
    print(f"Added mailserver account {email}")


def push_to_mongo(backend: MongoBackend, email: str, password: str) -> None:
    if not backend.enabled:
        print("  (MongoDB not configured — skipped shared user sync)")
        return
    if backend.upsert_user(
        email, password, role="tester", tester_id=os.environ.get("TESTER_ID", "")
    ):
        print(f"  synced {email} to MongoDB")
    else:
        print(f"  WARNING: could not sync {email} to MongoDB (check creds/connectivity)")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Provision tester accounts (mailserver + MongoDB)")
    parser.add_argument("email", nargs="?", help="email address, e.g. alice@demo.local")
    parser.add_argument("password", nargs="?", default="changeme")
    parser.add_argument("--from-file", help="file of 'email password' lines")
    parser.add_argument("--no-mongo", action="store_true", help="skip the MongoDB sync")
    args = parser.parse_args(argv)

    backend = MongoBackend()
    if backend.enabled and not args.no_mongo:
        backend.ensure_schema()

    def provision(email: str, password: str) -> None:
        add_mailserver_account(email, password)
        if not args.no_mongo:
            push_to_mongo(backend, email, password)

    if args.from_file:
        with open(args.from_file, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                email = parts[0]
                password = parts[1] if len(parts) > 1 else "changeme"
                provision(email, password)
        return 0

    if not args.email:
        parser.error("provide an email address, or --from-file")
    provision(args.email, args.password)
    return 0


if __name__ == "__main__":
    sys.exit(main())
