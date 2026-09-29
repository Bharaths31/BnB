#!/usr/bin/env python3
"""Provision mail accounts for testers on the running mailserver.

Examples:
    python3 scripts/add_tester.py alice@demo.local changeme
    python3 scripts/add_tester.py --from-file testers.txt

``testers.txt`` format (one per line, ``email password``; the password defaults to
``changeme`` when omitted):

    alice@demo.local changeme
    bob@demo.local   changeme
"""
import argparse
import subprocess
import sys


def add(email: str, password: str) -> None:
    subprocess.check_call([
        "docker", "compose", "exec", "-T", "mailserver",
        "setup", "email", "add", email, password,
    ])
    print(f"Added account {email}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Provision tester mail accounts")
    parser.add_argument("email", nargs="?", help="email address, e.g. alice@demo.local")
    parser.add_argument("password", nargs="?", default="changeme")
    parser.add_argument("--from-file", help="file of 'email password' lines")
    args = parser.parse_args(argv)

    if args.from_file:
        with open(args.from_file, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                email = parts[0]
                password = parts[1] if len(parts) > 1 else "changeme"
                add(email, password)
        return 0

    if not args.email:
        parser.error("provide an email address, or --from-file")
    add(args.email, args.password)
    return 0


if __name__ == "__main__":
    sys.exit(main())
