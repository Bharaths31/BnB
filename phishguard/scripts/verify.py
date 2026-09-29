#!/usr/bin/env python3
"""End-to-end verification that PhishGuard detects and blocks phishing.

The script is self-contained and safe to re-run:

1. checks the backend health endpoint;
2. records the current maximum email UID (a baseline so old events can't produce false passes);
3. sends one **phishing** and one **legitimate** demo email;
4. waits for both verdicts to appear in the API;
5. asserts the phishing message is FLAG/REVIEW/BLOCK and the legitimate one is ALLOW;
6. best-effort checks the `Quarantine` IMAP folder.

Exit code is ``0`` when verification passes and ``1`` when it fails, so it can be used in CI.

Usage (run from the ``phishguard/`` directory, with the stack running)::

    python3 scripts/verify.py
    python3 scripts/verify.py --timeout 90
    python3 scripts/verify.py --skip-send          # only re-check existing events
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional

PHISH_SUBJECT = "Update your account details"   # substring of the demo phishing subject
LEGIT_SUBJECT = "Weekly Team Update"            # demo legitimate subject
PHISH = "FLAG"  # minimal acceptable level for phishing (FLAG/REVIEW/BLOCK all count)
BLOCKING_LEVELS = {"FLAG", "REVIEW", "BLOCK"}


def http_json(url: str, timeout: float = 5.0):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_events(api: str) -> List[dict]:
    try:
        events = http_json(f"{api}/api/events?limit=200")
        return events if isinstance(events, list) else []
    except Exception:
        return []


def max_uid(events: List[dict], mailbox: str = "") -> int:
    values = [
        int(e.get("uid", 0) or 0)
        for e in events
        if not mailbox or (e.get("mailbox") or "") == mailbox
    ]
    return max(values, default=0)


def send_demo(mail_type: str, smtp_host: str, smtp_port: int, recipient: str) -> None:
    subprocess.check_call([
        sys.executable, "scripts/send_demo_mail.py",
        "--type", mail_type,
        "--smtp-host", smtp_host,
        "--smtp-port", str(smtp_port),
        "--to", recipient,
    ])


def wait_for_subject(
    api: str, subject_substr: str, baseline_uid: int, timeout: float, mailbox: str = ""
) -> Optional[dict]:
    deadline = time.time() + timeout
    best: Optional[dict] = None
    while time.time() < deadline:
        for event in fetch_events(api):
            subject = (event.get("subject") or "").lower()
            in_mailbox = not mailbox or (event.get("mailbox") or "") == mailbox
            if (
                subject_substr.lower() in subject
                and in_mailbox
                and int(event.get("uid", 0) or 0) > baseline_uid
            ):
                if best is None or int(event["uid"]) >= int(best["uid"]):
                    best = event
        if best is not None:
            return best
        time.sleep(2)
    return best


def imap_quarantine_check(host: str, port: int, user: str, password: str) -> str:
    try:
        import imaplib

        client = imaplib.IMAP4(host, port)
        client.login(user, password)
        _typ, boxes = client.list()
        listing = b" ".join(boxes or [])
        if b"Quarantine" not in listing:
            client.logout()
            return "Quarantine folder not present yet (no message was blocked)"
        client.select("Quarantine")
        _typ, data = client.search(None, "ALL")
        count = len((data[0] or b"").split())
        client.logout()
        return f"Quarantine folder contains {count} message(s)"
    except Exception as exc:  # pragma: no cover - best effort
        return f"IMAP quarantine check skipped ({exc})"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verify PhishGuard blocks phishing")
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--smtp-host", default="localhost")
    parser.add_argument("--smtp-port", type=int, default=25)
    parser.add_argument("--recipient", default="victim@demo.local")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--skip-send", action="store_true", help="do not send emails, just re-check")
    parser.add_argument("--imap-host", default="localhost")
    parser.add_argument("--imap-port", type=int, default=143)
    parser.add_argument("--imap-user", default="victim@demo.local")
    parser.add_argument("--imap-pass", default="changeme")
    args = parser.parse_args(argv)

    print("=" * 72)
    print("PhishGuard verification")
    print("=" * 72)

    # 1. Health -----------------------------------------------------------------
    print(f"[1/4] Health check .......... {args.api}/health")
    try:
        health = http_json(f"{args.api}/health")
    except Exception as exc:
        print(f"      FAIL: backend not reachable ({exc})")
        print("      Is the stack up? Try: docker compose ps")
        return 1
    if health.get("status") != "ok":
        print(f"      FAIL: unexpected health payload: {health}")
        return 1
    print("      OK")

    # 2. Baseline ---------------------------------------------------------------
    baseline = max_uid(fetch_events(args.api), args.recipient)
    print(f"[2/4] Baseline UID .......... {baseline} (mailbox {args.recipient})")

    # 3. Send -------------------------------------------------------------------
    if not args.skip_send:
        print(f"[3/4] Sending demo emails .. phish + legit -> {args.recipient}")
        try:
            send_demo("phish", args.smtp_host, args.smtp_port, args.recipient)
            send_demo("legit", args.smtp_host, args.smtp_port, args.recipient)
        except subprocess.CalledProcessError as exc:
            print(f"      FAIL: could not send demo mail ({exc})")
            print("      Is the mailserver healthy? docker compose ps")
            return 1
    else:
        print("[3/4] Skipping send (--skip-send)")

    # 4. Wait for verdicts ------------------------------------------------------
    print(f"[4/4] Waiting for verdicts .. up to {args.timeout:.0f}s")
    phish = wait_for_subject(args.api, PHISH_SUBJECT, baseline, args.timeout, args.recipient)
    legit = wait_for_subject(args.api, LEGIT_SUBJECT, baseline, args.timeout, args.recipient)

    passed = True

    print()
    if phish is None:
        print("  PHISH  : NOT FOUND (email not processed in time)")
        passed = False
    else:
        level = phish.get("verdict")
        score = float(phish.get("score") or 0.0)
        ok = level in BLOCKING_LEVELS and score >= 0.5
        passed = passed and ok
        print(f"  PHISH  : verdict={level} score={score:.2f}  ->  {'PASS' if ok else 'FAIL'}")

    if legit is None:
        print("  LEGIT  : NOT FOUND (email not processed in time)")
        passed = False
    else:
        level = legit.get("verdict")
        score = float(legit.get("score") or 0.0)
        ok = level == "ALLOW"
        passed = passed and ok
        print(f"  LEGIT  : verdict={level} score={score:.2f}  ->  {'PASS' if ok else 'FAIL'}")

    print()
    print(f"  {imap_quarantine_check(args.imap_host, args.imap_port, args.imap_user, args.imap_pass)}")

    print()
    print("=" * 72)
    print("RESULT:", "PASS — phishing is detected, legitimate mail is allowed" if passed
          else "FAIL — see the lines above")
    print("=" * 72)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
