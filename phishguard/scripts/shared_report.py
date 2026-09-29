#!/usr/bin/env python3
"""Print the shared multi-tester tracking summary (from MongoDB Atlas).

Usage:
    python3 scripts/shared_report.py
    python3 scripts/shared_report.py --limit 50
    python3 scripts/shared_report.py --json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guard.tracking.shared_store import SharedTracker


def _iso(obj) -> str:
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Shared tracking report")
    parser.add_argument("--uri", default=None, help="override MONGODB_URI")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    tracker = SharedTracker(uri=args.uri) if args.uri else SharedTracker()
    if not tracker.enabled:
        print("MONGODB_URI is not set — shared tracking is disabled.")
        return 1

    summary = tracker.summary()
    latest = tracker.latest(args.limit)

    if args.json:
        print(json.dumps({"summary": summary, "latest": latest}, default=_iso, indent=2))
        return 0

    print("=== Summary (tester x verdict) ===")
    for row in summary:
        group = row["_id"]
        tester = group.get("tester") or "?"
        verdict = group.get("verdict") or "?"
        print(f"  {tester:<20} {verdict:<8} {row['count']}")

    print(f"\n=== Latest {len(latest)} events ===")
    for row in latest:
        created = _iso(row["created_at"])[:19] if "created_at" in row else "?"
        tester = row.get("tester") or "?"
        verdict = row.get("verdict") or "?"
        print(f"  {created}  {tester:<20} {verdict:<8} {(row.get('subject') or '')[:45]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
