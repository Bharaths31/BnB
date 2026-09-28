from guard.store.database import get_db
import json

async def save_email(uid: int, mailbox: str, subject: str, sender: str, headers: dict):
    async with get_db() as db:
        await db.execute(
            "INSERT OR IGNORE INTO emails (uid, mailbox, subject, sender, raw_headers_json) VALUES (?, ?, ?, ?, ?)",
            (uid, mailbox, subject, sender, json.dumps(headers))
        )
        await db.commit()

async def save_verdict(verdict):
    async with get_db() as db:
        await db.execute(
            "INSERT OR REPLACE INTO verdicts (uid, score, verdict, reasons_json, component_scores_json, explanation) VALUES (?, ?, ?, ?, ?, ?)",
            (verdict.uid, verdict.score, verdict.level, json.dumps(verdict.reasons), json.dumps(verdict.component_scores), verdict.explanation)
        )
        await db.commit()

async def get_verdict(uid: int):
    async with get_db() as db:
        async with db.execute("SELECT * FROM verdicts WHERE uid = ?", (uid,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
    return None

async def list_recent(limit: int = 50):
    async with get_db() as db:
        async with db.execute("""
            SELECT e.uid, e.subject, e.sender, e.received_at, v.score, v.verdict, v.reasons_json
            FROM emails e
            LEFT JOIN verdicts v ON e.uid = v.uid
            ORDER BY e.received_at DESC
            LIMIT ?
        """, (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

async def get_last_uid(mailbox: str) -> int:
    async with get_db() as db:
        async with db.execute("SELECT last_uid FROM mailbox_state WHERE mailbox = ?", (mailbox,)) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

async def update_last_uid(mailbox: str, uid: int):
    async with get_db() as db:
        await db.execute("INSERT OR REPLACE INTO mailbox_state (mailbox, last_uid) VALUES (?, ?)", (mailbox, uid))
        await db.commit()
