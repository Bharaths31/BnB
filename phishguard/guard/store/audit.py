from guard.store.database import get_db

async def log_action(uid: int, action: str, reason: str, mailbox: str = ""):
    async with get_db() as db:
        await db.execute(
            "INSERT INTO audit_log (uid, mailbox, action, reason) VALUES (?, ?, ?, ?)",
            (uid, mailbox, action, reason)
        )
        await db.commit()
