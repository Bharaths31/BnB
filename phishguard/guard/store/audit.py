from guard.store.database import get_db

async def log_action(uid: int, action: str, reason: str):
    async with get_db() as db:
        await db.execute(
            "INSERT INTO audit_log (uid, action, reason) VALUES (?, ?, ?)",
            (uid, action, reason)
        )
        await db.commit()
