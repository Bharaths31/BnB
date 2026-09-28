import aiosqlite
from guard.config import settings

from contextlib import asynccontextmanager

@asynccontextmanager
async def get_db():
    db = await aiosqlite.connect(settings.sqlite_path)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()

async def init_db():
    async with get_db() as db:
        await db.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                uid INTEGER PRIMARY KEY,
                mailbox TEXT,
                subject TEXT,
                sender TEXT,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                raw_headers_json TEXT
            )
        ''')
        await db.execute('''
            CREATE TABLE IF NOT EXISTS verdicts (
                uid INTEGER PRIMARY KEY,
                score REAL,
                verdict TEXT,
                reasons_json TEXT,
                component_scores_json TEXT,
                explanation TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        await db.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid INTEGER,
                action TEXT,
                reason TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        await db.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid INTEGER,
                label TEXT,
                user TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Table to keep track of processed UIDs
        await db.execute('''
            CREATE TABLE IF NOT EXISTS mailbox_state (
                mailbox TEXT PRIMARY KEY,
                last_uid INTEGER
            )
        ''')
        await db.commit()
