import aiosqlite
from guard.config import settings

from contextlib import asynccontextmanager

_CREATE_EMAILS = '''
    CREATE TABLE IF NOT EXISTS emails (
        uid INTEGER,
        mailbox TEXT,
        subject TEXT,
        sender TEXT,
        received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        raw_headers_json TEXT,
        PRIMARY KEY (mailbox, uid)
    )
'''

_CREATE_VERDICTS = '''
    CREATE TABLE IF NOT EXISTS verdicts (
        uid INTEGER,
        mailbox TEXT,
        score REAL,
        verdict TEXT,
        reasons_json TEXT,
        component_scores_json TEXT,
        explanation TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (mailbox, uid)
    )
'''


@asynccontextmanager
async def get_db():
    db = await aiosqlite.connect(settings.sqlite_path)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()


async def _columns(db, table: str):
    cols = set()
    async with db.execute(f"PRAGMA table_info({table})") as cursor:
        async for row in cursor:
            cols.add(row[1])
    return cols


async def _create_sql(db, table: str):
    async with db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ) as cursor:
        row = await cursor.fetchone()
    return row[0] if row else None


async def _migrate(db) -> None:
    """Upgrade the pre-release single-column ``uid`` schema to ``(mailbox, uid)``.

    UIDs are per-mailbox, so a single-column primary key drops messages whenever two mailboxes
    reuse the same UID. Existing rows are preserved; old verdicts are attributed to a mailbox
    best-effort via the ``emails`` table.
    """
    emails_sql = await _create_sql(db, "emails")
    if emails_sql and "primary key (mailbox, uid)" not in emails_sql.replace(" ", "").lower():
        await db.execute("ALTER TABLE emails RENAME TO emails_old")
        await db.execute(_CREATE_EMAILS)
        await db.execute(
            "INSERT OR IGNORE INTO emails (uid, mailbox, subject, sender, received_at, raw_headers_json)"
            " SELECT uid, mailbox, subject, sender, received_at, raw_headers_json FROM emails_old"
        )
        await db.execute("DROP TABLE emails_old")

    verdicts_sql = await _create_sql(db, "verdicts")
    if verdicts_sql and "primary key (mailbox, uid)" not in verdicts_sql.replace(" ", "").lower():
        old_has_mailbox = "mailbox" in await _columns(db, "verdicts")
        await db.execute("ALTER TABLE verdicts RENAME TO verdicts_old")
        await db.execute(_CREATE_VERDICTS)
        mailbox_expr = "v.mailbox" if old_has_mailbox else (
            "COALESCE((SELECT e.mailbox FROM emails e WHERE e.uid = v.uid LIMIT 1), '')"
        )
        await db.execute(
            "INSERT OR IGNORE INTO verdicts"
            " (uid, mailbox, score, verdict, reasons_json, component_scores_json, explanation, created_at)"
            f" SELECT v.uid, {mailbox_expr}, v.score, v.verdict, v.reasons_json,"
            " v.component_scores_json, v.explanation, v.created_at FROM verdicts_old v"
        )
        await db.execute("DROP TABLE verdicts_old")

    if "mailbox" not in await _columns(db, "audit_log"):
        await db.execute("ALTER TABLE audit_log ADD COLUMN mailbox TEXT")


async def init_db():
    async with get_db() as db:
        # Create the current (composite-key) schema; _migrate upgrades any legacy tables.
        await db.execute(_CREATE_EMAILS)
        await db.execute(_CREATE_VERDICTS)
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
        await db.execute('''
            CREATE TABLE IF NOT EXISTS mailbox_state (
                mailbox TEXT PRIMARY KEY,
                last_uid INTEGER
            )
        ''')
        await _migrate(db)
        await db.commit()
