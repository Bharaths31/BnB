import asyncio
import os
import threading
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from guard.config import settings
from guard.store.database import init_db
from guard.watcher.imap_watcher import MailboxWatcher
from guard.api.routes import sessions, events, mailbox
import uvicorn
import structlog

logger = structlog.get_logger()

app = FastAPI(title="PhishGuard Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(sessions.router, prefix="/api", tags=["sessions"])
app.include_router(events.router, prefix="/api", tags=["events"])
app.include_router(mailbox.router, prefix="/api", tags=["mailbox"])
app.include_router(mailbox.page_router, tags=["pages"])

watchers = []

def _discover_mailboxes():
    """Watched mailboxes: WATCH_MAILBOXES env, else the mailserver account file, else demo."""
    override = os.environ.get("WATCH_MAILBOXES", "").strip()
    if override:
        return [m.strip() for m in override.split(",") if m.strip()]

    candidates = [
        os.path.join(os.environ.get("MAILSERVER_CONFIG_DIR", "/app/config/mailserver"),
                     "postfix-accounts.cf"),
        "config/mailserver/postfix-accounts.cf",
    ]
    for path in candidates:
        try:
            with open(path, encoding="utf-8") as handle:
                mailboxes = []
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#") or "|" not in line:
                        continue
                    email = line.split("|", 1)[0].strip()
                    if email:
                        mailboxes.append(email)
                if mailboxes:
                    return mailboxes
        except FileNotFoundError:
            continue
    return ["victim@demo.local", "boss@demo.local", "admin@demo.local"]


async def start_watchers():
    users = _discover_mailboxes()
    host = os.environ.get("DOVECOT_HOST", "mailserver")
    logger.info("Starting watchers", mailboxes=users)
    for u in users:
        watcher = MailboxWatcher(u, host)
        watchers.append(watcher)
        asyncio.create_task(watcher.run())

@app.on_event("startup")
async def startup_event():
    await init_db()
    logger.info("Database initialized")
    # Optional shared MongoDB (auto-detected from creds/atlas-credentials.env).
    try:
        from guard.tracking.credentials import load_credentials
        from guard.tracking.mongo_backend import mongo_backend

        load_credentials()
        if mongo_backend.enabled:
            reachable = mongo_backend.ping()
            logger.info("Shared MongoDB configured", database=mongo_backend.db_name, reachable=reachable)
            if reachable:
                mongo_backend.ensure_schema()
        else:
            logger.info("Shared MongoDB not configured (optional)")
    except Exception as exc:  # never block startup on the optional tracking layer
        logger.warning("Shared MongoDB init skipped", error=str(exc))
    await start_watchers()
    logger.info("Watchers started")

@app.on_event("shutdown")
async def shutdown_event():
    for w in watchers:
        w.stop()

@app.get("/health")
def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
