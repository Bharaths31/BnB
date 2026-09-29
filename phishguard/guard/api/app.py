import asyncio
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

async def start_watchers():
    users = ["victim@demo.local", "boss@demo.local", "admin@demo.local"]
    for u in users:
        watcher = MailboxWatcher(u, settings.dovecot_master_user) # Wait, host is settings.dovecot_master_user? No.
        # Imap host should be mailserver
        import os
        host = os.environ.get("DOVECOT_HOST", "mailserver")
        watcher.host = host
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
