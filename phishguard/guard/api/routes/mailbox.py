"""MongoDB-backed test APIs and a minimal webmail page.

These endpoints let a group of testers share one database: create accounts, send messages, and
read them back. They are only active when MongoDB is configured (``MONGODB_URI`` or
``creds/atlas-credentials.env``); otherwise they return HTTP 503.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from guard.tracking.mongo_backend import MongoBackend, mongo_backend

router = APIRouter()
page_router = APIRouter()


def _backend() -> MongoBackend:
    if not mongo_backend.enabled:
        raise HTTPException(status_code=503, detail="MongoDB is not configured on this server")
    return mongo_backend


class UserCreate(BaseModel):
    email: str
    password: Optional[str] = None
    role: str = "tester"
    tester_id: str = ""
    display: str = ""


class MessageCreate(BaseModel):
    sender: str
    to: str
    subject: str = ""
    body: str = ""


class LoginRequest(BaseModel):
    email: str
    password: str


@router.get("/mongo/status")
async def mongo_status():
    enabled = mongo_backend.enabled
    return {
        "enabled": enabled,
        "database": mongo_backend.db_name if enabled else None,
        "reachable": mongo_backend.ping() if enabled else False,
        "collections": mongo_backend.collection_names() if enabled else [],
    }


@router.post("/mongo/init")
async def mongo_init():
    backend = _backend()
    if not backend.ensure_schema():
        raise HTTPException(status_code=502, detail="Could not create the MongoDB schema")
    return {"ok": True, "collections": backend.collection_names()}


@router.get("/users")
async def list_users():
    return _backend().list_users()


@router.post("/users")
async def create_user(user: UserCreate):
    backend = _backend()
    backend.ensure_schema()
    if not backend.upsert_user(
        user.email, user.password, role=user.role, tester_id=user.tester_id, display=user.display
    ):
        raise HTTPException(status_code=502, detail="Could not store the user")
    return {"ok": True, "email": user.email}


@router.post("/login")
async def login(payload: LoginRequest):
    return {"authenticated": _backend().authenticate(payload.email, payload.password)}


@router.post("/messages")
async def send_message(message: MessageCreate):
    backend = _backend()
    message_id = backend.send_message(message.sender, message.to, message.subject, message.body)
    if message_id is None:
        raise HTTPException(status_code=502, detail="Could not store the message")
    return {"ok": True, "id": message_id}


@router.get("/messages")
async def list_messages(mailbox: str, folder: str = "inbox", limit: int = 50):
    return _backend().list_messages(mailbox, folder=folder, limit=limit)


@router.post("/messages/{message_id}/read")
async def mark_read(message_id: str):
    if not _backend().mark_read(message_id):
        raise HTTPException(status_code=404, detail="Message not found")
    return {"ok": True}


_MAIL_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>PhishGuard — Mongo Webmail</title>
<style>
 body{font-family:system-ui,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
 header{padding:16px 24px;background:#111827;border-bottom:1px solid #1f2937}
 h1{margin:0;font-size:18px}
 main{display:grid;grid-template-columns:340px 1fr;gap:24px;padding:24px;max-width:1100px;margin:0 auto}
 section{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:16px}
 label{display:block;font-size:12px;color:#94a3b8;margin:8px 0 4px}
 input,textarea,button{width:100%;box-sizing:border-box;padding:8px;border-radius:8px;
   border:1px solid #334155;background:#0b1220;color:#e2e8f0}
 button{margin-top:12px;background:#2563eb;border:none;font-weight:600;cursor:pointer}
 button.secondary{background:#374151}
 .msg{border-bottom:1px solid #1f2937;padding:10px 0}
 .msg h3{margin:0;font-size:14px}
 .meta{font-size:12px;color:#94a3b8}
 .pill{font-size:11px;padding:2px 8px;border-radius:999px;background:#1e293b;margin-left:6px}
 #status{font-size:13px;color:#93c5fd}
</style>
</head>
<body>
<header><h1>PhishGuard — MongoDB Webmail (test channel)</h1></header>
<main>
  <section>
    <label>Your email (mailbox)</label>
    <input id="me" placeholder="alice@demo.local"/>
    <label>Password (for login check)</label>
    <input id="pwd" type="password" placeholder="changeme"/>
    <button onclick="login()">Check login</button>
    <button class="secondary" onclick="load('inbox')">Load inbox</button>
    <button class="secondary" onclick="load('sent')">Load sent</button>
    <button class="secondary" onclick="status()">Mongo status</button>
    <p id="status"></p>
  </section>
  <section>
    <h2 style="margin-top:0;font-size:16px">Send a test message</h2>
    <label>To</label><input id="to" placeholder="bob@demo.local"/>
    <label>Subject</label><input id="subject" placeholder="Test subject"/>
    <label>Body</label><textarea id="body" rows="4" placeholder="Hello from MongoDB"></textarea>
    <button onclick="send()">Send</button>
    <h2 style="margin:20px 0 0;font-size:16px">Messages</h2>
    <div id="list"></div>
  </section>
</main>
<script>
const $ = (id) => document.getElementById(id);
function setStatus(t){ $('status').textContent = t; }
async function api(path, opts){ const r = await fetch('/api'+path, opts); return r.json(); }
async function status(){ const s = await api('/mongo/status');
  setStatus('enabled='+s.enabled+' reachable='+s.reachable+' db='+s.database+' collections='+(s.collections||[]).join(', ')); }
async function login(){ const b={email:$('me').value,password:$('pwd').value};
  const r = await api('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
  setStatus(r.authenticated ? 'login OK' : 'login FAILED'); }
async function load(folder){ const me=$('me').value;
  if(!me){ setStatus('enter your email first'); return; }
  const rows = await api('/messages?mailbox='+encodeURIComponent(me)+'&folder='+folder);
  $('list').innerHTML = rows.length ? rows.map(m => `<div class="msg"><h3>${m.subject||'(no subject)'}</h3>
    <div class="meta">${folder==='sent'?'to':'from'}: ${folder==='sent'?m.to:m.from} · ${new Date(m.created_at).toLocaleString()}
    <span class="pill">${m.read?'read':'unread'}</span></div><div>${(m.body||'').replace(/</g,'&lt;')}</div></div>`).join('')
    : '<p class="meta">No messages.</p>'; }
async function send(){ const b={sender:$('me').value,to:$('to').value,subject:$('subject').value,body:$('body').value};
  if(!b.sender||!b.to){ setStatus('sender and recipient are required'); return; }
  const r = await api('/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
  setStatus(r.ok ? 'sent ('+r.id+')' : ('send failed: '+(r.detail||'error'))); }
status();
</script>
</body>
</html>
"""


@page_router.get("/mail", response_class=HTMLResponse)
async def mail_page():
    return HTMLResponse(_MAIL_PAGE)
