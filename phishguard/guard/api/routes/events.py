from fastapi import APIRouter
from pydantic import BaseModel
from typing import List
from guard.store.events import list_recent

router = APIRouter()

class Event(BaseModel):
    uid: int
    subject: str
    sender: str
    received_at: str
    score: float
    verdict: str
    reasons: list

@router.get("/events", response_model=List[Event])
async def get_events(limit: int = 50):
    events = await list_recent(limit)
    res = []
    for e in events:
        import json
        reasons = []
        if e['reasons_json']:
            reasons = json.loads(e['reasons_json'])
        res.append(Event(
            uid=e['uid'],
            subject=e['subject'] or '',
            sender=e['sender'] or '',
            received_at=str(e['received_at']),
            score=e['score'] or 0.0,
            verdict=e['verdict'] or 'ALLOW',
            reasons=reasons
        ))
    return res
