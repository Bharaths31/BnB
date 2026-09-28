from fastapi import APIRouter
from pydantic import BaseModel
from typing import List

router = APIRouter()

class SessionConfig(BaseModel):
    user: str
    active: bool

# In-memory store for demo
sessions = {}

@router.post("/sessions", response_model=SessionConfig)
async def create_session(config: SessionConfig):
    sessions[config.user] = config
    return config

@router.get("/sessions", response_model=List[SessionConfig])
async def list_sessions():
    return list(sessions.values())
