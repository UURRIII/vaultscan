import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.database import get_db
from app.models.scan import Scan, User
from app.services.ai import analyst
from app.auth import get_current_user

router = APIRouter(prefix="/api", tags=["ai"])


class ChatRequest(BaseModel):
    question: str
    history: list[dict] = []


@router.get("/ai/status")
def ai_status():
    return {"available": analyst.is_available(), "model": analyst.MODEL}


def _load(scan_id: int, db: Session, user: User) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan or (scan.user_id != user.id and not user.is_admin):
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _sse(gen):
    async def event_stream():
        async for event in gen:
            yield f"data: {json.dumps(event)}\n\n"
    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/scans/{scan_id}/ai/analyze")
def ai_analyze(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = _load(scan_id, db, user)
    snap = analyst.snapshot(scan)  # materialize while the session is alive
    return _sse(analyst.stream_analysis(snap))


@router.post("/scans/{scan_id}/ai/chat")
def ai_chat(scan_id: int, body: ChatRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = _load(scan_id, db, user)
    snap = analyst.snapshot(scan)
    return _sse(analyst.stream_chat(snap, body.question, body.history))
