from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.database import get_db
from app.models.scan import Schedule, Alert

router = APIRouter(prefix="/api", tags=["monitoring"])


class ScheduleCreate(BaseModel):
    target: str
    mode: str = "safe"
    tags: str = ""
    interval_minutes: int = 1440


class ScheduleOut(BaseModel):
    id: int
    target: str
    mode: str
    tags: str
    interval_minutes: int
    enabled: int
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    created_at: datetime
    model_config = {"from_attributes": True}


class AlertOut(BaseModel):
    id: int
    scan_id: Optional[int]
    target: str
    level: str
    message: str
    is_read: int
    created_at: datetime
    model_config = {"from_attributes": True}


# ── Schedules ──
@router.get("/schedules", response_model=list[ScheduleOut])
def list_schedules(db: Session = Depends(get_db)):
    return db.query(Schedule).order_by(Schedule.created_at.desc()).all()


@router.post("/schedules", response_model=ScheduleOut, status_code=201)
def create_schedule(body: ScheduleCreate, db: Session = Depends(get_db)):
    target = body.target.strip().rstrip("/")
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    mode = "aggressive" if body.mode == "aggressive" else "safe"
    sched = Schedule(
        target=target, mode=mode, tags=body.tags,
        interval_minutes=max(1, body.interval_minutes), next_run=datetime.utcnow(),
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return sched


@router.patch("/schedules/{sid}", response_model=ScheduleOut)
def toggle_schedule(sid: int, db: Session = Depends(get_db)):
    sched = db.get(Schedule, sid)
    if not sched:
        raise HTTPException(status_code=404, detail="Not found")
    sched.enabled = 0 if sched.enabled else 1
    db.commit()
    db.refresh(sched)
    return sched


@router.delete("/schedules/{sid}", status_code=204)
def delete_schedule(sid: int, db: Session = Depends(get_db)):
    sched = db.get(Schedule, sid)
    if sched:
        db.delete(sched)
        db.commit()


# ── Alerts ──
@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(db: Session = Depends(get_db)):
    return db.query(Alert).order_by(Alert.created_at.desc()).limit(100).all()


@router.get("/alerts/unread_count")
def unread_count(db: Session = Depends(get_db)):
    return {"count": db.query(Alert).filter(Alert.is_read == 0).count()}


@router.post("/alerts/read_all")
def mark_all_read(db: Session = Depends(get_db)):
    db.query(Alert).filter(Alert.is_read == 0).update({"is_read": 1})
    db.commit()
    return {"ok": True}


@router.delete("/alerts/{aid}", status_code=204)
def delete_alert(aid: int, db: Session = Depends(get_db)):
    a = db.get(Alert, aid)
    if a:
        db.delete(a)
        db.commit()
