from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.database import get_db
from app.models.scan import Schedule, Alert, User, VerifiedDomain
from app.auth import get_current_user
from app.routers.auth import PLAN_LIMITS
from app.core.context import normalize

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
def list_schedules(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(Schedule)
    if not user.is_admin:
        q = q.filter(Schedule.user_id == user.id)
    return q.order_by(Schedule.created_at.desc()).all()


@router.post("/schedules", response_model=ScheduleOut, status_code=201)
def create_schedule(body: ScheduleCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    target = body.target.strip().rstrip("/")
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")

    limits = PLAN_LIMITS.get(user.plan, PLAN_LIMITS["free"])
    if not limits["scheduling"]:
        raise HTTPException(status_code=403, detail="Scheduled scans require the Pro plan.")
    mode = "aggressive" if body.mode == "aggressive" else "safe"
    if mode == "aggressive" and not limits["aggressive"]:
        raise HTTPException(status_code=403, detail="Aggressive scans require the Pro plan.")

    # Domain ownership gate.
    if not user.is_admin:
        _, host, _ = normalize(target)
        verified = {d.domain.lower() for d in
                    db.query(VerifiedDomain).filter(VerifiedDomain.user_id == user.id,
                                                    VerifiedDomain.verified == 1).all()}
        if not any(host == d or host.endswith("." + d) for d in verified):
            raise HTTPException(status_code=403, detail=f"Domain '{host}' is not verified.")

    sched = Schedule(
        user_id=user.id, target=target, mode=mode, tags=body.tags,
        interval_minutes=max(1, body.interval_minutes), next_run=datetime.utcnow(),
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return sched


def _owned_sched(sid: int, user: User, db: Session) -> Schedule:
    s = db.get(Schedule, sid)
    if not s or (s.user_id != user.id and not user.is_admin):
        raise HTTPException(status_code=404, detail="Not found")
    return s


@router.patch("/schedules/{sid}", response_model=ScheduleOut)
def toggle_schedule(sid: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sched = _owned_sched(sid, user, db)
    sched.enabled = 0 if sched.enabled else 1
    db.commit()
    db.refresh(sched)
    return sched


@router.delete("/schedules/{sid}", status_code=204)
def delete_schedule(sid: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sched = _owned_sched(sid, user, db)
    db.delete(sched)
    db.commit()


# ── Alerts ──
def _alert_q(user, db):
    q = db.query(Alert)
    return q if user.is_admin else q.filter(Alert.user_id == user.id)


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _alert_q(user, db).order_by(Alert.created_at.desc()).limit(100).all()


@router.get("/alerts/unread_count")
def unread_count(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"count": _alert_q(user, db).filter(Alert.is_read == 0).count()}


@router.post("/alerts/read_all")
def mark_all_read(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _alert_q(user, db).filter(Alert.is_read == 0).update({"is_read": 1})
    db.commit()
    return {"ok": True}


@router.delete("/alerts/{aid}", status_code=204)
def delete_alert(aid: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = db.get(Alert, aid)
    if a and (a.user_id == user.id or user.is_admin):
        db.delete(a)
        db.commit()
