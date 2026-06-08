import asyncio
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.scan import Scan, Finding, User, VerifiedDomain
from app.schemas.scan import (
    ScanCreate, MultiScanCreate, ScanUpdate, ScanOut, ScanSummary,
)
from app.services import engine
from app.routers.ws import scan_queues
from app.auth import get_current_user
from app.routers.auth import PLAN_LIMITS
from app.core.context import normalize

router = APIRouter(prefix="/api/scans", tags=["scans"])

SEV_KEYS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _summary(scan: Scan) -> ScanSummary:
    counts = {k: 0 for k in SEV_KEYS}
    for f in scan.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return ScanSummary(
        id=scan.id, target=scan.target, status=scan.status, mode=scan.mode or "safe",
        risk_score=scan.risk_score or 0, risk_grade=scan.risk_grade or "",
        tags=scan.tags or "",
        created_at=scan.created_at, finished_at=scan.finished_at,
        critical=counts["CRITICAL"], high=counts["HIGH"], medium=counts["MEDIUM"],
        low=counts["LOW"], info=counts["INFO"],
    )


def _owned(scan_id: int, user: User, db: Session) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan or (scan.user_id != user.id and not user.is_admin):
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _enforce_scan_policy(user: User, target: str, mode: str, db: Session):
    """Domain-ownership gate + plan limits. Admins bypass the ownership check."""
    limits = PLAN_LIMITS.get(user.plan, PLAN_LIMITS["free"])

    if mode == "aggressive" and not limits["aggressive"]:
        raise HTTPException(status_code=403,
                            detail="Aggressive scans require the Pro plan. Upgrade to enable active testing.")

    # Daily scan quota.
    since = datetime.utcnow() - timedelta(days=1)
    today = db.query(Scan).filter(Scan.user_id == user.id, Scan.created_at >= since).count()
    if today >= limits["scans_per_day"]:
        raise HTTPException(status_code=429,
                            detail=f"Daily scan limit reached ({limits['scans_per_day']}/day on the {user.plan} plan).")

    # Domain ownership — the legal gate.
    if user.is_admin:
        return
    _, host, _ = normalize(target)
    verified = {d.domain.lower() for d in
                db.query(VerifiedDomain).filter(VerifiedDomain.user_id == user.id,
                                                VerifiedDomain.verified == 1).all()}
    if not any(host == d or host.endswith("." + d) for d in verified):
        raise HTTPException(
            status_code=403,
            detail=f"Domain '{host}' is not verified. Verify ownership under Domains before scanning it.",
        )


@router.get("", response_model=list[ScanSummary])
def list_scans(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(Scan)
    if not user.is_admin:
        q = q.filter(Scan.user_id == user.id)
    scans = q.order_by(Scan.created_at.desc()).limit(100).all()
    return [_summary(s) for s in scans]


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(body: ScanCreate, background_tasks: BackgroundTasks,
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    target = body.target.strip().rstrip("/")
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    mode = "aggressive" if body.mode == "aggressive" else "safe"
    _enforce_scan_policy(user, target, mode, db)

    scan = Scan(target=target, status="pending", tags=body.tags, mode=mode, user_id=user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_queues[scan.id] = asyncio.Queue()
    background_tasks.add_task(_run_scan, scan.id, target, mode)
    return scan


@router.post("/batch", response_model=list[ScanSummary], status_code=201)
def create_batch(body: MultiScanCreate, background_tasks: BackgroundTasks,
                 user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    created = []
    mode = "aggressive" if body.mode == "aggressive" else "safe"
    for raw in body.targets:
        target = raw.strip().rstrip("/")
        if not target:
            continue
        _enforce_scan_policy(user, target, mode, db)
        scan = Scan(target=target, status="pending", tags=body.tags, mode=mode, user_id=user.id)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_queues[scan.id] = asyncio.Queue()
        background_tasks.add_task(_run_scan, scan.id, target, mode)
        created.append(_summary(scan))
    return created


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _owned(scan_id, user, db)


@router.patch("/{scan_id}", response_model=ScanOut)
def update_scan(scan_id: int, body: ScanUpdate,
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = _owned(scan_id, user, db)
    if body.tags is not None:
        scan.tags = body.tags
    if body.notes is not None:
        scan.notes = body.notes
    db.commit()
    db.refresh(scan)
    return scan


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = _owned(scan_id, user, db)
    db.delete(scan)
    db.commit()


@router.get("/{scan_id}/diff/{other_id}")
def diff_scans(scan_id: int, other_id: int,
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = _owned(scan_id, user, db)
    b = _owned(other_id, user, db)

    def key(f):
        return (f.title, f.url)

    a_keys = {key(f): f for f in a.findings}
    b_keys = {key(f): f for f in b.findings}

    return {
        "base": {"id": a.id, "target": a.target, "risk_score": a.risk_score, "date": a.created_at.isoformat()},
        "compare": {"id": b.id, "target": b.target, "risk_score": b.risk_score, "date": b.created_at.isoformat()},
        "resolved": [f.title for k, f in a_keys.items() if k not in b_keys],
        "introduced": [f.title for k, f in b_keys.items() if k not in a_keys],
        "persistent": [a_keys[k].title for k in a_keys if k in b_keys],
        "risk_delta": (b.risk_score or 0) - (a.risk_score or 0),
    }


async def _run_scan(scan_id: int, target: str, mode: str = "safe"):
    from app.database import SessionLocal
    db = SessionLocal()
    queue = scan_queues.get(scan_id) or asyncio.Queue()
    scan_queues[scan_id] = queue
    try:
        await engine.run_scan(scan_id, target, db, queue, mode)
    except Exception as e:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "error"
            db.commit()
        await queue.put({"type": "scan_error", "error": str(e)})
    finally:
        db.close()
