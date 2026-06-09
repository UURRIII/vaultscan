import asyncio
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.scan import Scan, Finding
from app.schemas.scan import (
    ScanCreate, MultiScanCreate, ScanUpdate, ScanOut, ScanSummary,
)
from app.services import engine
from app.routers.ws import scan_queues

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


@router.get("", response_model=list[ScanSummary])
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(100).all()
    return [_summary(s) for s in scans]


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(body: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = body.target.strip().rstrip("/")
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    mode = "aggressive" if body.mode == "aggressive" else "safe"
    scan = Scan(target=target, status="pending", tags=body.tags, mode=mode)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_queues[scan.id] = asyncio.Queue()
    background_tasks.add_task(_run_scan, scan.id, target, mode)
    return scan


@router.post("/batch", response_model=list[ScanSummary], status_code=201)
def create_batch(body: MultiScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    created = []
    mode = "aggressive" if body.mode == "aggressive" else "safe"
    for raw in body.targets:
        target = raw.strip().rstrip("/")
        if not target:
            continue
        scan = Scan(target=target, status="pending", tags=body.tags, mode=mode)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_queues[scan.id] = asyncio.Queue()
        background_tasks.add_task(_run_scan, scan.id, target, mode)
        created.append(_summary(scan))
    return created


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.patch("/{scan_id}", response_model=ScanOut)
def update_scan(scan_id: int, body: ScanUpdate, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if body.tags is not None:
        scan.tags = body.tags
    if body.notes is not None:
        scan.notes = body.notes
    db.commit()
    db.refresh(scan)
    return scan


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


@router.get("/{scan_id}/diff/{other_id}")
def diff_scans(scan_id: int, other_id: int, db: Session = Depends(get_db)):
    a = db.get(Scan, scan_id)
    b = db.get(Scan, other_id)
    if not a or not b:
        raise HTTPException(status_code=404, detail="Scan not found")

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
