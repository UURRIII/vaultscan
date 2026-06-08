"""Background scheduler: re-runs scheduled scans and raises alerts on changes."""
import asyncio
from datetime import datetime, timedelta
from app.database import SessionLocal
from app.models.scan import Scan, Schedule, Alert
from app.services import engine

CHECK_INTERVAL_SECONDS = 30
_task = None


def start():
    """Launch the scheduler loop on the running event loop (call from startup)."""
    global _task
    if _task is None or _task.done():
        _task = asyncio.create_task(_loop())


async def _loop():
    while True:
        try:
            await _tick()
        except Exception as e:
            print(f"[scheduler] error: {e}")
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)


async def _tick():
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        schedules = db.query(Schedule).filter(Schedule.enabled == 1).all()
        due = [s for s in schedules if s.next_run is None or s.next_run <= now]
    finally:
        db.close()

    for sched_id in [s.id for s in due]:
        await _run_one(sched_id)


async def _run_one(schedule_id: int):
    db = SessionLocal()
    try:
        sched = db.get(Schedule, schedule_id)
        if not sched or not sched.enabled:
            return

        tags = ",".join(t for t in [sched.tags, "scheduled"] if t).strip(",")
        scan = Scan(target=sched.target, mode=sched.mode, tags=tags, status="pending",
                    user_id=sched.user_id)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

        queue: asyncio.Queue = asyncio.Queue()  # dummy sink; puts never block
        try:
            await engine.run_scan(scan_id, sched.target, db, queue, sched.mode)
        except Exception:
            s = db.get(Scan, scan_id)
            if s:
                s.status = "error"
                db.commit()

        sched.last_run = datetime.utcnow()
        sched.next_run = datetime.utcnow() + timedelta(minutes=max(1, sched.interval_minutes))
        db.commit()

        _make_alerts(db, sched, scan_id)
    finally:
        db.close()


def _make_alerts(db, sched, scan_id: int):
    scan = db.get(Scan, scan_id)
    if not scan or scan.status != "done":
        return

    prev = (db.query(Scan)
            .filter(Scan.target == sched.target, Scan.id != scan_id, Scan.status == "done")
            .order_by(Scan.id.desc()).first())

    cur = {(f.title, f.url): f.severity for f in scan.findings}

    if not prev:
        _alert(db, scan_id, sched.id, sched.target, "info",
               f"First scheduled scan of {sched.target} complete — risk {scan.risk_score}/100 (grade {scan.risk_grade}).")
        return

    prev_keys = {(f.title, f.url) for f in prev.findings}
    new_keys = [k for k in cur if k not in prev_keys]
    new_high = [k for k in new_keys if cur[k] in ("CRITICAL", "HIGH")]
    risk_delta = (scan.risk_score or 0) - (prev.risk_score or 0)

    if new_high:
        _alert(db, scan_id, sched.id, sched.target, "critical",
               f"{len(new_high)} new high-severity finding(s) on {sched.target}: "
               + "; ".join(k[0] for k in new_high[:3]))
    elif new_keys:
        _alert(db, scan_id, sched.id, sched.target, "warning",
               f"{len(new_keys)} new finding(s) on {sched.target}.")

    if risk_delta > 0:
        _alert(db, scan_id, sched.id, sched.target, "warning",
               f"Risk increased +{risk_delta} on {sched.target} ({prev.risk_score} → {scan.risk_score}).")
    elif risk_delta < 0 and not new_keys:
        _alert(db, scan_id, sched.id, sched.target, "info",
               f"Risk improved {risk_delta} on {sched.target} ({prev.risk_score} → {scan.risk_score}).")


def _alert(db, scan_id, schedule_id, target, level, message):
    sched = db.get(Schedule, schedule_id)
    db.add(Alert(scan_id=scan_id, schedule_id=schedule_id, target=target, level=level,
                 message=message, user_id=sched.user_id if sched else None))
    db.commit()
