import csv
import io
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.scan import Scan, User
from app.core.risk import compute_risk
from app.reporting.html_report import render_report
from app.auth import get_user_flexible

router = APIRouter(prefix="/api/scans", tags=["reports"])

SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _load(scan_id: int, db: Session, user: User) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan or (scan.user_id != user.id and not user.is_admin):
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/report", response_class=HTMLResponse)
def html_report(scan_id: int, user: User = Depends(get_user_flexible), db: Session = Depends(get_db)):
    scan = _load(scan_id, db, user)
    findings = sorted(scan.findings, key=lambda f: (-SEV_ORDER.get(f.severity, 0), -f.cvss))
    counts = {k: 0 for k in SEV_ORDER}
    for f in scan.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    risk = compute_risk(counts)
    return render_report(scan, findings, counts, risk)


@router.get("/{scan_id}/export.json")
def export_json(scan_id: int, user: User = Depends(get_user_flexible), db: Session = Depends(get_db)):
    scan = _load(scan_id, db, user)
    data = {
        "target": scan.target,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "risk_grade": scan.risk_grade,
        "tags": scan.tags,
        "notes": scan.notes,
        "created_at": scan.created_at.isoformat(),
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "findings": [
            {
                "title": f.title, "severity": f.severity, "cvss": f.cvss,
                "owasp": f.owasp, "cwe": f.cwe, "confidence": f.confidence,
                "category": f.category, "description": f.description,
                "evidence": f.evidence, "recommendation": f.recommendation, "url": f.url,
            }
            for f in sorted(scan.findings, key=lambda f: (-SEV_ORDER.get(f.severity, 0), -f.cvss))
        ],
    }
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f'attachment; filename="vaultscan_{scan.id}.json"'},
    )


@router.get("/{scan_id}/export.csv")
def export_csv(scan_id: int, user: User = Depends(get_user_flexible), db: Session = Depends(get_db)):
    scan = _load(scan_id, db, user)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Severity", "CVSS", "Confidence", "OWASP", "CWE", "Title", "Category", "URL", "Description", "Recommendation"])
    for f in sorted(scan.findings, key=lambda f: (-SEV_ORDER.get(f.severity, 0), -f.cvss)):
        writer.writerow([f.severity, f.cvss, f.confidence, f.owasp, f.cwe, f.title, f.category, f.url,
                         f.description.replace("\n", " "), f.recommendation.replace("\n", " ")])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="vaultscan_{scan.id}.csv"'},
    )
