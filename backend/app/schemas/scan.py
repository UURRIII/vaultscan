from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class ScanCreate(BaseModel):
    target: str
    tags: str = ""
    mode: str = "safe"


class MultiScanCreate(BaseModel):
    targets: list[str]
    tags: str = ""
    mode: str = "safe"


class ScanUpdate(BaseModel):
    tags: Optional[str] = None
    notes: Optional[str] = None


class FindingOut(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    category: str
    evidence: str
    recommendation: str
    url: str
    cvss: float
    owasp: str = ""
    cwe: str = ""
    confidence: str = ""
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: int
    target: str
    status: str
    mode: str
    risk_score: int
    risk_grade: str
    tags: str
    notes: str
    created_at: datetime
    finished_at: Optional[datetime]
    findings: list[FindingOut] = []

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    id: int
    target: str
    status: str
    mode: str
    risk_score: int
    risk_grade: str
    tags: str
    created_at: datetime
    finished_at: Optional[datetime]
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    model_config = {"from_attributes": True}
