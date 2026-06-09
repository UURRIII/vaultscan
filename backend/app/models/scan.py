from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending | running | done | error
    mode = Column(String, default="safe")       # safe | aggressive
    risk_score = Column(Integer, default=0)
    risk_grade = Column(String, default="")
    tags = Column(String, default="")           # comma-separated
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Schedule(Base):
    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, nullable=False)
    mode = Column(String, default="safe")
    tags = Column(String, default="")
    interval_minutes = Column(Integer, default=1440)  # default daily
    enabled = Column(Integer, default=1)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    schedule_id = Column(Integer, ForeignKey("schedules.id"), nullable=True)
    target = Column(String, default="")
    level = Column(String, default="info")  # info | warning | critical
    message = Column(Text, default="")
    is_read = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)
    category = Column(String, nullable=False)
    evidence = Column(Text, default="")
    recommendation = Column(Text, default="")
    url = Column(String, default="")
    cvss = Column(Float, default=0.0)
    owasp = Column(String, default="")
    cwe = Column(String, default="")
    confidence = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
