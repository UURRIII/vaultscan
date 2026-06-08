"""Domain ownership verification — the legal gate for scanning.

A user may only scan domains they have proven they control, via a DNS TXT
record or a file at /.well-known/. This is what keeps a public scanner SaaS
lawful (the same model Detectify, Intruder, etc. use).
"""
import secrets
from datetime import datetime
import httpx
import dns.asyncresolver
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.database import get_db
from app.models.scan import VerifiedDomain, User
from app.auth import get_current_user
from app.routers.auth import PLAN_LIMITS
from app.core.context import normalize

router = APIRouter(prefix="/api/domains", tags=["domains"])


class DomainCreate(BaseModel):
    domain: str


class DomainOut(BaseModel):
    id: int
    domain: str
    token: str
    method: str
    verified: int
    created_at: datetime
    verified_at: datetime | None
    model_config = {"from_attributes": True}


@router.get("", response_model=list[DomainOut])
def list_domains(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(VerifiedDomain).filter(VerifiedDomain.user_id == user.id) \
             .order_by(VerifiedDomain.created_at.desc()).all()


@router.post("", response_model=DomainOut, status_code=201)
def add_domain(body: DomainCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _, host, _ = normalize(body.domain)
    if not host or "." not in host:
        raise HTTPException(status_code=400, detail="Enter a valid domain (e.g. example.com)")

    existing = db.query(VerifiedDomain).filter(VerifiedDomain.user_id == user.id,
                                               VerifiedDomain.domain == host).first()
    if existing:
        return existing

    limits = PLAN_LIMITS.get(user.plan, PLAN_LIMITS["free"])
    count = db.query(VerifiedDomain).filter(VerifiedDomain.user_id == user.id).count()
    if count >= limits["max_domains"]:
        raise HTTPException(status_code=403,
                            detail=f"Domain limit reached ({limits['max_domains']} on the {user.plan} plan).")

    vd = VerifiedDomain(user_id=user.id, domain=host, token="vaultscan-verify=" + secrets.token_hex(16))
    db.add(vd)
    db.commit()
    db.refresh(vd)
    return vd


@router.post("/{did}/verify", response_model=DomainOut)
async def verify_domain(did: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    vd = db.get(VerifiedDomain, did)
    if not vd or vd.user_id != user.id:
        raise HTTPException(status_code=404, detail="Not found")
    if vd.verified:
        return vd

    method = None
    if await _check_dns(vd.domain, vd.token):
        method = "dns"
    elif await _check_file(vd.domain, vd.token):
        method = "file"

    if not method:
        raise HTTPException(
            status_code=400,
            detail="Verification token not found yet. Add the DNS TXT record or the file, then retry "
                   "(DNS changes can take a few minutes to propagate).",
        )

    vd.verified = 1
    vd.method = method
    vd.verified_at = datetime.utcnow()
    db.commit()
    db.refresh(vd)
    return vd


@router.delete("/{did}", status_code=204)
def delete_domain(did: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    vd = db.get(VerifiedDomain, did)
    if vd and vd.user_id == user.id:
        db.delete(vd)
        db.commit()


async def _check_dns(domain: str, token: str) -> bool:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6
    for name in (domain, f"_vaultscan.{domain}"):
        try:
            answers = await resolver.resolve(name, "TXT")
            for r in answers:
                if token in str(r).strip('"'):
                    return True
        except Exception:
            continue
    return False


async def _check_file(domain: str, token: str) -> bool:
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/.well-known/vaultscan-verify.txt"
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
                r = await client.get(url)
                if r.status_code == 200 and token in r.text:
                    return True
        except Exception:
            continue
    return False
