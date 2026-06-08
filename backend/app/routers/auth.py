from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import re
from pydantic import BaseModel
from app.database import get_db

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
from app.models.scan import User, VerifiedDomain
from app import auth as auth_utils

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Plan limits (also referenced by scans/domains routers).
PLAN_LIMITS = {
    "free": {"max_domains": 2, "scans_per_day": 5, "aggressive": False, "scheduling": False},
    "pro":  {"max_domains": 100, "scans_per_day": 1000, "aggressive": True, "scheduling": True},
}


class Credentials(BaseModel):
    email: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email: str
    plan: str


class MeOut(BaseModel):
    id: int
    email: str
    plan: str
    is_admin: int
    limits: dict


@router.post("/register", response_model=TokenOut, status_code=201)
def register(body: Credentials, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    body.email = email
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=body.email, hashed_password=auth_utils.hash_password(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    token = auth_utils.create_token(user.id, user.email)
    return TokenOut(access_token=token, email=user.email, plan=user.plan)


@router.post("/login", response_model=TokenOut)
def login(body: Credentials, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email.strip().lower()).first()
    if not user or not auth_utils.verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = auth_utils.create_token(user.id, user.email)
    return TokenOut(access_token=token, email=user.email, plan=user.plan)


@router.get("/me", response_model=MeOut)
def me(user: User = Depends(auth_utils.get_current_user)):
    return MeOut(id=user.id, email=user.email, plan=user.plan, is_admin=user.is_admin,
                 limits=PLAN_LIMITS.get(user.plan, PLAN_LIMITS["free"]))
