"""Authentication: password hashing + JWT, plus FastAPI dependencies."""
import os
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.scan import User

# pbkdf2_sha256 is pure-Python — avoids the passlib/bcrypt version headaches.
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

SECRET_KEY = os.environ.get("VAULTSCAN_SECRET", "dev-secret-change-me-in-production")
ALGORITHM = "HS256"
TOKEN_TTL_HOURS = 24 * 7


def hash_password(p: str) -> str:
    return pwd_context.hash(p)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


def create_token(user_id: int, email: str) -> str:
    payload = {
        "sub": str(user_id),
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_TTL_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: Optional[str] = Depends(oauth2_scheme),
                     db: Session = Depends(get_db)) -> User:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise cred_exc
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise cred_exc
    user = db.get(User, user_id)
    if not user:
        raise cred_exc
    return user


def _decode(token: str, db: Session) -> Optional[User]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return db.get(User, int(payload.get("sub")))
    except Exception:
        return None


def get_user_flexible(token: Optional[str] = Query(None),
                      header_token: Optional[str] = Depends(oauth2_scheme),
                      db: Session = Depends(get_db)) -> User:
    """Accept a JWT from the Authorization header OR a ?token= query param.

    Needed for links the browser opens directly (report/export), which can't
    attach an Authorization header.
    """
    user = _decode(header_token or token or "", db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated",
                            headers={"WWW-Authenticate": "Bearer"})
    return user
