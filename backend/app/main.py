import os
from dotenv import load_dotenv

# Load backend/.env (e.g. ANTHROPIC_API_KEY) before anything reads the env.
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.database import engine, run_lightweight_migrations, SessionLocal
from app.models import scan as scan_models
from app.routers import scans, ws, reports, ai, monitoring, auth as auth_router, domains

scan_models.Base.metadata.create_all(bind=engine)
run_lightweight_migrations()


def _seed_admin():
    """Create a default admin on first run and adopt any pre-auth data."""
    from app.models.scan import User, Scan, Schedule, Alert
    from app.auth import hash_password
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            admin_email = os.environ.get("VAULTSCAN_ADMIN_EMAIL", "admin@vaultscan.local")
            admin_pw = os.environ.get("VAULTSCAN_ADMIN_PASSWORD", "changeme123")
            admin = User(email=admin_email, hashed_password=hash_password(admin_pw),
                         plan="pro", is_admin=1)
            db.add(admin)
            db.commit()
            db.refresh(admin)
            # Adopt existing single-user data into the admin account.
            for model in (Scan, Schedule, Alert):
                db.query(model).filter(model.user_id.is_(None)).update({"user_id": admin.id})
            db.commit()
            print(f"[seed] created admin {admin_email} and adopted existing data")
    finally:
        db.close()


_seed_admin()

app = FastAPI(title="VaultScan", version="6.0.0", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(domains.router)
app.include_router(reports.router)
app.include_router(ai.router)
app.include_router(monitoring.router)
app.include_router(scans.router)
app.include_router(ws.router)


@app.on_event("startup")
async def _start_scheduler():
    from app.services import scheduler
    scheduler.start()

FRONTEND = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(FRONTEND, "index.html"))


@app.get("/{page}.html", include_in_schema=False)
def page(page: str):
    path = os.path.join(FRONTEND, f"{page}.html")
    return FileResponse(path if os.path.exists(path) else os.path.join(FRONTEND, "index.html"))
