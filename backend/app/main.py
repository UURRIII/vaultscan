import os
from dotenv import load_dotenv

# Load backend/.env (e.g. ANTHROPIC_API_KEY) before anything reads the env.
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.database import engine, run_lightweight_migrations
from app.models import scan as scan_models
from app.routers import scans, ws, reports, ai, monitoring

scan_models.Base.metadata.create_all(bind=engine)
run_lightweight_migrations()

app = FastAPI(title="VaultScan", version="5.0.0", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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
