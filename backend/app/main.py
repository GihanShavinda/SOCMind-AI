from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, assets, events, incidents

app = FastAPI(
    title="SOCMind AI",
    version="0.1.0",
    description="Explainable, human-in-the-loop SOC platform — Phase 1 scaffold.",
)

# Allow the Angular dev server during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(assets.router)
app.include_router(events.router)
app.include_router(incidents.router)
app.include_router(incidents.audit_router)


@app.on_event("startup")
def _load_rules():
    from app.detection.engine import reload_rules
    count = reload_rules()
    print(f"[detection] loaded {count} rules")


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "service": "socmind-ai"}
