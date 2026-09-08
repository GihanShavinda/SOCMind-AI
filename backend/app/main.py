from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, assets, events, incidents, mitre, ai, response, reports, users, advanced

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
app.include_router(mitre.router)
app.include_router(ai.router)
app.include_router(response.router)
app.include_router(response.actions_router)
app.include_router(response.decisions_router)
app.include_router(reports.router)
app.include_router(users.router)
app.include_router(advanced.router)


@app.on_event("startup")
def _load_rules():
    from app.detection.engine import reload_rules
    from app.ai.catalog import load_catalog
    count = reload_rules()
    cmds = load_catalog()
    from app.response.playbooks import load_playbooks
    pbs = load_playbooks()
    from app.intel.enrichment import load_iocs
    iocs = load_iocs()
    print(f"[detection] loaded {count} rules")
    print(f"[assistant] loaded {cmds} approved commands")
    print(f"[response] loaded {pbs} playbooks")
    print(f"[intel] loaded {iocs} IOC indicators")


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "service": "socmind-ai"}
