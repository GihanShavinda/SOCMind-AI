# SOCMind AI

An explainable, human-in-the-loop AI platform for security incident investigation
and response. This repository is the **Phase 1 (Foundation) + first vertical slice**
scaffold: it stands up the backend, database, auth/RBAC, asset management, the unified
event-ingest pipeline, and a working **SSH brute-force → incident** detection slice
end to end.

> Build order follows Section 14 of the project document: build one scenario end to end
> first (SSH brute force on Ubuntu), then widen.

---

## What already works in this scaffold

- `docker compose up` brings up **PostgreSQL + Redis + FastAPI backend**
- JWT auth with **refresh tokens** and **role-based access control** (Administrator / SOC Analyst / Viewer)
- **Asset CRUD** (register monitored VMs with OS, IP, owner, criticality)
- **Unified event schema** + `POST /api/events/ingest` endpoint (the seam the collectors talk to)
- A **rule-based detection engine** that, on ingest, detects repeated failed SSH logins,
  **correlates** them, **creates an incident**, and writes an **append-only audit entry**
- A **Linux collector** script (`collectors/linux/authlog_collector.py`) that tails
  `/var/log/auth.log` and ships normalised events to the backend
- Sample **Sigma-style detection rule** and **brute-force playbook**
- Interactive API docs at `http://localhost:8000/docs`

---

## Quick start

### 1. Prerequisites
- Docker + Docker Compose (only thing you strictly need to run the backend)
- (Optional, for later) Node.js 20+ for the Angular frontend

### 2. Configure
```bash
cp .env.example .env
# edit .env if you want to change the DB password or JWT secret
```

### 3. Run
```bash
docker compose up --build
```
This starts Postgres, Redis and the API. On first boot the backend:
- runs database migrations,
- seeds a default admin user and one sample asset.

### 4. Log in
Default seeded admin (change immediately in a real deployment):
```
email:    admin@socmind.io
password: ChangeMe123!
```

Open **http://localhost:8000/docs**, call `POST /api/auth/login`, copy the
`access_token`, click **Authorize**, and try the other endpoints.

### 5. Try the vertical slice (no VM needed)
Simulate a brute force by posting several failed-login events, then a success:
```bash
python backend/scripts/demo_bruteforce.py
```
Then `GET /api/incidents` — you should see one correlated brute-force incident with
an audit trail. (Requires `requests`: `pip install requests`.)

---

## Project structure

```
socmind-ai/
├── docker-compose.yml
├── .env.example
├── backend/                    # FastAPI
│   ├── app/
│   │   ├── main.py             # app factory, startup: migrate + seed
│   │   ├── core/               # config, db session, security (JWT), deps (RBAC)
│   │   ├── models/             # SQLAlchemy entities (Section 11 of the doc)
│   │   ├── schemas/            # Pydantic request/response models
│   │   ├── api/                # routers: auth, assets, events, incidents
│   │   ├── services/           # business logic (routers stay thin)
│   │   ├── detection/          # rule engine + correlation (the brute-force slice)
│   │   └── audit/              # append-only audit logging
│   ├── alembic/                # DB migrations
│   └── scripts/                # seed + demo helpers
├── collectors/linux/           # agent that ships auth.log events to the backend
├── detection-rules/            # Sigma-style YAML (detection-as-code)
├── playbooks/                  # YAML playbooks
├── frontend/                   # Angular workspace (scaffold instructions inside)
└── lab/                        # virtual lab notes
```

---

## Where to go next (mapped to the document phases)

| Phase | What to add next |
|-------|------------------|
| P2 | Anomaly (baseline) detection + more Sigma rules; widen correlation keys |
| P3 | Attack-story timeline + graph + MITRE ATT&CK mapping |
| P4 | AI investigation assistant (LLM + RAG) with the safety wrapper — keep the deterministic path working when the LLM is off |
| P5 | Playbook execution, decision engine, controlled/reversible actions |
| P6 | Angular dashboard/workspace, Flutter mobile approvals, reporting |

Keep the audit log wired from the start, and keep the LLM strictly optional.
```
