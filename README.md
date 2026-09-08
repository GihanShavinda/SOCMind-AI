# SOCMind AI

**An explainable, human-in-the-loop AI platform for security incident investigation and response.**

Detect · Correlate · Reconstruct · Explain · Guide · Respond — safely, with humans in control.

SOCMind AI ingests security telemetry, detects suspicious activity through layered
detection, correlates related events into incidents, reconstructs the attack story,
and then **guides** the analyst: it explains what happened and why, maps activity to
MITRE ATT&CK, recommends safe investigation commands, and applies a risk-aware
decision engine that decides whether a response can be automated or needs human
approval — with a full audit trail throughout.

---

## Table of contents
- [Highlights](#highlights)
- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Quick start](#quick-start)
- [Using the platform](#using-the-platform)
- [Project structure](#project-structure)
- [Detection & response, explained](#detection--response-explained)
- [Configuration](#configuration)
- [Collectors & the virtual lab](#collectors--the-virtual-lab)
- [Testing](#testing)
- [Requirements coverage](#requirements-coverage)
- [Security & design notes](#security--design-notes)

---

## Highlights

- **Layered detection** — rule-based (Sigma-style YAML), baseline anomaly, and
  correlation, producing scored incidents with de-duplication.
- **Attack-story reconstruction** — a chronological, MITRE-tagged narrative and an
  interactive attack graph (attacker → account → host → process → external).
- **Explainable AI assistant** — answers *what happened / why suspicious / what next*,
  grounded in the incident's own evidence and similar past incidents (RAG). Works
  with **no LLM** (deterministic fallback); an LLM is optional.
- **Safe action space** — the AI can only recommend commands from an approved,
  OS-aware catalog; every command is risk-classified; nothing destructive auto-runs.
- **Risk-aware human-in-the-loop** — a transparent decision engine weighs threat
  confidence, response confidence, asset criticality and business impact to choose
  automation vs approval, with the reasoning shown.
- **Controlled, reversible, audited response** — propose → approve/auto → execute →
  rollback, every step in an append-only audit log.
- **Advanced analytics** — UEBA entity risk, a threat-hunting workspace (promote a
  hunt into a detection rule), tamper-evident forensic case packages, triage scoring
  + SLA, analyst feedback with bounded active learning, and per-component model cards.
- **Reporting** — full incident reports exportable as PDF, CSV and JSON.
- **Accounts** — registration (admin-managed), login, MFA (TOTP), password reset,
  RBAC (Administrator / SOC Analyst / Viewer), self-service profile.

---

## Architecture

```
Security events -> Collection -> Detection -> Correlation -> Incident -> Attack story ->
Explainable AI -> Next-step guidance -> Response recommendation -> Risk evaluation ->
Auto-response OR human approval -> Audit
```

| Layer         | Components                                                        |
|---------------|-------------------------------------------------------------------|
| Collection    | Linux & Windows collectors, normaliser, enrichment                |
| Detection     | Rule engine, anomaly engine, correlation engine                   |
| Intelligence  | MITRE mapper, threat-intel/IOC, RAG knowledge base                |
| Reasoning     | AI assistant, command recommender, safety engine, decision engine |
| Response      | Playbook engine, action executor, audit logger                    |
| Presentation  | Angular analyst console                                           |
| Platform      | Auth/RBAC, API, PostgreSQL, Redis                                 |

---

## Technology stack

Angular 18 (TypeScript) · FastAPI (Python 3.12) · PostgreSQL · Redis · SQLAlchemy +
Alembic · JWT auth · reportlab (PDF) · Sigma-style YAML detection rules · Docker
Compose. Optional LLM via OpenAI / Anthropic / Ollama.

---

## Quick start

### Prerequisites
- **Docker Desktop** (runs the backend, PostgreSQL and Redis)
- **Node.js 20+** (for the Angular frontend)

### 1. Configure
```bash
cp .env.example .env
# optional: edit DB password / JWT secret / email / LLM settings
```

### 2. Start the backend stack
```bash
docker compose up --build
```
On first boot this runs database migrations and seeds a default admin and a sample
asset. Watch for `Application startup complete` and the `[detection] loaded ... rules`
lines. The API is at **http://localhost:8000** (interactive docs at `/docs`).

> **Rebuild note:** use `--build` after pulling changes that touch
> `backend/requirements.txt`; otherwise `docker compose up` is enough.

### 3. Start the frontend
```bash
cd frontend
npm install      # first time only
npm start        # http://localhost:4200
```

### 4. Log in
```
email:    admin@socmind.io
password: ChangeMe123!
```

### 5. Generate demo data (no VMs needed)
In a new terminal, with the stack running:
```bash
pip install requests
python backend/scripts/demo_scenarios.py
```
This creates brute-force, port-scan, suspicious-process, C2 and anomalous-login
incidents. Refresh the dashboard to see them.

---

## Using the platform

- **Dashboard** — live incident counts by severity and a recent feed.
- **Incidents** — cases ordered by triage priority, with SLA status.
- **Incident detail** — the investigation workspace: kill chain, attack graph,
  attack story, evidence, response actions, AI assistant, similar past incidents,
  analyst feedback, and report/case-package export.
- **Assets** — inventory with criticality and per-asset auto-response opt-in.
- **MITRE ATT&CK** — techniques observed across all incidents along the kill chain.
- **Threat Hunting** — query events, spot clusters, promote a hunt to a rule.
- **Decision Panel** — every automation decision with its inputs and rationale.
- **Playbooks / Approvals** — structured response playbooks and the approval queue.
- **Model Cards** — per-component model cards and a confidence-calibration table.
- **Audit Trail / Reports / Users / Settings** — records, exports, user admin, MFA.

---

## Project structure

```
socmind-ai/
|-- docker-compose.yml          # postgres, redis, backend
|-- .env.example
|-- backend/                    # FastAPI
|   |-- app/
|   |   |-- main.py             # app factory + startup loaders
|   |   |-- core/               # config, db, security (JWT), deps (RBAC), totp, email
|   |   |-- models/             # SQLAlchemy entities
|   |   |-- schemas/            # Pydantic models
|   |   |-- api/                # routers: auth, assets, events, incidents, mitre,
|   |   |                       #          ai, response, reports, users, advanced
|   |   |-- services/           # ingest pipeline
|   |   |-- detection/          # rules, anomaly, correlation, engine, mitre,
|   |   |                       # graph, triage, learning
|   |   |-- ai/                 # assistant, catalog, safety, rag, llm, model_cards
|   |   |-- response/           # playbooks, decision engine, actions
|   |   |-- intel/              # threat-intel enrichment
|   |   |-- ueba/               # entity risk analytics
|   |   |-- hunting/            # threat-hunting engine
|   |   |-- forensics/          # chain of custody / case package
|   |   |-- reporting/          # report builder + PDF/CSV exporters
|   |   \-- audit/              # append-only audit logging
|   |-- alembic/                # migrations (0001-0006)
|   |-- tests/                  # pytest suite
|   \-- scripts/                # seed + demo scenario generators
|-- frontend/                   # Angular 18 analyst console
|-- collectors/
|   |-- linux/authlog_collector.py
|   \-- windows/authlog_collector.ps1
|-- detection-rules/            # Sigma-style YAML (detection-as-code)
|-- playbooks/                  # response playbooks (YAML)
|-- command-catalog/            # approved investigation commands (linux/windows)
|-- intel-feeds/                # local IOC feed
|-- lab/LAB_SETUP_GUIDE.md      # virtual lab setup (Section 9.3)
\-- docs/                       # per-phase changelogs + requirements traceability
```

---

## Detection & response, explained

**Detection is deterministic and LLM-free** so the platform keeps working when the
LLM is unavailable. Rules live in `detection-rules/*.yml` and load at startup — add a
detection by dropping in a YAML file, no code change. Three layers combine:

1. **Rule** — e.g. repeated failed logins from one source.
2. **Anomaly** — per-user/asset baselines flag new-IP or off-hours logins.
3. **Correlation** — a failed->success sequence escalates to a critical compromise.

**Response is safe by construction.** The AI recommends only commands present in the
approved catalog. Each command/action is classified **Low / Medium / High /
Restricted**. The decision engine automates **only** low-impact, reversible,
high-confidence actions on **low-criticality** assets that have opted in — everything
else escalates to a human, and destructive actions never auto-run. Every action is
reversible where possible and always audited.

---

## Configuration

All via `.env` (see `.env.example`). Key settings:

| Variable | Purpose | Default |
|----------|---------|---------|
| `JWT_SECRET` | Token signing secret — change for anything real | dev value |
| `EMAIL_MODE` | `console` (dev, logs/returns reset link) or `smtp` | `console` |
| `SMTP_*` | SMTP server for real password-reset emails | empty |
| `LLM_PROVIDER` | `openai` / `anthropic` / `ollama`, or empty for rule-based | empty |
| `LLM_API_KEY`, `LLM_MODEL`, `LLM_BASE_URL` | LLM connection | — |

**LLM is optional.** With `LLM_PROVIDER` empty, the assistant uses its deterministic,
evidence-grounded engine. Set a provider to have the LLM draft the narrative —
recommended commands still come only from the approved catalog.

**Email is pluggable.** `console` mode returns the reset link in the API response and
logs it (works offline in the lab). `smtp` mode sends a real email — set `SMTP_HOST`,
`SMTP_USER`, `SMTP_PASSWORD` (e.g. a Gmail App Password), `SMTP_FROM`. SMTP requires
internet access from the backend.

---

## Collectors & the virtual lab

- **Linux** (`collectors/linux/authlog_collector.py`): tails `/var/log/auth.log`,
  ships SSH auth events. Run on an Ubuntu VM.
- **Windows** (`collectors/windows/authlog_collector.ps1`): reads Security events
  4624/4625 (and Sysmon). Run in an Administrator PowerShell on a Windows VM.

Both post normalised events to `POST /api/events/ingest`. For a full isolated VM lab
(Windows 11 host, Ubuntu/Windows 10/Metasploitable targets, Kali attacker,
host-only network, and how to run real attacks), follow **`lab/LAB_SETUP_GUIDE.md`**.

---

## Testing

```bash
cd backend
DATABASE_URL="sqlite+pysqlite:///./test.db" pytest -q
```
The suite covers detection (all scenarios), correlation/escalation, the AI assistant
and safety engine, the decision engine and approvals, reporting/export, MFA and
account flows, RAG/triage/feedback, and the advanced analytics (UEBA, hunting,
forensics, model cards).

Frontend production build:
```bash
cd frontend && npm run build
```

---

## Requirements coverage

All functional requirements (FR-1 - FR-42) are implemented except **FR-40** (a
native mobile app, a separate Flutter deliverable). Nine of the ten Section-8
advanced enhancements are implemented (honeypot signals, 8.7, deferred as it needs
dedicated infrastructure). See **`docs/REQUIREMENTS_TRACEABILITY.md`** for the full
per-requirement mapping and **`docs/PHASE*_CHANGELOG.md`** for what each phase added.

---

## Security & design notes

- Passwords are hashed (bcrypt); JWT access + refresh tokens; RBAC on every
  sensitive route; High/Restricted approvals require an Administrator.
- MFA via TOTP (RFC 6238), compatible with standard authenticator apps.
- Append-only audit log for all decisions, approvals and actions.
- Prompt-injection resistance: untrusted log content is treated as data, never as
  instructions, on the optional LLM path.
- **Lab-only by design:** response actions are *simulated* — the platform records
  and audits an isolate/block with full undo, but never touches real infrastructure.
  All offensive activity is confined to an isolated virtual network.

---

