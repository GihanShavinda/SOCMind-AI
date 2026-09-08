# Phase 4 — AI Investigation Assistant, Command Recommendation & Safety Engine

This phase adds the platform's flagship capability: an explainable assistant that
reads an incident's evidence and produces a structured analysis, with a
safety-classified command recommender constrained to an approved action space.

## Built fallback-first (works with no LLM)
Per section 3.3 and the reliability NFR, the assistant runs fully **without an
LLM**: a deterministic, evidence-grounded engine composes the analysis directly
from the incident's own data, so every claim is traceable. If an LLM is
configured it drafts the narrative instead — but recommended commands are
**always** taken from the approved catalog and validated, never invented by the
model. On any LLM error/timeout it degrades gracefully to the deterministic path.

## What was added

### AI investigation assistant (FR-21, FR-22, FR-23)
`app/ai/assistant.py` builds a grounded context (events, MITRE techniques, asset
OS, similar past incidents) and returns a fixed structure: **what happened**,
**why it's suspicious**, and **prioritised next steps** — plus a `grounded_on`
list making every claim traceable to evidence.
`GET /api/incidents/{id}/analysis`.

### Command recommendation, OS-aware (FR-24, FR-25, FR-26)
`command-catalog/linux.yaml` and `windows.yaml` define approved investigation
commands, each with purpose, rationale and risk. The recommender picks commands
matching the asset OS (shell for Linux, PowerShell for Windows) and the
incident's event types. `GET /api/incidents/{id}/commands`.

### Command safety engine (FR-27, FR-28, FR-29)
`app/ai/safety.py`:
- **Risk classification** — Low / Medium / High / Restricted.
- **Catalog validation** — a command may be surfaced only if it exists in the
  approved catalog; free-form model output is rejected (safe action space).
- **Guardrails** — destructive patterns force Restricted; nothing is auto-run
  (only Low read-only could ever be, and execution itself is Phase 5).
- **Injection resistance** — when the LLM path is used, log content is passed as
  data with explicit instructions never to treat it as commands.

### Optional LLM client (`app/ai/llm.py`)
Std-lib only (no new dependency). Supports OpenAI / Anthropic / Ollama, disabled
by default. Enable via env (`LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL`,
`LLM_BASE_URL`) — see `.env.example`.

## Frontend
The incident page's Phase-4 placeholder is now a live **AI investigation
assistant** panel: what happened / why suspicious / numbered next steps with
copy-able, risk-badged commands, a "grounded on" chip list, and a source badge
(rule-based vs the LLM model). A note makes the safety posture explicit.

## Requirements advanced to ✅
FR-21, FR-22, FR-23 (grounded to incident evidence; vector-store RAG remains the
P7 enhancement), FR-24, FR-25, FR-26, FR-27, FR-28, FR-29.

## No schema/migration change
Phase 4 is read-only over existing data — no new tables. Runs against your
current database as-is.

## Try it
```bash
docker compose up
# open an incident -> scroll to "AI investigation assistant"
```
To use a real LLM, set `LLM_PROVIDER` + `LLM_API_KEY` in `.env` and restart;
the source badge will switch from "rule-based" to the model name.
