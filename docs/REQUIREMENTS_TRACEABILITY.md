# SOCMind AI — Requirements Traceability Matrix

This document guarantees **no requirement is dropped**. Every functional
requirement (FR) from the project document is mapped to where it is delivered:
the backend module, the frontend screen, and the build phase. Status reflects the
current scaffold.

Legend — **Status**: ✅ working now · 🟡 shell present, backend in later phase · ⬜ planned

## Identity, Authentication & Access Control
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-1 | Registration (admin), login, password reset, profile | Login/Forgot/Reset/Settings/Users | auth + users routers | P1/P6 | ✅ |
| FR-2 | Multi-factor auth (TOTP) | Settings + login | `core/totp.py` + auth MFA endpoints | P6 | ✅ |
| FR-3 | Role-based access control | Route guards, conditional UI | `require_role` dependency | P1 | ✅ |
| FR-4 | Session security (access/refresh tokens) | Auth interceptor | JWT access + refresh | P1 | ✅ |

## Asset Management
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-5 | Asset inventory (add/edit/retire) | Assets screen | `/api/assets` CRUD | P1 | ✅ |
| FR-6 | Asset attributes (OS/IP/owner/criticality) | Assets form | Asset model | P1 | ✅ |
| FR-7 | Agent status | Assets table badge | `agent_status` field | P1 | ✅ |
| FR-8 | Business context feeds automation | Assets — auto toggle | criticality → decision engine | P5 | ✅ |

## Collection, Normalisation & Storage
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-9 | Windows collection | — | `collectors/windows/authlog_collector.ps1` | P6 | ✅ |
| FR-10 | Linux collection | — | `collectors/linux/authlog_collector.py` | P1 | ✅ |
| FR-11 | Normalisation to unified schema | — | `services/ingest.py` | P1 | ✅ |
| FR-12 | Enrichment (geo/reputation) | Report reputation col | `intel/enrichment.py` + IOC feed | P6 | ✅ |

## Detection Engine
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| — | Layer 1 rule-based | (Incidents) | `detection/engine.py` | P1 | ✅ |
| — | Layer 2 anomaly/baseline | (Incidents) | `detection/anomaly.py` | P2 | ✅ |
| — | Layer 3 correlation | (Incidents) | `detection/engine.py` | P1 | ✅ |
| — | Sigma-style rules | — | `detection-rules/*.yml` + `rules/loader.py` | P2 | ✅ |

## Correlation, Story & Mapping
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-13 | Correlation keys | — | `detection/engine.py` | P1 | ✅ |
| FR-14 | Incident creation w/ confidence | Incidents list | Incident model | P1 | ✅ |
| FR-15 | De-duplication | — | engine (reuses open incident) | P1 | ✅ |
| FR-16 | Timeline narrative | Incident detail — story timeline | AttackStep + `/story` | P2/P3 | ✅ |
| FR-17 | Interactive attack graph | Incident detail — SVG graph | `detection/graph.py` + `/graph` | P3 | ✅ |
| FR-18 | Plain-language assessment | Incident detail — story + graph | attack steps | P3 | ✅ |
| FR-19 | MITRE technique mapping | Story tags + MITRE screen | `detection/mitre.py` | P3 | ✅ |
| FR-20 | Kill-chain view | MITRE screen + incident strip | `/killchain` + `/mitre/killchain` | P3 | ✅ |

## AI Assistant & Commands
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-21 | Contextual input to assistant | Incident detail — AI panel | AI module | P4 | ✅ |
| FR-22 | Structured output (what/why/next) | Incident detail — AI panel | AI module | P4 | ✅ |
| FR-23 | Grounding (evidence + KB) | AI panel — grounded_on + Similar | `ai/rag.py` retrieval | P7 | ✅ |
| FR-24 | Investigation commands | Incident detail | command recommender | P4 | ✅ |
| FR-25 | Command explanation | Incident detail | recommender | P4 | ✅ |
| FR-26 | OS awareness | — | recommender | P4 | ✅ |

## Command Safety & Response
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-27 | Risk classification | Playbooks (risk badges) | safety engine | P4/P5 | ✅ |
| FR-28 | Playbook validation | — | safety engine | P4 | ✅ |
| FR-29 | Guardrails (no blind execution) | — | safety engine | P4 | ✅ |
| FR-30 | Structured playbooks | Playbooks screen | `playbooks/*.yaml` + `response/playbooks.py` | P5 | ✅ |
| FR-31 | Adaptive selection | Playbooks screen | `select_for_incident` | P5 | ✅ |

## Human-in-the-Loop & Actions
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-32 | Decision inputs | Decision panel | `response/decision.py` | P5 | ✅ |
| FR-33 | Decision output + reasoning | Decision panel | `response/decision.py` | P5 | ✅ |
| FR-34 | Per-asset automation policy | Assets — auto toggle | `automation_enabled`/`auto_action_types` | P5 | ✅ |
| FR-35 | Audit on every action | Audit screen | `audit/logger.py` | P1 | ✅ |
| FR-36 | Reversibility | Incident — Undo action | `rollback_action` + undo_ref | P5 | ✅ |

## Explainability, Dashboards & Surfaces
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-37 | Explainable decision panel | Decision Panel screen | `response/decision.py` rationale | P5 | ✅ |
| FR-38 | Real-time dashboard | Dashboard | incidents API (+ WebSocket P6) | P1/P6 | ✅ |
| FR-39 | Investigation workspace | Incident detail | incident APIs | P1 | ✅ |
| FR-40 | Mobile app | (Flutter — separate) | same APIs | P6 | ⬜ |
| FR-41 | Reporting | Reports screen + incident export | `reporting/builder.py` | P6 | ✅ |
| FR-42 | Export PDF/CSV/JSON | Reports/incident buttons | `reporting/exporters.py` | P6 | ✅ |

---

### How to read status
- **✅ working now** — you can click through it against the running backend today.
- **🟡 shell present** — the screen/route/model exists and is navigable; the
  backend logic that fills it arrives in the noted phase.
- **⬜ planned** — has a defined home (module or screen) but not yet built.

Every FR appears exactly once above. As you complete each phase, flip its rows to
✅ — the matrix doubles as your progress tracker and examiner checklist.

---

## Section 8 — Advanced Enhancements status

| # | Enhancement | Status | Where |
|---|-------------|--------|-------|
| 8.1 | Threat-intel enrichment + IOC | ✅ | `intel/enrichment.py` + IOC feed (P6/P7) |
| 8.2 | RAG knowledge base | ✅ | `ai/rag.py` (P7) |
| 8.3 | UEBA — entity risk + timeline | ✅ | `ueba/scoring.py` (P8) |
| 8.4 | Threat hunting workspace | ✅ | `hunting/engine.py` + screen (P8) |
| 8.5 | Triage scoring + SLA | ✅ | `detection/triage.py` (P7) |
| 8.6 | Forensics + chain of custody | ✅ | `forensics/custody.py` (P8) |
| 8.7 | Honeypot / honeytoken signals | ⬜ | needs honeypot host (optional) |
| 8.8 | Analyst feedback + active learning | ✅ | `detection/learning.py` (P7) |
| 8.9 | Purple-team simulation harness | ✅ | `scripts/demo_scenarios.py` + lab guide |
| 8.10 | Confidence calibration + model cards | ✅ | `ai/model_cards.py` (P8) |
