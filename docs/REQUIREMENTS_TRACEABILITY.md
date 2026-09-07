# SOCMind AI — Requirements Traceability Matrix

This document guarantees **no requirement is dropped**. Every functional
requirement (FR) from the project document is mapped to where it is delivered:
the backend module, the frontend screen, and the build phase. Status reflects the
current scaffold.

Legend — **Status**: ✅ working now · 🟡 shell present, backend in later phase · ⬜ planned

## Identity, Authentication & Access Control
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-1 | Registration & login | Login screen | `/api/auth/login`, `/refresh`, `/me` | P1 | ✅ |
| FR-2 | Multi-factor auth (TOTP) | (Profile — later) | `mfa_enabled` field stubbed | P1/P7 | ⬜ |
| FR-3 | Role-based access control | Route guards, conditional UI | `require_role` dependency | P1 | ✅ |
| FR-4 | Session security (access/refresh tokens) | Auth interceptor | JWT access + refresh | P1 | ✅ |

## Asset Management
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-5 | Asset inventory (add/edit/retire) | Assets screen | `/api/assets` CRUD | P1 | ✅ |
| FR-6 | Asset attributes (OS/IP/owner/criticality) | Assets form | Asset model | P1 | ✅ |
| FR-7 | Agent status | Assets table badge | `agent_status` field | P1 | ✅ |
| FR-8 | Business context feeds automation | (Decision engine input) | `criticality` on Asset | P1/P5 | 🟡 |

## Collection, Normalisation & Storage
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-9 | Windows collection | — | Windows collector | P1/P2 | ⬜ |
| FR-10 | Linux collection | — | `collectors/linux/authlog_collector.py` | P1 | ✅ |
| FR-11 | Normalisation to unified schema | — | `services/ingest.py` | P1 | ✅ |
| FR-12 | Enrichment (geo/reputation/baselines) | — | Threat-intel module | P7 | ⬜ |

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
| FR-17 | Interactive attack graph | Incident detail | graph builder | P3 | ⬜ |
| FR-18 | Plain-language assessment | Incident detail — story | attack steps | P2/P3 | 🟡 |
| FR-19 | MITRE technique mapping | Story tags + MITRE screen | `detection/mitre.py` | P2/P3 | 🟡 |
| FR-20 | Kill-chain view | MITRE screen | mapper | P3 | 🟡 |

## AI Assistant & Commands
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-21 | Contextual input to assistant | Incident detail — AI panel | AI module | P4 | 🟡 |
| FR-22 | Structured output (what/why/next) | Incident detail — AI panel | AI module | P4 | 🟡 |
| FR-23 | Grounding (RAG) | — | vector store | P4/P7 | ⬜ |
| FR-24 | Investigation commands | Incident detail | command recommender | P4 | ⬜ |
| FR-25 | Command explanation | Incident detail | recommender | P4 | ⬜ |
| FR-26 | OS awareness | — | recommender | P4 | ⬜ |

## Command Safety & Response
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-27 | Risk classification | Playbooks (risk badges) | safety engine | P4/P5 | 🟡 |
| FR-28 | Playbook validation | — | safety engine | P4 | ⬜ |
| FR-29 | Guardrails (no blind execution) | — | safety engine | P4 | ⬜ |
| FR-30 | Structured playbooks | Playbooks screen | `playbooks/*.yaml` + engine | P1/P5 | 🟡 |
| FR-31 | Adaptive selection | Playbooks screen | playbook engine | P5 | ⬜ |

## Human-in-the-Loop & Actions
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-32 | Decision inputs | Decision panel | decision engine | P5 | 🟡 |
| FR-33 | Decision output + reasoning | Decision panel | decision engine | P5 | 🟡 |
| FR-34 | Per-asset automation policy | Assets / Approvals | policy on Asset | P5 | ⬜ |
| FR-35 | Audit on every action | Audit screen | `audit/logger.py` | P1 | ✅ |
| FR-36 | Reversibility | — | Action.undo_ref | P5 | ⬜ |

## Explainability, Dashboards & Surfaces
| FR | Requirement | Frontend | Backend | Phase | Status |
|----|-------------|----------|---------|-------|--------|
| FR-37 | Explainable decision panel | Decision panel | decision engine | P5 | 🟡 |
| FR-38 | Real-time dashboard | Dashboard | incidents API (+ WebSocket P6) | P1/P6 | ✅ |
| FR-39 | Investigation workspace | Incident detail | incident APIs | P1 | ✅ |
| FR-40 | Mobile app | (Flutter — separate) | same APIs | P6 | ⬜ |
| FR-41 | Reporting | Reports screen | report generator | P6 | 🟡 |
| FR-42 | Export PDF/CSV/JSON | Reports screen | exporters | P6 | 🟡 |

---

### How to read status
- **✅ working now** — you can click through it against the running backend today.
- **🟡 shell present** — the screen/route/model exists and is navigable; the
  backend logic that fills it arrives in the noted phase.
- **⬜ planned** — has a defined home (module or screen) but not yet built.

Every FR appears exactly once above. As you complete each phase, flip its rows to
✅ — the matrix doubles as your progress tracker and examiner checklist.
