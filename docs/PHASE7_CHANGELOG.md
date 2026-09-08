# Phase 7 — Advanced Features: RAG, Triage/SLA, Feedback & IOC Provenance

This phase adds four Section-8 enhancements that lift the platform from MVP to
research-grade, and closes the last partial requirement (FR-23).

## What was added

### RAG knowledge base (Section 8.2) — finishes FR-23
`app/ai/rag.py` implements lightweight, **offline** retrieval: past incidents are
scored against the current one by shared MITRE techniques, shared event types and
title overlap, returning the closest matches with what was done about them
(actions taken, final status). The assistant now grounds its analysis on these —
"we've seen this before, and here's what worked" — and every citation traces to a
real prior incident. `GET /api/incidents/{id}/similar`; the incident page shows a
**Similar past incidents** list. (A pgvector backend can replace the scorer later
without changing callers.)

### Triage scoring + SLA tracking (Section 8.5)
`app/detection/triage.py` assigns each incident a 0–100 **triage score**
(severity + confidence + asset criticality + event spread) to order the analyst
queue, and an **SLA due time** per severity (critical 15 min → low 24 h) with
breach computed on read. The incidents list is ordered by triage score and shows
an SLA status badge; the incident page shows both.

### Analyst feedback + active learning (Section 8.8)
`app/detection/learning.py` + a `Feedback` entity. Analysts mark an incident
**Confirm / Dismiss (false positive) / Correct**; the verdict updates the incident
status and feeds a **bounded** confidence nudge (±0.15 max) on the responsible
rule — a rule repeatedly dismissed loses a little confidence, one repeatedly
confirmed gains a little, but feedback can never silence a rule (matches the
confidence-calibration goal, 8.10). `POST/GET /api/incidents/{id}/feedback`.

### Threat-intel / IOC provenance (Section 8.1)
The enrichment from Phase 6 now surfaces its provenance in the assistant's
grounding and the report (reputation + source), and a malicious-IOC match nudges
confidence — with the reason shown, not hidden.

## Schema / migration
Migration `0006_phase7` adds `incidents.triage_score`, `incidents.sla_due_at`, and
the `feedback` table (idempotent). Runs automatically on `docker compose up`.

## Requirements
FR-23 now ✅ (grounded on incident evidence **and** a knowledge base of past
incidents; vector store is an optional future swap). Sections 8.1, 8.2, 8.5, 8.8
implemented.

## Try it
1. Generate a couple of brute-force incidents (`demo_scenarios.py`, or run it
   twice with different IPs).
2. Open the second incident → **Similar past incidents** shows the first, with
   shared techniques and how it was resolved; the AI assistant cites it.
3. The incidents list is ordered by **triage score**; each row shows an **SLA**
   badge (On track / Breached).
4. On an incident, click **Confirm / Dismiss / Correct** — the status updates and
   the verdict tunes future detection (bounded).

## Remaining
FR-40 (mobile app, separate Flutter build) and the remaining Section 8 items
(UEBA 8.3, threat hunting 8.4, forensics/chain-of-custody 8.6, honeypots 8.7,
model cards 8.10) for a future Phase 8, plus the evaluation write-up.
