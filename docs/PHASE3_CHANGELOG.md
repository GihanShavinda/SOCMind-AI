# Phase 3 — Attack Story, Graph & MITRE Kill Chain (changelog)

This phase completes the investigation workspace: the flat evidence table is now
backed by an interactive attack graph and a MITRE ATT&CK kill-chain view.

## What was added

### Interactive attack graph (FR-17)
`GET /api/incidents/{id}/graph` reconstructs a typed node/edge graph from the
incident's events:

    attacker IP → account → host → process → external connection

The builder (`detection/graph.py`) is generic — it reads `event_type` and
`attributes`, so every scenario contributes nodes/edges with no special-casing.
The frontend renders it as an SVG with columns by node type (no external graph
library), colour-coded per node type with labelled edges.

### MITRE ATT&CK kill chain (FR-19, FR-20)
`detection/mitre.py` now carries each technique's kill-chain phase and ordering.

- `GET /api/incidents/{id}/killchain` — techniques observed in this incident,
  placed along the full 6-phase lifecycle (unobserved phases still returned).
- `GET /api/mitre/killchain` — the same, aggregated across **all** incidents, for
  the standardised platform-wide view.

The incident page shows a per-incident kill-chain strip; the **MITRE ATT&CK**
screen (previously a placeholder) is now a real 6-phase matrix highlighting
observed techniques.

## Kill-chain phases
Reconnaissance → Credential Access → Initial Access → Execution →
Command & Control → Exfiltration
(mapped from T1046, T1110, T1078, T1059, T1071, T1041 respectively.)

## Bug fixed
`Incident` had no `asset` relationship (only `asset_id`); added it so the graph
builder can resolve the host's hostname. No migration needed (relationship only).

## Requirements advanced to ✅
FR-17 (attack graph), FR-20 (kill-chain view), FR-19 (MITRE mapping now surfaced
in two views), and FR-18/FR-16 further realised.

## No schema/migration change
Phase 3 is read-only over existing data — no new tables or columns, so no new
Alembic migration. It works against your current database as-is.

## Try it
With the stack running and some incidents generated
(`python backend/scripts/demo_scenarios.py`), open an incident → you'll see the
kill-chain strip, the attack graph, and the MITRE-tagged story. The **MITRE
ATT&CK** screen shows the aggregate lifecycle.
