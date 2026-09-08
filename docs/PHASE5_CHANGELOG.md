# Phase 5 — Playbooks, Decision Engine & Controlled Response (changelog)

This phase closes the "respond safely, with humans in control" half of the
platform: structured playbooks, a transparent risk-aware decision engine, and
controlled, reversible, fully-audited response actions.

## What was added

### Structured response playbooks (FR-30, FR-31)
Playbooks are versioned YAML in `playbooks/` (brute_force, port_scan,
suspicious_process), each an ordered set of steps with action, risk, approval
requirement and expected result. The selector picks the best-matching playbook
for an incident from its MITRE techniques / events (adaptive selection).
`GET /api/incidents/{id}/playbook`.

### Risk-aware human-in-the-loop decision engine (FR-32, FR-33, FR-34)
`app/response/decision.py` combines four inputs — threat confidence, response
confidence, asset criticality, business impact — into an outcome (automate vs
human approval) with a transparent rationale. Safety invariants:
- Restricted/destructive actions are **never** automated.
- Non-reversible actions require approval.
- Automation only for low-impact, reversible, high-confidence actions on
  **low-criticality** assets — and only where the asset has **opted in** (FR-34).

Per-asset opt-in is a toggle on the Assets screen; `auto_action_types` restricts
which action types may automate.

### Controlled response actions + reversibility (FR-13 set, FR-35, FR-36)
`app/response/actions.py` proposes → (auto-executes | pending approval) →
approve/reject → execute → rollback. Actions are **simulated** in the lab (no
real infrastructure is touched, per scope 3.2) but every state change is written
to the append-only audit log, and reversible actions record an undo reference and
can be rolled back (FR-36). Action set: firewall block, disable account, stop
process, isolate endpoint, create ticket, notify.

### Approvals & explainable decisions (FR-3, FR-37)
- **Approvals** screen: the pending-approval queue with approve/reject.
- High/Restricted actions require an **Administrator** to approve (FR-3).
- **Decision Panel** screen: every decision with its four inputs and rationale —
  the explainability surface (FR-37).

## Schema / migration
Migration `0003_phase5` adds `assets.automation_enabled`,
`assets.auto_action_types`, and the `decisions` and `actions` tables. It is
**idempotent** (guarded), and migrations 0002/0003 were made idempotent so the
whole chain now applies cleanly on a brand-new database as well as on an existing
one. Runs automatically on `docker compose up`.

## Requirements advanced to ✅
FR-30, FR-31, FR-32, FR-33, FR-34, FR-36, FR-37 (and FR-3 approval gating, FR-35
extended to all action lifecycle events).

## Try it
```bash
docker compose up
```
Open an incident → **Response actions** → propose "Isolate endpoint" (High) → it
goes to **Approvals** → approve as admin → **Undo** to roll back. Propose
"Create ticket" on a low-criticality asset you've toggled auto-response on for →
it auto-executes. See the reasoning for every case on the **Decision Panel**.
