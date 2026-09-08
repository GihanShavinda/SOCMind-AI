# Phase 8 — Advanced Analytics: UEBA, Threat Hunting, Forensics & Model Cards

The final set of Section-8 enhancements. All are read-only over existing data —
**no migration** — and work fully offline.

## What was added

### UEBA — user & entity behaviour analytics (Section 8.3)
`app/ueba/scoring.py`: a 0–100 risk score for any entity (user, host, or source
IP) derived from its recent events, anomaly scores and IOC reputation, plus a
**risk timeline** showing how risk accumulated across an incident's events.
- `GET /api/ueba/entity?entity_type=ip&value=...`
- `GET /api/incidents/{id}/risk-timeline`

### Threat hunting workspace (Section 8.4)
`app/hunting/engine.py`: ad-hoc, hypothesis-driven querying over normalised
events with a **safe, whitelisted filter language** (no raw SQL from the user),
returning matches plus source/type clustering. A successful hunt can be
**promoted into a Sigma-style detection rule** (detection-as-code) — closing the
loop from hunt to durable detection.
- `POST /api/hunt`, `POST /api/hunt/promote`
- New **Threat Hunting** screen: build a query, see clusters, promote to a rule.

### Digital forensics & chain of custody (Section 8.6)
`app/forensics/custody.py`: every evidence item is SHA-256 hashed and
time-stamped; the case package is sealed with a Merkle-style **manifest hash** so
tampering is detectable, and includes the full chain-of-custody (audit) trail.
`verify_package()` recomputes and confirms integrity.
- `GET /api/incidents/{id}/case-package`
- **Case pkg** export button on the incident page (downloadable JSON).

### Confidence calibration & model cards (Section 8.10)
`app/ai/model_cards.py`: a **model card** for each AI/detection component
(method, inputs, limits, failure modes, confidence basis), and a **calibration
report** that bins incidents by confidence band and shows observed precision from
analyst feedback — surfacing over/under-confidence honestly.
- `GET /api/model-cards`, `GET /api/calibration`
- New **Model Cards** screen with the calibration table.

## Not included
Section 8.7 (honeypot/honeytoken signals) was deliberately left out: it needs
actual honeypot infrastructure to be meaningful and would only be a stub in the
lab. Easy to add later if the lab gains a honeypot host.

## Requirements / sections
Sections 8.3, 8.4, 8.6, 8.10 implemented. All 42 FRs remain complete; the only
outstanding project item is FR-40 (mobile app, separate Flutter build).

## Try it
- **Threat Hunting** (sidebar): query `event_type = authentication_failure` →
  see clusters → name it → **Promote to rule** → copy the generated YAML.
- **Model Cards** (sidebar): read each component's card; give incident feedback
  and watch the calibration table populate.
- **Incident page**: **Case pkg** button downloads the sealed forensic package;
  the risk timeline shows entity risk escalating.

## No new dependency / no migration
Pure Python (stdlib hashing). Just `docker compose up`.
