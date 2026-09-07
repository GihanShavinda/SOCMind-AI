# Phase 2 — Detection Engine (changelog)

This phase widens detection from a single hardcoded rule to a layered,
extensible engine, and begins attack-story reconstruction with MITRE mapping.

## What was added

### Detection-as-code (Sigma-style rules)
Rules now live in `detection-rules/*.yml` and are loaded at startup — adding a
detection needs **no code change**. Shipped rules:

| Rule file | Scenario | Type | Severity | MITRE |
|-----------|----------|------|----------|-------|
| `ssh_bruteforce.yml` | Repeated auth failures | threshold (5 / 120s) | High | T1110 |
| `port_scan.yml` | Many distinct dest ports | threshold (10 distinct / 60s) | Medium | T1046 |
| `suspicious_process.yml` | Suspicious process exec | single | Medium | T1059 |
| `outbound_c2.yml` | Unusual outbound connection | single | High | T1071 |

The rule engine supports `single` and `threshold` correlation, grouping by any
event field, and counting **distinct** attribute values (used for port scan).

### Layer 3 — success-after-failures escalation
A successful login following brute-force failures from the same source now
escalates the incident to **Critical** and records the compromise as an attack
step (T1078 Valid Accounts). This is the key "attacker got in" signal.

### Layer 2 — baseline anomaly detection
Per asset+user baselines of normal login source IPs and hours are computed from
history. A login from a never-seen IP or at off-hours raises an anomaly score and
opens a "Suspicious login" incident. Cold-start guarded (needs ≥3 prior logins).

### Attack-story reconstruction (start of FR-16 / FR-19)
New `AttackStep` entity records an ordered, MITRE-tagged narrative per incident.
New endpoint `GET /api/incidents/{id}/story`. The frontend incident page now
renders this as a visual timeline with MITRE technique tags.

### Flexible event attributes
`Event.attributes` (JSON) carries scenario-specific fields (dest_port,
process_name, dest_ip) so new detections need no schema change.
`Event.anomaly_score` stores the Layer-2 score.

## Schema changes
Migration `0002_phase2`: adds `events.attributes`, `events.anomaly_score`, and
the `attack_steps` table. Run automatically on `docker compose up`.

## Requirements advanced to ✅
FR-13 (correlation keys), detection Layers 1–3, detection-as-code, plus partial
progress on FR-16/FR-18 (timeline & assessment) and FR-19 (MITRE mapping).

## Try it
```bash
docker compose up            # applies migration 0002 automatically
python backend/scripts/demo_scenarios.py   # generates all five scenarios
```
Then open the dashboard — you'll see brute-force (critical), port scan,
suspicious process, outbound C2, and a suspicious login. Click the critical
incident to see the reconstructed attack story.
