# Phase 6 — Reporting, Export, Enrichment, MFA & Windows Collector

This phase closes the remaining in-repo functional requirements and adds the
virtual-lab setup guide (Section 9.3).

## What was added

### Incident reporting + export (FR-41, FR-42)
`app/reporting/builder.py` assembles a complete case report (summary, assessment,
attack story, kill chain, evidence, decisions, actions, audit). Exporters render
it three ways:
- `GET /api/incidents/{id}/report` → **JSON**
- `GET /api/incidents/{id}/report.csv` → **CSV**
- `GET /api/incidents/{id}/report.pdf` → **PDF** (reportlab)

The **Reports** screen (was a placeholder) lists incidents with PDF/CSV/JSON
download buttons; the incident page header also has export buttons.

### Threat-intel enrichment (FR-12, Section 8.1)
`app/intel/enrichment.py` annotates every event's source IP at ingest with
reputation (from a local IOC feed `intel-feeds/*.yml`), private/internal
detection, and provenance. Malicious/suspicious IPs are flagged and can nudge
confidence. Offline-first — no external calls required. The report shows the
reputation column.

### Multi-factor authentication (FR-2)
Stdlib TOTP (RFC 6238, `app/core/totp.py`, no new dependency). New endpoints:
`/api/auth/mfa/setup`, `/mfa/enable`, `/mfa/disable`. Login now accepts an `otp`
field and enforces it when MFA is enabled. The **Settings** screen (topbar) lets a
user enrol with any authenticator app; the login screen shows an MFA field when
required.

### Windows collector (FR-9)
`collectors/windows/authlog_collector.ps1` — PowerShell script that reads Windows
Security events 4624/4625 (and Sysmon process-creation) and ships them to the
ingest endpoint, mirroring the Linux collector.

### Virtual lab setup guide (Section 9.3)
`lab/LAB_SETUP_GUIDE.md` — full walkthrough to build the isolated VM lab
(Windows 11 host, Ubuntu/Windows 10/Metasploitable targets, Kali attacker),
network setup, running both collectors, and the demo flow.

## Schema / migration
Migration `0004_phase6` adds `users.mfa_secret` (idempotent, like 0002–0003).
Runs automatically on `docker compose up`.

## New dependency
`reportlab==4.2.2` (PDF generation). **Rebuild the backend image** this phase:
```bash
docker compose up --build
```

## Requirements advanced to ✅
FR-2 (MFA), FR-9 (Windows collector), FR-12 (enrichment), FR-41 (reporting),
FR-42 (export).

## Remaining after Phase 6
FR-40 (mobile app — separate Flutter deliverable) and FR-23 full vector-store RAG
(grounding is done; vector DB is a Section 8.2 / P7 item), plus the Section 8
advanced enhancements (Phases 7–8).
