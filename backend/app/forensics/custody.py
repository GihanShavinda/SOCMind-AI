"""Digital forensics & chain of custody (Section 8.6).

Every evidence item (event) is hashed and time-stamped, and the incident's case
package is sealed with a Merkle-style manifest hash so any later tampering with
the evidence is detectable. The package is exportable for after-action review.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import Event, Incident, Action, AuditLog


def _event_canonical(e: Event) -> str:
    """A stable, canonical string for an event so its hash is reproducible."""
    return json.dumps({
        "id": e.id,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "asset_id": e.asset_id,
        "event_type": e.event_type,
        "source_ip": e.source_ip,
        "username": e.username,
        "severity": e.severity.value,
        "attributes": e.attributes,
    }, sort_keys=True, separators=(",", ":"))


def evidence_hash(e: Event) -> str:
    return hashlib.sha256(_event_canonical(e).encode()).hexdigest()


def case_package(db: Session, incident: Incident) -> dict:
    """Build a tamper-evident case package: every evidence item hashed and
    time-stamped, plus a manifest hash sealing the whole set."""
    events = (db.query(Event).filter(Event.incident_id == incident.id)
              .order_by(Event.timestamp).all())

    items = []
    for e in events:
        items.append({
            "event_id": e.id,
            "collected_at": e.timestamp.isoformat() if e.timestamp else None,
            "sha256": evidence_hash(e),
            "summary": f"{e.event_type} from {e.source_ip or '—'} user {e.username or '—'}",
        })

    actions = [{"type": a.type, "status": a.status.value,
                "performed_by": a.performed_by} for a in
               db.query(Action).filter(Action.incident_id == incident.id).all()]

    # Chain-of-custody = the audit entries touching this incident/its actions.
    action_targets = {f"action:{a.id}" for a in
                      db.query(Action).filter(Action.incident_id == incident.id).all()}
    action_targets.add(f"incident:{incident.id}")
    custody = [{"timestamp": a.timestamp.isoformat(), "actor": a.actor,
                "action": a.action, "target": a.target}
               for a in db.query(AuditLog).order_by(AuditLog.timestamp).all()
               if a.target in action_targets]

    # Seal: hash of all evidence hashes in order (Merkle-style manifest).
    manifest = "".join(i["sha256"] for i in items)
    manifest_hash = hashlib.sha256(manifest.encode()).hexdigest()

    return {
        "incident_id": incident.id,
        "title": incident.title,
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "evidence_count": len(items),
        "evidence": items,
        "response_actions": actions,
        "chain_of_custody": custody,
        "manifest_sha256": manifest_hash,
        "integrity": "sealed",
    }


def verify_package(db: Session, incident: Incident, manifest_sha256: str) -> bool:
    """Recompute the manifest and confirm the evidence hasn't been tampered with."""
    fresh = case_package(db, incident)
    return fresh["manifest_sha256"] == manifest_sha256
