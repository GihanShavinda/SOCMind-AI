"""Incident report builder (FR-41).

Assembles a complete case report from all the pieces the platform produced:
summary, attack story, evidence timeline, MITRE kill chain, AI analysis,
decisions, response actions and the audit trail. Returns a plain dict that the
exporters (JSON/CSV/PDF) render.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import Incident, Event, AttackStep, Decision, Action, AuditLog
from app.detection.mitre import build_kill_chain
from app.ai import assistant


def build_report(db: Session, incident: Incident) -> dict:
    events = (db.query(Event).filter(Event.incident_id == incident.id)
              .order_by(Event.timestamp).all())
    steps = (db.query(AttackStep).filter(AttackStep.incident_id == incident.id)
             .order_by(AttackStep.order).all())
    decisions = (db.query(Decision).filter(Decision.incident_id == incident.id)
                 .order_by(Decision.created_at).all())
    actions = (db.query(Action).filter(Action.incident_id == incident.id)
               .order_by(Action.created_at).all())
    # Audit entries that reference this incident or its actions.
    action_targets = {f"action:{a.id}" for a in actions} | {f"incident:{incident.id}"}
    audit = [a for a in db.query(AuditLog).order_by(AuditLog.timestamp).all()
             if a.target in action_targets]

    analysis = assistant.analyse(db, incident)
    kill_chain = build_kill_chain([s.mitre_id for s in steps if s.mitre_id])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident": {
            "id": incident.id, "title": incident.title,
            "severity": incident.severity.value, "status": incident.status.value,
            "confidence": incident.confidence, "related_count": incident.related_count,
            "asset": incident.asset.hostname if incident.asset else None,
            "created_at": incident.created_at.isoformat() if incident.created_at else None,
        },
        "assessment": {
            "what_happened": analysis["what_happened"],
            "why_suspicious": analysis["why_suspicious"],
            "grounded_on": analysis["grounded_on"],
        },
        "attack_story": [
            {"order": s.order, "description": s.description,
             "mitre_id": s.mitre_id, "mitre_name": s.mitre_name,
             "timestamp": s.timestamp.isoformat() if s.timestamp else None}
            for s in steps
        ],
        "kill_chain": [
            {"phase": p["phase"], "observed": p["observed"],
             "techniques": [t["id"] for t in p["techniques"]]}
            for p in kill_chain
        ],
        "evidence": [
            {"timestamp": e.timestamp.isoformat(), "event_type": e.event_type,
             "source_ip": e.source_ip, "username": e.username,
             "severity": e.severity.value,
             "reputation": (e.attributes or {}).get("enrichment", {}).get("reputation")}
            for e in events
        ],
        "decisions": [
            {"action_type": d.action_type, "outcome": d.outcome.value,
             "threat_conf": d.threat_conf, "response_conf": d.response_conf,
             "asset_crit": d.asset_crit, "impact": d.impact, "rationale": d.rationale}
            for d in decisions
        ],
        "actions": [
            {"type": a.type, "description": a.description,
             "risk_level": a.risk_level.value, "status": a.status.value,
             "reversible": a.reversible, "performed_by": a.performed_by}
            for a in actions
        ],
        "audit": [
            {"timestamp": a.timestamp.isoformat(), "actor": a.actor,
             "action": a.action, "target": a.target}
            for a in audit
        ],
    }
