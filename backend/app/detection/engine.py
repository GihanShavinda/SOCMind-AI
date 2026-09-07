"""Layered detection orchestrator (Phase 2).

Pipeline per ingested event:
  1. Rule + correlation layer  — evaluate every loaded YAML rule (single & threshold)
  2. Escalation                — success after brute-force failures => critical
  3. Anomaly layer (L2)        — baseline deviation on successful logins

Deterministic and LLM-free by design (reliability NFR). Rules are loaded once
from detection-rules/ and cached; call reload_rules() to pick up edits.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Event, Alert, Incident
from app.models.common import Severity, IncidentStatus, utcnow
from app.detection.rules.loader import load_rules, Rule
from app.detection import correlation as corr
from app.detection import anomaly

# Rules directory is repo-root/detection-rules (two levels up from app/).
_RULES_DIR = Path(__file__).resolve().parents[3] / "detection-rules"
_RULES: list[Rule] = []


def reload_rules() -> int:
    global _RULES
    _RULES = load_rules(_RULES_DIR)
    return len(_RULES)


def _ensure_rules() -> None:
    if not _RULES:
        reload_rules()


def run_detection(db: Session, event: Event) -> Incident | None:
    """Run all layers for one event. Returns the affected incident, if any."""
    _ensure_rules()
    incident: Incident | None = None

    # --- Layer 1 + 3: YAML rules (single & threshold/correlation) ---
    for rule in _RULES:
        if not rule.matches(event):
            continue
        if rule.correlation.type == "single":
            incident = corr.create_single_incident(db, event, rule)
        elif rule.correlation.type == "threshold":
            hit = corr.evaluate_threshold(db, event, rule)
            if hit:
                incident = corr.create_or_update_incident(db, event, rule, hit)

    # --- Escalation: successful login after recent brute-force failures ---
    if event.event_type == "authentication_success":
        esc = _check_escalation(db, event)
        if esc is not None:
            incident = esc

    # --- Layer 2: baseline anomaly on successful logins ---
    if event.event_type == "authentication_success":
        score, reasons = anomaly.score_login(db, event)
        event.anomaly_score = score
        if score > 0:
            incident = _handle_anomaly(db, event, score, reasons) or incident

    db.flush()
    return incident


def _check_escalation(db: Session, event: Event) -> Incident | None:
    window_start = event.timestamp - timedelta(
        seconds=settings.BRUTEFORCE_WINDOW_SECONDS
    )
    failures = (
        db.query(Event)
        .filter(
            Event.event_type == "authentication_failure",
            Event.asset_id == event.asset_id,
            Event.source_ip == event.source_ip,
            Event.timestamp >= window_start,
            Event.timestamp <= event.timestamp,
        )
        .all()
    )
    if len(failures) < settings.BRUTEFORCE_FAILED_THRESHOLD:
        return None

    incident = corr.open_incident_for(failures)
    if incident is None:
        # Failures never crossed the alert threshold on their own but a success
        # followed — still a compromise. Open an incident and attach failures.
        incident = Incident(
            title=f"Successful compromise after brute force from {event.source_ip}",
            confidence=0.9, severity=Severity.HIGH,
            status=IncidentStatus.OPEN, related_count=len(failures),
            asset_id=event.asset_id,
        )
        db.add(incident)
        db.flush()
        for f in failures:
            f.incident_id = incident.id
        corr.add_step(db, incident,
                      f"{len(failures)} failed logins from {event.source_ip}.",
                      mitre_id="T1110", ts=failures[0].timestamp)

    corr.escalate(db, incident, event, len(failures))
    return incident


def _handle_anomaly(db: Session, event: Event, score: float,
                    reasons: list[str]) -> Incident | None:
    # If the login is already part of an incident (e.g. escalation), just
    # record the anomaly alert and note it — don't open a duplicate incident.
    reason_text = "; ".join(reasons)
    if event.incident_id is not None:
        db.add(Alert(event_id=event.id, rule_id="baseline_anomaly",
                     layer="anomaly", score=score, created_at=utcnow(),
                     incident_id=event.incident_id))
        return None

    incident = Incident(
        title=f"Suspicious login for '{event.username}' on {corr._asset_name(event)}",
        confidence=0.5 + 0.3 * score,
        severity=anomaly.anomaly_severity(score),
        status=IncidentStatus.OPEN, related_count=1, asset_id=event.asset_id,
    )
    db.add(incident)
    db.flush()
    event.incident_id = incident.id
    corr.add_step(db, incident, f"Anomalous login: {reason_text}.",
                  mitre_id="T1078", ts=event.timestamp)
    db.add(Alert(event_id=event.id, rule_id="baseline_anomaly", layer="anomaly",
                 score=score, created_at=utcnow(), incident_id=incident.id))
    from app.audit.logger import write_audit
    write_audit(db, actor="system", action="incident.created",
                target=f"incident:{incident.id}", after=f"anomaly: {reason_text}")
    db.flush()
    return incident
