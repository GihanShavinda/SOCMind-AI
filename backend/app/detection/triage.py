"""Triage scoring and SLA tracking (Section 8.5).

Triage score orders the analyst queue. SLA timers set a due time per severity and
we compute breach on read. Both are deterministic and offline.
"""
from __future__ import annotations

from datetime import timedelta

from app.models import Incident
from app.models.common import Severity, Criticality, IncidentStatus, utcnow

# Minutes to respond, per severity.
SLA_MINUTES = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 60,
    Severity.MEDIUM: 240,
    Severity.LOW: 1440,
}

_SEV_WEIGHT = {Severity.LOW: 0.25, Severity.MEDIUM: 0.5,
               Severity.HIGH: 0.8, Severity.CRITICAL: 1.0}
_CRIT_WEIGHT = {Criticality.LOW: 0.25, Criticality.MEDIUM: 0.5,
                Criticality.HIGH: 0.8, Criticality.CRITICAL: 1.0}


def compute_triage_score(incident: Incident) -> float:
    """0..100 priority score: severity + confidence + asset criticality + spread."""
    sev = _SEV_WEIGHT.get(incident.severity, 0.5)
    crit = _CRIT_WEIGHT.get(incident.asset.criticality, 0.25) if incident.asset else 0.25
    conf = incident.confidence or 0.0
    spread = min(incident.related_count / 10.0, 1.0)   # more events => higher

    score = 100 * (0.40 * sev + 0.25 * conf + 0.25 * crit + 0.10 * spread)
    return round(score, 1)


def sla_due(incident: Incident):
    minutes = SLA_MINUTES.get(incident.severity, 240)
    base = incident.created_at or utcnow()
    return base + timedelta(minutes=minutes)


def is_breached(incident: Incident) -> bool:
    """SLA breached if past due and not yet resolved/dismissed."""
    if incident.status in (IncidentStatus.RESOLVED, IncidentStatus.DISMISSED):
        return False
    due = incident.sla_due_at
    if not due:
        return False
    if due.tzinfo is None:
        from datetime import timezone
        due = due.replace(tzinfo=timezone.utc)   # SQLite returns naive
    return due < utcnow()


def apply_triage_and_sla(incident: Incident) -> None:
    """Set triage score and SLA due time on an incident (at creation/update)."""
    incident.triage_score = compute_triage_score(incident)
    incident.sla_due_at = sla_due(incident)
