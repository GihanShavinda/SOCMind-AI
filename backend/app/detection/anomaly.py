"""Layer 2 — baseline / anomaly detection (FR — Layer 2).

Learns each asset+user's normal successful-login source IPs and hours from
history, then flags logins that deviate. Baselines are computed on demand from
stored events (no extra table needed at lab scale).
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Event
from app.models.common import Severity

MIN_HISTORY = 3            # cold-start guard: need some history to baseline
BUSINESS_HOURS = range(8, 19)   # 08:00–18:59 considered normal off-baseline


def score_login(db: Session, event: Event) -> tuple[float, list[str]]:
    """Return (anomaly_score 0..1, reasons) for a successful-login event."""
    if event.event_type != "authentication_success":
        return 0.0, []

    history = (
        db.query(Event)
        .filter(
            Event.event_type == "authentication_success",
            Event.asset_id == event.asset_id,
            Event.username == event.username,
            Event.id != event.id,
        )
        .all()
    )
    if len(history) < MIN_HISTORY:
        return 0.0, []  # not enough baseline yet

    known_ips = {e.source_ip for e in history if e.source_ip}
    known_hours = {e.timestamp.hour for e in history}

    score = 0.0
    reasons: list[str] = []

    if event.source_ip and event.source_ip not in known_ips:
        score += 0.5
        reasons.append(f"login from a source IP never seen for this user ({event.source_ip})")

    hour = event.timestamp.hour
    if hour not in known_hours and hour not in BUSINESS_HOURS:
        score += 0.5
        reasons.append(f"off-hours login at {hour:02d}:00")

    return min(score, 1.0), reasons


def anomaly_severity(score: float) -> Severity:
    return Severity.HIGH if score >= 1.0 else Severity.MEDIUM
