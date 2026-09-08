"""Analyst feedback + active learning (Section 8.8).

Analyst verdicts (confirm / dismiss / correct) are stored and then bias future
detections: a rule that analysts keep dismissing as false-positive gets a small
confidence penalty; a repeatedly-confirmed rule gets a small boost. This is a
transparent, bounded nudge — never enough to silence a rule, matching the
confidence-calibration goal (8.10).
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Feedback, Alert
from app.models.common import FeedbackVerdict

MAX_ADJUST = 0.15   # cap the nudge so feedback tunes but never overrides detection


def rule_confidence_adjustment(db: Session, rule_id: str | None) -> float:
    """Return a confidence delta in [-MAX_ADJUST, +MAX_ADJUST] for a rule, based on
    the balance of confirm vs dismiss feedback on incidents raised by that rule."""
    if not rule_id:
        return 0.0
    rows = db.query(Feedback).filter(Feedback.rule_id == rule_id).all()
    if not rows:
        return 0.0
    confirms = sum(1 for r in rows if r.verdict == FeedbackVerdict.CONFIRM)
    dismisses = sum(1 for r in rows if r.verdict == FeedbackVerdict.DISMISS)
    total = confirms + dismisses
    if total == 0:
        return 0.0
    balance = (confirms - dismisses) / total     # -1..+1
    return round(MAX_ADJUST * balance, 3)


def primary_rule_for_incident(db: Session, incident_id: int) -> str | None:
    """The rule_id most responsible for an incident (first alert's rule)."""
    alert = (db.query(Alert).filter(Alert.incident_id == incident_id)
             .order_by(Alert.id).first())
    return alert.rule_id if alert else None
