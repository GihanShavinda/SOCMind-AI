"""Confidence calibration & model cards (Section 8.10).

Model cards describe each AI/detection component honestly — inputs, method,
limits and failure modes — so the system's confidence is interpretable rather
than a black box. Calibration reports how detection confidence relates to
analyst-confirmed outcomes (using the feedback store), surfacing over- or
under-confidence instead of hiding it.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Feedback, Alert, Incident
from app.models.common import FeedbackVerdict


MODEL_CARDS = [
    {
        "component": "Rule + correlation detection",
        "method": "Deterministic Sigma-style rules and time-window correlation.",
        "inputs": "Normalised events (type, source IP, user, timestamps).",
        "limits": "Only detects modelled scenarios; thresholds are heuristic.",
        "failure_modes": "Noisy sources can raise false positives; novel TTPs missed.",
        "confidence_basis": "Event count vs threshold; calibrated by analyst feedback.",
    },
    {
        "component": "Baseline anomaly detection (Layer 2)",
        "method": "Per-user/asset baselines of login IPs and hours; statistical outlier.",
        "inputs": "Historical successful logins per entity.",
        "limits": "Cold-start needs ≥3 prior logins; simple univariate baselines.",
        "failure_modes": "Legitimate travel/off-hours work can flag as anomalous.",
        "confidence_basis": "Deviation count (new IP, off-hours) → 0..1 score.",
    },
    {
        "component": "AI investigation assistant",
        "method": "Deterministic evidence-grounded generation; optional LLM drafting.",
        "inputs": "Incident evidence, MITRE mapping, similar past incidents (RAG).",
        "limits": "Explanations only; recommends commands only from approved catalog.",
        "failure_modes": "LLM (if enabled) may phrase poorly; never invents commands.",
        "confidence_basis": "Traceable to cited evidence; no confidence asserted beyond it.",
    },
    {
        "component": "Risk-aware decision engine",
        "method": "Transparent function of threat/response confidence, criticality, impact.",
        "inputs": "Incident confidence, action risk, asset criticality, opt-in policy.",
        "limits": "Automation only for low-impact reversible actions on low-crit assets.",
        "failure_modes": "Conservative by design — errs toward requiring human approval.",
        "confidence_basis": "Explicit thresholds; every decision shows its rationale.",
    },
]


def model_cards() -> list[dict]:
    return MODEL_CARDS


def calibration_report(db: Session) -> dict:
    """Compare detection confidence against analyst verdicts to expose mis-calibration.

    For each confidence band, report how many incidents analysts CONFIRMED vs
    DISMISSED. A well-calibrated detector confirms most high-confidence incidents
    and dismisses most low-confidence ones."""
    bands = {"0.5-0.7": [0, 0], "0.7-0.85": [0, 0], "0.85-1.0": [0, 0]}

    feedback = db.query(Feedback).all()
    for fb in feedback:
        inc = db.get(Incident, fb.incident_id)
        if not inc:
            continue
        c = inc.confidence or 0
        band = "0.5-0.7" if c < 0.7 else "0.7-0.85" if c < 0.85 else "0.85-1.0"
        if fb.verdict == FeedbackVerdict.CONFIRM:
            bands[band][0] += 1
        elif fb.verdict == FeedbackVerdict.DISMISS:
            bands[band][1] += 1

    report = []
    for band, (confirmed, dismissed) in bands.items():
        total = confirmed + dismissed
        precision = round(confirmed / total, 2) if total else None
        report.append({
            "confidence_band": band,
            "confirmed": confirmed,
            "dismissed": dismissed,
            "observed_precision": precision,   # None until feedback exists
        })
    return {
        "note": "Observed precision per confidence band, from analyst feedback. "
                "Well-calibrated detection shows higher precision in higher bands.",
        "bands": report,
        "total_feedback": len(feedback),
    }
