"""Risk-aware human-in-the-loop decision engine (FR-32, FR-33, FR-34).

Combines four inputs — threat confidence, response confidence, asset criticality
and business impact — to decide whether a response may be automated or must be
escalated for human approval, and returns a transparent rationale (this rationale
is also what the explainable decision panel shows, FR-37).

Safety invariants (never violated):
  - Restricted / destructive actions are NEVER automated, regardless of confidence.
  - Automation only for low-impact, high-confidence, reversible actions on
    low-criticality assets, AND only where the asset has opted in (FR-34).
"""
from __future__ import annotations

from app.models import Asset
from app.models.common import DecisionOutcome

# Per-action-type metadata: default risk, business impact, whether reversible,
# and a baseline response confidence (how reliably this action achieves its goal).
ACTION_META: dict[str, dict] = {
    "firewall_block":   {"risk": "Medium", "impact": "Low",    "reversible": True,  "response_conf": 0.92},
    "disable_account":  {"risk": "High",   "impact": "Medium", "reversible": True,  "response_conf": 0.90},
    "stop_process":     {"risk": "Medium", "impact": "Low",    "reversible": False, "response_conf": 0.85},
    "isolate_endpoint": {"risk": "High",   "impact": "High",   "reversible": True,  "response_conf": 0.88},
    "create_ticket":    {"risk": "Low",    "impact": "Low",    "reversible": True,  "response_conf": 0.99},
    "send_notification":{"risk": "Low",    "impact": "Low",    "reversible": True,  "response_conf": 0.99},
}

_HIGH_CONF = 0.90


def evaluate(action_type: str, threat_conf: float, asset: Asset | None) -> dict:
    """Return the decision: outcome, the four inputs, and a rationale string."""
    meta = ACTION_META.get(action_type)
    if meta is None:
        return {
            "outcome": DecisionOutcome.APPROVAL_REQUIRED,
            "threat_conf": threat_conf, "response_conf": 0.0,
            "asset_crit": asset.criticality.value if asset else "Low",
            "impact": "Unknown", "risk": "Restricted",
            "reversible": False,
            "rationale": f"Unknown action type '{action_type}' — approval required by default.",
        }

    risk = meta["risk"]
    impact = meta["impact"]
    reversible = meta["reversible"]
    response_conf = meta["response_conf"]
    crit = asset.criticality.value if asset else "Low"
    automation_enabled = bool(asset and asset.automation_enabled)
    allowed_types = (asset.auto_action_types or []) if asset else []

    reasons: list[str] = []

    def approve(reason: str) -> dict:
        reasons.append(reason)
        return _result(DecisionOutcome.APPROVAL_REQUIRED, reasons,
                       threat_conf, response_conf, crit, impact, risk, reversible)

    # --- Hard safety gates first ---
    if risk == "Restricted":
        return approve("action is Restricted (destructive) and can never be automated")
    if not reversible:
        return approve("action is not reversible, so human approval is required")

    # --- Per-asset opt-in policy (FR-34) ---
    if not automation_enabled:
        return approve(f"automation is not enabled for asset criticality {crit}")
    if allowed_types and action_type not in allowed_types:
        return approve(f"action '{action_type}' is not in the asset's allowed auto-actions")

    # --- Risk-aware thresholds ---
    if crit not in ("Low",):
        return approve(f"asset criticality is {crit}; only low-criticality assets may auto-respond")
    if impact != "Low":
        return approve(f"business impact is {impact}; only low-impact actions may auto-respond")
    if threat_conf < _HIGH_CONF:
        return approve(f"threat confidence {threat_conf*100:.0f}% is below the {_HIGH_CONF*100:.0f}% automation bar")
    if response_conf < _HIGH_CONF:
        return approve(f"response confidence {response_conf*100:.0f}% is below the {_HIGH_CONF*100:.0f}% automation bar")

    reasons.append(
        f"low-impact, reversible action on a low-criticality asset with "
        f"threat {threat_conf*100:.0f}% and response {response_conf*100:.0f}% confidence, "
        f"and the asset has opted in"
    )
    return _result(DecisionOutcome.AUTOMATE, reasons,
                   threat_conf, response_conf, crit, impact, risk, reversible)


def _result(outcome, reasons, threat_conf, response_conf, crit, impact, risk, reversible) -> dict:
    lead = ("Safe for automated response: " if outcome == DecisionOutcome.AUTOMATE
            else "Human approval required: ")
    return {
        "outcome": outcome,
        "threat_conf": threat_conf,
        "response_conf": response_conf,
        "asset_crit": crit,
        "impact": impact,
        "risk": risk,
        "reversible": reversible,
        "rationale": lead + "; ".join(reasons) + ".",
    }
