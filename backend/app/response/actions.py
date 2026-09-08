"""Controlled response actions (FR-13 response set, FR-35 audit, FR-36 reversibility).

Actions are SIMULATED in the lab — the platform records that a firewall block /
account disable / isolation "was performed" with an undo reference, but never
actually mutates real infrastructure (see scope 3.2). Every state change is
written to the append-only audit log.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Incident, Asset, Decision, Action
from app.models.common import (
    ActionStatus, DecisionOutcome, RiskLevel, utcnow,
)
from app.response import decision as decision_engine
from app.audit.logger import write_audit

_RISK = {"Low": RiskLevel.LOW, "Medium": RiskLevel.MEDIUM,
         "High": RiskLevel.HIGH, "Restricted": RiskLevel.RESTRICTED}

_DESCRIPTIONS = {
    "firewall_block": "Create a firewall block for the malicious source IP",
    "disable_account": "Disable the potentially compromised account",
    "stop_process": "Stop the suspicious process",
    "isolate_endpoint": "Isolate the affected endpoint from the network",
    "create_ticket": "Create an incident ticket",
    "send_notification": "Send a notification to the on-call analyst",
}


def propose_action(db: Session, incident: Incident, action_type: str,
                   actor: str) -> Action:
    """Run the decision engine, create the Decision + Action. If the decision is
    to automate, execute (simulated) immediately; otherwise leave it pending
    human approval."""
    asset: Asset | None = incident.asset
    verdict = decision_engine.evaluate(action_type, incident.confidence, asset)

    decision = Decision(
        incident_id=incident.id, action_type=action_type,
        threat_conf=verdict["threat_conf"], response_conf=verdict["response_conf"],
        asset_crit=verdict["asset_crit"], impact=verdict["impact"],
        outcome=verdict["outcome"], rationale=verdict["rationale"],
    )
    db.add(decision)
    db.flush()

    action = Action(
        incident_id=incident.id, decision_id=decision.id, type=action_type,
        description=_DESCRIPTIONS.get(action_type, action_type),
        risk_level=_RISK.get(verdict["risk"], RiskLevel.MEDIUM),
        reversible=verdict["reversible"],
        status=ActionStatus.PROPOSED,
    )
    db.add(action)
    db.flush()

    write_audit(db, actor=actor, action="action.proposed",
                target=f"action:{action.id}",
                after=f"{action_type} -> {verdict['outcome'].value}")

    if verdict["outcome"] == DecisionOutcome.AUTOMATE:
        _execute(db, action, actor="system (automated)")
    else:
        action.status = ActionStatus.PENDING_APPROVAL

    db.flush()
    return action


def _execute(db: Session, action: Action, actor: str) -> None:
    """Simulate performing the action and record an undo reference."""
    action.status = ActionStatus.EXECUTED
    action.performed_by = actor
    action.executed_at = utcnow()
    action.undo_ref = f"undo-{action.type}-{action.id}" if action.reversible else None
    write_audit(db, actor=actor, action="action.executed",
                target=f"action:{action.id}",
                before="pending", after="executed")


def approve_action(db: Session, action: Action, actor: str) -> Action:
    if action.status != ActionStatus.PENDING_APPROVAL:
        raise ValueError("Action is not pending approval")
    action.status = ActionStatus.APPROVED
    write_audit(db, actor=actor, action="action.approved",
                target=f"action:{action.id}")
    _execute(db, action, actor=actor)
    db.flush()
    return action


def reject_action(db: Session, action: Action, actor: str) -> Action:
    if action.status != ActionStatus.PENDING_APPROVAL:
        raise ValueError("Action is not pending approval")
    action.status = ActionStatus.REJECTED
    action.performed_by = actor
    write_audit(db, actor=actor, action="action.rejected",
                target=f"action:{action.id}")
    db.flush()
    return action


def rollback_action(db: Session, action: Action, actor: str) -> Action:
    """Reverse an executed, reversible action (FR-36)."""
    if action.status != ActionStatus.EXECUTED:
        raise ValueError("Only executed actions can be rolled back")
    if not action.reversible:
        raise ValueError("This action is not reversible")
    action.status = ActionStatus.ROLLED_BACK
    write_audit(db, actor=actor, action="action.rolled_back",
                target=f"action:{action.id}",
                before=action.undo_ref or "", after="reverted")
    db.flush()
    return action
