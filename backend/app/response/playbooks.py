"""Structured response playbooks (FR-30, FR-31).

Playbook *templates* are detection-as-code style YAML in playbooks/. Each is an
ordered set of steps with description, risk, approval requirement and expected
result. The selector picks the best-matching playbook for an incident from the
techniques/events observed (adaptive selection, FR-31).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from app.models import Incident, AttackStep, Event

_PLAYBOOK_DIR = Path(__file__).resolve().parents[3] / "playbooks"

# MITRE technique -> attack_type used to match a playbook.
_MITRE_TO_TYPE = {
    "T1110": "brute_force", "T1078": "brute_force",
    "T1046": "port_scan", "T1059": "suspicious_process",
    "T1071": "suspicious_process", "T1041": "suspicious_process",
}


@dataclass
class PlaybookStep:
    order: int
    action: str
    risk: str = "Low"
    approval_required: bool = False
    expected_result: str = ""


@dataclass
class Playbook:
    name: str
    attack_type: str
    mitre: list[str] = field(default_factory=list)
    steps: list[PlaybookStep] = field(default_factory=list)


_PLAYBOOKS: dict[str, Playbook] = {}


def load_playbooks() -> int:
    global _PLAYBOOKS
    _PLAYBOOKS = {}
    if not _PLAYBOOK_DIR.exists():
        return 0
    for f in sorted([*_PLAYBOOK_DIR.glob("*.yml"), *_PLAYBOOK_DIR.glob("*.yaml")]):
        data = yaml.safe_load(open(f, encoding="utf-8"))
        if not data:
            continue
        steps = [
            PlaybookStep(
                order=s.get("order", i + 1), action=s["action"],
                risk=s.get("risk", "Low"),
                approval_required=bool(s.get("approval_required", False)),
                expected_result=s.get("expected_result", ""),
            )
            for i, s in enumerate(data.get("steps", []))
        ]
        pb = Playbook(name=data["name"], attack_type=data["attack_type"],
                      mitre=list(data.get("mitre", [])), steps=steps)
        _PLAYBOOKS[pb.attack_type] = pb
    return len(_PLAYBOOKS)


def all_playbooks() -> dict[str, Playbook]:
    if not _PLAYBOOKS:
        load_playbooks()
    return _PLAYBOOKS


def select_for_incident(steps: list[AttackStep], events: list[Event]) -> Playbook | None:
    """Adaptive selection (FR-31): match on observed MITRE technique, then fall
    back to event-type heuristics."""
    pbs = all_playbooks()
    for s in steps:
        t = _MITRE_TO_TYPE.get(s.mitre_id or "")
        if t and t in pbs:
            return pbs[t]
    etypes = {e.event_type for e in events}
    if "authentication_failure" in etypes:
        return pbs.get("brute_force")
    if "network_connection" in etypes:
        return pbs.get("port_scan")
    if "suspicious_process" in etypes or "outbound_connection" in etypes:
        return pbs.get("suspicious_process")
    return next(iter(pbs.values()), None)
