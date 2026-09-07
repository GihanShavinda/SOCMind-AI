"""MITRE ATT&CK technique lookup + kill-chain positioning (FR-19, FR-20).

Local table so the platform works offline; Phase 3+ can expand it or pull from
the official ATT&CK dataset. Each technique carries the kill-chain phase it sits
in and an order index so techniques can be laid out along the attack lifecycle.
"""
from __future__ import annotations

# Ordered kill-chain phases (ATT&CK-tactic flavoured lifecycle).
KILL_CHAIN: list[str] = [
    "Reconnaissance",
    "Credential Access",
    "Initial Access",
    "Execution",
    "Command & Control",
    "Exfiltration",
]

TECHNIQUES: dict[str, dict] = {
    "T1046": {"name": "Network Service Discovery", "phase": "Reconnaissance"},
    "T1110": {"name": "Brute Force",                "phase": "Credential Access"},
    "T1078": {"name": "Valid Accounts",             "phase": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "phase": "Execution"},
    "T1071": {"name": "Application Layer Protocol", "phase": "Command & Control"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "phase": "Exfiltration"},
}


def technique_name(mitre_id: str | None) -> str | None:
    if not mitre_id:
        return None
    return TECHNIQUES.get(mitre_id, {}).get("name")


def technique_phase(mitre_id: str | None) -> str | None:
    if not mitre_id:
        return None
    return TECHNIQUES.get(mitre_id, {}).get("phase")


def phase_order(phase: str) -> int:
    return KILL_CHAIN.index(phase) if phase in KILL_CHAIN else len(KILL_CHAIN)


def build_kill_chain(mitre_ids: list[str]) -> list[dict]:
    """Return every kill-chain phase with the observed techniques placed in it.

    Phases with no observed technique are still returned (marked not observed) so
    the frontend can render the full standardised lifecycle.
    """
    observed: dict[str, list[dict]] = {p: [] for p in KILL_CHAIN}
    for mid in dict.fromkeys(mitre_ids):        # de-dupe, keep order
        phase = technique_phase(mid)
        if phase:
            observed[phase].append({"id": mid, "name": technique_name(mid)})

    return [
        {
            "phase": phase,
            "order": i,
            "observed": len(observed[phase]) > 0,
            "techniques": observed[phase],
        }
        for i, phase in enumerate(KILL_CHAIN)
    ]
