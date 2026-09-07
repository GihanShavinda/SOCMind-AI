"""Minimal MITRE ATT&CK technique lookup for the lab scenarios (FR-19).

Kept as a local table so the platform works offline; Phase 3 can expand this or
pull from the official ATT&CK data.
"""

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion / Persistence"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
}


def technique_name(mitre_id: str | None) -> str | None:
    if not mitre_id:
        return None
    return TECHNIQUES.get(mitre_id, {}).get("name")
