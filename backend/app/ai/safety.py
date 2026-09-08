"""Command safety engine (FR-27, FR-28, FR-29).

- Risk classification: Low | Medium | High | Restricted
- Playbook/catalog validation: a command may be surfaced only if it exists in the
  approved catalog. Anything else (e.g. free-form text from an LLM) is rejected.
- Guardrails: nothing is auto-executed here; this module only decides what may be
  *surfaced*. Execution + approval is Phase 5, and destructive actions are never
  auto-run regardless of confidence.
"""
from __future__ import annotations

from app.ai.catalog import get_command, Command

RISK_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Restricted": 4}

# Substrings that force a Restricted classification if they ever appear.
_DESTRUCTIVE = ("rm -rf", "mkfs", "dd if=", "format ", "shutdown", "reboot",
                "del /f", "Remove-Item -Recurse", ":(){", "> /dev/sda")


def classify(command_text: str, declared: str | None = None) -> str:
    """Return the risk level for a command. Declared catalog risk is trusted
    unless the text contains a destructive pattern, which forces Restricted."""
    if any(pat in command_text for pat in _DESTRUCTIVE):
        return "Restricted"
    return declared or "Medium"


def validate_command_id(cmd_id: str) -> Command | None:
    """A command may be surfaced only if it is in the approved catalog (FR-28)."""
    return get_command(cmd_id)


def may_autoexecute(risk: str) -> bool:
    """Guardrail (FR-29): only Low-risk, read-only commands could ever be
    auto-run. Everything Medium+ needs confirmation/approval (enforced in P5)."""
    return risk == "Low"
