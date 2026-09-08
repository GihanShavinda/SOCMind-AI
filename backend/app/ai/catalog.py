"""Approved command catalog loader (FR-24, FR-26, FR-28).

The catalog is the *only* source of runnable commands. The AI selects from it;
it can never invent commands. This is the "safe action space by construction".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

_CATALOG_DIR = Path(__file__).resolve().parents[3] / "command-catalog"


@dataclass
class Command:
    id: str
    os: str                       # linux | windows
    command: str
    purpose: str
    why: str
    risk: str = "Low"
    applies_to: list[str] = field(default_factory=list)


_CATALOG: dict[str, Command] = {}


def load_catalog() -> int:
    global _CATALOG
    _CATALOG = {}
    if not _CATALOG_DIR.exists():
        return 0
    for f in sorted([*_CATALOG_DIR.glob("*.yml"), *_CATALOG_DIR.glob("*.yaml")]):
        data = yaml.safe_load(open(f, encoding="utf-8")) or []
        for raw in data:
            cmd = Command(
                id=raw["id"], os=raw.get("os", "linux"),
                command=raw["command"], purpose=raw.get("purpose", ""),
                why=raw.get("why", ""), risk=raw.get("risk", "Low"),
                applies_to=list(raw.get("applies_to", [])),
            )
            _CATALOG[cmd.id] = cmd
    return len(_CATALOG)


def all_commands() -> dict[str, Command]:
    if not _CATALOG:
        load_catalog()
    return _CATALOG


def get_command(cmd_id: str) -> Command | None:
    return all_commands().get(cmd_id)


def recommend(os_name: str, event_types: set[str]) -> list[Command]:
    """Pick approved commands matching the asset OS and the incident's events."""
    os_key = "windows" if "windows" in (os_name or "").lower() else "linux"
    out: list[Command] = []
    for cmd in all_commands().values():
        if cmd.os != os_key:
            continue
        if not cmd.applies_to or event_types.intersection(cmd.applies_to):
            out.append(cmd)
    return out
