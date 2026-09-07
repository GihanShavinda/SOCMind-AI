"""Detection-as-code: load rules from YAML at startup so new detections need no
code change (FR — detection-as-code, Sigma-style).

We implement a pragmatic subset of Sigma tailored to the lab:

  - selection by event_type (and optional attribute equals)
  - correlation types:
      single    -> every matching event raises an alert / opens an incident
      threshold -> N matching events grouped by keys within a time window
                   (optionally counting DISTINCT values of one attribute,
                    e.g. distinct dest_port => port scan)

Rule YAML shape (see detection-rules/*.yml):

  id: ssh_bruteforce
  title: SSH Brute Force
  event_type: authentication_failure
  match:                     # optional extra equality checks on attributes
    protocol: ssh
  correlation:
    type: threshold
    count: 5
    window_seconds: 120
    group_by: [asset_id, source_ip]
    distinct_field: null     # or e.g. dest_port
  severity: high
  mitre: T1110
  incident_title: "SSH brute force from {source_ip}"
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Correlation:
    type: str = "single"                 # single | threshold
    count: int = 1
    window_seconds: int = 0
    group_by: list[str] = field(default_factory=list)
    distinct_field: str | None = None


@dataclass
class Rule:
    id: str
    title: str
    event_type: str
    severity: str = "medium"
    mitre: str | None = None
    incident_title: str = "{event_type} on {asset}"
    match: dict = field(default_factory=dict)
    correlation: Correlation = field(default_factory=Correlation)

    def matches(self, event) -> bool:
        """Does this rule's selection match a single event?"""
        if event.event_type != self.event_type:
            return False
        attrs = event.attributes or {}
        for k, v in self.match.items():
            if attrs.get(k) != v:
                return False
        return True


def _parse(raw: dict) -> Rule:
    corr_raw = raw.get("correlation", {}) or {}
    corr = Correlation(
        type=corr_raw.get("type", "single"),
        count=int(corr_raw.get("count", 1)),
        window_seconds=int(corr_raw.get("window_seconds", 0)),
        group_by=list(corr_raw.get("group_by", []) or []),
        distinct_field=corr_raw.get("distinct_field"),
    )
    return Rule(
        id=raw["id"],
        title=raw.get("title", raw["id"]),
        event_type=raw["event_type"],
        severity=raw.get("severity", "medium"),
        mitre=raw.get("mitre"),
        incident_title=raw.get("incident_title", "{event_type} on {asset}"),
        match=raw.get("match", {}) or {},
        correlation=corr,
    )


def load_rules(rules_dir: str | Path) -> list[Rule]:
    """Load and parse every *.yml / *.yaml rule in a directory."""
    path = Path(rules_dir)
    rules: list[Rule] = []
    if not path.exists():
        return rules
    for file in sorted([*path.glob("*.yml"), *path.glob("*.yaml")]):
        with open(file, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not data:
            continue
        # A file may hold one rule (dict) or several (list).
        for raw in (data if isinstance(data, list) else [data]):
            try:
                rules.append(_parse(raw))
            except KeyError as exc:
                print(f"[rules] skipping {file.name}: missing key {exc}")
    return rules
