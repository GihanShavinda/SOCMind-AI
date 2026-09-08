"""Threat-intelligence enrichment (FR-12, Section 8.1).

Annotates events with source-IP context: whether the IP is internal/private,
its reputation from a local IOC feed, and a coarse geo label. The design is
offline-first (works with no external feeds, per the LLM/feed-unavailability
tolerance): reputation comes from a local YAML IOC list that can be extended.
Provenance is attached so the explanation can cite where a verdict came from.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml

_FEED_DIR = Path(__file__).resolve().parents[3] / "intel-feeds"
_IOCS: dict[str, dict] = {}


def load_iocs() -> int:
    """Load IOC entries (malicious IPs/CIDRs) from intel-feeds/*.yml."""
    global _IOCS
    _IOCS = {}
    if not _FEED_DIR.exists():
        return 0
    for f in sorted([*_FEED_DIR.glob("*.yml"), *_FEED_DIR.glob("*.yaml")]):
        data = yaml.safe_load(open(f, encoding="utf-8")) or {}
        for entry in data.get("indicators", []):
            _IOCS[entry["value"]] = {
                "type": entry.get("type", "ip"),
                "verdict": entry.get("verdict", "malicious"),
                "source": entry.get("source", f.name),
                "note": entry.get("note", ""),
            }
    return len(_IOCS)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _match_ioc(ip: str) -> dict | None:
    if not _IOCS:
        load_iocs()
    if ip in _IOCS:
        return _IOCS[ip]
    # CIDR matches
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for value, meta in _IOCS.items():
        if "/" in value:
            try:
                if addr in ipaddress.ip_network(value, strict=False):
                    return meta
            except ValueError:
                continue
    return None


def enrich_ip(ip: str | None) -> dict | None:
    """Return an enrichment dict for a source IP, or None if there's no IP."""
    if not ip:
        return None

    private = _is_private(ip)
    ioc = _match_ioc(ip)

    if ioc:
        reputation = ioc["verdict"]          # malicious | suspicious
        source = ioc["source"]
    elif private:
        reputation = "internal"
        source = "rfc1918"
    else:
        reputation = "unknown"
        source = "none"

    return {
        "ip": ip,
        "is_private": private,
        "reputation": reputation,
        "geo": "Internal network" if private else "External",
        "source": source,
        "ioc_note": ioc["note"] if ioc else None,
    }


def confidence_modifier(enrichment: dict | None) -> float:
    """A small confidence nudge based on reputation (used at detection time)."""
    if not enrichment:
        return 0.0
    return {"malicious": 0.1, "suspicious": 0.05}.get(enrichment["reputation"], 0.0)
