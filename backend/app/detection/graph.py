"""Attack-graph reconstruction (FR-17).

Turns an incident's raw events into a typed node/edge graph:

    attacker IP  ->  account  ->  host  ->  process  ->  external connection

The builder is generic: it inspects event_type and attributes, so new scenarios
contribute to the graph without special-casing.
"""
from __future__ import annotations

from app.models import Event, Incident


def _node(nodes: dict, node_id: str, ntype: str, label: str) -> str:
    if node_id not in nodes:
        nodes[node_id] = {"id": node_id, "type": ntype, "label": label}
    return node_id


def build_graph(incident: Incident, events: list[Event]) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    seen_edges: set[tuple] = set()

    def link(src: str, dst: str, label: str) -> None:
        key = (src, dst)
        if key in seen_edges:
            # Upgrade label if a stronger one comes along (e.g. login > attempt).
            for e in edges:
                if (e["source"], e["target"]) == key and label not in e["label"]:
                    e["label"] = label
            return
        seen_edges.add(key)
        edges.append({"source": src, "target": dst, "label": label})

    host_label = incident.asset.hostname if incident.asset else "unknown host"
    host_id = _node(nodes, f"host:{host_label}", "host", host_label)

    for e in events:
        attrs = e.attributes or {}

        ip_id = None
        if e.source_ip:
            ip_id = _node(nodes, f"ip:{e.source_ip}", "attacker", e.source_ip)

        acct_id = None
        if e.username:
            acct_id = _node(nodes, f"acct:{e.username}", "account", e.username)

        if e.event_type == "authentication_failure" and ip_id and acct_id:
            link(ip_id, acct_id, "brute force")
        elif e.event_type == "authentication_success":
            if ip_id and acct_id:
                link(ip_id, acct_id, "login")
            if acct_id:
                link(acct_id, host_id, "access")
            elif ip_id:
                link(ip_id, host_id, "access")

        elif e.event_type == "network_connection" and ip_id:
            # port scan / recon against the host
            link(ip_id, host_id, "scan")

        elif e.event_type == "suspicious_process":
            proc = attrs.get("process_name", "process")
            proc_id = _node(nodes, f"proc:{proc}", "process", proc)
            link(host_id, proc_id, "executes")

        elif e.event_type == "outbound_connection":
            dest = attrs.get("dest_ip", "external")
            port = attrs.get("dest_port")
            label_ext = f"{dest}:{port}" if port else dest
            ext_id = _node(nodes, f"ext:{label_ext}", "external", label_ext)
            link(host_id, ext_id, "connects")

    return {"nodes": list(nodes.values()), "edges": edges}
