"""Lightweight retrieval-augmented grounding (FR-23, Section 8.2).

An offline knowledge base: instead of a vector store, we score past incidents by
feature overlap with the current one — shared MITRE techniques, shared event
types, and title-token overlap — and return the closest matches with what was
done about them (actions taken, final status). This lets the assistant say
"we've seen this before, and here is what worked", with every citation traceable
to a real prior incident. A pgvector backend can replace scoring later without
changing callers.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Incident, AttackStep, Event, Action


def _tokens(text: str) -> set[str]:
    return {t for t in (text or "").lower().replace("/", " ").split() if len(t) > 2}


def retrieve_similar(db: Session, incident: Incident, top_k: int = 3) -> list[dict]:
    """Return up to top_k similar past incidents with a score and a resolution note."""
    cur_mitre = {s.mitre_id for s in
                 db.query(AttackStep).filter(AttackStep.incident_id == incident.id).all()
                 if s.mitre_id}
    cur_etypes = {e.event_type for e in
                  db.query(Event).filter(Event.incident_id == incident.id).all()}
    cur_title = _tokens(incident.title)

    candidates = (db.query(Incident)
                  .filter(Incident.id != incident.id)
                  .order_by(Incident.created_at.desc()).limit(200).all())

    scored: list[tuple[float, Incident, dict]] = []
    for c in candidates:
        c_mitre = {s.mitre_id for s in
                   db.query(AttackStep).filter(AttackStep.incident_id == c.id).all()
                   if s.mitre_id}
        c_etypes = {e.event_type for e in
                    db.query(Event).filter(Event.incident_id == c.id).all()}
        c_title = _tokens(c.title)

        mitre_overlap = len(cur_mitre & c_mitre)
        etype_overlap = len(cur_etypes & c_etypes)
        title_overlap = len(cur_title & c_title)
        score = 3 * mitre_overlap + 2 * etype_overlap + title_overlap
        if score <= 0:
            continue

        actions = db.query(Action).filter(Action.incident_id == c.id).all()
        resolution = ", ".join(sorted({a.type for a in actions})) or "no response actions recorded"
        scored.append((score, c, {
            "id": c.id, "title": c.title, "severity": c.severity.value,
            "status": c.status.value, "score": score,
            "shared_techniques": sorted(cur_mitre & c_mitre),
            "resolution": resolution,
        }))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [meta for _, _, meta in scored[:top_k]]


def kb_citation(similar: list[dict]) -> str | None:
    """A one-line 'we've seen this before' note for the assistant, or None."""
    if not similar:
        return None
    top = similar[0]
    return (f"Similar past incident #{top['id']} ({top['title']}) was handled with: "
            f"{top['resolution']}.")
