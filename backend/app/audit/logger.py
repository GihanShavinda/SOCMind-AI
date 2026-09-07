from sqlalchemy.orm import Session

from app.models import AuditLog
from app.models.common import utcnow


def write_audit(
    db: Session,
    actor: str,
    action: str,
    target: str | None = None,
    before: str | None = None,
    after: str | None = None,
) -> AuditLog:
    """Append an immutable entry to the audit trail. Never update/delete these."""
    entry = AuditLog(
        actor=actor,
        action=action,
        target=target,
        timestamp=utcnow(),
        before=before,
        after=after,
    )
    db.add(entry)
    db.flush()
    return entry
