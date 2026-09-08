from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import Incident, User
from app.reporting.builder import build_report
from app.reporting.exporters import to_csv, to_pdf

router = APIRouter(prefix="/api/incidents", tags=["reports"])


def _report(db: Session, incident_id: int) -> dict:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return build_report(db, incident)


@router.get("/{incident_id}/report")
def report_json(incident_id: int, db: Session = Depends(get_db),
                _: User = Depends(get_current_user)):
    """Full incident report as JSON (FR-41, FR-42 JSON)."""
    return JSONResponse(_report(db, incident_id))


@router.get("/{incident_id}/report.csv")
def report_csv(incident_id: int, db: Session = Depends(get_db),
               _: User = Depends(get_current_user)):
    """Incident report as CSV (FR-42)."""
    csv_text = to_csv(_report(db, incident_id))
    return PlainTextResponse(
        csv_text, media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}.csv"'},
    )


@router.get("/{incident_id}/report.pdf")
def report_pdf(incident_id: int, db: Session = Depends(get_db),
               _: User = Depends(get_current_user)):
    """Incident report as PDF (FR-42)."""
    pdf_bytes = to_pdf(_report(db, incident_id))
    return Response(
        pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}.pdf"'},
    )
