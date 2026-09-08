"""Report exporters (FR-42): CSV and PDF. JSON is the raw report dict itself."""
from __future__ import annotations

import csv
import io


def to_csv(report: dict) -> str:
    """Flatten the report into a sectioned CSV."""
    buf = io.StringIO()
    w = csv.writer(buf)
    inc = report["incident"]

    w.writerow(["SOCMind AI — Incident Report"])
    w.writerow(["Generated", report["generated_at"]])
    w.writerow([])
    w.writerow(["Incident", inc["id"], inc["title"]])
    w.writerow(["Severity", inc["severity"], "Status", inc["status"]])
    w.writerow(["Confidence", f"{inc['confidence']*100:.0f}%", "Asset", inc["asset"]])
    w.writerow([])

    w.writerow(["Evidence timeline"])
    w.writerow(["timestamp", "event_type", "source_ip", "username", "severity", "reputation"])
    for e in report["evidence"]:
        w.writerow([e["timestamp"], e["event_type"], e["source_ip"],
                    e["username"], e["severity"], e["reputation"]])
    w.writerow([])

    w.writerow(["Attack story"])
    w.writerow(["order", "description", "mitre_id", "mitre_name"])
    for s in report["attack_story"]:
        w.writerow([s["order"], s["description"], s["mitre_id"], s["mitre_name"]])
    w.writerow([])

    w.writerow(["Decisions"])
    w.writerow(["action_type", "outcome", "threat_conf", "response_conf",
                "asset_crit", "impact", "rationale"])
    for d in report["decisions"]:
        w.writerow([d["action_type"], d["outcome"], d["threat_conf"],
                    d["response_conf"], d["asset_crit"], d["impact"], d["rationale"]])
    w.writerow([])

    w.writerow(["Response actions"])
    w.writerow(["type", "description", "risk_level", "status", "reversible", "performed_by"])
    for a in report["actions"]:
        w.writerow([a["type"], a["description"], a["risk_level"],
                    a["status"], a["reversible"], a["performed_by"]])
    w.writerow([])

    w.writerow(["Audit trail"])
    w.writerow(["timestamp", "actor", "action", "target"])
    for a in report["audit"]:
        w.writerow([a["timestamp"], a["actor"], a["action"], a["target"]])

    return buf.getvalue()


def to_pdf(report: dict) -> bytes:
    """Render the report as a PDF using reportlab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18*mm, bottomMargin=18*mm)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=16, spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4)
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, textColor=colors.grey)

    inc = report["incident"]
    story = []
    story.append(Paragraph("SOCMind AI — Incident Report", h1))
    story.append(Paragraph(f"Generated {report['generated_at']}", small))
    story.append(Spacer(1, 8))

    story.append(Paragraph(f"#{inc['id']} — {inc['title']}", h2))
    meta = [
        ["Severity", inc["severity"], "Status", inc["status"]],
        ["Confidence", f"{inc['confidence']*100:.0f}%", "Asset", inc["asset"] or "—"],
    ]
    t = Table(meta, colWidths=[70, 150, 70, 150])
    t.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 9),
                           ("TEXTCOLOR", (0, 0), (0, -1), colors.grey),
                           ("TEXTCOLOR", (2, 0), (2, -1), colors.grey)]))
    story.append(t)

    story.append(Paragraph("Assessment", h2))
    story.append(Paragraph("<b>What happened:</b> " + report["assessment"]["what_happened"], body))
    story.append(Paragraph("<b>Why suspicious:</b> " + report["assessment"]["why_suspicious"], body))

    def section_table(title, headers, rows):
        story.append(Paragraph(title, h2))
        if not rows:
            story.append(Paragraph("None.", small)); return
        data = [headers] + rows
        tbl = Table(data, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e2530")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tbl)

    section_table("Attack story", ["#", "Description", "MITRE"],
                  [[s["order"], Paragraph(s["description"], small),
                    f"{s['mitre_id']} {s['mitre_name'] or ''}"] for s in report["attack_story"]])

    section_table("Evidence timeline", ["Time", "Type", "Source IP", "User", "Sev", "Rep"],
                  [[e["timestamp"][11:19], e["event_type"], e["source_ip"] or "—",
                    e["username"] or "—", e["severity"], e["reputation"] or "—"]
                   for e in report["evidence"]])

    section_table("Decisions", ["Action", "Outcome", "Rationale"],
                  [[d["action_type"], d["outcome"], Paragraph(d["rationale"], small)]
                   for d in report["decisions"]])

    section_table("Response actions", ["Type", "Risk", "Status", "By"],
                  [[a["type"], a["risk_level"], a["status"], a["performed_by"] or "—"]
                   for a in report["actions"]])

    section_table("Audit trail", ["Time", "Actor", "Action", "Target"],
                  [[a["timestamp"][11:19], a["actor"], a["action"], a["target"]]
                   for a in report["audit"]])

    doc.build(story)
    return buf.getvalue()
