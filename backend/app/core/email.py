"""Email delivery for password reset (FR-1).

Two modes (config EMAIL_MODE):
  console — dev/lab default: logs the message (and reset link) to stdout, and the
            link is also surfaced in the API response so it works fully offline.
  smtp    — sends a real email via the configured SMTP server.
"""
from __future__ import annotations

import smtplib
from email.mime.text import MIMEText

from app.core.config import settings


def send_email(to: str, subject: str, body: str) -> None:
    if settings.EMAIL_MODE == "smtp" and settings.SMTP_HOST:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM
        msg["To"] = to
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as s:
            s.starttls()
            if settings.SMTP_USER:
                s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            s.sendmail(settings.SMTP_FROM, [to], msg.as_string())
    else:
        # Console/dev mode — never fails, works offline in the lab.
        print(f"\n[email:console] To: {to}\n[email:console] Subject: {subject}\n"
              f"[email:console] {body}\n")


def send_reset_link(to: str, link: str) -> None:
    send_email(
        to,
        "SOCMind AI — password reset",
        f"A password reset was requested for your account.\n\n"
        f"Reset your password using this link (valid "
        f"{settings.RESET_TOKEN_EXPIRE_MINUTES} minutes):\n{link}\n\n"
        f"If you did not request this, you can ignore this email.",
    )
