from datetime import datetime

from sqlalchemy import (
    String, Integer, Boolean, ForeignKey, DateTime, Text, Float, Enum as SAEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.common import (
    TimestampMixin, Role, Criticality, Severity, IncidentStatus,
)


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(SAEnum(Role), default=Role.ANALYST)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    os: Mapped[str] = mapped_column(String(80))
    ip: Mapped[str] = mapped_column(String(64))
    owner: Mapped[str | None] = mapped_column(String(120), nullable=True)
    environment: Mapped[str] = mapped_column(String(60), default="lab")
    criticality: Mapped[Criticality] = mapped_column(
        SAEnum(Criticality), default=Criticality.LOW
    )
    agent_status: Mapped[str] = mapped_column(String(20), default="offline")

    events: Mapped[list["Event"]] = relationship(back_populates="asset")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(120), nullable=True)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), default=Severity.LOW)
    raw_ref: Mapped[str | None] = mapped_column(Text, nullable=True)

    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id"), nullable=True
    )

    asset: Mapped["Asset"] = relationship(back_populates="events")
    incident: Mapped["Incident"] = relationship(back_populates="events")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id"), nullable=True)
    rule_id: Mapped[str] = mapped_column(String(120))
    layer: Mapped[str] = mapped_column(String(40), default="rule")  # rule|anomaly|correlation
    score: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id"), nullable=True
    )
    incident: Mapped["Incident"] = relationship(back_populates="alerts")


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), default=Severity.MEDIUM)
    status: Mapped[IncidentStatus] = mapped_column(
        SAEnum(IncidentStatus), default=IncidentStatus.OPEN
    )
    related_count: Mapped[int] = mapped_column(Integer, default=0)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)

    events: Mapped[list["Event"]] = relationship(back_populates="incident")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident")


class AuditLog(Base):
    """Append-only audit trail. Never updated or deleted."""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor: Mapped[str] = mapped_column(String(120))          # user email or "system"
    action: Mapped[str] = mapped_column(String(120))
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    before: Mapped[str | None] = mapped_column(Text, nullable=True)
    after: Mapped[str | None] = mapped_column(Text, nullable=True)
