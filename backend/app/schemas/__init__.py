from datetime import datetime

from pydantic import BaseModel, EmailStr, ConfigDict

from app.models.common import Role, Criticality, Severity, IncidentStatus


# ---- Auth ----
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


# ---- Users ----
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Role = Role.ANALYST


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    email: EmailStr
    role: Role
    mfa_enabled: bool
    is_active: bool


# ---- Assets ----
class AssetCreate(BaseModel):
    hostname: str
    os: str
    ip: str
    owner: str | None = None
    environment: str = "lab"
    criticality: Criticality = Criticality.LOW


class AssetUpdate(BaseModel):
    hostname: str | None = None
    os: str | None = None
    ip: str | None = None
    owner: str | None = None
    environment: str | None = None
    criticality: Criticality | None = None
    agent_status: str | None = None
    automation_enabled: bool | None = None
    auto_action_types: list[str] | None = None


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    hostname: str
    os: str
    ip: str
    owner: str | None
    environment: str
    criticality: Criticality
    agent_status: str
    automation_enabled: bool = False
    auto_action_types: list[str] | None = None


# ---- Events (unified schema) ----
class EventIn(BaseModel):
    """The unified event schema the collectors POST to /api/events/ingest."""
    timestamp: datetime
    asset: str                       # hostname; resolved to asset_id server-side
    event_type: str                  # e.g. authentication_failure
    source_ip: str | None = None
    username: str | None = None
    severity: Severity = Severity.LOW
    raw_ref: str | None = None
    attributes: dict | None = None   # dest_port, process_name, dest_ip, ...


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    asset_id: int | None
    timestamp: datetime
    event_type: str
    source_ip: str | None
    username: str | None
    severity: Severity
    incident_id: int | None


class IngestResult(BaseModel):
    event_id: int
    incident_id: int | None = None
    detection: str | None = None


# ---- Incidents ----
class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    title: str
    confidence: float
    severity: Severity
    status: IncidentStatus
    related_count: int
    asset_id: int | None
    created_at: datetime


class AttackStepOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    order: int
    timestamp: datetime | None
    description: str
    mitre_id: str | None
    mitre_name: str | None


# ---- Attack graph (FR-17) ----
class GraphNode(BaseModel):
    id: str
    type: str            # attacker | account | host | process | external
    label: str


class GraphEdge(BaseModel):
    source: str
    target: str
    label: str


class IncidentGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


# ---- MITRE kill chain (FR-19, FR-20) ----
class Technique(BaseModel):
    id: str
    name: str | None


class KillChainPhase(BaseModel):
    phase: str
    order: int
    observed: bool
    techniques: list[Technique]


# ---- AI assistant (FR-21..29) ----
class CommandRec(BaseModel):
    id: str
    os: str
    command: str
    purpose: str
    why: str
    risk: str


class NextStep(BaseModel):
    order: int
    action: str
    rationale: str
    command: CommandRec | None = None


class AssistantAnalysis(BaseModel):
    incident_id: int
    what_happened: str
    why_suspicious: str
    next_steps: list[NextStep]
    recommended_commands: list[CommandRec]
    grounded_on: list[str]
    source: str          # "rule-based" | "llm"
    model: str | None = None


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    actor: str
    action: str
    target: str | None
    timestamp: datetime


# ---- Phase 5: playbooks, decisions, actions ----
class PlaybookStepOut(BaseModel):
    order: int
    action: str
    risk: str
    approval_required: bool
    expected_result: str


class PlaybookOut(BaseModel):
    name: str
    attack_type: str
    mitre: list[str]
    steps: list[PlaybookStepOut]


class DecisionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    incident_id: int
    action_type: str
    threat_conf: float
    response_conf: float
    asset_crit: str
    impact: str
    outcome: str
    rationale: str
    created_at: datetime


class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    incident_id: int
    decision_id: int | None
    type: str
    description: str
    risk_level: str
    status: str
    reversible: bool
    undo_ref: str | None
    performed_by: str | None
    created_at: datetime
    executed_at: datetime | None


class ProposeActionIn(BaseModel):
    action_type: str


class AutomationPolicyIn(BaseModel):
    automation_enabled: bool
    auto_action_types: list[str] | None = None
