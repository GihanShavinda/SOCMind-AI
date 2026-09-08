// Mirrors the backend Pydantic schemas so the whole app is typed end to end.

export type Role = 'Administrator' | 'SOC Analyst' | 'Viewer';
export type Criticality = 'Low' | 'Medium' | 'High' | 'Critical';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type IncidentStatus = 'open' | 'investigating' | 'resolved' | 'dismissed';
export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Restricted';

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface User {
  id: number;
  name: string;
  email: string;
  role: Role;
  mfa_enabled: boolean;
  is_active: boolean;
}

export interface Asset {
  id: number;
  hostname: string;
  os: string;
  ip: string;
  owner: string | null;
  environment: string;
  criticality: Criticality;
  agent_status: string;
  automation_enabled?: boolean;
  auto_action_types?: string[] | null;
}

export interface Event {
  id: number;
  asset_id: number | null;
  timestamp: string;
  event_type: string;
  source_ip: string | null;
  username: string | null;
  severity: Severity;
  incident_id: number | null;
}

export interface Incident {
  id: number;
  title: string;
  confidence: number;
  severity: Severity;
  status: IncidentStatus;
  related_count: number;
  asset_id: number | null;
  created_at: string;
  triage_score?: number;
  sla_due_at?: string | null;
  sla_breached?: boolean;
}

export interface SimilarIncident {
  id: number;
  title: string;
  severity: string;
  status: string;
  score: number;
  shared_techniques: string[];
  resolution: string;
}

export interface AttackStep {
  id: number;
  order: number;
  timestamp: string | null;
  description: string;
  mitre_id: string | null;
  mitre_name: string | null;
}

export interface GraphNode {
  id: string;
  type: 'attacker' | 'account' | 'host' | 'process' | 'external';
  label: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

export interface IncidentGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Technique {
  id: string;
  name: string | null;
}

export interface KillChainPhase {
  phase: string;
  order: number;
  observed: boolean;
  techniques: Technique[];
}

export interface CommandRec {
  id: string;
  os: string;
  command: string;
  purpose: string;
  why: string;
  risk: 'Low' | 'Medium' | 'High' | 'Restricted';
}

export interface NextStep {
  order: number;
  action: string;
  rationale: string;
  command: CommandRec | null;
}

export interface AssistantAnalysis {
  incident_id: number;
  what_happened: string;
  why_suspicious: string;
  next_steps: NextStep[];
  recommended_commands: CommandRec[];
  grounded_on: string[];
  source: string;        // "rule-based" | "llm"
  model: string | null;
  similar_incidents?: SimilarIncident[];
  kb_note?: string | null;
}

export interface PlaybookStep {
  order: number;
  action: string;
  risk: string;
  approval_required: boolean;
  expected_result: string;
}

export interface Playbook {
  name: string;
  attack_type: string;
  mitre: string[];
  steps: PlaybookStep[];
}

export interface Decision {
  id: number;
  incident_id: number;
  action_type: string;
  threat_conf: number;
  response_conf: number;
  asset_crit: string;
  impact: string;
  outcome: 'automate' | 'approval_required';
  rationale: string;
  created_at: string | null;
}

export interface ResponseAction {
  id: number;
  incident_id: number;
  decision_id: number | null;
  type: string;
  description: string;
  risk_level: 'Low' | 'Medium' | 'High' | 'Restricted';
  status: 'proposed' | 'pending_approval' | 'approved' | 'rejected' | 'executed' | 'rolled_back';
  reversible: boolean;
  undo_ref: string | null;
  performed_by: string | null;
  created_at: string | null;
  executed_at: string | null;
}

export interface AuditEntry {
  id: number;
  actor: string;
  action: string;
  target: string | null;
  timestamp: string;
}
