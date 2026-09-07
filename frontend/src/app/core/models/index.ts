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
}

export interface AttackStep {
  id: number;
  order: number;
  timestamp: string | null;
  description: string;
  mitre_id: string | null;
  mitre_name: string | null;
}

export interface AuditEntry {
  id: number;
  actor: string;
  action: string;
  target: string | null;
  timestamp: string;
}
