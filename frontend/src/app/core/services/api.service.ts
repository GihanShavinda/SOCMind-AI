import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

import { environment } from '../../../environments/environment';
import { Asset, Event, Incident, AttackStep, IncidentGraph, KillChainPhase, AssistantAnalysis, Playbook, Decision, ResponseAction, AuditEntry } from '../models';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private base = environment.apiBase;

  constructor(private http: HttpClient) {}

  // Assets (FR-5..8)
  listAssets(): Observable<Asset[]> {
    return this.http.get<Asset[]>(`${this.base}/api/assets`);
  }
  createAsset(payload: Partial<Asset>): Observable<Asset> {
    return this.http.post<Asset>(`${this.base}/api/assets`, payload);
  }

  // Incidents (FR-14, FR-39)
  listIncidents(): Observable<Incident[]> {
    return this.http.get<Incident[]>(`${this.base}/api/incidents`);
  }
  getIncident(id: number): Observable<Incident> {
    return this.http.get<Incident>(`${this.base}/api/incidents/${id}`);
  }
  incidentEvents(id: number): Observable<Event[]> {
    return this.http.get<Event[]>(`${this.base}/api/incidents/${id}/events`);
  }
  incidentStory(id: number): Observable<AttackStep[]> {
    return this.http.get<AttackStep[]>(`${this.base}/api/incidents/${id}/story`);
  }
  incidentGraph(id: number): Observable<IncidentGraph> {
    return this.http.get<IncidentGraph>(`${this.base}/api/incidents/${id}/graph`);
  }
  incidentKillchain(id: number): Observable<KillChainPhase[]> {
    return this.http.get<KillChainPhase[]>(`${this.base}/api/incidents/${id}/killchain`);
  }
  mitreKillchain(): Observable<KillChainPhase[]> {
    return this.http.get<KillChainPhase[]>(`${this.base}/api/mitre/killchain`);
  }
  incidentAnalysis(id: number): Observable<AssistantAnalysis> {
    return this.http.get<AssistantAnalysis>(`${this.base}/api/incidents/${id}/assistant`);
  }
  incidentFeedback(id: number, verdict: string, note?: string): Observable<any> {
    return this.http.post(`${this.base}/api/incidents/${id}/feedback`, { verdict, note });
  }

  // Response (Phase 5)
  incidentPlaybook(id: number): Observable<Playbook | null> {
    return this.http.get<Playbook | null>(`${this.base}/api/incidents/${id}/playbook`);
  }
  incidentActions(id: number): Observable<ResponseAction[]> {
    return this.http.get<ResponseAction[]>(`${this.base}/api/incidents/${id}/actions`);
  }
  incidentDecisions(id: number): Observable<Decision[]> {
    return this.http.get<Decision[]>(`${this.base}/api/incidents/${id}/decisions`);
  }
  proposeAction(id: number, action_type: string): Observable<ResponseAction> {
    return this.http.post<ResponseAction>(`${this.base}/api/incidents/${id}/actions`, { action_type });
  }
  listActions(status?: string): Observable<ResponseAction[]> {
    const q = status ? `?status=${status}` : '';
    return this.http.get<ResponseAction[]>(`${this.base}/api/actions${q}`);
  }
  approveAction(id: number): Observable<ResponseAction> {
    return this.http.post<ResponseAction>(`${this.base}/api/actions/${id}/approve`, {});
  }
  rejectAction(id: number): Observable<ResponseAction> {
    return this.http.post<ResponseAction>(`${this.base}/api/actions/${id}/reject`, {});
  }
  rollbackAction(id: number): Observable<ResponseAction> {
    return this.http.post<ResponseAction>(`${this.base}/api/actions/${id}/rollback`, {});
  }
  recentDecisions(): Observable<Decision[]> {
    return this.http.get<Decision[]>(`${this.base}/api/decisions`);
  }
  updateAsset(id: number, patch: Partial<Asset>): Observable<Asset> {
    return this.http.patch<Asset>(`${this.base}/api/assets/${id}`, patch);
  }

  // Reports (Phase 6)
  incidentReport(id: number): Observable<any> {
    return this.http.get<any>(`${this.base}/api/incidents/${id}/report`);
  }
  downloadReport(id: number, fmt: 'csv' | 'pdf'): void {
    const url = `${this.base}/api/incidents/${id}/report.${fmt}`;
    this.http.get(url, { responseType: 'blob' }).subscribe(blob => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `incident-${id}.${fmt}`;
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }
  downloadReportJson(id: number): void {
    this.incidentReport(id).subscribe(r => {
      const blob = new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `incident-${id}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }

  // MFA (Phase 6)
  mfaSetup(): Observable<{ secret: string; otpauth_uri: string }> {
    return this.http.post<{ secret: string; otpauth_uri: string }>(`${this.base}/api/auth/mfa/setup`, {});
  }
  mfaEnable(code: string): Observable<any> {
    return this.http.post(`${this.base}/api/auth/mfa/enable`, { code });
  }
  mfaDisable(code: string): Observable<any> {
    return this.http.post(`${this.base}/api/auth/mfa/disable`, { code });
  }

  // Account & profile (FR-1)
  forgotPassword(email: string): Observable<{ message: string; dev_reset_link: string | null }> {
    return this.http.post<{ message: string; dev_reset_link: string | null }>(
      `${this.base}/api/auth/forgot-password`, { email });
  }
  resetPassword(token: string, new_password: string): Observable<any> {
    return this.http.post(`${this.base}/api/auth/reset-password`, { token, new_password });
  }
  changePassword(current_password: string, new_password: string): Observable<any> {
    return this.http.post(`${this.base}/api/auth/change-password`, { current_password, new_password });
  }
  updateProfile(name: string): Observable<any> {
    return this.http.patch(`${this.base}/api/auth/me`, { name });
  }
  // Admin user management (FR-1, FR-3)
  listUsers(): Observable<any[]> {
    return this.http.get<any[]>(`${this.base}/api/users`);
  }
  createUser(body: { name: string; email: string; password: string; role: string }): Observable<any> {
    return this.http.post(`${this.base}/api/users`, body);
  }
  updateUser(id: number, patch: { role?: string; is_active?: boolean }): Observable<any> {
    return this.http.patch(`${this.base}/api/users/${id}`, patch);
  }

  // Advanced (Phase 8)
  entityRisk(entity_type: string, value: string): Observable<any> {
    return this.http.get<any>(`${this.base}/api/ueba/entity?entity_type=${entity_type}&value=${encodeURIComponent(value)}`);
  }
  riskTimeline(id: number): Observable<any[]> {
    return this.http.get<any[]>(`${this.base}/api/incidents/${id}/risk-timeline`);
  }
  runHunt(filters: any[], hours = 168): Observable<any> {
    return this.http.post<any>(`${this.base}/api/hunt`, { filters, hours });
  }
  promoteHunt(name: string, filters: any[]): Observable<{ rule_yaml: string; note: string }> {
    return this.http.post<{ rule_yaml: string; note: string }>(`${this.base}/api/hunt/promote`, { name, filters });
  }
  casePackage(id: number): Observable<any> {
    return this.http.get<any>(`${this.base}/api/incidents/${id}/case-package`);
  }
  modelCards(): Observable<any[]> {
    return this.http.get<any[]>(`${this.base}/api/model-cards`);
  }
  calibration(): Observable<any> {
    return this.http.get<any>(`${this.base}/api/calibration`);
  }
  downloadCasePackage(id: number): void {
    this.casePackage(id).subscribe(pkg => {
      const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `case-package-incident-${id}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }

  // Events (FR-9..11)
  listEvents(limit = 100): Observable<Event[]> {
    return this.http.get<Event[]>(`${this.base}/api/events?limit=${limit}`);
  }

  // Audit (FR-35)
  listAudit(limit = 100): Observable<AuditEntry[]> {
    return this.http.get<AuditEntry[]>(`${this.base}/api/audit?limit=${limit}`);
  }
}
