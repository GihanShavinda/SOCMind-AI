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
    return this.http.get<AssistantAnalysis>(`${this.base}/api/incidents/${id}/analysis`);
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

  // Events (FR-9..11)
  listEvents(limit = 100): Observable<Event[]> {
    return this.http.get<Event[]>(`${this.base}/api/events?limit=${limit}`);
  }

  // Audit (FR-35)
  listAudit(limit = 100): Observable<AuditEntry[]> {
    return this.http.get<AuditEntry[]>(`${this.base}/api/audit?limit=${limit}`);
  }
}
