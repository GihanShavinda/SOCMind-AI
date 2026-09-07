import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

import { environment } from '../../../environments/environment';
import { Asset, Event, Incident, AttackStep, AuditEntry } from '../models';

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

  // Events (FR-9..11)
  listEvents(limit = 100): Observable<Event[]> {
    return this.http.get<Event[]>(`${this.base}/api/events?limit=${limit}`);
  }

  // Audit (FR-35)
  listAudit(limit = 100): Observable<AuditEntry[]> {
    return this.http.get<AuditEntry[]>(`${this.base}/api/audit?limit=${limit}`);
  }
}
