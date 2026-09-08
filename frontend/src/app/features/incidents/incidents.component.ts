import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';

import { ApiService } from '../../core/services/api.service';
import { Incident } from '../../core/models';

@Component({
  selector: 'app-incidents',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <h1>Incidents</h1>
    <p class="page-sub">Correlated cases, ordered by triage priority.</p>

    <div class="card">
      <table>
        <thead>
          <tr><th>Triage</th><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>SLA</th><th>Related</th><th>Confidence</th></tr>
        </thead>
        <tbody>
          <tr *ngFor="let i of incidents()" class="clickable" [routerLink]="['/incidents', i.id]">
            <td><span class="triage">{{ i.triage_score | number:'1.0-0' }}</span></td>
            <td>#{{ i.id }}</td>
            <td>{{ i.title }}</td>
            <td><span class="badge sev-{{ i.severity }}">{{ i.severity }}</span></td>
            <td>{{ i.status }}</td>
            <td>
              <span class="badge" [class.sev-high]="i.sla_breached" [class.sev-low]="!i.sla_breached">
                {{ i.sla_breached ? 'Breached' : 'On track' }}
              </span>
            </td>
            <td>{{ i.related_count }}</td>
            <td>{{ (i.confidence * 100) | number:'1.0-0' }}%</td>
          </tr>
          <tr *ngIf="incidents().length === 0">
            <td colspan="8" class="muted" style="text-align:center; padding:30px">No incidents yet.</td>
          </tr>
        </tbody>
      </table>
    </div>
  `,
  styles: [`
    .triage { display:inline-block; min-width:34px; text-align:center; font-weight:700;
              background: var(--panel-hi); border-radius:6px; padding:2px 6px; }
  `],
})
export class IncidentsComponent implements OnInit {
  incidents = signal<Incident[]>([]);
  constructor(private api: ApiService) {}
  ngOnInit(): void {
    this.api.listIncidents().subscribe(list => this.incidents.set(list));
  }
}
