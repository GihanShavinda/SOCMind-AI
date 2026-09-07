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
    <p class="page-sub">Correlated groups of related events, each an investigable case.</p>

    <div class="card">
      <table>
        <thead>
          <tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Related events</th><th>Confidence</th><th>Created</th></tr>
        </thead>
        <tbody>
          <tr *ngFor="let i of incidents()" class="clickable" [routerLink]="['/incidents', i.id]">
            <td>#{{ i.id }}</td>
            <td>{{ i.title }}</td>
            <td><span class="badge sev-{{ i.severity }}">{{ i.severity }}</span></td>
            <td>{{ i.status }}</td>
            <td>{{ i.related_count }}</td>
            <td>{{ (i.confidence * 100) | number:'1.0-0' }}%</td>
            <td class="muted">{{ i.created_at | date:'medium' }}</td>
          </tr>
          <tr *ngIf="incidents().length === 0">
            <td colspan="7" class="muted" style="text-align:center; padding:30px">No incidents yet.</td>
          </tr>
        </tbody>
      </table>
    </div>
  `,
})
export class IncidentsComponent implements OnInit {
  incidents = signal<Incident[]>([]);
  constructor(private api: ApiService) {}
  ngOnInit(): void {
    this.api.listIncidents().subscribe(list => this.incidents.set(list));
  }
}
