import { Component, OnInit, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';

import { ApiService } from '../../core/services/api.service';
import { Incident } from '../../core/models';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <h1>Dashboard</h1>
    <p class="page-sub">Live incident overview across monitored assets.</p>

    <div class="grid grid-4" style="margin-bottom:24px">
      <div class="card stat"><div class="num">{{ incidents().length }}</div><div class="lbl">Total incidents</div></div>
      <div class="card stat"><div class="num" style="color:var(--high)">{{ count('high') + count('critical') }}</div><div class="lbl">High / Critical</div></div>
      <div class="card stat"><div class="num" style="color:var(--medium)">{{ count('medium') }}</div><div class="lbl">Medium</div></div>
      <div class="card stat"><div class="num" style="color:var(--low)">{{ openCount() }}</div><div class="lbl">Open</div></div>
    </div>

    <div class="card">
      <h2>Recent incidents</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Related</th><th>Confidence</th><th>Created</th></tr>
        </thead>
        <tbody>
          <tr *ngFor="let i of incidents()" class="clickable" [routerLink]="['/incidents', i.id]">
            <td>#{{ i.id }}</td>
            <td>{{ i.title }}</td>
            <td><span class="badge sev-{{ i.severity }}">{{ i.severity }}</span></td>
            <td>{{ i.status }}</td>
            <td>{{ i.related_count }}</td>
            <td>{{ (i.confidence * 100) | number:'1.0-0' }}%</td>
            <td class="muted">{{ i.created_at | date:'short' }}</td>
          </tr>
          <tr *ngIf="incidents().length === 0">
            <td colspan="7" class="muted" style="text-align:center; padding:30px">
              No incidents yet. Run <code>python backend/scripts/demo_bruteforce.py</code> to generate one.
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  `,
})
export class DashboardComponent implements OnInit {
  incidents = signal<Incident[]>([]);
  openCount = computed(() => this.incidents().filter(i => i.status === 'open').length);

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.api.listIncidents().subscribe(list => this.incidents.set(list));
  }

  count(sev: string): number {
    return this.incidents().filter(i => i.severity === sev).length;
  }
}
