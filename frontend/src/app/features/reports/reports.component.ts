import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

import { ApiService } from '../../core/services/api.service';
import { Incident } from '../../core/models';

@Component({
  selector: 'app-reports',
  standalone: true,
  imports: [CommonModule],
  template: `
    <h1>Reports</h1>
    <p class="page-sub">Generate a full incident case report and export it as PDF, CSV or JSON.</p>

    <div class="card">
      <table>
        <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Created</th><th style="text-align:right">Export</th></tr></thead>
        <tbody>
          <tr *ngFor="let i of incidents()">
            <td>#{{ i.id }}</td>
            <td>{{ i.title }}</td>
            <td><span class="badge sev-{{ i.severity }}">{{ i.severity }}</span></td>
            <td class="muted">{{ i.created_at | date:'medium' }}</td>
            <td style="text-align:right; white-space:nowrap">
              <button class="btn-ghost sm" (click)="api.downloadReport(i.id, 'pdf')">PDF</button>
              <button class="btn-ghost sm" (click)="api.downloadReport(i.id, 'csv')">CSV</button>
              <button class="btn-ghost sm" (click)="api.downloadReportJson(i.id)">JSON</button>
            </td>
          </tr>
          <tr *ngIf="incidents().length === 0">
            <td colspan="5" class="muted" style="text-align:center; padding:30px">No incidents to report on yet.</td>
          </tr>
        </tbody>
      </table>
    </div>
  `,
  styles: [`
    .btn-ghost.sm { padding: 4px 12px; font-size: 12px; margin-left: 6px; }
  `],
})
export class ReportsComponent implements OnInit {
  incidents = signal<Incident[]>([]);
  constructor(public api: ApiService) {}
  ngOnInit(): void {
    this.api.listIncidents().subscribe(i => this.incidents.set(i));
  }
}
