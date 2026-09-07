import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

import { ApiService } from '../../core/services/api.service';
import { AuditEntry } from '../../core/models';

@Component({
  selector: 'app-audit',
  standalone: true,
  imports: [CommonModule],
  template: `
    <h1>Audit Trail</h1>
    <p class="page-sub">Append-only record of every decision, approval and action.</p>

    <div class="card">
      <table>
        <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th></tr></thead>
        <tbody>
          <tr *ngFor="let a of entries()">
            <td class="muted">{{ a.timestamp | date:'medium' }}</td>
            <td>{{ a.actor }}</td>
            <td>{{ a.action }}</td>
            <td class="muted">{{ a.target }}</td>
          </tr>
          <tr *ngIf="entries().length === 0">
            <td colspan="4" class="muted" style="text-align:center; padding:30px">No audit entries yet.</td>
          </tr>
        </tbody>
      </table>
    </div>
  `,
})
export class AuditComponent implements OnInit {
  entries = signal<AuditEntry[]>([]);
  constructor(private api: ApiService) {}
  ngOnInit(): void { this.api.listAudit().subscribe(e => this.entries.set(e)); }
}
