import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';

import { ApiService } from '../../core/services/api.service';
import { ResponseAction } from '../../core/models';

@Component({
  selector: 'app-approvals',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <h1>Approvals</h1>
    <p class="page-sub">High-impact actions awaiting human sign-off before execution.</p>

    <div class="card">
      <table>
        <thead><tr><th>Action</th><th>Incident</th><th>Risk</th><th>Reversible</th><th></th></tr></thead>
        <tbody>
          <tr *ngFor="let a of pending()">
            <td>{{ a.description }}</td>
            <td><a [routerLink]="['/incidents', a.incident_id]">#{{ a.incident_id }}</a></td>
            <td><span class="badge risk-{{ a.risk_level }}">{{ a.risk_level }}</span></td>
            <td>{{ a.reversible ? 'Yes' : 'No' }}</td>
            <td style="text-align:right; white-space:nowrap">
              <button class="btn-ghost" (click)="reject(a)">Reject</button>
              <button class="btn" style="margin-left:8px" (click)="approve(a)">Approve</button>
            </td>
          </tr>
          <tr *ngIf="pending().length === 0">
            <td colspan="5" class="muted" style="text-align:center; padding:30px">
              No actions awaiting approval.
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="error" *ngIf="error">{{ error }}</p>
  `,
  styles: [`
    .risk-Low { background: rgba(63,185,80,.15); color: var(--low); }
    .risk-Medium { background: rgba(210,153,34,.15); color: var(--medium); }
    .risk-High { background: rgba(248,81,73,.15); color: var(--high); }
    .risk-Restricted { background: rgba(255,107,157,.15); color: var(--critical); }
    a { color: var(--accent); text-decoration: none; }
  `],
})
export class ApprovalsComponent implements OnInit {
  pending = signal<ResponseAction[]>([]);
  error = '';
  constructor(private api: ApiService) {}
  ngOnInit(): void { this.load(); }
  load(): void {
    this.api.listActions('pending_approval').subscribe(a => this.pending.set(a));
  }
  approve(a: ResponseAction): void {
    this.error = '';
    this.api.approveAction(a.id).subscribe({
      next: () => this.load(),
      error: (e) => this.error = e?.error?.detail ?? 'Approval failed (Administrator required for High/Restricted).',
    });
  }
  reject(a: ResponseAction): void {
    this.api.rejectAction(a.id).subscribe({ next: () => this.load() });
  }
}
