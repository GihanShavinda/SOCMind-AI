import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

import { ApiService } from '../../core/services/api.service';
import { Incident, Playbook } from '../../core/models';

@Component({
  selector: 'app-playbooks',
  standalone: true,
  imports: [CommonModule],
  template: `
    <h1>Response Playbooks</h1>
    <p class="page-sub">Structured, risk-classified response steps the decision engine selects per incident.</p>

    <div class="card" *ngIf="playbook() as pb; else empty">
      <div style="display:flex; align-items:center; gap:10px; margin-bottom:4px">
        <h2 style="margin:0">{{ pb.name }}</h2>
        <span class="mitre" *ngFor="let m of pb.mitre">{{ m }}</span>
      </div>
      <p class="muted" style="margin-top:0">Matched to incident #{{ incidentId() }} ({{ pb.attack_type }})</p>

      <table>
        <thead><tr><th>#</th><th>Action</th><th>Risk</th><th>Approval</th><th>Expected result</th></tr></thead>
        <tbody>
          <tr *ngFor="let s of pb.steps">
            <td>{{ s.order }}</td>
            <td>{{ s.action }}</td>
            <td><span class="badge risk-{{ s.risk }}">{{ s.risk }}</span></td>
            <td>{{ s.approval_required ? 'Required' : 'Auto-eligible' }}</td>
            <td class="muted">{{ s.expected_result }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <ng-template #empty>
      <div class="phase-note"><p>Select an incident to see its matched playbook. Showing the most recent incident's playbook when available.</p></div>
    </ng-template>
  `,
  styles: [`
    .mitre { background: var(--panel-hi); color: var(--accent); padding: 1px 8px; border-radius: 999px; font-size: 11px; }
    .risk-Low { background: rgba(63,185,80,.15); color: var(--low); }
    .risk-Medium { background: rgba(210,153,34,.15); color: var(--medium); }
    .risk-High { background: rgba(248,81,73,.15); color: var(--high); }
    .risk-Restricted { background: rgba(255,107,157,.15); color: var(--critical); }
  `],
})
export class PlaybooksComponent implements OnInit {
  playbook = signal<Playbook | null>(null);
  incidentId = signal<number | null>(null);
  constructor(private api: ApiService) {}
  ngOnInit(): void {
    // Show the playbook for the most recent incident as a representative example.
    this.api.listIncidents().subscribe((incs: Incident[]) => {
      if (incs.length) {
        this.incidentId.set(incs[0].id);
        this.api.incidentPlaybook(incs[0].id).subscribe(pb => this.playbook.set(pb));
      }
    });
  }
}
