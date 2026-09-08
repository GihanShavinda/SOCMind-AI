import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { ApiService } from '../../core/services/api.service';

@Component({
  selector: 'app-hunting',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <h1>Threat Hunting</h1>
    <p class="page-sub">Query normalised events, spot clusters, and promote a hunt into a detection rule.</p>

    <div class="card" style="margin-bottom:16px">
      <h2>Hunt query</h2>
      <div class="filters">
        <select [(ngModel)]="field">
          <option value="event_type">event_type</option>
          <option value="source_ip">source_ip</option>
          <option value="username">username</option>
          <option value="severity">severity</option>
        </select>
        <select [(ngModel)]="op">
          <option value="eq">equals</option>
          <option value="contains">contains</option>
        </select>
        <input [(ngModel)]="value" placeholder="value e.g. authentication_failure" (keyup.enter)="run()" />
        <button class="btn" (click)="run()">Run hunt</button>
      </div>
    </div>

    <div class="card" *ngIf="result() as r" style="margin-bottom:16px">
      <div style="display:flex; align-items:center; gap:12px">
        <h2 style="margin:0">Results — {{ r.match_count }} events</h2>
        <span style="flex:1"></span>
        <input [(ngModel)]="ruleName" placeholder="Rule name" style="max-width:200px" />
        <button class="btn-ghost sm" (click)="promote()" [disabled]="!ruleName">Promote to rule</button>
      </div>

      <div class="clusters" *ngIf="r.top_source_ips?.length">
        <span class="muted" style="font-size:12px">Top sources:</span>
        <span class="chip" *ngFor="let ip of r.top_source_ips">{{ ip[0] }} ({{ ip[1] }})</span>
      </div>

      <table style="margin-top:12px">
        <thead><tr><th>Time</th><th>Type</th><th>Source</th><th>User</th><th>Sev</th></tr></thead>
        <tbody>
          <tr *ngFor="let e of r.events">
            <td class="muted">{{ e.timestamp | date:'short' }}</td>
            <td>{{ e.event_type }}</td>
            <td>{{ e.source_ip || '—' }}</td>
            <td>{{ e.username || '—' }}</td>
            <td><span class="badge sev-{{ e.severity }}">{{ e.severity }}</span></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card" *ngIf="ruleYaml()">
      <h2>Generated detection rule</h2>
      <p class="muted" style="font-size:12px">Save to <code>detection-rules/</code> and restart to activate.</p>
      <pre>{{ ruleYaml() }}</pre>
    </div>
  `,
  styles: [`
    .filters { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
    .filters select, .filters input { max-width: 240px; }
    .clusters { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 12px; }
    .chip { background: var(--panel-hi); border-radius: 999px; padding: 3px 10px; font-size: 12px; }
    .btn-ghost.sm { padding: 6px 12px; font-size: 13px; }
    pre { background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
          padding: 14px; overflow-x: auto; font-size: 12px; color: var(--low); }
  `],
})
export class HuntingComponent {
  field = 'event_type';
  op = 'eq';
  value = 'authentication_failure';
  ruleName = '';
  result = signal<any | null>(null);
  ruleYaml = signal<string>('');

  constructor(private api: ApiService) {}

  private filters() { return [{ field: this.field, op: this.op, value: this.value }]; }

  run(): void {
    this.api.runHunt(this.filters(), 999999).subscribe(r => this.result.set(r));
  }
  promote(): void {
    this.api.promoteHunt(this.ruleName, this.filters()).subscribe(r => this.ruleYaml.set(r.rule_yaml));
  }
}
