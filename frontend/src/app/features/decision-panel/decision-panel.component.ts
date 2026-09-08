import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';

import { ApiService } from '../../core/services/api.service';
import { Decision } from '../../core/models';

@Component({
  selector: 'app-decision-panel',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <h1>Explainable Decision Panel</h1>
    <p class="page-sub">Every automation decision with the four inputs and the reasoning behind it.</p>

    <div class="card" *ngFor="let d of decisions()" style="margin-bottom:12px">
      <div class="head">
        <div>
          <span class="type">{{ d.action_type }}</span>
          on <a [routerLink]="['/incidents', d.incident_id]">incident #{{ d.incident_id }}</a>
        </div>
        <span class="badge" [class.auto]="d.outcome === 'automate'" [class.appr]="d.outcome !== 'automate'">
          {{ d.outcome === 'automate' ? 'Automated' : 'Approval required' }}
        </span>
      </div>

      <div class="inputs">
        <div class="metric"><div class="m-val">{{ (d.threat_conf*100)|number:'1.0-0' }}%</div><div class="m-lbl">Threat conf.</div></div>
        <div class="metric"><div class="m-val">{{ (d.response_conf*100)|number:'1.0-0' }}%</div><div class="m-lbl">Response conf.</div></div>
        <div class="metric"><div class="m-val">{{ d.asset_crit }}</div><div class="m-lbl">Asset criticality</div></div>
        <div class="metric"><div class="m-val">{{ d.impact }}</div><div class="m-lbl">Business impact</div></div>
      </div>

      <p class="rationale">{{ d.rationale }}</p>
    </div>

    <div class="phase-note" *ngIf="decisions().length === 0">
      <p>No decisions yet. Propose a response action on an incident to generate one.</p>
    </div>
  `,
  styles: [`
    .head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
    .type { font-weight: 700; }
    a { color: var(--accent); text-decoration: none; }
    .badge.auto { background: rgba(63,185,80,.15); color: var(--low); }
    .badge.appr { background: rgba(210,153,34,.15); color: var(--medium); }
    .inputs { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 12px; }
    .metric { background: var(--panel-hi); border-radius: 8px; padding: 12px; text-align: center; }
    .m-val { font-size: 20px; font-weight: 700; }
    .m-lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; margin-top: 2px; }
    .rationale { margin: 0; color: var(--text); font-size: 13px; }
  `],
})
export class DecisionPanelComponent implements OnInit {
  decisions = signal<Decision[]>([]);
  constructor(private api: ApiService) {}
  ngOnInit(): void {
    this.api.recentDecisions().subscribe(d => this.decisions.set(d));
  }
}
