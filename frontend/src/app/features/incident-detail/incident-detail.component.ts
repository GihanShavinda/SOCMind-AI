import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';

import { ApiService } from '../../core/services/api.service';
import { AttackGraphComponent } from '../../shared/attack-graph.component';
import { Incident, Event, AttackStep, IncidentGraph, KillChainPhase, AssistantAnalysis, ResponseAction } from '../../core/models';

@Component({
  selector: 'app-incident-detail',
  standalone: true,
  imports: [CommonModule, RouterLink, AttackGraphComponent],
  template: `
    <a routerLink="/incidents" class="muted" style="text-decoration:none">← Back to incidents</a>

    <ng-container *ngIf="incident() as i">
      <div style="display:flex; align-items:center; gap:14px; margin:14px 0 4px">
        <h1 style="margin:0">{{ i.title }}</h1>
        <span class="badge sev-{{ i.severity }}">{{ i.severity }}</span>
        <span style="flex:1"></span>
        <button class="btn-ghost sm" (click)="api.downloadReport(i.id, 'pdf')">PDF</button>
        <button class="btn-ghost sm" (click)="api.downloadReport(i.id, 'csv')">CSV</button>
        <button class="btn-ghost sm" (click)="api.downloadReportJson(i.id)">JSON</button>
        <button class="btn-ghost sm" (click)="api.downloadCasePackage(i.id)" title="Tamper-evident forensic package">Case pkg</button>
      </div>
      <p class="page-sub">Incident #{{ i.id }} · {{ i.status }} · confidence {{ (i.confidence*100)|number:'1.0-0' }}%</p>

      <!-- Triage + SLA + analyst feedback (Phase 7) -->
      <div class="card" style="margin-bottom:16px">
        <div class="triage-row">
          <div class="metric">
            <div class="m-val">{{ i.triage_score | number:'1.0-0' }}</div>
            <div class="m-lbl">Triage score</div>
          </div>
          <div class="metric">
            <div class="m-val" [style.color]="i.sla_breached ? 'var(--high)' : 'var(--low)'">
              {{ i.sla_breached ? 'BREACHED' : 'On track' }}
            </div>
            <div class="m-lbl">SLA {{ i.sla_due_at ? ('· due ' + (i.sla_due_at | date:'short')) : '' }}</div>
          </div>
          <div style="flex:1"></div>
          <div class="feedback">
            <span class="muted" style="font-size:12px; margin-right:8px">Analyst verdict:</span>
            <button class="btn-ghost sm" (click)="feedback('confirm')">Confirm</button>
            <button class="btn-ghost sm" (click)="feedback('dismiss')">Dismiss (FP)</button>
            <button class="btn-ghost sm" (click)="feedback('correct')">Correct</button>
          </div>
        </div>
        <p *ngIf="feedbackMsg" style="color:var(--low); font-size:12px; margin:8px 0 0">{{ feedbackMsg }}</p>
      </div>

      <!-- Kill-chain strip (FR-20) -->
      <div class="card" style="margin-bottom:16px">
        <h2>Kill chain</h2>
        <div class="killchain">
          <div class="kc-phase" *ngFor="let p of killchain(); let last = last"
               [class.observed]="p.observed">
            <div class="kc-name">{{ p.phase }}</div>
            <div class="kc-techs">
              <span *ngFor="let t of p.techniques" class="mitre">{{ t.id }}</span>
              <span *ngIf="!p.observed" class="muted" style="font-size:11px">—</span>
            </div>
            <div class="kc-arrow" *ngIf="!last">→</div>
          </div>
        </div>
      </div>

      <!-- Attack graph (FR-17) -->
      <div class="card" style="margin-bottom:16px">
        <h2>Attack graph</h2>
        <app-attack-graph [graph]="graph()"></app-attack-graph>
      </div>

      <div class="grid grid-2">
        <!-- Attack story (FR-16) + MITRE tags (FR-19) -->
        <div class="card">
          <h2>Attack story</h2>
          <div class="timeline" *ngIf="story().length; else noStory">
            <div class="step" *ngFor="let s of story()">
              <div class="dot"></div>
              <div class="step-body">
                <div class="step-desc">{{ s.description }}</div>
                <div class="step-meta">
                  <span *ngIf="s.timestamp" class="muted">{{ s.timestamp | date:'HH:mm:ss' }}</span>
                  <span *ngIf="s.mitre_id" class="mitre">{{ s.mitre_id }} · {{ s.mitre_name }}</span>
                </div>
              </div>
            </div>
          </div>
          <ng-template #noStory><p class="muted">No reconstructed steps.</p></ng-template>
        </div>

        <!-- Evidence -->
        <div class="card">
          <h2>Evidence ({{ events().length }} events)</h2>
          <table>
            <thead><tr><th>Time</th><th>Type</th><th>Source</th><th>User</th><th>Sev</th></tr></thead>
            <tbody>
              <tr *ngFor="let e of events()">
                <td class="muted">{{ e.timestamp | date:'HH:mm:ss' }}</td>
                <td>{{ e.event_type }}</td>
                <td>{{ e.source_ip || '—' }}</td>
                <td>{{ e.username || '—' }}</td>
                <td><span class="badge sev-{{ e.severity }}">{{ e.severity }}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Response actions (Phase 5) -->
      <div class="card" style="margin-top:16px">
        <h2>Response actions</h2>
        <p class="muted" style="margin-top:0; font-size:13px">
          Propose a controlled action. The decision engine decides automate vs approval based on
          risk, asset criticality, confidence and impact — nothing destructive ever auto-runs.
        </p>
        <div class="action-buttons">
          <button class="btn-ghost" *ngFor="let t of actionTypes" (click)="propose(t.type)">
            {{ t.label }}
          </button>
        </div>

        <table *ngIf="actions().length" style="margin-top:16px">
          <thead><tr><th>Action</th><th>Risk</th><th>Status</th><th>By</th><th></th></tr></thead>
          <tbody>
            <tr *ngFor="let a of actions()">
              <td>{{ a.description }}</td>
              <td><span class="badge risk-{{ a.risk_level }}">{{ a.risk_level }}</span></td>
              <td><span class="status s-{{ a.status }}">{{ a.status.replace('_', ' ') }}</span></td>
              <td class="muted">{{ a.performed_by || '—' }}</td>
              <td style="text-align:right">
                <button *ngIf="a.status === 'pending_approval'" class="btn-ghost sm" (click)="approve(a)">Approve</button>
                <button *ngIf="a.status === 'executed' && a.reversible" class="btn-ghost sm" (click)="rollback(a)">Undo</button>
              </td>
            </tr>
          </tbody>
        </table>
        <p class="error" *ngIf="actionError">{{ actionError }}</p>
      </div>

      <div class="card" style="margin-top:16px" *ngIf="analysis() as a">
        <div style="display:flex; align-items:center; gap:10px">
          <h2 style="margin:0">AI investigation assistant</h2>
          <span class="src-badge" [class.llm]="a.source === 'llm'">
            {{ a.source === 'llm' ? (a.model || 'LLM') : 'rule-based' }}
          </span>
        </div>

        <div class="ai-block">
          <div class="ai-label">What happened</div>
          <p>{{ a.what_happened }}</p>
        </div>
        <div class="ai-block">
          <div class="ai-label">Why it's suspicious</div>
          <p>{{ a.why_suspicious }}</p>
        </div>

        <div class="ai-block">
          <div class="ai-label">Prioritised next steps</div>
          <div class="step-card" *ngFor="let s of a.next_steps">
            <div class="step-top">
              <span class="step-n">{{ s.order }}</span>
              <span class="step-action">{{ s.action }}</span>
              <span *ngIf="s.command" class="badge risk-{{ s.command.risk }}">{{ s.command.risk }}</span>
            </div>
            <p class="step-why muted">{{ s.rationale }}</p>
            <div class="cmd" *ngIf="s.command">
              <code>{{ s.command.command }}</code>
              <button class="copy" (click)="copy(s.command!.command)">copy</button>
            </div>
          </div>
        </div>

        <div class="ai-block" *ngIf="a.kb_note">
          <div class="ai-label">Knowledge base</div>
          <p>{{ a.kb_note }}</p>
          <div class="kb-list" *ngIf="a.similar_incidents?.length">
            <a class="kb-item" *ngFor="let s of a.similar_incidents" [routerLink]="['/incidents', s.id]">
              #{{ s.id }} {{ s.title }}
              <span class="muted" style="font-size:11px">— {{ s.resolution }}</span>
            </a>
          </div>
        </div>

        <div class="ai-block">
          <div class="ai-label">Grounded on</div>
          <div class="grounding">
            <span class="chip" *ngFor="let g of a.grounded_on">{{ g }}</span>
          </div>
        </div>

        <p class="muted safe-note">
          Commands are drawn only from the approved catalog and risk-classified.
          Nothing runs automatically — execution &amp; approval arrive in Phase 5.
        </p>
      </div>
    </ng-container>
  `,
  styles: [`
    .timeline { display: flex; flex-direction: column; }
    .step { display: flex; gap: 12px; padding-bottom: 16px; position: relative; }
    .step:not(:last-child)::before {
      content: ''; position: absolute; left: 5px; top: 14px; bottom: -2px;
      width: 2px; background: var(--border);
    }
    .dot { width: 12px; height: 12px; border-radius: 50%; background: var(--accent);
           margin-top: 3px; flex-shrink: 0; z-index: 1; }
    .step-desc { font-size: 14px; }
    .step-meta { display: flex; gap: 12px; margin-top: 4px; font-size: 12px; }
    .mitre { background: var(--panel-hi); color: var(--accent);
             padding: 1px 8px; border-radius: 999px; font-size: 11px; margin-right: 4px; }

    .killchain { display: flex; align-items: stretch; gap: 0; overflow-x: auto; }
    .kc-phase { flex: 1; min-width: 120px; padding: 10px 8px; text-align: center;
                border-radius: 8px; position: relative; opacity: .45; }
    .kc-phase.observed { opacity: 1; background: var(--panel-hi); }
    .kc-name { font-size: 12px; font-weight: 600; margin-bottom: 6px; }
    .kc-techs { display: flex; flex-direction: column; gap: 3px; align-items: center; }
    .kc-arrow { position: absolute; right: -7px; top: 50%; transform: translateY(-50%);
                color: var(--border); font-size: 14px; }

    .src-badge { font-size: 11px; padding: 2px 10px; border-radius: 999px;
                 background: var(--panel-hi); color: var(--muted); text-transform: uppercase;
                 letter-spacing: .05em; }
    .src-badge.llm { color: var(--accent); }
    .ai-block { margin-top: 16px; }
    .ai-label { font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
                color: var(--muted); margin-bottom: 6px; }
    .step-card { background: var(--panel-hi); border-radius: 8px; padding: 12px; margin-bottom: 10px; }
    .step-top { display: flex; align-items: center; gap: 10px; }
    .step-n { width: 20px; height: 20px; border-radius: 50%; background: var(--bg);
              color: var(--accent); display: flex; align-items: center; justify-content: center;
              font-size: 11px; font-weight: 700; flex-shrink: 0; }
    .step-action { font-weight: 600; flex: 1; }
    .step-why { font-size: 13px; margin: 6px 0 8px; }
    .cmd { display: flex; align-items: center; gap: 8px; background: var(--bg);
           border-radius: 6px; padding: 8px 10px; }
    .cmd code { color: var(--low); font-size: 12px; flex: 1; word-break: break-all; }
    .copy { background: transparent; border: 1px solid var(--border); color: var(--muted);
            border-radius: 5px; padding: 3px 10px; font-size: 11px; }
    .copy:hover { color: var(--text); }
    .grounding { display: flex; flex-wrap: wrap; gap: 6px; }
    .chip { background: var(--panel-hi); border-radius: 999px; padding: 3px 10px; font-size: 11px; color: var(--muted); }
    .risk-Low { background: rgba(63,185,80,.15); color: var(--low); }
    .risk-Medium { background: rgba(210,153,34,.15); color: var(--medium); }
    .risk-High { background: rgba(248,81,73,.15); color: var(--high); }
    .risk-Restricted { background: rgba(255,107,157,.15); color: var(--critical); }
    .safe-note { font-size: 11px; margin-top: 14px; }
    .action-buttons { display: flex; flex-wrap: wrap; gap: 8px; }
    .btn-ghost.sm { padding: 4px 10px; font-size: 12px; }
    .triage-row { display: flex; align-items: center; gap: 24px; }
    .triage-row .metric { text-align: center; }
    .triage-row .m-val { font-size: 22px; font-weight: 700; }
    .triage-row .m-lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
    .feedback { display: flex; align-items: center; }
    .kb-list { display: flex; flex-direction: column; gap: 6px; margin-top: 8px; }
    .kb-item { background: var(--panel-hi); border-radius: 6px; padding: 8px 10px;
               text-decoration: none; color: var(--accent); font-size: 13px; }
    .btn-ghost.sm { padding: 4px 10px; font-size: 12px; }
    .status { font-size: 12px; text-transform: capitalize; }
    .s-executed { color: var(--low); }
    .s-pending_approval { color: var(--medium); }
    .s-rejected { color: var(--high); }
    .s-rolled_back { color: var(--muted); }
  `],
})
export class IncidentDetailComponent implements OnInit {
  incident = signal<Incident | null>(null);
  events = signal<Event[]>([]);
  story = signal<AttackStep[]>([]);
  graph = signal<IncidentGraph>({ nodes: [], edges: [] });
  killchain = signal<KillChainPhase[]>([]);
  analysis = signal<AssistantAnalysis | null>(null);
  actions = signal<ResponseAction[]>([]);
  actionError = '';
  feedbackMsg = '';

  actionTypes = [
    { type: 'firewall_block', label: 'Block source IP' },
    { type: 'disable_account', label: 'Disable account' },
    { type: 'stop_process', label: 'Stop process' },
    { type: 'isolate_endpoint', label: 'Isolate endpoint' },
    { type: 'create_ticket', label: 'Create ticket' },
    { type: 'send_notification', label: 'Notify analyst' },
  ];

  constructor(private route: ActivatedRoute, public api: ApiService) {}

  private id = 0;

  ngOnInit(): void {
    this.id = Number(this.route.snapshot.paramMap.get('id'));
    const id = this.id;
    this.api.getIncident(id).subscribe(i => this.incident.set(i));
    this.api.incidentEvents(id).subscribe(ev => this.events.set(ev));
    this.api.incidentStory(id).subscribe(s => this.story.set(s));
    this.api.incidentGraph(id).subscribe(g => this.graph.set(g));
    this.api.incidentKillchain(id).subscribe(k => this.killchain.set(k));
    this.api.incidentAnalysis(id).subscribe(a => this.analysis.set(a));
    this.loadActions();
  }

  loadActions(): void {
    this.api.incidentActions(this.id).subscribe(a => this.actions.set(a));
  }

  propose(type: string): void {
    this.actionError = '';
    this.api.proposeAction(this.id, type).subscribe({
      next: () => this.loadActions(),
      error: (e) => this.actionError = e?.error?.detail ?? 'Could not propose action.',
    });
  }

  approve(a: ResponseAction): void {
    this.actionError = '';
    this.api.approveAction(a.id).subscribe({
      next: () => this.loadActions(),
      error: (e) => this.actionError = e?.error?.detail ?? 'Approval failed (Administrator required for High/Restricted).',
    });
  }

  rollback(a: ResponseAction): void {
    this.api.rollbackAction(a.id).subscribe({ next: () => this.loadActions() });
  }

  copy(text: string): void {
    navigator.clipboard?.writeText(text);
  }

  feedback(verdict: string): void {
    this.feedbackMsg = '';
    this.api.incidentFeedback(this.id, verdict).subscribe({
      next: () => {
        this.feedbackMsg = `Recorded "${verdict}". Thanks — this tunes future detection.`;
        this.api.getIncident(this.id).subscribe(i => this.incident.set(i));
      },
    });
  }
}
