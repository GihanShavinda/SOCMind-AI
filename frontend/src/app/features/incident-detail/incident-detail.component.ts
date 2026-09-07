import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';

import { ApiService } from '../../core/services/api.service';
import { Incident, Event, AttackStep } from '../../core/models';

@Component({
  selector: 'app-incident-detail',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <a routerLink="/incidents" class="muted" style="text-decoration:none">← Back to incidents</a>

    <ng-container *ngIf="incident() as i">
      <div style="display:flex; align-items:center; gap:14px; margin:14px 0 4px">
        <h1 style="margin:0">{{ i.title }}</h1>
        <span class="badge sev-{{ i.severity }}">{{ i.severity }}</span>
      </div>
      <p class="page-sub">Incident #{{ i.id }} · {{ i.status }} · confidence {{ (i.confidence*100)|number:'1.0-0' }}%</p>

      <div class="grid grid-2">
        <!-- Attack story (FR-16) + MITRE (FR-19) -->
        <div style="display:flex; flex-direction:column; gap:16px">
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
            <ng-template #noStory>
              <p class="muted">No reconstructed steps for this incident.</p>
            </ng-template>
          </div>

          <div class="card">
            <h2>AI guidance &amp; recommended steps</h2>
            <div class="phase-note" style="padding:24px">
              <span class="tag">Phase 4</span>
              <p>Grounded AI investigation assistant and safe command recommendations (FR-21–29).</p>
            </div>
          </div>
        </div>

        <!-- Evidence timeline -->
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
    .mitre {
      background: var(--panel-hi); color: var(--accent);
      padding: 1px 8px; border-radius: 999px; font-size: 11px;
    }
  `],
})
export class IncidentDetailComponent implements OnInit {
  incident = signal<Incident | null>(null);
  events = signal<Event[]>([]);
  story = signal<AttackStep[]>([]);

  constructor(private route: ActivatedRoute, private api: ApiService) {}

  ngOnInit(): void {
    const id = Number(this.route.snapshot.paramMap.get('id'));
    this.api.getIncident(id).subscribe(i => this.incident.set(i));
    this.api.incidentEvents(id).subscribe(ev => this.events.set(ev));
    this.api.incidentStory(id).subscribe(s => this.story.set(s));
  }
}
