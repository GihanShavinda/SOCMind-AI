import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

import { ApiService } from '../../core/services/api.service';
import { KillChainPhase } from '../../core/models';

@Component({
  selector: 'app-mitre',
  standalone: true,
  imports: [CommonModule],
  template: `
    <h1>MITRE ATT&CK</h1>
    <p class="page-sub">Techniques observed across all incidents, positioned along the attack lifecycle.</p>

    <div class="chain">
      <div class="phase card" *ngFor="let p of phases()" [class.observed]="p.observed">
        <div class="phase-head">
          <span class="phase-order">{{ p.order + 1 }}</span>
          <span class="phase-name">{{ p.phase }}</span>
        </div>
        <div class="techs" *ngIf="p.techniques.length; else none">
          <div class="tech" *ngFor="let t of p.techniques">
            <div class="tech-id">{{ t.id }}</div>
            <div class="tech-name">{{ t.name }}</div>
          </div>
        </div>
        <ng-template #none><div class="muted empty">Not observed</div></ng-template>
      </div>
    </div>
  `,
  styles: [`
    .chain { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; }
    .phase { padding: 14px; opacity: .5; }
    .phase.observed { opacity: 1; border-color: var(--accent); }
    .phase-head { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
    .phase-order {
      width: 22px; height: 22px; border-radius: 50%; background: var(--panel-hi);
      color: var(--accent); display: flex; align-items: center; justify-content: center;
      font-size: 12px; font-weight: 700; flex-shrink: 0;
    }
    .phase-name { font-size: 13px; font-weight: 600; }
    .techs { display: flex; flex-direction: column; gap: 8px; }
    .tech { background: var(--panel-hi); border-radius: 6px; padding: 8px; }
    .tech-id { color: var(--accent); font-size: 12px; font-weight: 700; }
    .tech-name { font-size: 12px; color: var(--muted); margin-top: 2px; }
    .empty { font-size: 12px; }
    @media (max-width: 1100px) { .chain { grid-template-columns: repeat(3, 1fr); } }
  `],
})
export class MitreComponent implements OnInit {
  phases = signal<KillChainPhase[]>([]);
  constructor(private api: ApiService) {}
  ngOnInit(): void {
    this.api.mitreKillchain().subscribe(p => this.phases.set(p));
  }
}
