import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { Asset, Criticality } from '../../core/models';

@Component({
  selector: 'app-assets',
  standalone: true,
  imports: [CommonModule, FormsModule],
  styles: [`
    .toggle { background: var(--panel-hi); border: 1px solid var(--border); color: var(--muted);
              border-radius: 999px; padding: 3px 12px; font-size: 12px; }
    .toggle.on { background: rgba(63,185,80,.15); color: var(--low); border-color: var(--low); }
    .toggle:disabled { opacity: .5; cursor: not-allowed; }
  `],
  template: `
    <h1>Assets</h1>
    <p class="page-sub">Monitored endpoints and servers. Criticality feeds the automation decision engine.</p>

    <div class="grid grid-2">
      <div class="card">
        <h2>Inventory</h2>
        <table>
          <thead><tr><th>Host</th><th>OS</th><th>IP</th><th>Criticality</th><th>Agent</th><th>Auto-response</th></tr></thead>
          <tbody>
            <tr *ngFor="let a of assets()">
              <td>{{ a.hostname }}</td>
              <td class="muted">{{ a.os }}</td>
              <td class="muted">{{ a.ip }}</td>
              <td>{{ a.criticality }}</td>
              <td>
                <span class="badge" [class.sev-low]="a.agent_status==='online'" [class.sev-high]="a.agent_status!=='online'">
                  {{ a.agent_status }}
                </span>
              </td>
              <td>
                <button class="toggle" [class.on]="a.automation_enabled"
                        [disabled]="!canEdit()" (click)="toggleAuto(a)">
                  {{ a.automation_enabled ? 'Enabled' : 'Disabled' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
        <p class="muted" style="font-size:11px; margin-top:10px">
          Auto-response is opt-in per asset (FR-34). Even when enabled, only low-impact,
          reversible actions on low-criticality assets can automate; everything else needs approval.
        </p>
      </div>

      <div class="card" *ngIf="canEdit()">
        <h2>Register asset</h2>
        <label>Hostname</label>
        <input [(ngModel)]="form.hostname" placeholder="WIN10-ENDPOINT-01" />
        <label>Operating system</label>
        <input [(ngModel)]="form.os" placeholder="Windows 11" />
        <label>IP address</label>
        <input [(ngModel)]="form.ip" placeholder="192.168.56.30" />
        <label>Criticality</label>
        <select [(ngModel)]="form.criticality">
          <option>Low</option><option>Medium</option><option>High</option><option>Critical</option>
        </select>
        <button class="btn" style="width:100%; margin-top:20px" (click)="create()">Add asset</button>
        <p class="error" *ngIf="error">{{ error }}</p>
      </div>
    </div>
  `,
})
export class AssetsComponent implements OnInit {
  assets = signal<Asset[]>([]);
  error = '';
  form: Partial<Asset> = { criticality: 'Low' as Criticality, environment: 'lab' };

  constructor(private api: ApiService, private auth: AuthService) {}

  ngOnInit(): void { this.load(); }

  canEdit(): boolean { return this.auth.hasRole('Administrator', 'SOC Analyst'); }

  load(): void { this.api.listAssets().subscribe(a => this.assets.set(a)); }

  create(): void {
    this.error = '';
    this.api.createAsset(this.form).subscribe({
      next: () => { this.form = { criticality: 'Low' as Criticality, environment: 'lab' }; this.load(); },
      error: (e) => this.error = e?.error?.detail ?? 'Could not create asset.',
    });
  }

  toggleAuto(a: Asset): void {
    this.api.updateAsset(a.id, { automation_enabled: !a.automation_enabled }).subscribe({
      next: () => this.load(),
    });
  }
}
