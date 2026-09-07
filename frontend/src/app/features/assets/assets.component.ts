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
  template: `
    <h1>Assets</h1>
    <p class="page-sub">Monitored endpoints and servers. Criticality feeds the automation decision engine.</p>

    <div class="grid grid-2">
      <div class="card">
        <h2>Inventory</h2>
        <table>
          <thead><tr><th>Host</th><th>OS</th><th>IP</th><th>Criticality</th><th>Agent</th></tr></thead>
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
            </tr>
          </tbody>
        </table>
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
}
