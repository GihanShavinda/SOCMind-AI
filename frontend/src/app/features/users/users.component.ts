import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { ApiService } from '../../core/services/api.service';

@Component({
  selector: 'app-users',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <h1>Users</h1>
    <p class="page-sub">Administrators create and manage analyst and viewer accounts.</p>

    <div class="grid grid-2">
      <div class="card">
        <h2>Accounts</h2>
        <table>
          <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Active</th></tr></thead>
          <tbody>
            <tr *ngFor="let u of users()">
              <td>{{ u.name }}</td>
              <td class="muted">{{ u.email }}</td>
              <td>
                <select [ngModel]="u.role" (ngModelChange)="changeRole(u, $event)" style="max-width:150px">
                  <option>Administrator</option><option>SOC Analyst</option><option>Viewer</option>
                </select>
              </td>
              <td>
                <button class="toggle" [class.on]="u.is_active" (click)="toggleActive(u)">
                  {{ u.is_active ? 'Active' : 'Disabled' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <h2>Create user</h2>
        <label>Name</label>
        <input [(ngModel)]="form.name" placeholder="Jane Analyst" />
        <label>Email</label>
        <input [(ngModel)]="form.email" type="email" placeholder="jane@socmind.io" />
        <label>Temporary password</label>
        <input [(ngModel)]="form.password" type="text" placeholder="At least 8 chars" />
        <label>Role</label>
        <select [(ngModel)]="form.role">
          <option>SOC Analyst</option><option>Viewer</option><option>Administrator</option>
        </select>
        <button class="btn" style="width:100%; margin-top:18px" (click)="create()">Add user</button>
        <p class="error" *ngIf="error">{{ error }}</p>
        <p *ngIf="msg" style="color:var(--low); font-size:13px; margin-top:10px">{{ msg }}</p>
      </div>
    </div>
  `,
  styles: [`
    .toggle { background: var(--panel-hi); border: 1px solid var(--border); color: var(--muted);
              border-radius: 999px; padding: 3px 12px; font-size: 12px; }
    .toggle.on { background: rgba(63,185,80,.15); color: var(--low); border-color: var(--low); }
  `],
})
export class UsersComponent implements OnInit {
  users = signal<any[]>([]);
  error = ''; msg = '';
  form = { name: '', email: '', password: '', role: 'SOC Analyst' };

  constructor(private api: ApiService) {}
  ngOnInit(): void { this.load(); }
  load(): void { this.api.listUsers().subscribe(u => this.users.set(u)); }

  create(): void {
    this.error = ''; this.msg = '';
    this.api.createUser(this.form).subscribe({
      next: () => { this.msg = `Created ${this.form.email}`;
                    this.form = { name: '', email: '', password: '', role: 'SOC Analyst' }; this.load(); },
      error: (e) => this.error = e?.error?.detail ?? 'Could not create user.',
    });
  }
  changeRole(u: any, role: string): void {
    this.api.updateUser(u.id, { role }).subscribe({ next: () => this.load() });
  }
  toggleActive(u: any): void {
    this.api.updateUser(u.id, { is_active: !u.is_active }).subscribe({ next: () => this.load() });
  }
}
