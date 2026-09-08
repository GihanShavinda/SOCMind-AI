import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet, RouterLink, RouterLinkActive, Router } from '@angular/router';

import { AuthService } from '../core/services/auth.service';

@Component({
  selector: 'app-shell',
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <div class="layout">
      <aside class="sidebar">
        <div class="brand">
          <span class="logo">◈</span>
          <div>
            <div class="brand-name">SOCMind AI</div>
            <div class="brand-sub">Detect · Explain · Respond</div>
          </div>
        </div>

        <nav>
          <div class="nav-group">Operations</div>
          <a routerLink="/dashboard" routerLinkActive="active">Dashboard</a>
          <a routerLink="/incidents" routerLinkActive="active">Incidents</a>
          <a routerLink="/assets" routerLinkActive="active">Assets</a>

          <div class="nav-group">Analysis</div>
          <a routerLink="/mitre" routerLinkActive="active">MITRE ATT&amp;CK</a>
          <a routerLink="/hunting" routerLinkActive="active">Threat Hunting</a>
          <a routerLink="/decision" routerLinkActive="active">Decision Panel</a>
          <a routerLink="/model-cards" routerLinkActive="active">Model Cards</a>

          <div class="nav-group">Response</div>
          <a routerLink="/playbooks" routerLinkActive="active">Playbooks</a>
          <a routerLink="/approvals" routerLinkActive="active">Approvals</a>

          <div class="nav-group">Records</div>
          <a routerLink="/audit" routerLinkActive="active">Audit Trail</a>
          <a routerLink="/reports" routerLinkActive="active">Reports</a>
          <a *ngIf="auth.hasRole('Administrator')" routerLink="/users" routerLinkActive="active">Users</a>
        </nav>
      </aside>

      <div class="main">
        <header class="topbar">
          <div class="spacer"></div>
          <div class="user" *ngIf="auth.user() as u">
            <div class="user-meta">
              <div class="user-name">{{ u.name }}</div>
              <div class="user-role">{{ u.role }}</div>
            </div>
            <a routerLink="/settings" class="btn-ghost" style="text-decoration:none">Settings</a>
            <button class="btn-ghost" (click)="logout()">Sign out</button>
          </div>
        </header>

        <main class="content">
          <router-outlet></router-outlet>
        </main>
      </div>
    </div>
  `,
  styles: [`
    .layout { display: flex; min-height: 100vh; }
    .sidebar {
      width: 240px; background: var(--panel); border-right: 1px solid var(--border);
      display: flex; flex-direction: column; padding: 20px 0;
    }
    .brand { display: flex; gap: 12px; align-items: center; padding: 0 20px 24px; }
    .logo { font-size: 26px; color: var(--accent); }
    .brand-name { font-weight: 700; letter-spacing: .3px; }
    .brand-sub { font-size: 11px; color: var(--muted); }
    nav { display: flex; flex-direction: column; }
    .nav-group {
      font-size: 11px; text-transform: uppercase; letter-spacing: .08em;
      color: var(--muted); padding: 16px 20px 6px;
    }
    nav a {
      padding: 9px 20px; color: var(--text); text-decoration: none; font-size: 14px;
      border-left: 3px solid transparent;
    }
    nav a:hover { background: var(--panel-hi); }
    nav a.active { border-left-color: var(--accent); background: var(--panel-hi); color: var(--accent); }
    .main { flex: 1; display: flex; flex-direction: column; }
    .topbar {
      height: 60px; border-bottom: 1px solid var(--border); display: flex;
      align-items: center; padding: 0 24px; background: var(--panel);
    }
    .spacer { flex: 1; }
    .user { display: flex; align-items: center; gap: 14px; }
    .user-meta { text-align: right; }
    .user-name { font-size: 13px; font-weight: 600; }
    .user-role { font-size: 11px; color: var(--muted); }
    .content { padding: 28px; flex: 1; }
  `],
})
export class ShellComponent implements OnInit {
  constructor(public auth: AuthService, private router: Router) {}

  ngOnInit(): void {
    // Hydrate the current user on refresh if a token exists.
    if (this.auth.accessToken && !this.auth.user()) {
      this.auth.loadCurrentUser().subscribe({ error: () => this.logout() });
    }
  }

  logout(): void {
    this.auth.logout();
    this.router.navigate(['/login']);
  }
}
