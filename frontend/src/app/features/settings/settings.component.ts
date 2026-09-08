import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <h1>Settings</h1>
    <p class="page-sub">Account security.</p>

    <div class="card" style="max-width:560px">
      <h2>Multi-factor authentication (TOTP)</h2>
      <p class="muted" *ngIf="auth.user() as u">
        Status: <strong [style.color]="u.mfa_enabled ? 'var(--low)' : 'var(--muted)'">
          {{ u.mfa_enabled ? 'Enabled' : 'Disabled' }}
        </strong>
      </p>

      <!-- Enable flow -->
      <div *ngIf="!enabled()">
        <button class="btn" *ngIf="!secret()" (click)="startSetup()">Set up MFA</button>

        <div *ngIf="secret() as s" class="setup">
          <p>1. Add this secret to your authenticator app (Google Authenticator, Authy, etc.):</p>
          <div class="secret">{{ s }}</div>
          <p class="muted" style="font-size:12px; word-break:break-all">Or paste this URI: {{ otpauth() }}</p>
          <p>2. Enter the 6-digit code it shows:</p>
          <input [(ngModel)]="code" placeholder="123456" maxlength="6" style="max-width:160px" />
          <button class="btn" style="margin-left:10px" (click)="enable()">Enable</button>
        </div>
      </div>

      <!-- Disable flow -->
      <div *ngIf="enabled()">
        <p class="muted">Enter a current code to turn MFA off:</p>
        <input [(ngModel)]="code" placeholder="123456" maxlength="6" style="max-width:160px" />
        <button class="btn-ghost" style="margin-left:10px" (click)="disable()">Disable MFA</button>
      </div>

      <p class="error" *ngIf="error">{{ error }}</p>
      <p *ngIf="msg" style="color:var(--low); font-size:13px; margin-top:12px">{{ msg }}</p>
    </div>
  `,
  styles: [`
    .secret { font-family: monospace; font-size: 18px; letter-spacing: 2px;
              background: var(--panel-hi); padding: 12px; border-radius: 8px;
              text-align: center; margin: 8px 0; }
    .setup p { margin: 14px 0 6px; }
  `],
})
export class SettingsComponent {
  secret = signal<string | null>(null);
  otpauth = signal<string>('');
  code = '';
  error = '';
  msg = '';

  constructor(private api: ApiService, public auth: AuthService) {}

  enabled(): boolean { return !!this.auth.user()?.mfa_enabled; }

  startSetup(): void {
    this.error = ''; this.msg = '';
    this.api.mfaSetup().subscribe({
      next: (r) => { this.secret.set(r.secret); this.otpauth.set(r.otpauth_uri); },
      error: () => this.error = 'Could not start MFA setup.',
    });
  }

  enable(): void {
    this.error = ''; this.msg = '';
    this.api.mfaEnable(this.code).subscribe({
      next: () => { this.secret.set(null); this.code = ''; this.msg = 'MFA enabled.';
                    this.auth.loadCurrentUser().subscribe(); },
      error: (e) => this.error = e?.error?.detail ?? 'Invalid code.',
    });
  }

  disable(): void {
    this.error = ''; this.msg = '';
    this.api.mfaDisable(this.code).subscribe({
      next: () => { this.code = ''; this.msg = 'MFA disabled.';
                    this.auth.loadCurrentUser().subscribe(); },
      error: (e) => this.error = e?.error?.detail ?? 'Invalid code.',
    });
  }
}
