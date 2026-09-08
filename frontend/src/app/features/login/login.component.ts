import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';

import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="wrap">
      <div class="card login">
        <div class="brand">
          <span class="logo">◈</span>
          <div>
            <div class="name">SOCMind AI</div>
            <div class="sub">Security Operations Console</div>
          </div>
        </div>

        <label>Email</label>
        <input [(ngModel)]="email" type="email" placeholder="admin@socmind.io" (keyup.enter)="submit()" />

        <label>Password</label>
        <input [(ngModel)]="password" type="password" placeholder="••••••••" (keyup.enter)="submit()" />

        <div *ngIf="mfaRequired">
          <label>MFA code</label>
          <input [(ngModel)]="otp" placeholder="123456" maxlength="6" (keyup.enter)="submit()" />
        </div>

        <button class="btn" style="width:100%; margin-top:22px" [disabled]="loading" (click)="submit()">
          {{ loading ? 'Signing in…' : 'Sign in' }}
        </button>

        <p class="error" *ngIf="error">{{ error }}</p>
        <p class="hint muted">Default lab admin: admin&#64;socmind.io / ChangeMe123!</p>
      </div>
    </div>
  `,
  styles: [`
    .wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .login { width: 360px; }
    .brand { display: flex; gap: 12px; align-items: center; margin-bottom: 22px; }
    .logo { font-size: 30px; color: var(--accent); }
    .name { font-weight: 700; font-size: 18px; }
    .sub { font-size: 12px; color: var(--muted); }
    .hint { font-size: 11px; text-align: center; margin-top: 16px; }
  `],
})
export class LoginComponent {
  email = 'admin@socmind.io';
  password = 'ChangeMe123!';
  otp = '';
  mfaRequired = false;
  loading = false;
  error = '';

  constructor(private auth: AuthService, private router: Router) {}

  submit(): void {
    this.error = '';
    this.loading = true;
    this.auth.login(this.email, this.password, this.otp || undefined).subscribe({
      next: () => {
        this.auth.loadCurrentUser().subscribe({
          next: () => { this.loading = false; this.router.navigate(['/dashboard']); },
          error: () => { this.loading = false; this.router.navigate(['/dashboard']); },
        });
      },
      error: (err) => {
        this.loading = false;
        const detail = err?.error?.detail ?? '';
        if (detail === 'MFA code required' || detail === 'Invalid MFA code') {
          this.mfaRequired = true;
          this.error = detail === 'Invalid MFA code' ? 'Invalid MFA code — try again.' : 'Enter your MFA code.';
        } else {
          this.error = err?.status === 401
            ? 'Incorrect email or password.'
            : 'Could not reach the backend. Is it running on :8000?';
        }
      },
    });
  }
}
