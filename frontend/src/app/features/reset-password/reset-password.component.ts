import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';

import { ApiService } from '../../core/services/api.service';

@Component({
  selector: 'app-reset-password',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="wrap">
      <div class="card box">
        <h2>Set a new password</h2>
        <label>New password</label>
        <input [(ngModel)]="password" type="password" placeholder="At least 8 characters" (keyup.enter)="submit()" />
        <label>Confirm password</label>
        <input [(ngModel)]="confirm" type="password" placeholder="Repeat password" (keyup.enter)="submit()" />
        <button class="btn" style="width:100%; margin-top:18px" (click)="submit()">Reset password</button>
        <p class="error" *ngIf="error">{{ error }}</p>
        <p *ngIf="done" style="color:var(--low); font-size:13px; margin-top:14px">
          Password reset. <a routerLink="/login">Sign in →</a>
        </p>
      </div>
    </div>
  `,
  styles: [`
    .wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .box { width: 380px; }
    a { color: var(--accent); text-decoration: none; }
  `],
})
export class ResetPasswordComponent implements OnInit {
  token = '';
  password = '';
  confirm = '';
  error = '';
  done = false;

  constructor(private route: ActivatedRoute, private api: ApiService, private router: Router) {}

  ngOnInit(): void {
    this.token = this.route.snapshot.queryParamMap.get('token') ?? '';
    if (!this.token) this.error = 'Missing reset token.';
  }

  submit(): void {
    this.error = '';
    if (this.password.length < 8) { this.error = 'Password must be at least 8 characters.'; return; }
    if (this.password !== this.confirm) { this.error = 'Passwords do not match.'; return; }
    this.api.resetPassword(this.token, this.password).subscribe({
      next: () => { this.done = true; },
      error: (e) => this.error = e?.error?.detail ?? 'Reset failed — the link may have expired.',
    });
  }
}
