import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';

import { ApiService } from '../../core/services/api.service';

@Component({
  selector: 'app-forgot-password',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="wrap">
      <div class="card box">
        <h2>Reset your password</h2>
        <p class="muted" style="font-size:13px">Enter your email and we'll send a reset link.</p>
        <label>Email</label>
        <input [(ngModel)]="email" type="email" placeholder="you@socmind.io" (keyup.enter)="submit()" />
        <button class="btn" style="width:100%; margin-top:18px" (click)="submit()">Send reset link</button>

        <p *ngIf="sent" style="color:var(--low); font-size:13px; margin-top:14px">{{ message }}</p>
        <!-- Dev/lab mode: the reset link is shown here since email is offline -->
        <div *ngIf="devLink" class="devlink">
          <p class="muted" style="font-size:12px">Dev mode — open this link to reset:</p>
          <a [routerLink]="'/reset-password'" [queryParams]="{ token: devToken }">{{ devLink }}</a>
        </div>

        <p style="margin-top:16px"><a routerLink="/login" class="muted">← Back to sign in</a></p>
      </div>
    </div>
  `,
  styles: [`
    .wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .box { width: 380px; }
    a { color: var(--accent); text-decoration: none; }
    .devlink { margin-top: 14px; padding: 12px; background: var(--panel-hi); border-radius: 8px; word-break: break-all; }
  `],
})
export class ForgotPasswordComponent {
  email = '';
  sent = false;
  message = '';
  devLink: string | null = null;
  devToken = '';

  constructor(private api: ApiService) {}

  submit(): void {
    this.api.forgotPassword(this.email).subscribe({
      next: (r) => {
        this.sent = true; this.message = r.message;
        this.devLink = r.dev_reset_link;
        if (r.dev_reset_link) this.devToken = r.dev_reset_link.split('token=')[1];
      },
    });
  }
}
