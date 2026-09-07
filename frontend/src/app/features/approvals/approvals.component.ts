import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-approvals',
  standalone: true,
  imports: [CommonModule],
  template: `
    <h1>Approvals</h1>
    <p class="page-sub">Human-in-the-loop queue for high-impact actions requiring sign-off (FR-32–34).</p>
    <div class="phase-note">
      <span class="tag">Phase 5</span>
      <p>This screen is wired into navigation and routing now. Its backend and full<br>
      interactivity are delivered in Phase 5 of the build plan.</p>
    </div>
  `,
})
export class ApprovalsComponent {}
