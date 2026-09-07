import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-playbooks',
  standalone: true,
  imports: [CommonModule],
  template: `
    <h1>Response Playbooks</h1>
    <p class="page-sub">Structured, risk-classified playbooks the decision engine selects and adapts (FR-30–31).</p>
    <div class="phase-note">
      <span class="tag">Phase 5</span>
      <p>This screen is wired into navigation and routing now. Its backend and full<br>
      interactivity are delivered in Phase 5 of the build plan.</p>
    </div>
  `,
})
export class PlaybooksComponent {}
