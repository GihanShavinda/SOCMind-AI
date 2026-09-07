import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-decision-panel',
  standalone: true,
  imports: [CommonModule],
  template: `
    <h1>Explainable Decision Panel</h1>
    <p class="page-sub">Concrete evidence behind each severity and automation decision (FR-37).</p>
    <div class="phase-note">
      <span class="tag">Phase 5</span>
      <p>This screen is wired into navigation and routing now. Its backend and full<br>
      interactivity are delivered in Phase 5 of the build plan.</p>
    </div>
  `,
})
export class DecisionPanelComponent {}
