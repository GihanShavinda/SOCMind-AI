import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-mitre',
  standalone: true,
  imports: [CommonModule],
  template: `
    <h1>MITRE ATT&CK</h1>
    <p class="page-sub">Techniques mapped to observed behaviour and positioned along the kill chain (FR-19–20).</p>
    <div class="phase-note">
      <span class="tag">Phase 3</span>
      <p>This screen is wired into navigation and routing now. Its backend and full<br>
      interactivity are delivered in Phase 3 of the build plan.</p>
    </div>
  `,
})
export class MitreComponent {}
