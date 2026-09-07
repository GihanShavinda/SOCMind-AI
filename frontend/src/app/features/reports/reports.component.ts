import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-reports',
  standalone: true,
  imports: [CommonModule],
  template: `
    <h1>Reports</h1>
    <p class="page-sub">Incident reports with export to PDF, CSV and JSON (FR-41–42).</p>
    <div class="phase-note">
      <span class="tag">Phase 6</span>
      <p>This screen is wired into navigation and routing now. Its backend and full<br>
      interactivity are delivered in Phase 6 of the build plan.</p>
    </div>
  `,
})
export class ReportsComponent {}
