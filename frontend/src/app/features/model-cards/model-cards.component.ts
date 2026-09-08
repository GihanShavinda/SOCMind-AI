import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

import { ApiService } from '../../core/services/api.service';

@Component({
  selector: 'app-model-cards',
  standalone: true,
  imports: [CommonModule],
  template: `
    <h1>Model Cards &amp; Calibration</h1>
    <p class="page-sub">Honest description of each AI/detection component and how confidence tracks outcomes.</p>

    <div class="card" style="margin-bottom:16px">
      <h2>Confidence calibration</h2>
      <p class="muted" style="font-size:13px; margin-top:0">{{ calibration()?.note }}</p>
      <table>
        <thead><tr><th>Confidence band</th><th>Confirmed</th><th>Dismissed</th><th>Observed precision</th></tr></thead>
        <tbody>
          <tr *ngFor="let b of calibration()?.bands || []">
            <td>{{ b.confidence_band }}</td>
            <td>{{ b.confirmed }}</td>
            <td>{{ b.dismissed }}</td>
            <td>{{ b.observed_precision === null ? '—' : (b.observed_precision * 100 | number:'1.0-0') + '%' }}</td>
          </tr>
        </tbody>
      </table>
      <p class="muted" style="font-size:12px">Total analyst feedback: {{ calibration()?.total_feedback || 0 }}</p>
    </div>

    <div class="grid grid-2">
      <div class="card" *ngFor="let c of cards()">
        <h2 style="margin-bottom:6px">{{ c.component }}</h2>
        <div class="row"><span class="k">Method</span><span>{{ c.method }}</span></div>
        <div class="row"><span class="k">Inputs</span><span>{{ c.inputs }}</span></div>
        <div class="row"><span class="k">Limits</span><span>{{ c.limits }}</span></div>
        <div class="row"><span class="k">Failure modes</span><span>{{ c.failure_modes }}</span></div>
        <div class="row"><span class="k">Confidence basis</span><span>{{ c.confidence_basis }}</span></div>
      </div>
    </div>
  `,
  styles: [`
    .row { display: grid; grid-template-columns: 130px 1fr; gap: 10px; padding: 5px 0;
           border-top: 1px solid var(--border); font-size: 13px; }
    .row:first-of-type { border-top: 0; }
    .k { color: var(--muted); font-size: 12px; }
  `],
})
export class ModelCardsComponent implements OnInit {
  cards = signal<any[]>([]);
  calibration = signal<any | null>(null);
  constructor(private api: ApiService) {}
  ngOnInit(): void {
    this.api.modelCards().subscribe(c => this.cards.set(c));
    this.api.calibration().subscribe(c => this.calibration.set(c));
  }
}
