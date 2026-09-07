import { Component, Input, computed, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

import { IncidentGraph, GraphNode, GraphEdge } from '../core/models';

interface Positioned extends GraphNode { x: number; y: number; }
interface DrawnEdge { x1: number; y1: number; x2: number; y2: number; label: string; mx: number; my: number; }

// Left-to-right columns by node type = the attack progression.
const COLUMN_ORDER: GraphNode['type'][] = ['attacker', 'account', 'host', 'process', 'external'];
const COL_LABEL: Record<string, string> = {
  attacker: 'Source', account: 'Account', host: 'Host', process: 'Process', external: 'External',
};
const NODE_COLOR: Record<string, string> = {
  attacker: '#f85149', account: '#d29922', host: '#4dabf7', process: '#a371f7', external: '#ff6b9d',
};

@Component({
  selector: 'app-attack-graph',
  standalone: true,
  imports: [CommonModule],
  template: `
    <svg *ngIf="nodes().length" [attr.viewBox]="'0 0 ' + width() + ' ' + height()"
         width="100%" [attr.height]="height()" style="max-width:100%">
      <!-- column headers -->
      <text *ngFor="let c of usedColumns()" [attr.x]="colX(c)" y="16"
            text-anchor="middle" fill="var(--muted)" font-size="11"
            style="text-transform:uppercase; letter-spacing:.06em">{{ colLabel(c) }}</text>

      <!-- edges -->
      <g *ngFor="let e of drawnEdges()">
        <line [attr.x1]="e.x1" [attr.y1]="e.y1" [attr.x2]="e.x2" [attr.y2]="e.y2"
              stroke="var(--border)" stroke-width="2" marker-end="url(#arrow)" />
        <text [attr.x]="e.mx" [attr.y]="e.my - 4" text-anchor="middle"
              fill="var(--muted)" font-size="10">{{ e.label }}</text>
      </g>

      <!-- nodes -->
      <g *ngFor="let n of positioned()">
        <rect [attr.x]="n.x - 66" [attr.y]="n.y - 18" width="132" height="36" rx="8"
              [attr.fill]="'var(--panel-hi)'" [attr.stroke]="color(n.type)" stroke-width="1.5" />
        <circle [attr.cx]="n.x - 50" [attr.cy]="n.y" r="4" [attr.fill]="color(n.type)" />
        <text [attr.x]="n.x - 40" [attr.y]="n.y + 4" fill="var(--text)" font-size="12">
          {{ trim(n.label) }}
        </text>
      </g>

      <defs>
        <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3"
                orient="auto" markerUnits="strokeWidth">
          <path d="M0,0 L7,3 L0,6 Z" fill="var(--border)" />
        </marker>
      </defs>
    </svg>
    <p *ngIf="!nodes().length" class="muted">No graph data for this incident.</p>
  `,
})
export class AttackGraphComponent {
  private _graph = signal<IncidentGraph>({ nodes: [], edges: [] });
  @Input() set graph(g: IncidentGraph | null) {
    this._graph.set(g ?? { nodes: [], edges: [] });
  }

  nodes = computed(() => this._graph().nodes);
  private edges = computed(() => this._graph().edges);

  usedColumns = computed(() =>
    COLUMN_ORDER.filter(c => this.nodes().some(n => n.type === c)));

  private colGap = 170;
  private rowGap = 60;

  width = computed(() => Math.max(1, this.usedColumns().length) * this.colGap);
  height = computed(() => {
    const perCol = this.usedColumns().map(c =>
      this.nodes().filter(n => n.type === c).length);
    return Math.max(80, (Math.max(1, ...perCol)) * this.rowGap + 40);
  });

  positioned = computed<Positioned[]>(() => {
    const cols = this.usedColumns();
    const out: Positioned[] = [];
    cols.forEach((c, ci) => {
      const inCol = this.nodes().filter(n => n.type === c);
      inCol.forEach((n, ri) => {
        out.push({ ...n, x: ci * this.colGap + this.colGap / 2,
                   y: ri * this.rowGap + 45 });
      });
    });
    return out;
  });

  drawnEdges = computed<DrawnEdge[]>(() => {
    const pos = new Map(this.positioned().map(n => [n.id, n]));
    const drawn: DrawnEdge[] = [];
    for (const e of this.edges()) {
      const s = pos.get(e.source), t = pos.get(e.target);
      if (!s || !t) continue;
      const x1 = s.x + 66, y1 = s.y, x2 = t.x - 66, y2 = t.y;
      drawn.push({ x1, y1, x2, y2, label: e.label, mx: (x1 + x2) / 2, my: (y1 + y2) / 2 });
    }
    return drawn;
  });

  colX(c: string): number { return this.usedColumns().indexOf(c as any) * this.colGap + this.colGap / 2; }
  colLabel(c: string): string { return COL_LABEL[c] ?? c; }
  color(t: string): string { return NODE_COLOR[t] ?? 'var(--accent)'; }
  trim(label: string): string { return label.length > 15 ? label.slice(0, 14) + '…' : label; }
}
