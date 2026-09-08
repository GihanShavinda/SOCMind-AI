import { Routes } from '@angular/router';

import { authGuard, roleGuard } from './core/guards/auth.guard';

/**
 * Every screen the SOCMind AI platform requires has a route here, so no
 * requirement is orphaned. Screens whose backend arrives in a later phase are
 * marked (placeholder) and render a "coming in Phase N" panel today.
 */
export const routes: Routes = [
  { path: 'login', loadComponent: () => import('./features/login/login.component').then(m => m.LoginComponent) },
  { path: 'forgot-password', loadComponent: () => import('./features/forgot-password/forgot-password.component').then(m => m.ForgotPasswordComponent) },
  { path: 'reset-password', loadComponent: () => import('./features/reset-password/reset-password.component').then(m => m.ResetPasswordComponent) },

  {
    path: '',
    loadComponent: () => import('./layout/shell.component').then(m => m.ShellComponent),
    canActivate: [authGuard],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },

      // --- Working now (Phase 1 backend) ---
      { path: 'dashboard', loadComponent: () => import('./features/dashboard/dashboard.component').then(m => m.DashboardComponent) },
      { path: 'incidents', loadComponent: () => import('./features/incidents/incidents.component').then(m => m.IncidentsComponent) },
      { path: 'incidents/:id', loadComponent: () => import('./features/incident-detail/incident-detail.component').then(m => m.IncidentDetailComponent) },
      { path: 'assets', loadComponent: () => import('./features/assets/assets.component').then(m => m.AssetsComponent) },
      { path: 'audit', loadComponent: () => import('./features/audit/audit.component').then(m => m.AuditComponent) },

      // --- Placeholder shells (backend lands in later phases) ---
      { path: 'mitre', loadComponent: () => import('./features/mitre/mitre.component').then(m => m.MitreComponent) },
      { path: 'hunting', loadComponent: () => import('./features/hunting/hunting.component').then(m => m.HuntingComponent) },
      { path: 'model-cards', loadComponent: () => import('./features/model-cards/model-cards.component').then(m => m.ModelCardsComponent) },
      { path: 'decision', loadComponent: () => import('./features/decision-panel/decision-panel.component').then(m => m.DecisionPanelComponent) },
      { path: 'playbooks', loadComponent: () => import('./features/playbooks/playbooks.component').then(m => m.PlaybooksComponent) },
      {
        path: 'approvals',
        canActivate: [roleGuard('Administrator', 'SOC Analyst')],
        loadComponent: () => import('./features/approvals/approvals.component').then(m => m.ApprovalsComponent),
      },
      { path: 'reports', loadComponent: () => import('./features/reports/reports.component').then(m => m.ReportsComponent) },
      { path: 'settings', loadComponent: () => import('./features/settings/settings.component').then(m => m.SettingsComponent) },
      {
        path: 'users',
        canActivate: [roleGuard('Administrator')],
        loadComponent: () => import('./features/users/users.component').then(m => m.UsersComponent),
      },
    ],
  },

  { path: '**', redirectTo: '' },
];
