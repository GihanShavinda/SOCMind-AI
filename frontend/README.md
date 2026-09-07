# SOCMind AI — Frontend (Angular 18)

The analyst web console. Standalone-component Angular app, typed end to end
against the FastAPI backend.

## Run

```bash
# from the frontend/ folder
npm install          # first time only
npm start            # ng serve -> http://localhost:4200
```

Make sure the backend is running (`docker compose up` in the repo root). The app
talks to `http://localhost:8000` — change `src/environments/environment.ts` if
your backend is elsewhere. CORS for `http://localhost:4200` is already enabled
server-side.

Log in with the seeded lab admin: `admin@socmind.io` / `ChangeMe123!`

To see data, generate an incident first:
```bash
python backend/scripts/demo_bruteforce.py
```

## What's here

Working now (Phase 1 backend):
- **Login** — JWT auth, token stored, attached via HTTP interceptor
- **Dashboard** — live incident counts by severity + recent feed
- **Incidents** — correlated incident list
- **Incident detail** — evidence timeline + attack-story summary (workspace)
- **Assets** — inventory + register form (role-gated)
- **Audit trail** — append-only action record

Navigable shells (backend arrives in later phases): MITRE ATT&CK, Decision Panel,
Playbooks, Approvals, Reports. Each shows the phase it's delivered in.

See `../docs/REQUIREMENTS_TRACEABILITY.md` for the full FR → screen → phase map.

## Structure

```
src/app/
├── core/
│   ├── models/            # TypeScript types mirroring backend schemas
│   ├── services/          # auth.service, api.service, auth.interceptor
│   └── guards/            # authGuard, roleGuard (RBAC)
├── layout/
│   └── shell.component.ts # sidebar nav + topbar, hosts the router outlet
├── features/
│   ├── login, dashboard, incidents, incident-detail, assets, audit  (working)
│   └── mitre, decision-panel, playbooks, approvals, reports          (shells)
├── app.routes.ts          # every screen routed; role guards applied
└── app.config.ts          # router + http client + interceptor
```

## Build for production
```bash
npm run build   # outputs to dist/frontend
```
