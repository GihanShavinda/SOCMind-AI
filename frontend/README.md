# SOCMind AI — Frontend (Angular)

The Angular workspace is deferred to Phase 6 (Surfaces). Scaffold it when you
reach that phase; the backend already exposes CORS for `http://localhost:4200`.

## Scaffold when ready

```bash
# from the repo root
npm install -g @angular/cli
ng new frontend --routing --style=scss --skip-git
cd frontend
ng serve            # http://localhost:4200
```

## Suggested structure

```
src/app/
├── core/
│   ├── auth.interceptor.ts     # attaches the JWT access token
│   ├── auth.guard.ts           # protects routes
│   ├── auth.service.ts         # login / refresh / logout
│   └── api.service.ts          # base HTTP client
├── features/
│   ├── login/
│   ├── dashboard/              # live incident counts (WebSocket in P6)
│   ├── incidents/              # list + investigation workspace
│   └── assets/                 # asset inventory CRUD
└── shared/
```

## First screens to build (thin-first)

1. Login page  → `POST /api/auth/login`, store tokens, attach via interceptor.
2. Asset list  → `GET /api/assets`.
3. Incident list → `GET /api/incidents`.
4. Incident detail → `GET /api/incidents/{id}` + `/events`.

Backend base URL during dev: `http://localhost:8000`.
