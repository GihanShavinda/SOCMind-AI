# FR-1 Completion — Password Reset, Profile & Admin User Management

This step fully closes **FR-1** ("users register, log in, reset passwords and
manage profiles") and reinforces **FR-3**. It follows the SOC domain model where
Administrators manage accounts (rather than open public signup).

## What was added

### Password reset by email (FR-1)
Token-based, single-use, 30-minute expiry, with **anti-enumeration** (the
response never reveals whether an email is registered). Tokens are stored hashed.
- `POST /api/auth/forgot-password` — request a reset link
- `POST /api/auth/reset-password` — set a new password with the token

**Email delivery is pluggable** (`EMAIL_MODE`):
- `console` (default, lab-friendly): the link is logged and also returned in the
  API response, so reset works fully offline — no SMTP needed.
- `smtp`: sends a real email (set `SMTP_*` in `.env`).

### Self-service profile (FR-1)
- `PATCH /api/auth/me` — update display name
- `POST /api/auth/change-password` — change own password (requires current one)

### Admin user management (FR-1, FR-3)
Administrator-only endpoints and a **Users** screen (admin-only nav item):
- `GET /api/users`, `POST /api/users` (create), `PATCH /api/users/{id}` (role / active)
Analysts and viewers are correctly forbidden (403).

## Frontend
- **Forgot password** and **Reset password** public screens (link from login).
- **Settings**: added Profile (name) and Change-password cards alongside MFA.
- **Users**: admin screen to create accounts and change roles / enable-disable.

## Why admin-managed instead of public signup
A security console shouldn't allow open self-registration — the role table states
Administrators manage users. This is the faithful, more professional interpretation
of FR-1's "register", and avoids an anonymous-account attack surface.

## Schema / migration
Migration `0005_pwreset` adds the `password_reset_tokens` table (idempotent).
Runs automatically on `docker compose up`.

## Requirements
FR-1 now fully ✅ (registration-by-admin, login, password reset, profile
management). No new Python dependency; TOTP/MFA from Phase 6 unchanged.

## Try it
- **Forgot password:** login screen → "Forgot password?" → enter email → in
  console mode the reset link appears on screen → open it → set new password.
- **Admin users:** log in as admin → **Users** (sidebar) → create an analyst →
  log in as them.
- **Profile:** **Settings** → change your name / password.
