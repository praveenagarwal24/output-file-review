# website-review

Internal Spyne tool: a set of static review dashboards (image/output-file QC)
served behind Google sign-in.

## Deployment type

**TYPE B** — a long-running Node/Express web server running as a container on
Spyne AWS (ECS Fargate behind a load balancer).

The dashboards themselves are static HTML (in `public/`), but the app is served
by a web server (`server.js`) so that Google sign-in can be enforced
server-side on every route. It is **not** static S3/CloudFront hosting, because
that cannot enforce authentication per route.

## Where it runs

- Runs on **Spyne's own AWS**.
- The pipeline **builds from the `aws-prod` branch**.
- Served at https://website-review.spyne.ai

## Configuration

- **All config comes from `APP_SECRETS`**, a single JSON-string environment
  variable, parsed once at startup. The app fails fast at boot, naming any
  missing key. There are no development fallbacks and no `.env` file.
- The values live only in AWS. The code only names the keys.
- Keys read from `APP_SECRETS`:
  - `CLIENT_ID`, `CLIENT_SECRET` — the shared Spyne Google OAuth client.
  - `GOOGLE_REDIRECT_URI` — `https://website-review.spyne.ai/api/auth/callback/google`
  - `GOOGLE_ALLOWED_DOMAIN` — `spyne.ai`
  - `AUTH_SECRET` — signs the session cookie, unique to this app.
  - `NAME` (optional) — service name reported by `/health` (default `website-review`).
  - `ALLOWED_EMAILS` (optional) — comma-separated allow-list. When set, only
    these addresses may sign in; when unset, any verified `@spyne.ai` account is
    allowed.
  - `PORT` (optional) — defaults to `3000`.

## Authentication

- **Sign-in is required on every route except `/health` and the auth routes**
  (`/api/auth/*`).
- Server-side session (signed cookie). Unauthenticated requests are redirected
  to Google.
- By default any verified `@spyne.ai` account is allowed; `ALLOWED_EMAILS`
  narrows it further when present.

## Health

- `GET /health` → `{ status, service, timestamp }`, unauthenticated, never
  redirects (the load balancer polls it signed out).

## Local run

```
npm ci
APP_SECRETS='{"CLIENT_ID":"...","CLIENT_SECRET":"...","GOOGLE_REDIRECT_URI":"...","GOOGLE_ALLOWED_DOMAIN":"spyne.ai","AUTH_SECRET":"..."}' npm start
```

Without `APP_SECRETS` (or with a required key missing) the app refuses to boot
by design.
