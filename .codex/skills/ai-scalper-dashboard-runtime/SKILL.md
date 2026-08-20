---
name: ai-scalper-dashboard-runtime
description: Implement, diagnose, or verify the AI_SCALPER canonical backend and React frontend dashboard, including REST/WebSocket contracts, realtime file ingestion, stale-state semantics, loopback deployment, and frontend quality gates. Use for backend/ or frontend-dashboard/ work; do not use for trading execution or Windows broker-acceptance workflows.
metadata:
  short-description: Maintain the canonical AI_SCALPER dashboard
---

# AI_SCALPER dashboard runtime

Use `backend/` as the canonical service for `frontend-dashboard/`.
`dashboard_api/` is a legacy compatibility service and must not be substituted
for the canonical backend merely because it answers on port 8000. Read
`frontend-dashboard/README.md` and the relevant backend contract before
changing integration behavior.

## Data and safety boundaries

- The backend is the single source of dashboard data. The frontend must not
  read engine files directly or invent trading values when evidence is absent.
- Preserve source timestamps, freshness/staleness, partial/unavailable states,
  and last-known-good provenance. Do not turn missing values into zero or a
  healthy state.
- REST and WebSocket payloads must share reviewed schemas and safety semantics.
  Realtime events may invalidate or update only the relevant domain cache.
- Keep browser and API bindings loopback-only unless authentication, TLS,
  origin policy, and public deployment are separately reviewed.
- The dashboard remains observational. Do not add an order, live-enable, risk-
  limit mutation, or command endpoint as a UI convenience.

## Workflow

1. Confirm which backend owns the endpoint and check the actual health route
   before diagnosing connectivity.
2. Trace the domain end to end: source registry/normalizer, API schema, REST
   endpoint, WebSocket event, client type/guard, cache, hook, and rendered
   empty/stale/error state.
3. Preserve explicit states for loading, offline, reconnecting, stale, partial,
   invalid, and unavailable data. Keep mock fallback visibly labeled and out of
   production evidence.
4. Run focused backend and frontend tests, then the applicable quality gates:
   backend tests/type/lint/security checks; frontend lint, typecheck, unit tests,
   production build, bundle budget, and browser E2E when behavior or layout
   changes.
5. On Windows, use the repository-pinned Python and Node requirements. Vite's
   pinned version requires Node `^20.19.0` or `>=22.12.0`.

Report API availability, WebSocket connectivity, source freshness, and UI
rendering as separate observations. A healthy process with stale source data
is not a healthy realtime dashboard.
