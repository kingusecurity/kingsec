# KingSec Frontend — Architecture

## Origin

This document is the output of Phase 0 (repository inspection). Every statement below
is a direct observation of the backend code at `src/kingsec/`. The frontend is a thin
client that maps 1:1 to the existing REST API — no behaviour is invented, no endpoint
is called beyond what the backend defines.

## Backend Identity

```
app_name:     KingSec
version:      1.0.0
api_base:     /api/v1
server_port:  8765 (default)
server_host:  127.0.0.1 (default, loopback-only by default)
jwt:          HMAC-HS256, 30 min access / 7 day refresh
docs:         /docs (Swagger UI), /redoc (ReDoc)
openapi:      /api/v1/openapi.json
```

## Authentication Flow

| Step | Endpoint | Auth | Notes |
|------|----------|------|-------|
| Register | `POST /api/v1/auth/register` | None | First user → `ADMIN`, subsequent → `VIEWER` |
| Login | `POST /api/v1/auth/login` | Rate-limited | Returns `{user_id, username, role, access_token, refresh_token, expires_in}` |
| Refresh | `POST /api/v1/auth/refresh` | Rate-limited | Body: `{refresh_token}` → `{access_token, token_type, expires_in}` |
| Me | `GET /api/v1/auth/me` | Bearer token | Returns `{user_id, username, email, role, is_active, created_at, last_login_at}` |

**Token storage**: In-memory only (Zustand store). Never persisted to localStorage.

**Auth header**: `Authorization: Bearer <access_token>` via `HTTPBearer` scheme.

**Default credentials**: `CHANGE-ME-IN-PRODUCTION-DO-NOT-USE-DEFAULT` (HS256).

## Role Hierarchy

| Role | IntEnum value | Label | Capabilities |
|------|--------------|-------|-------------|
| `VIEWER` | 10 | Viewer | Read-only: list assessments, view findings, dashboard |
| `ANALYST` | 20 | Analyst | Create/modify assessments, generate reports, start/cancel scans |
| `ADMIN` | 30 | Admin | Full access, user management, role assignment, secrets, audit |

The check is `current_user.role >= required_role` — hierarchy is monotonic.

**Assign role**: `PUT /api/v1/users/{user_id}/role` body `{role: "viewer|analyst|admin"}` — requires `ADMIN`.

## Domain Enums (API surface only)

### AssessmentStatus
`draft`, `authorized`, `running`, `completed`, `cancelled`, `failed`
Terminal: `completed`, `cancelled`, `failed`

### FindingStatus
`open`, `confirmed`, `false_positive`, `remediated`
Closed: `false_positive`, `remediated`

### Severity (IntEnum)
`informational(0)`, `low(1)`, `medium(2)`, `high(3)`, `critical(4)`

### TargetType
`ip_address`, `hostname`, `url`, `network`

## Complete Endpoint Inventory

### Public (no auth)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/health` | Health check |
| POST | `/api/v1/auth/register` | New user registration |
| POST | `/api/v1/auth/login` | Login (rate-limited) |
| POST | `/api/v1/auth/refresh` | Token refresh (rate-limited) |
| GET | `/api/v1/healthz/live` | K8s liveness |
| GET | `/api/v1/healthz/ready` | K8s readiness |

### Auth (any authenticated user)

| Method | Path | Min role |
|--------|------|----------|
| GET | `/api/v1/auth/me` | VIEWER |

### Assessments

| Method | Path | Min role |
|--------|------|----------|
| GET | `/api/v1/assessments` | VIEWER |
| POST | `/api/v1/assessments` | ANALYST |
| GET | `/api/v1/assessments/{id}` | VIEWER |
| POST | `/api/v1/assessments/{id}/start` | ANALYST |
| POST | `/api/v1/assessments/{id}/report` | ANALYST |
| POST | `/api/v1/assessments/{id}/cancel` | ANALYST |
| DELETE | `/api/v1/assessments/{id}` | ANALYST |

### Dashboard (VIEWER+)

| Method | Path |
|--------|------|
| GET | `/api/v1/dashboard` |
| GET | `/api/v1/dashboard/summary` |
| GET | `/api/v1/dashboard/severity` |
| GET | `/api/v1/dashboard/trends?period=daily|weekly|monthly` |
| GET | `/api/v1/dashboard/scanners` |
| GET | `/api/v1/dashboard/workers` |
| GET | `/api/v1/dashboard/jobs` |
| GET | `/api/v1/dashboard/schedules` |
| GET | `/api/v1/dashboard/notifications` |
| GET | `/api/v1/dashboard/activity` |

### API Keys (permission-gated)

| Method | Path | Permission |
|--------|------|------------|
| POST | `/api/v1/apikeys` | `CREATE_API_KEY` |
| GET | `/api/v1/apikeys` | `LIST_API_KEYS` |
| GET | `/api/v1/apikeys/me` | auth only |
| DELETE | `/api/v1/apikeys/{id}` | `DELETE_API_KEY` |
| POST | `/api/v1/apikeys/{id}/rotate` | `ROTATE_API_KEY` |

### Schedules

| Method | Path | Min role |
|--------|------|----------|
| GET | `/api/v1/schedules` | VIEWER |
| GET | `/api/v1/schedules/due` | ADMIN |
| POST | `/api/v1/schedules` | ANALYST |
| GET | `/api/v1/schedules/{id}` | VIEWER |
| PUT | `/api/v1/schedules/{id}` | ANALYST |
| DELETE | `/api/v1/schedules/{id}` | ANALYST |
| POST | `/api/v1/schedules/{id}/pause` | ANALYST |
| POST | `/api/v1/schedules/{id}/resume` | ANALYST |
| POST | `/api/v1/schedules/{id}/enable` | ANALYST |
| POST | `/api/v1/schedules/{id}/disable` | ANALYST |
| POST | `/api/v1/schedules/{id}/trigger` | ANALYST |

### Sessions (any authenticated user)

| Method | Path |
|--------|------|
| GET | `/api/v1/sessions` |
| GET | `/api/v1/sessions/current` |
| DELETE | `/api/v1/sessions/current` |
| DELETE | `/api/v1/sessions/{id}` |
| DELETE | `/api/v1/sessions` |
| POST | `/api/v1/sessions/refresh` |

### Notifications (any authenticated user)

| Method | Path | Min role |
|--------|------|----------|
| GET | `/api/v1/notifications` | any |
| GET | `/api/v1/notifications/{id}` | any |
| POST | `/api/v1/notifications/send` | VIEWER |
| POST | `/api/v1/notifications/bulk` | ADMIN |
| POST | `/api/v1/notifications/{id}/read` | any |
| DELETE | `/api/v1/notifications/{id}` | any |
| POST | `/api/v1/notifications/retry` | ADMIN |

### MFA

| Method | Path | Auth |
|--------|------|------|
| GET | `/api/v1/mfa/status` | any |
| POST | `/api/v1/mfa/enable` | any |
| POST | `/api/v1/mfa/verify` | rate-limited |
| POST | `/api/v1/mfa/disable` | any |
| POST | `/api/v1/mfa/disable/{user_id}` | ADMIN |
| POST | `/api/v1/mfa/recovery` | rate-limited |
| POST | `/api/v1/mfa/recovery/generate` | any |
| POST | `/api/v1/mfa/recovery/rotate` | any |

### Events (SSE)

| Method | Path | Auth |
|--------|------|------|
| GET | `/api/v1/events?assessment_id=` | any |

### Audit

| Method | Path | Min role |
|--------|------|----------|
| GET | `/api/v1/audit` | ADMIN |
| GET | `/api/v1/audit/events` | ADMIN |
| GET | `/api/v1/audit/events/{id}` | ADMIN |

### Admin — Secrets

| Method | Path |
|--------|------|
| GET | `/api/v1/admin/secrets` |
| GET | `/api/v1/admin/secrets/status` |
| POST | `/api/v1/admin/secrets` |
| DELETE | `/api/v1/admin/secrets/{name}` |
| POST | `/api/v1/admin/secrets/rotate` |

### Admin — Healthz

| Method | Path |
|--------|------|
| GET | `/api/v1/healthz/health` |
| GET | `/api/v1/healthz/metrics` |
| GET | `/api/v1/healthz/startup` |
| GET | `/api/v1/healthz/configuration` |
| GET | `/api/v1/healthz/dependencies` |
| GET | `/api/v1/healthz/resources` |
| POST | `/api/v1/healthz/shutdown` |
| POST | `/api/v1/healthz/restart` |

### Admin — Users

| Method | Path | Min role |
|--------|------|----------|
| PUT | `/api/v1/users/{user_id}/role` | ADMIN |

### Admin — Plugins, Agents, Queue, Pipelines, Backups

All require ADMIN (router-level or via `_require_admin` guard):

- **Plugins** (12 endpoints): CRUD, install/uninstall, enable/disable, update/rollback, validate, import/export
- **Agents** (11 endpoints): register, heartbeat, CRUD, job assignment, progress, complete/fail
- **Queue** (11 endpoints): enqueue, cancel, priority, move, assign, list, stats, pause/resume
- **Pipelines** (7 endpoints): start, cancel, retry, resume, pause, list, get
- **Backups** (10 endpoints): CRUD, restore, verify, cleanup, snapshots

## API Schema Patterns

All schemas use `extra="forbid"` by convention. Key response shapes:

```
LoginResponse:     {user_id, username, role, access_token, refresh_token, token_type, expires_in}
UserResponse:      {user_id, username, email, role, is_active, created_at, last_login_at}
AssessmentResponse: {assessment_id, target, status, is_authorized, created_at, findings: [...]}
FindingResponse:    {finding_id, title, severity, status, evidence_count, recommendation_count}
ListAssessments:    {items: [AssessmentSummary], total, limit, offset}
AssessmentSummary:  {assessment_id, target, status, is_authorized, created_at, findings_count}
ErrorResponse:      {error_code, message}
```

Pagination params accepted by list endpoints: `limit`, `offset`.

## Frontend Responsibilities

| Concern | Approach |
|---------|----------|
| Auth | Zustand store (in-memory), refresh interceptor in API service |
| API calls | Typed service layer via `fetch` (no Axios), TanStack Query for caching |
| Forms | React Hook Form + Zod, validation mirrors backend rules |
| Routing | React Router v6, protected by role-based guards |
| State | TanStack Query (server), Zustand (client/auth/UI) |
| Styling | Tailwind CSS v3+, shadcn/ui components |
| Charts | Recharts (dashboard) |
| Tables | TanStack Table v8 (assessments, findings) |
| Animations | Framer Motion (transitions, loading states) |
| Real-time | EventSource (SSE) for `/api/v1/events` |
| Fonts | Self-hosted Inter + JetBrains Mono — no CDN |

## Screen-to-Endpoint Mapping (Blueprint v2)

| Screen | Endpoints | Min Role |
|--------|-----------|----------|
| Login | `POST /auth/login` | None |
| Register | `POST /auth/register` | None |
| Dashboard | `GET /dashboard/*` (10 endpoints) | VIEWER |
| Assessment List | `GET /assessments` | VIEWER |
| Assessment Create | `POST /assessments` | ANALYST |
| Assessment Detail | `GET /assessments/{id}`, SSE `/events` | VIEWER |
| Finding Detail | `GET /assessments/{id}` (extract finding) | VIEWER |
| Findings Browser | `GET /assessments` (aggregate) | VIEWER |
| Reports | `POST /assessments/{id}/report`, `GET /assessments/{id}` | ANALYST |
| Settings | MFA, API keys, sessions, notifications | VIEWER+ |
| User Profile | `GET /auth/me`, `PUT /users/{id}/role` (admin) | VIEWER |

## Technology Constraints

- **Zero external CDN** — fonts, icons (Lucide), everything bundled
- **No telemetry, no analytics, no external requests** from the browser
- **Dark mode only** for v1
- **In-memory token storage** — no localStorage for tokens
- **Strict TypeScript** — `strict: true` in tsconfig
- **Test requirements**: Vitest (unit), Testing Library (component), Playwright (e2e)

## Key Backend Idiosyncrasies

1. `POST /assessments/{id}/report` returns 409 if assessment hasn't been scanned (known gap)
2. `POST /assessments` body includes `authorized_by` and `scope` fields for audit trail
3. `StartAssessmentBody`, `GenerateReportBody`, `CancelAssessmentBody` are all empty objects (`extra="forbid"`)
4. Login is rate-limited via `require_rate_limit(LOGIN)` — frontend must handle 429
5. First registered user gets ADMIN, subsequent get VIEWER — no ANALYST assignment via registration
6. Only ADMIN can assign roles (analyst/promote to admin)
7. SSE endpoint at `/api/v1/events` supports optional `assessment_id` query filter
8. Audit endpoint (`GET /api/v1/audit`) supports rich filtering: `user_id`, `action`, `resource_type`, `since`, `until`, `success`
9. API key auth supports both `Authorization: Bearer <key>` and `X-API-Key` header
10. Password min 8 chars with mixed case + digit requirement
