# KingSec API Reference

**Version:** 1.1.0  
**Last Updated:** 2026-07-27  
**Base URL:** `http://127.0.0.1:8765/api/v1`

## Authentication

Most endpoints require a Bearer token in the Authorization header:

```
Authorization: Bearer <access_token>
```

Obtain a token via `POST /auth/login` or `POST /auth/register`.

### Headers

| Header | Value | Required |
|--------|-------|----------|
| `Authorization` | `Bearer <token>` | For authenticated endpoints |
| `Content-Type` | `application/json` | For POST/PUT bodies |

### Rate Limiting

Rate limit headers are returned on all endpoints:

- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

### Error Response Format

```json
{
  "detail": "Human-readable error message"
}
```

HTTP status codes: 200 (success), 201 (created), 400 (bad request), 401 (unauthorized), 403 (forbidden), 404 (not found), 422 (validation error), 429 (rate limited), 500 (server error).

## Endpoints

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /auth/register | No | Register a new user (first user becomes ADMIN) |
| POST | /auth/login | No | Login with username/password |
| POST | /auth/refresh | No | Refresh access token using refresh token |
| GET | /auth/me | Yes | Get current user info |
| POST | /auth/logout | Yes | Logout (revoke session) |

### Multi-Factor Authentication (MFA)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /auth/mfa/status | Yes | Check MFA enrollment status |
| POST | /auth/mfa/enable | Yes | Enable MFA (returns TOTP secret + QR code) |
| POST | /auth/mfa/verify | No | Verify MFA code during login |
| POST | /auth/mfa/recovery | No | Use recovery code during login |
| POST | /auth/mfa/disable | Yes | Disable MFA |
| POST | /auth/mfa/recovery-codes | Yes | Generate new recovery codes |

### Assessments

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /assessments | Yes | List assessments (paginated) |
| POST | /assessments | Yes | Create a new assessment |
| GET | /assessments/{id} | Yes | Get assessment details |
| POST | /assessments/{id}/start | Yes | Start assessment execution |
| POST | /assessments/{id}/cancel | Yes | Cancel running assessment |
| POST | /assessments/{id}/report | Yes | Generate/regenerate report |
| DELETE | /assessments/{id} | Yes | Delete assessment |

**List parameters:** `limit` (1-200, default 50), `offset` (default 0), `order_by`, `order_dir`.

### Execution

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /assessments/{id}/execution/status | Yes | Phase + per-scanner progress |
| GET | /assessments/{id}/execution/events | Yes | Ordered lifecycle event log |
| GET | /assessments/{id}/execution/progress | Yes | Overall progress percentage |
| POST | /assessments/{id}/execution/cancel | Yes | Cancel running execution |

### Findings

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /findings | Yes | List findings with filters |

**Filter parameters:** `severity`, `status`, `assessment_id`, `search`, `order_by`, `order_dir`, `limit`, `offset`.

### Reports

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /reports | Yes | List reports (paginated) |
| GET | /reports?assessment_id={id} | Yes | Get specific report |
| GET | /assessments/{id}/report | Yes | Download report file |
| POST | /assessments/{id}/report | Yes | Regenerate report |

**List parameters:** `search`, `severity`, `target`, `order_by`, `order_dir`, `limit`, `offset`.

### Profiles

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /profiles | Yes | List all assessment profiles |
| GET | /profiles/{profile_id} | Yes | Single profile details |
| POST | /profiles/{profile_id}/plan | Yes | Generate an execution plan |

**Plan request body:**
```json
{
  "target": "10.0.0.5",
  "target_type": "ip_address"
}
```

### Scanners

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /scanners | Yes | List all scanners with status |
| GET | /scanners/health | Yes | Aggregate health score |
| GET | /scanners/{scanner_id} | Yes | Detailed scanner status |

### Admin

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /admin/users | Admin | List users |
| PUT | /admin/users/{id}/role | Admin | Assign user role |
| GET | /admin/users/search | Admin | Search users with filters |
| POST | /admin/users/{id}/deactivate | Admin | Deactivate user |
| POST | /admin/users/{id}/activate | Admin | Activate user |
| POST | /admin/users/{id}/reset-password | Admin | Reset user password |
| GET | /admin/roles | Admin | List all roles |
| GET | /admin/audit | Admin | Search audit log |

### API Keys

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /apikeys | Yes | List user's API keys |
| POST | /apikeys | Yes | Create a new API key |
| GET | /apikeys/me | No | Get current API key info |
| POST | /apikeys/{id}/revoke | Yes | Revoke an API key |
| POST | /apikeys/{id}/rotate | Yes | Rotate an API key |

### Dashboard

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /dashboard | Yes | Combined dashboard data |
| GET | /dashboard/summary | Yes | Summary statistics |
| GET | /dashboard/severity | Yes | Severity breakdown |
| GET | /dashboard/trends | Yes | Finding trends over time |
| GET | /dashboard/scanners | Yes | Scanner status summary |
| GET | /dashboard/workers | Yes | Worker status |
| GET | /dashboard/jobs | Yes | Job statistics |
| GET | /dashboard/activity | Yes | Recent activity |
| GET | /dashboard/schedules | Yes | Schedule statistics |
| GET | /dashboard/notifications | Yes | Notification statistics |

### Settings

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /settings/health | Yes | System health check |
| GET | /settings/healthz | No | Simple health check (no auth) |
| GET | /settings/sessions | Yes | List active sessions |
| POST | /settings/sessions/{id}/revoke | Yes | Revoke a session |

## Pagination

All list endpoints support pagination:

| Parameter | Type | Default | Range |
|-----------|------|---------|-------|
| `limit` | integer | 50 | 1-200 |
| `offset` | integer | 0 | 0+ |

Response includes `total` (total matching records), `limit`, and `offset`.
