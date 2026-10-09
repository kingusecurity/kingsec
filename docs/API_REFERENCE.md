# KingSec Core API Reference

Base URL: `http://127.0.0.1:8765/api/v1`

This document covers the core assessment workflow. The generated OpenAPI
document and Swagger UI at `/openapi.json` and `/docs` are authoritative for
the complete route set, request schemas, response schemas, and role
requirements of the running build.

## Verification boundary

- **INFERRED (2026-10-07):** paths, request fields, enums, and permissions in
  this guide were cross-checked against the current FastAPI routes, Pydantic
  schemas, domain enums, and assessment-profile registry.
- **NOT TESTED (2026-10-07):** the current working tree has not been started
  and its generated OpenAPI document has not been compared byte-for-byte with
  this guide.

## Authentication and bootstrap

Most endpoints require either a JWT bearer token or a permitted API key. JWT
requests use:

```http
Authorization: Bearer <access_token>
```

`POST /auth/register` creates a Viewer account. It never creates the first
administrator. An operator must create the initial administrator with
`kingsec-bootstrap`; `GET /health` exposes the public boolean
`bootstrap_required` so deployment automation can detect that state.

Core authentication routes:

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| `GET` | `/health` | Public | Basic status and `bootstrap_required` |
| `POST` | `/auth/register` | Public, subject to registration policy | Create a Viewer |
| `POST` | `/auth/login` | Public | Exchange credentials for JWTs, or begin MFA completion |
| `POST` | `/auth/refresh` | Refresh token | Rotate an access token |
| `GET` | `/auth/me` | Viewer+ | Current user profile |
| `POST` | `/auth/change-password` | JWT Viewer+ | Change the caller's password |

A login response has one of two shapes: access and refresh tokens are present,
or `mfa_required` is true and a `pending_token` must be completed through an
MFA verification/recovery endpoint.

## Errors

Handled KingSec errors normally use:

```json
{
  "error_code": "KS-VAL-001",
  "message": "Safe client-facing message"
}
```

FastAPI validation errors and route-local `HTTPException` responses use a
`detail` field instead. Clients must branch on HTTP status first and tolerate
both documented error envelopes.

## Target types

Assessment target values are validated according to `target_type`:

| Value | Expected target |
|---|---|
| `ip_address` | One IPv4 or IPv6 address |
| `hostname` | One DNS hostname |
| `url` | An `http` or `https` URL without embedded credentials |
| `network` | An IPv4 or IPv6 CIDR network |
| `domain` | A public-style, multi-label DNS domain for domain enumeration |
| `source_path` | An absolute path visible to the KingSec server |
| `container_image` | An OCI/Docker image reference |

Do not send a source path or container image as a `hostname`. The explicit
types decide both scanner compatibility and authorization coverage.

## Assessment profiles

| Profile ID | Target types | Scanner plan |
|---|---|---|
| `quick-scan` | `ip_address`, `hostname` | Nmap (required) |
| `network-scan` | `network`, `ip_address`, `hostname` | Nmap (required), Nuclei |
| `web-scan` | `url` | Nmap, Gobuster, FFUF, Nuclei, ZAP |
| `api-scan` | `url` | FFUF, Nuclei, ZAP |
| `external-footprint` | `hostname`, `ip_address` | Nmap (required) |
| `full-assessment` | `ip_address`, `hostname`, `url` | Nmap, Nuclei, Gobuster, FFUF, ZAP, Nikto |
| `code-review` | `source_path` | Semgrep and Trivy (both required) |
| `container-scan` | `container_image` | Trivy (required) |
| `domain-enumeration` | `domain` | Amass (required) |

The planner, rather than this table, is the runtime source of truth. Query it
before submission:

| Method | Path | Minimum role | Purpose |
|---|---|---|---|
| `GET` | `/profiles` | Viewer | List profiles |
| `GET` | `/profiles/{profile_id}` | Viewer | Get one profile |
| `POST` | `/profiles/{profile_id}/plan` | Viewer | Check target compatibility and scanner readiness |

Plan request:

```json
{
  "target": "127.0.0.1",
  "target_type": "ip_address"
}
```

## Authorization grants

Scope enforcement is enabled by default. Creating an assessment requires an
active grant that covers every effective scan-surface tier in its chosen
profile. An Admin can explicitly override the check for an individual request,
but the override is an emergency control rather than the normal workflow.

Grant specification types are:

`ip_address`, `network`, `hostname`, `wildcard_hostname`, `url_prefix`,
`domain`, `source_path`, and `container_image`.

The last three are exact-resource grants. In particular, domain enumeration
requires an explicit `domain` grant; a hostname or wildcard-hostname grant
does not authorize domain-wide enumeration.

| Method | Path | Minimum role | Purpose |
|---|---|---|---|
| `POST` | `/authorization-grants` | Admin | Create a time-bounded grant |
| `GET` | `/authorization-grants` | Analyst | List grants |
| `GET` | `/authorization-grants/check` | Analyst | Dry-run the same coverage logic used at assessment creation |
| `DELETE` | `/authorization-grants/{grant_id}` | Admin | Revoke a grant |

Example grant request:

```json
{
  "authorized_by": "Security owner / ticket SEC-123",
  "authorizing_organization": "Example Corp",
  "target_specification_type": "ip_address",
  "target_specification_value": "127.0.0.1",
  "valid_from": "2026-10-07T09:00:00Z",
  "valid_until": "2026-10-08T09:00:00Z"
}
```

Coverage check query:

```text
GET /authorization-grants/check?target_type=ip_address&target_value=127.0.0.1&profile_id=quick-scan
```

## Assessment lifecycle

Creating and starting are intentionally separate operations.

| Method | Path | Minimum role | Purpose |
|---|---|---|---|
| `GET` | `/assessments` | Viewer | Paginated assessments visible to the caller |
| `POST` | `/assessments` | Analyst | Validate and save an authorized assessment |
| `GET` | `/assessments/{assessment_id}` | Viewer | Assessment, findings, and scanner outcomes |
| `POST` | `/assessments/{assessment_id}/start` | Analyst | Submit the saved assessment for execution |
| `POST` | `/assessments/{assessment_id}/cancel` | Analyst | Request cancellation |
| `DELETE` | `/assessments/{assessment_id}` | Analyst | Delete an assessment and its owned data/artifacts |

Create request:

```json
{
  "target_value": "127.0.0.1",
  "target_type": "ip_address",
  "authorized_by": "Security owner / ticket SEC-123",
  "scope": "Loopback host only",
  "profile_id": "quick-scan",
  "override_scope_check": false
}
```

`profile_id` is required. Unknown profiles, mismatched profile/target types,
and uncovered surfaces are rejected before persistence. Creating the record
does not begin scanner execution.

Assessment terminal states include:

- `completed`: every planned scanner succeeded.
- `completed_with_gaps`: one or more scanners were skipped, failed, or timed
  out, but at least one scanner succeeded.
- `failed`: the run did not produce a successful scanner result.
- `cancelled`: execution was cancelled.

List parameters include `limit`, `offset`, `search`, `status`, `order_by`, and
`order_dir`. The OpenAPI schema defines the current bounds and sort values.

Execution detail routes:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/assessments/{assessment_id}/execution/status` | Phase and per-scanner state |
| `GET` | `/assessments/{assessment_id}/execution/events` | Ordered lifecycle events |
| `GET` | `/assessments/{assessment_id}/execution/progress` | Overall progress |
| `POST` | `/assessments/{assessment_id}/execution/cancel` | Execution-layer cancellation |

## Findings and reports

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/findings` | Paginated findings with filters |
| `POST` | `/assessments/{assessment_id}/report` | Generate or regenerate report data/artifact |
| `GET` | `/reports` | Paginated report metadata |
| `GET` | `/reports/{assessment_id}` | One report's metadata |
| `GET` | `/reports/{assessment_id}/download` | Download PDF by default; use `?format=html` for HTML |

A report is a scoped assessment result, not a penetration-test attestation.
Read its scanner outcomes and coverage limitations together with its findings
and executive score.

## Scanner readiness

These routes report status; they do not install or mutate scanner software:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/scanners` | Every known scanner and its discovery status |
| `GET` | `/scanners/health` | Aggregate and per-scanner readiness |
| `GET` | `/scanners/{scanner_id}` | One scanner's status |
| `GET` | `/scanners/{scanner_id}/diagnostics` | Detailed diagnostics |
| `GET` | `/scanners/{scanner_id}/install` | Platform-specific installation guidance |

## Pagination and ownership

List endpoints generally accept `limit` and `offset`, with endpoint-specific
filters and sort keys documented by OpenAPI. Non-admin users only receive
resources they are permitted to view; Admin access does not change the
authorization-grant requirement for normal assessment creation.
