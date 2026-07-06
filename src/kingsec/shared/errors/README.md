# Exception System — Module 2.3

A production-grade exception hierarchy for KingSec: stable error codes, safe
user-facing messages, exception chaining, and zero-touch structured-logging
integration. Lives in the **shared kernel** (`kingsec.shared.errors`) so every
layer — domain, application, infrastructure — can raise these without importing
infrastructure. The package depends on **nothing but the standard library**.

## Why the shared kernel (not `infrastructure/`)

Exceptions are cross-cutting: the domain must be able to raise
`AuthorizationError` when a scan target isn't authorized. If the base lived in
`infrastructure/`, the domain would have to import infrastructure to raise an
error — violating the hexagonal dependency rule. The shared kernel sits at the
bottom of the dependency graph: everyone may import it; it imports no one.

## Public API

```python
from kingsec.shared.errors import (
    KingSecError,            # base
    ConfigurationError, ValidationError, AuthorizationError,
    ResourceNotFoundError, ExternalServiceError, ServiceTimeoutError,
    ScannerError, PersistenceError,
    ErrorCode,               # catalog of stable code constants
    get_exception_for_code, registered_codes,
    log_exception,           # log an exception with safe structured fields
    add_exception_context,   # optional structlog processor (not wired by default)
)
```

## Hierarchy

```
KingSecError                       KS-ERR-000
  ├─ ConfigurationError            KS-CFG-001
  ├─ ValidationError               KS-VAL-001
  ├─ AuthorizationError            KS-AUTHZ-001   ← trust guardrail
  ├─ ResourceNotFoundError         KS-RES-001
  ├─ ExternalServiceError          KS-EXT-001
  │    └─ ServiceTimeoutError      KS-EXT-002
  ├─ ScannerError                  KS-SCAN-001
  └─ PersistenceError              KS-STORE-001
```

Codes are globally unique — a duplicate raises `ValueError` **at import time**,
so the mistake surfaces on first load, not in production.

## Two messages, on purpose

Every error carries an internal `message` (rich detail, for logs) and a safe
`user_message` (generic, for humans/APIs). `to_dict()` exposes only the code and
`user_message` — never the internal detail, context, or cause. This is the OWASP
"improper error handling" guidance made structural: internals never reach a user.

```python
raise ValidationError(
    "port 70000 exceeds maximum 65535 in server.port",   # internal → logs
    context={"field": "server.port"},                    # structured → logs
)
# API/user sees only: {"error_code": "KS-VAL-001", "message": "The provided input is invalid..."}
```

## Chaining

Preserve the root cause for debugging while the user still sees only the safe
message:

```python
try:
    provider.call()
except TimeoutError as original:
    raise ServiceTimeoutError("AI provider timed out", cause=original) from original
```

## Logging integration (no changes to Module 2.2)

`log_exception` attaches the error's safe fields **and** its traceback in one
call, through the existing logger:

```python
from kingsec.infrastructure.logging import get_logger
from kingsec.shared.errors import log_exception, ExternalServiceError

log = get_logger(__name__)
try:
    ...
except ExternalServiceError as exc:
    log_exception(log, exc)   # → error_code, error_type, context, traceback
```

Any secret that slips into `message` or `context` is still masked by 2.2's
redaction — defence in depth across the module boundary. An optional
`add_exception_context` structlog processor is provided for teams that prefer
automatic extraction; it is deliberately **not** added to 2.2's chain here.

## Integration seam — Module 2.4

- **Global error handling / boundary translation.** 2.4 (or the FastAPI error
  layer) maps a caught `KingSecError` to a response via `to_dict()` and a status
  code — one mapping from category → HTTP status, with any non-`KingSecError`
  becoming a generic 500 (never leaking internals).
- **`ConfigError` re-parenting (optional).** Module 2.1's local `ConfigError`
  can later subclass `ConfigurationError` so config failures flow through the
  same handling; left undone here to avoid modifying a frozen module.
- **Retry/back-off signals.** `ExternalServiceError` / `ServiceTimeoutError` are
  the natural markers for a retry policy in the outbound adapters.
