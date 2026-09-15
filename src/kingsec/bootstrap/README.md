# Bootstrap & Composition Root — Module 2.4

The single place that wires KingSec together and manages its lifecycle. It is the
**outermost layer**: it may import config (2.1), logging (2.2), and the error
kernel (2.3); nothing imports it except the process entrypoint.

## Public API

```python
from kingsec.bootstrap import (
    create_application,       # wire config -> logging -> DI -> handlers
    Application,              # the wired, lifecycle-managed app (context manager)
    Container,               # the DI container
    ExceptionHandlerRegistry,# boundary-translation registry
    BootstrapError,          # composition/lifecycle failure (KS-BOOT-001)
)
```

## Usage

```python
from kingsec.bootstrap import create_application

with create_application() as app:          # start() on enter, stop() on exit
    app.logger.info("ready")
    app.register_shutdown(lambda: db.close())   # runs LIFO on shutdown
    payload = app.translate_exception(exc)      # safe, leak-free dict
```

## Boot order (and why)

1. **Load settings** — first, so an invalid config fails fast with a clear
   `ConfigError` to stderr *before* any subsystem exists.
2. **Configure logging** — from the now-valid `settings.logging`.
3. **Wire container + exception handlers** — safe to log from here on.
4. **`start()`** — ensure the data directory, install `sys`/`threading`
   excepthooks, emit lifecycle logs. `stop()` reverses this: run shutdown hooks
   LIFO, restore the excepthooks. Both are idempotent.

## Dependency injection

A tiny, explicit, type-keyed `Container`: `register_instance`,
`register_factory` (lazy singleton), `resolve`, and LIFO `add_shutdown_hook`. No
framework — deliberate, per the modular-monolith design. Future modules register
their services here; today it holds the `Settings` singleton.

## Exception handling

- **Process last resort:** uncaught exceptions are logged as structured,
  redacted, `critical` events instead of raw stderr tracebacks. Ctrl-C is passed
  through untouched.
- **Boundary translation:** `ExceptionHandlerRegistry` resolves handlers by MRO.
  The default maps any `KingSecError` → its safe `to_dict()`, and anything else →
  a generic `KS-ERR-000` payload that never leaks internals.

## Integration points

- **Web layer (future):** wrap `create_application()` in a FastAPI `lifespan`
  (`start()` on startup, `stop()` on shutdown); register HTTP-status-aware
  handlers on `app.exception_handlers`; call `app.translate_exception(exc)` in a
  global handler.
- **Service modules (DB, scanners, AI):** register factories on `app.container`
  and teardown via `app.register_shutdown(...)`.
- **Async:** the sync lifecycle maps cleanly onto an async `lifespan`; add an
  asyncio exception handler alongside the existing excepthooks when the event
  loop is introduced.

## Full composition root (Module 5.4)

`create_application()` above builds the *core* (config, logging, DI container,
exception handlers). `create_wired_application()` in `composition.py` layers the
*adapters* on top — it is the single place that names concrete implementations.

```python
from kingsec.bootstrap.composition import create_wired_application

with create_wired_application() as app:          # start() on enter, stop() on exit
    use_case = app.resolve(SubmitAssessment)      # fully constructed from DI
    use_case.execute(request)
```

It registers, in order:

1. **Persistence** (`register_persistence`) — builds the SQLite engine + schema,
   binds `AssessmentRepository` / `ReportRepository`, adds `engine.dispose` as a
   shutdown hook.
2. **Unit of Work** (`register_unit_of_work`) — binds `UnitOfWorkFactory` to the
   same engine's session factory.
3. **Scanner** (`register_scanner`) — binds `ScannerPort` (Nuclei).
4. **AI** (`register_ai`) — binds `AIPort`, adds the http-client `close` hook.
5. **Reporting** (`register_reporting`) — binds `ReportGeneratorPort` (WeasyPrint).
6. **Use cases** — `CreateAssessment`, `SubmitAssessment`, `GetAssessment`,
   `GenerateReport` are registered as DI factories that resolve their ports from
   the container, so `app.resolve(UseCase)` needs no manual construction.

Resource lifecycle: the database engine and HTTP client are disposed on
`stop()` (LIFO). The scanner (per-scan subprocess) and reporting (stateless
render) hold no long-lived resources.

Dependency direction: this module imports application + infrastructure; **no
adapter imports it** (enforced by an integration test). `create_application()`
(2.4) is unchanged, so the lightweight core remains available on its own.
