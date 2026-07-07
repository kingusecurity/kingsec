# SQLite Persistence Adapter — Module 4.1

The first outward adapter: implements the application's repository ports using
SQLAlchemy 2.x + SQLite, following the **Data Mapper** pattern (ORM models kept
strictly separate from the pure domain).

## Dependency direction

```
application (ports)  ◀── infrastructure.persistence ──▶ domain (mapping)
                                    │
                                    └──▶ shared kernel (PersistenceError, logging)
```

Infrastructure depends on application, domain, and the shared kernel. It does
**not** import the bootstrap layer — DI wiring takes a structural `Protocol` the
2.4 `Container` satisfies.

## Public API

```python
from kingsec.infrastructure.persistence import (
    create_database_engine, create_session_factory, create_schema,
    SqlAlchemyAssessmentRepository, SqlAlchemyReportRepository,
    register_persistence, Base,
)
```

## Wiring into the app (composition root)

```python
from kingsec.bootstrap import create_application
from kingsec.infrastructure.persistence import register_persistence

app = create_application()
register_persistence(app.container, app.settings)   # binds ports, adds dispose hook
# use cases now resolve real repositories:
repo = app.resolve(AssessmentRepository)
```

## Key decisions

- **Data Mapper** — separate ORM models + hand-written mappers keep the domain
  free of SQLAlchemy.
- **Aggregate reconstitution** — `Assessment.reconstitute` / `Finding.reconstitute`
  rebuild stored state directly (replay would be lossy/fragile).
- **Delete-then-insert on save** — child value objects (`Evidence`,
  `Recommendation`) have no identity, so full replace is correct; reports use
  merge-upsert (their entries are JSON).
- **ISO-8601 timestamps** — preserves timezone across SQLite's typeless storage.
- **`PRAGMA foreign_keys=ON`** per connection — SQLite doesn't enforce FKs by default.
- **Exception translation** — `SQLAlchemyError → PersistenceError` (KS-STORE-001);
  the application never sees a SQLAlchemy exception.
- **Transactions** — session-per-operation via `sessionmaker.begin()`. A Unit of
  Work for multi-repository atomicity is deliberately deferred (would require
  touching Module 3.2 use cases).

## Schema

`assessments` 1─* `findings` 1─* `evidence` / `recommendations` (all
`ON DELETE CASCADE`); `reports` keyed by `assessment_id` with JSON entries. Schema
is created via `create_all`; versioned Alembic migrations are a future module.

## Unit of Work & transactions (Module 4.2)

Two transaction-ownership styles share one core (`_operations.py`):

- **Autocommit repositories** (`repositories.py`) — one transaction per call.
  What Module 3.2's single-write use cases resolve today.
- **Unit of Work** (`unit_of_work.py`) — one transaction spanning many
  operations, for atomic multi-aggregate writes.

```python
from kingsec.application import UnitOfWorkFactory

uow_factory = app.resolve(UnitOfWorkFactory)   # after register_unit_of_work(...)
with uow_factory() as uow:
    assessment = uow.assessments.get(assessment_id)
    assessment.complete()
    uow.assessments.save(assessment)
    uow.reports.save(report)
    uow.commit()          # both writes commit together, or neither does
```

**Safe-by-default semantics:** changes persist only if `commit()` is called. On
an exception, or a clean exit without commit, the Unit of Work rolls back — so a
forgotten commit loses the work loudly rather than persisting half of it.

**DI:** `register_unit_of_work(container, session_factory)` binds a
`UnitOfWorkFactory` (a *factory*, not a singleton, so each transaction gets a
fresh session — thread-safe for the future web layer).

Wire both at the composition root:

```python
engine = register_persistence(app.container, app.settings)
register_unit_of_work(app.container, create_session_factory(engine))
```
