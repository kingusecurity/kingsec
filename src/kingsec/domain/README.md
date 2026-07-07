# Domain Model Foundation — Module 3.1

The pure business core of KingSec. This layer has **no outward dependencies** —
standard library only, no infrastructure, no application, no shared kernel, no
third-party packages. Purity is enforced by a static test (`import`-scan) as well
as by review.

## Public API

```python
from kingsec.domain import (
    # aggregate + entity
    Assessment, Finding,
    # value objects
    AssessmentId, FindingId, Target, TargetType, Authorization,
    Evidence, Recommendation, Report, Verdict, FindingSummary,
    # enums
    Severity, AssessmentStatus, FindingStatus,
    # errors
    DomainError, InvariantViolation, IllegalStateTransition,
)
```

## Model at a glance

| Type | Kind | Notes |
|---|---|---|
| `Assessment` | aggregate root | owns the lifecycle and all findings; identity equality |
| `Finding` | entity | own status lifecycle; accrues evidence/recommendations; identity equality |
| `Evidence`, `Recommendation` | value objects | immutable, value equality |
| `Target`, `Authorization`, `AssessmentId`, `FindingId` | value objects | immutable, validated |
| `Report`, `Verdict`, `FindingSummary` | snapshot value objects | immutable, built from a completed assessment |
| `Severity`, `AssessmentStatus`, `FindingStatus` | enums | `Severity` is ordered |

## The authorization gate (the invariant that defines KingSec)

`RUNNING` is reachable only from `AUTHORIZED`, and `AUTHORIZED` only via
`authorize(Authorization)`. So an assessment that was never authorized can never
start — enforced in the purest layer, independent of any infrastructure check.

```
DRAFT ─authorize()→ AUTHORIZED ─start()→ RUNNING ─complete()→ COMPLETED
  │                     │                   │
  └─────────┬───────────┴────────┬──────────┼─fail()→ FAILED
            ▼                     ▼          ▼
         CANCELLED ◀──────── cancel() ◀──────┘
```

Findings may be recorded **only while RUNNING**; a `Report` may be generated
**only from a COMPLETED** assessment.

## Design decisions

- **Local errors, not the shared kernel.** The domain defines its own
  `DomainError`/`InvariantViolation`/`IllegalStateTransition` so it imports
  nothing outward. The application layer translates these to `KingSecError` at
  the boundary (next modules).
- **Value objects are frozen dataclasses; entities are controlled-mutation
  classes.** Value objects get immutability + value equality for free; entities
  keep state private and mutate only through intention-revealing methods, so
  invariants can't be bypassed by attribute assignment.
- **Entity equality is by id**; value-object equality is by content.
- **`Report` is a true snapshot** — findings are copied into immutable
  `FindingSummary` value objects, so a report never drifts if entities change.
- **Honest reporting** — severity counts cover all findings; the verdict is
  derived from actionable findings (false positives excluded).

## Integration seam — next module (application / persistence)

- **Repository ports** will define `save(assessment)` / `get(id)` in terms of
  these domain types; the domain stays unaware of how it's stored.
- **`DomainError → KingSecError` translation** happens in the application layer,
  not here.
- **Reconstitution:** persistence will need to rebuild an `Assessment` in a
  given state from stored rows; a dedicated reconstitution constructor/factory
  can be added at that point without weakening the public lifecycle methods.
