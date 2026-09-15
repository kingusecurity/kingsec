# Application Layer Foundation — Module 3.2

Use cases and ports for KingSec. This layer orchestrates the domain and defines
the abstract contracts that infrastructure implements. It **depends only on the
domain layer and the standard library** — enforced by a static import test.

## Public API

```python
from kingsec.application import (
    # use cases
    CreateAssessment, SubmitAssessment, GetAssessment, GenerateReport,
    # ports (ABCs implemented by infrastructure)
    AssessmentRepository, ReportRepository,
    ScannerPort, AIPort, ReportGeneratorPort,
    # DTOs
    CreateAssessmentRequest, SubmitAssessmentRequest, GetAssessmentRequest,
    GenerateReportRequest, AssessmentView, RenderedReport, ...,
    # errors
    ApplicationError, InputValidationError,
    AssessmentNotFoundError, ReportNotFoundError,
)
```

## Ports

| Port | Kind | Implemented later by |
|---|---|---|
| `AssessmentRepository`, `ReportRepository` | driven (persistence) | SQLite adapter |
| `ScannerPort` | driven (capability) | Nuclei adapter |
| `AIPort` | driven (capability) | BYO-key AI client |
| `ReportGeneratorPort` | driven (capability) | WeasyPrint renderer |

**ABC over Protocol (justification).** These ports are contracts the application
*owns* and adapters *opt into*. `abc.ABC` gives an explicit, greppable "implements
this port" relationship, and `@abstractmethod` fails fast — an incomplete adapter
can't be instantiated (there's a test for exactly this). Protocol's structural
typing is better when adapting objects you don't control or when you want zero
coupling; here we own both sides and want the explicit contract.

## Use cases

Each is a class with dependencies injected via `__init__` (dependency inversion)
and a single `execute(request) -> response`:

- **CreateAssessment** — builds a `Target`, creates the assessment, captures
  `Authorization` up front (trust-first), persists it (→ `AUTHORIZED`).
- **SubmitAssessment** — enforces the authorization gate (`assessment.start()`),
  submits the scan to a `JobRunner` for background execution (async
  counterpart of the old synchronous `StartAssessment`, removed as dead code
  in Phase 2C Step 2 — zero real callers, and its unconditional
  `assessment.complete()` bypassed Phase 2A's success-counting policy).
- **GetAssessment** — loads and maps to an `AssessmentView` (no domain leak).
- **GenerateReport** — builds the immutable `Report` snapshot (domain requires
  `COMPLETED`), persists it, renders a deliverable via `ReportGeneratorPort`.

## DTOs

Flat, immutable (`frozen=True`) bags of primitives. Callers speak strings/ints;
use cases own the translation to/from domain types. Domain objects never cross
the boundary — `from_domain` mappers convert on the way out.

## Error boundary policy

- **Input / persistence problems → application errors** (`InputValidationError`,
  `AssessmentNotFoundError`). These are what a use-case caller handles.
- **Domain-rule violations → propagate as domain errors** (`IllegalStateTransition`
  for the authorization gate and "report needs a completed assessment"). They are
  precise signals; a further-out boundary translates them to transport responses.

## Integration seam — next module (infrastructure)

- Implement the ports as adapters: `SqliteAssessmentRepository(AssessmentRepository)`,
  etc. — each subclasses the ABC.
- The **composition root (2.4)** registers concrete adapters on the container and
  injects them into these use cases — no application/domain code changes.
- The **web layer** will translate application + domain errors into HTTP responses
  using the `ExceptionHandlerRegistry` from 2.4.
