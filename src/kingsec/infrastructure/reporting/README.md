# Report Generation Adapter — Module 5.3

Implements the application's `ReportGeneratorPort` by rendering a domain `Report`
snapshot into a professional **HTML** document and a **PDF** derived from it.
Infrastructure layer only: the domain and application never import a reporting
library — **WeasyPrint lives solely in `renderer.py`**.

## Architecture & dependency direction

```
Domain (Report snapshot — pure)
   ↓
Application port  (ReportGeneratorPort.render(report) -> RenderedReport)
   ↓
Infrastructure adapter  (ReportGeneratorAdapter)
   ↓
renderer.py  (isolates the PDF library)
   ↓
WeasyPrint / html (external)
```

Dependencies point inward only. `templates.py` is pure standard-library HTML
generation; `renderer.py` is the sole importer of WeasyPrint (lazily, inside the
PDF path).

## Rendering flow

1. `templates.render_report_html(report)` builds a semantic, escaped HTML string.
2. For PDF, `ReportRenderer.to_pdf` passes that HTML to WeasyPrint and returns bytes.
3. `ReportGeneratorAdapter.render` wraps the bytes in a `RenderedReport`
   (`content`, `media_type`, `filename`) — never a library object.

## Report contents

Executive Summary (verdict, action required, totals) · Assessment Information
(target, assessment id, scan date, status) · Risk Summary (counts by severity) ·
Findings (severity, title, status, evidence & recommendation counts) · Conclusion
· Footer with a **company-branding placeholder** (configurable `brand_name`).

> Note: the domain `Report` snapshot (frozen since Module 3.1) carries
> `FindingSummary` entries with **counts**, not full per-finding description /
> evidence / recommendation text. The report renders exactly what the snapshot
> exposes. Richer per-finding detail would require extending the domain snapshot
> (a future domain change, deliberately out of scope for this infrastructure module).

## Output formats

`ReportGeneratorAdapter(output_format="pdf")` (default) → `application/pdf`;
`output_format="html"` → `text/html`. Filenames are deterministic:
`kingsec-report-<assessment_id>.<ext>`.

## Security

- **Every dynamic value is `html.escape`d** — finding data cannot inject HTML.
- **No JavaScript**, **no remote resources** (no external CSS/fonts/images), **no
  `url()` fetches** — a single embedded `<style>` block with a system font stack.
- Deterministic HTML: all content derives from the immutable `Report` (including
  its `generated_at`); nothing is read from the clock at render time.

## Error handling

Every rendering/library exception (HTML build failure, WeasyPrint failure, or a
missing PDF library) is translated to `ReportGenerationError` (KS-REPORT-001). No
WeasyPrint exception escapes infrastructure.

## Dependency injection

```python
from kingsec.infrastructure.reporting import register_reporting
register_reporting(app.container, output_format="pdf", brand_name="AcmeSec")
generator = app.resolve(ReportGeneratorPort)   # ReportGeneratorAdapter
```

## Testing

Unit tests cover HTML section presence, escaping/injection prevention, no
JS/remote resources, determinism, error translation, adapter format selection,
and DI (no PDF library required — HTML path only). Integration tests generate a
**real PDF** and **real HTML**, verify DI wiring, and run the full
`CreateAssessment → StartAssessment → GenerateReport` slice with real SQLite
persistence.
