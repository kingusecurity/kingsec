# KingSec — Screen 6: PDF Report (Design Spec)

| | |
|---|---|
| **Screen** | 6 of 7 — PDF Preview / Report |
| **Version** | 1.0 (v1 requirements frozen) |
| **Status** | Awaiting founder approval |
| **Role** | The ambassador — the only artifact that leaves the building (emailed, printed, shown to managers, presented to clients) |
| **Benchmark** | Reads like Mandiant / Google Cloud / Cloudflare / Microsoft Security |
| **Files** | `KingSec-UI-06-PDF-Preview.html` (screen preview + print-ready; use the browser's Print to see pagination) |

---

## 0. Philosophy — this document does the selling that the app can't

The app is seen by the operator; the **report is seen by the decision-maker** — the CEO, the board, the insurer, the client — in rooms KingSec will never enter. It is therefore the highest-leverage marketing surface in the entire product, and it earns disproportionate polish. Every page must say *"produced by people who know this cold."* And it must do so the KingSec way: **trust is the marketing, honesty is the conversion** — so the report persuades by being genuinely excellent and genuinely honest, never by alarm or hard sell.

**The six sections, and the job each does:**

| Section | Job |
|---|---|
| **1. Executive Summary** | The decision-maker's 30-second read: status, what we found, what it means, in plain business language. |
| **2. Business Risk** | Translate findings into business terms (reputation, continuity, trust) — honestly, without fear-selling. |
| **3. Top Priorities** | The same prioritized three as the app, with time-based effort. |
| **4. Recommended Actions** | A clean action table: what to do, effort, and who can do it. |
| **5. Technical Appendix** | Scope, methodology, evidence for the IT team — and the honest limitations section. |
| **6. About KingSec / Consulting** | A dignified close: who we are, the local-data trust note, and a quiet, educational consulting offer. |

---

## 1. Branding rationale

- **Cover = premium restraint.** A deep trust-blue band carries the KingSec mark; the title is large and confident; the metadata (prepared-for, date, status, prepared-by) is set like a real consultancy cover. **No sales copy on the cover** — professionalism *is* the message. This is the page most people see first, so it must earn credibility in one glance.
- **One brand system, document-grade.** The frozen tokens carry through — trust-blue `#2A3F73`, Inter, restrained semantic colours — so the report is unmistakably the same product as the app. Consistency reads as competence.
- **Calm authority in the data.** Severity and effort use colour + word (never colour alone); the status is amber, not red, because the findings genuinely aren't critical — the same anti-alarm discipline as the app. A report that screams is a report that gets distrusted.
- **Running header/footer on every content page** (logo · "acme.com · Confidential" · page X of 5) — the small signal that says "formal deliverable," and it makes printed pages self-identifying.
- **The honesty section is the signature move.** "What this assessment can — and cannot — tell you" is the most trust-building element in the document *and* the natural, non-salesy bridge to consulting: for what a scan can't cover, a manual review goes further. Honesty and lead-gen, unified.

---

## 2. Print optimization

The report is built to print as cleanly as it renders on screen.

- **True paging:** each section is a `.page` with `page-break-after: always`; the last page clears it, so there are no stray blank pages.
- **`@page { size: A4; margin: 0 }`** with internal padding (`16mm/15mm`), so the cover's colour band can run edge-to-edge while content pages keep proper margins. (Letter is a one-line change.)
- **Colour fidelity:** `print-color-adjust: exact` on the cover band, verdict box, and section markers so brand colour survives the print dialog's "background graphics" default.
- **No orphaned cards:** `break-inside: avoid` on priority cards, stat tiles, the evidence block, the limitations box, and the consulting card, so nothing splits awkwardly across a page boundary.
- **Screen chrome disappears:** the preview toolbar is `display:none` in print — only the document prints.
- **Greyscale-safe:** because severity and effort carry a word (and the icons differ in shape), a black-and-white printout remains fully legible — important, since many recipients print.

---

## 3. Accessibility review

- **Real, selectable text throughout** — nothing important is baked into an image, so the report is screen-reader-navigable, searchable, and (when exported as a tagged PDF) accessible. *Developer note: the production PDF must be exported **tagged**, with a logical reading order and document title, not as a flat raster.*
- **Semantic heading order:** the six sections are real headings in sequence, so assistive tech and PDF bookmarks can navigate them.
- **Severity/effort never by colour alone:** every chip and status pairs colour with a word (and distinct icon shapes), surviving colour-blindness and greyscale.
- **Contrast:** body text and the muted labels meet AA against paper; the cover's white-on-navy is high-contrast.
- **Reading order matches visual order** (cover → summary → risk → priorities → actions → appendix → consulting), so linear navigation follows the intended narrative.
- **Structure over density:** generous spacing and short paragraphs aid cognitive accessibility for non-technical readers — the whole point of the product.

---

## Developer Notes

*Technical considerations for future implementation (no backend code here).*

- **One source of truth.** The report and the Results screen render from the **same underlying result object** (verdict, prioritized findings, effort, evidence), so they can never disagree. Generation is a distinct core call (e.g., `generate_report(assessment_id)` on the Service API) returning a file artifact.
- **Server-side / deterministic rendering.** Produce the PDF from an HTML/CSS template via a headless renderer (or a PDF library) in the core, not by "printing the browser tab," so output is consistent regardless of the user's browser. This HTML *is* effectively that template.
- **Tagged, accessible PDF output (required).** Emit a tagged PDF with document metadata (title, author=KingSec), logical structure, and selectable text — for accessibility and for looking professional in every viewer.
- **Never fabricate; degrade honestly.** All narrative (summary, business-risk, fixes) is AI-generated **grounded in real findings**; if AI enrichment is unavailable, the report still generates with factual findings and a note that plain-English narrative is limited — it never invents.
- **Never paywall criticality.** Any critical/high finding appears fully in the report; white-label (branding removed) is the paid feature for resellers/MSPs, not the visibility of risk.
- **White-label switch.** A build flag swaps the KingSec cover/branding/consulting page for the consultant's own (a Pro feature) — the report structure stays identical.
- **Localization-ready & timestamped.** Date/number formats and copy should be localizable; every page carries the assessed timestamp and a confidentiality line (point-in-time honesty).
- **Sanitized evidence.** The appendix renders structured, escaped engine output — no raw untrusted strings injected into the template.
- **Reference id** on the report ties back to the assessment for support and consulting follow-up.

---

## Future Version 2 ideas (intentionally postponed)

*None ship without explicit approval.*

- **Comparison report** ("since your last assessment: 2 fixed, 1 new") — a before/after page.
- **White-label / co-brand** polish for MSPs (logo, colours, contact) as a first-class Pro flow.
- **Per-finding深 remediation guides** appended for the technical audience who wants step-by-step.
- **Executive one-pager** export (a single-page summary for boards).
- **Signed / watermarked PDFs** for authenticity when reports are forwarded.
- **Multiple formats** (an HTML email-friendly version alongside the PDF).
- **Compliance-mapped view** (findings tagged to SOC 2 / PCI / HIPAA controls) for regulated recipients.

---

*End of Screen 6 spec. The ambassador: premium on the cover, honest in the appendix, quiet in the consulting close — persuading by competence, not alarm. No backend code, no prior screens redesigned, per the freeze. Awaiting approval before Screen 7 (Settings).*
