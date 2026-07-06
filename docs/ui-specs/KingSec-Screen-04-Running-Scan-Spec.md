# KingSec — Screen 4: Running Scan (Design Spec)

| | |
|---|---|
| **Screen** | 4 of 7 — Running Assessment |
| **Version** | 1.0 (v1 requirements frozen) |
| **Status** | Awaiting founder approval |
| **Role** | The emotional centerpiece — users spend the longest here (2–4 min) |
| **Mandate** | Reduce anxiety · build confidence · communicate progress · zero technical jargon |
| **Files** | `KingSec-UI-04-Running-Scan.html` (live auto-demo of the full milestone experience) |

---

## 0. Design philosophy — the emotional problem

This screen exists in an anxious moment: a non-technical person is waiting, unable to act, while software examines the security of something they care about. A spinner and a silent wait would let dread fill the vacuum. So the entire design is built to **fill that time with calm, visible, trustworthy progress**. Three principles:

1. **Show work, not waiting.** Every second should read as *purposeful activity* — named phases completing — not as a hang.
2. **Process language, never result language.** During the scan we say what we're *doing* ("Looking for common exposures…"), never what we're *finding*. Flashing "12 vulnerabilities found!" mid-scan would spike exactly the anxiety we're managing. Findings belong to Screen 5, framed and prioritized.
3. **Calm authority.** The motion is slow and soft; the words are plain and reassuring; nothing shouts. The tone is a competent professional quietly working — not an alarm system.

---

## 1. Milestone-based progress (and why we refuse fake percentages)

A percentage bar implies precision the system doesn't have. Security scans don't advance linearly — one phase finishes in seconds, another crawls — so a "47%" that stalls or jumps *destroys* trust in a security product, the one place trust is everything. Instead:

- **Five named milestones** the user can actually understand, each moving through *upcoming → active → complete*:
  1. Discovering public assets
  2. Checking encryption & security headers
  3. Looking for common exposures
  4. Analyzing and prioritizing findings
  5. Preparing your report
- **A five-segment bar** that fills one segment per completed milestone — honest, because each segment maps to a *real* phase boundary, not an invented fraction.
- **"Step 3 of 5"** rather than a percentage — truthful and legible.

This is honesty as design: we only ever show progress we can actually vouch for. (If a single phase is genuinely long, the honest move is a reassuring "still working…" message — never a fake creeping number.)

---

## 2. Layouts

One centered, single-column composition, fluid across breakpoints — the calm focus is the point, and a divergent multi-column layout would fracture it.

**Desktop (≥ 1024px).** A centered stage (max-width 500px): the site being assessed at top, the radar motif as the visual anchor, the current-activity line beneath it, the segmented progress, the milestone checklist, then reassurance and a low-emphasis "Run in background." Everything on one calm axis; the top bar carries only the brand and a single "Cancel."

**Tablet (600–1023px).** Identical centered stage; spacing holds comfortably. No structural change.

**Mobile (< 600px).** The stage goes near-full-width; the radar shrinks slightly (116px), the activity text steps down a size, and the milestone list and buttons go full-width with touch-comfortable targets. Because the design is already a single centered column, it is effectively mobile-native.

```
        Desktop / Tablet                     Mobile
        ┌──────────────────────┐             ┌──────────────┐
        │   Assessing acme.com │             │ Assessing …  │
        │        (radar)       │             │   (radar)    │
        │  Looking for common  │             │ Looking for  │
        │     exposures…       │             │  exposures…  │
        │  ▰▰▰▱▱   Step 3 of 5 │             │ ▰▰▰▱▱  3/5   │
        │  ✓ Discovering …     │             │ ✓ Discover…  │
        │  ✓ Checking …        │             │ ✓ Checking…  │
        │  ⟳ Looking …         │             │ ⟳ Looking…   │
        │  ○ Analyzing …       │             │ ○ Analyzing… │
        │  ○ Preparing …       │             │ ○ Preparing… │
        │  usually 2–4 min …   │             │ 2–4 min…     │
        │  [ Run in background]│             │ [ background]│
        └──────────────────────┘             └──────────────┘
```

---

## 3. States

- **Running (default).** The live experience above: radar animating, active milestone spinning, others pending/complete, activity line and segments advancing.
- **Leave-and-return.** "Run in background" acknowledges the user can step away; the assessment continues (the job runs in the core, not the tab). On return, the UI resumes at the true current phase; on completion while away, an OS/desktop notification fires. This is what makes a multi-minute wait humane.
- **Complete (success).** The radar resolves into a single calm green check, the line becomes *"Your report is ready,"* the reassurance switches to *"nothing was uploaded — everything stayed on your machine,"* and a primary **"View your results →"** appears (focus moves to it). The success beat is quietly earned, not celebratory-loud. (Live in the demo.)
- **Error / partial (documented for build).** Failures stay calm and honest, never technical: a phase that fails is skipped with the run continuing where safe ("One check couldn't finish — we'll note it in your report."); a total failure shows *"We hit a problem finishing this assessment,"* preserves whatever completed, and offers **Try again**. A partial result is a first-class outcome, not an error screen.
- **Taking longer than usual.** If a phase exceeds its expected window, the activity line softens to *"This part is taking a little longer — still working…"* — reassuring, never a stalled percentage.

---

## 4. Accessibility considerations

- **Announced progress without jargon.** The activity line is an `aria-live="polite"` / `role="status"` region, so screen-reader users hear each phase ("Looking for common exposures… Your report is ready") — the calm narration works non-visually too.
- **Honest progressbar semantics.** The segments carry `role="progressbar"` with `aria-valuemin/max/now` set to the *milestone* count (now 3 of 5), not a fabricated percentage.
- **State never by colour alone.** Milestones use distinct *shapes* — hollow dot (upcoming), spinner (active), check (done) — so status survives colour-blindness and greyscale.
- **Reduced motion.** `prefers-reduced-motion` disables the radar pulse and slows spinners while keeping the discrete milestone updates, so progress is still conveyed without animation.
- **Focus management.** On completion, focus moves to "View your results" so keyboard users are carried forward; all controls are keyboard-operable with visible focus.
- **Contrast & scaling.** Calm palette meets AA; text scales with OS settings; touch targets are comfortable on mobile.

---

## 5. Loading states

The transition *into* this screen is the loading state itself. On Screen 3's "Start," the button already shows a spinner and rotates the same reassuring, jargon-free messages — this screen is the full-page continuation of that moment, and the Welcome logo pulse is the same motif grown up. There is no separate blank "loading" flash; the milestone experience *is* the load, so the user never stares at emptiness.

---

## Developer Notes

*Technical considerations for future implementation (no backend code here).*

- **Milestones are driven by REAL engine events, not timers.** The demo advances on a `setInterval` purely to show the experience. In production, the core engine emits a **phase event** as each stage begins/completes (discovery → TLS/headers → exposure checks → AI triage → report render); the UI maps those to the five milestones. Never synthesize progress.
- **Async job + honest status contract.** The scan runs as a durable async job in the core (per the frozen hexagonal architecture). The UI subscribes to `get_status(job_id)` — via short-interval polling or SSE/WebSocket — which returns a **structured phase + completed-phases list**, *not* a raw percentage, so the client can render milestone progress truthfully.
- **Leave-and-return / notification.** The job's source of truth is server/core-side, so closing the tab must not kill it. On reconnect, resume from the reported phase; on completion-while-away, deliver an OS/desktop notification. "Run in background" is a UI affordance over this reality.
- **Page refresh / reopen must reconnect, not restart (required).** Each assessment has a stable job id. On load, the UI checks for an in-flight job for the current asset and, if found, **rejoins it at its true current phase** — it never kick-starts a fresh scan on refresh. Practically: persist the active job id locally (or re-query the core for running jobs on startup), then resume polling/streaming that job's status. A refresh in the middle of a 3-minute scan should drop the user straight back onto the live progress, exactly where it was.
- **Cancel is a real operation.** "Cancel assessment" (after confirmation) calls `cancel_assessment(job_id)`; the core must stop workers cleanly, release resources, and mark the job canceled so no partial report is generated or persisted. The UI's canceled state reflects this — no report, clean exit, easy restart.
- **"Taking longer than usual" is threshold-driven, not fake.** Each phase carries a soft expected-duration; only when the *real* elapsed time exceeds it does the copy switch to the reassuring longer-wait message. It is never shown speculatively, and it never implies failure.
- **Session recovery on refresh/reopen (required).** Refreshing or reopening the page must **reconnect to the in-flight assessment and resume at its true current phase — never restart the scan**. The running `job_id` is persisted client-side (and validated against the core) so the UI rehydrates milestone state from `get_status(job_id)` on load. If the job already finished while away, land directly on the results; if it was cancelled or lost, show a clear recovery state rather than a blank restart.
- **Cancel confirmation & clean stop.** "Cancel assessment" opens a confirmation that explicitly states no report will be generated; on confirm, call `cancel_assessment(job_id)`, stop workers cleanly, release resources, and show the cancelled state (no partial report). The **"Running locally"** badge is a persistent trust signal that must reflect the true local execution model.
- **Graceful degradation.** A failed phase must not fail the whole run — surface completed work, note what was skipped, and treat partial results as success (this mirrors the architecture's degradation principle, incl. the AI step: if triage fails, still deliver findings, just without plain-English enrichment).
- **Long-phase handling.** Set per-phase soft thresholds; past them, switch the activity copy to a reassuring "still working…" rather than letting the UI look stalled. Enforce an overall timeout that resolves to the partial/error state, never an infinite spinner.
- **Cancel.** "Cancel" calls `cancel_assessment(job_id)`; workers must stop cleanly and release resources.
- **No jargon in the default view.** Any verbose/technical activity log (for consultants) lives behind an off-by-default toggle and is fed from the same structured, sanitized events — the default experience stays plain-language.
- **Performance.** Animations are CSS-driven and must not block the main thread; polling/streaming should be lightweight and backed off appropriately.

---

*End of Screen 4 spec. Milestone-based (no fake percentages), jargon-free, and honest by design. No backend code, and no prior screens redesigned, per the freeze. Awaiting approval before Screen 5 (Results).*
