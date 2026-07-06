# KingSec — Screen 5: Results (Design Spec)

| | |
|---|---|
| **Screen** | 5 of 7 — Results |
| **Version** | 1.0 (v1 requirements frozen) |
| **Status** | Awaiting founder approval |
| **Why it matters most** | This screen decides whether a business owner trusts KingSec enough to become a consulting client |
| **Mandate** | Answer four questions, in under 10 seconds, without overwhelming anyone |
| **Files** | `KingSec-UI-05-Results.html` (interactive: expandable fixes + reveal-on-request technical evidence) |

---

## 0. Philosophy — the whole product resolves here

Everything before this screen was setup; this is the payoff, and it is where the product's thesis ("trust is our marketing; honesty is our conversion") is won or lost. The design obeys one discipline: **conclusions first, evidence last.** A non-technical owner should look once and *know where they stand* — then choose how much further to go. This is the inverted pyramid, and it is the opposite of how every scanner presents data (a wall of findings), which is precisely why KingSec exists.

**The four questions, mapped to the layout:**

| Question | Where it's answered |
|---|---|
| **1. Am I safe?** | The Overall Security Status card — one plain-language verdict + a calm severity breakdown, readable in seconds. |
| **2. What should I fix first?** | "Fix these first" — exactly three prioritized issues, in order, in plain words. |
| **3. How difficult are the fixes?** | An effort chip on each priority (Quick fix / Moderate / Needs an expert). |
| **4. Where do I get help?** | A quiet "a KingSec specialist can help" panel — offered as service, never a pitch. |

Everything else — per-issue fix steps and the raw technical evidence — is **hidden behind progressive disclosure**, so the default view stays a 10-second read.

---

## 1. The 10-second test

Above the fold, in order of the eye's path: the site + a **Download PDF** button (the deliverable is immediately reachable), then the **verdict** ("Needs attention," one honest sentence, and "1 this week · 2 when you can · 4 minor"). A first-time user has their answer to *"Am I safe?"* before reading anything else. The three priorities sit right below for *"what do I do,"* each carrying its difficulty. Nothing competes; nothing shouts.

**Deliberate calm:** the status uses **amber, not red**, because the example finding set is genuinely *not critical* — and drowning a non-expert in red teaches them to ignore the tool. Red is reserved for genuinely critical outcomes. Severity is shown as **colour + icon shape + word**, never colour alone.

---

## 2. Anti-overwhelm decisions

- **Three priorities, hard cap.** Not thirty findings. The AI's job is to choose the three that matter; the rest live in the report and a one-line "4 minor items… none are urgent."
- **Plain language only, on the surface.** "Outdated encryption is still allowed," not "TLS 1.0 enabled / weak cipher suites." The technical truth exists — one click away, cordoned in monospace "for your IT team."
- **Progressive disclosure everywhere.** How-to-fix is collapsed per issue; the entire technical evidence block is hidden until "View technical details" is pressed.
- **One primary action.** Download the PDF. Everything else (technical details, new assessment) is visibly secondary.

---

## 3. The consulting on-ramp (honest, not salesy)

Per our trust design layer, the ask on this screen is **quiet, singular, and earned by the content**: the third priority is legitimately "Needs an expert," so the help panel reads as a *natural consequence*, not an interruption — "some fixes are safer with an expert… a KingSec specialist can help." It is offered as service to someone who has just been shown a task beyond them. There is **no fear language and nothing critical is hidden behind it** — the two cardinal sins we refuse. This is honesty-as-conversion: the same transparency that builds trust also opens the door to help.

---

## 4. Self-critique — three lenses

**Apple's Head of Product — "did you actually keep it to 10 seconds?"**
Praise: the verdict-first hierarchy and the three-cap are right; most teams would dump the full findings table here and call it "powerful." Push: watch the density creep — the verdict card, breakdown chips, three cards, help panel, and action row are *a lot* stacked together. Make sure the verdict truly dominates the first screen and the rest feels like it's *below* the fold, not crowding it. Consider whether the breakdown chips ("2 when you can · 4 minor") are even needed on first paint, or whether the single sentence carries it. Verdict: protect the verdict's breathing room; resist adding a fourth thing.

**Cloudflare's Design Lead — "the calm state is easy; design the honest edges."**
Praise: hiding technical evidence by default with a clean reveal is exactly right, and the plain-language layer over real data is the hard part done well. Push: this screen must also gracefully render the states the demo doesn't show — an **all-clear "Looking good"** result (make good news feel earned, not empty), a **genuinely critical** result (red, unambiguous, still calm), and a **partial/degraded** result where the AI enrichment failed (show findings ranked by severity, honestly flag that plain-English guidance is unavailable, never fabricate). The effort ratings are a *claim* — they must come from real signal, or they erode trust. Verdict: the four questions are answered for the happy path; now answer them for every path.

**CEO of a cybersecurity consultancy — "does a business owner trust this enough to call us?"**
Praise: this is the whole funnel, and it's pitched correctly — the owner feels informed and capable, the expert door is open exactly where they'd feel out of their depth, and there's zero manipulation. The honest "none are critical" *builds* the credibility that converts. Push: make sure the help panel is present but never leans harder than the content warrants — the moment it feels like the point of the screen, trust drops. And the **PDF is the real ambassador** (it leaves the building): this screen's job is partly to make downloading it feel obvious, which it does. Verdict: right trust posture; guard it as we tune.

**Reconciliation.** Simplicity (Apple), robustness across result-states (Cloudflare), and earned trust (CEO) don't conflict: **keep the verdict dominant and the three-cap firm, build the other result-states (all-clear, critical, partial) to the same honest bar, ground effort ratings in real signal, and keep the help panel quiet.** No redesign — these are completeness and tuning.

---

## Developer Notes

*Technical considerations for future implementation (no backend code here).*

- **The "top 3" is an AI-prioritization output, not the raw scan.** The core ranks normalized, deduplicated findings by contextual risk (exposure + exploitability + asset criticality, beyond raw CVSS) and returns a small prioritized set; the UI shows the top three and files the rest into the report. Ranking must be explainable and reproducible.
- **Plain-language + effort come from the AI layer, over real data.** Titles, "why it matters," fix guidance, and the effort rating are generated grounded in actual findings (RAG), clearly derived — never invented. Effort should map to real signal (e.g., config change vs. version upgrade), not a guess.
- **Graceful degradation (required).** If the AI enrichment step failed but the scan succeeded, render findings ranked by severity with a clear "plain-English guidance unavailable — showing raw severity" note. The screen must never fabricate a verdict or fixes. (Mirrors the architecture's degradation principle.)
- **Result-state matrix to build:** all-clear ("Looking good," positive/earned), needs-attention (shown), critical (red, unambiguous, still calm), and partial/degraded. Each answers the same four questions.
- **Never paywall criticality.** Any critical/high finding is always fully visible on this screen and in the report — Premium may gate depth/monitoring/white-label, never the visibility of a real risk. This is a hard product rule.
- **Technical evidence is sanitized and read-only.** The revealed block is structured, escaped output from the engine (no raw untrusted strings injected into the DOM), cordoned as "for your IT team."
- **PDF export uses the same underlying result object** as this screen, so the report and the screen never disagree; generation is a separate core call (see Screen 6).
- **Point-in-time honesty.** The result reflects the moment it was run; the UI/report should carry the assessed timestamp and never imply permanent safety.
- **Accessibility hooks** as in §Accessibility below (aria-expanded on the disclosure, focus handling, colour-independent severity).

---

## Version 2 ideas (intentionally postponed)

*None ship without explicit approval.*

- **Trend / change-over-time** ("since your last assessment, 2 fixed, 1 new") — deferred to keep v1 free of analytics.
- **Assign / track remediation** (mark fixed, assign to a teammate, re-verify).
- **"Explain this to me" per finding** — an inline AI expander for the curious.
- **Ticketing / Slack export** of a specific priority.
- **Shareable read-only result link** (hosted) for owners who want to send the screen, not the PDF.
- **Per-issue "book a fix" ** consulting hand-off with context attached.
- **Filter/search** within the full findings list (only once lists routinely get long).

---

## Accessibility review

- **Verdict is readable non-visually:** the status word and sentence are real text (not baked into an image), so screen readers convey "Needs attention…" directly.
- **Severity never by colour alone:** every breakdown chip and effort chip pairs colour with a distinct **icon shape** and a **word**, surviving colour-blindness and greyscale printing of the PDF.
- **Progressive disclosure is announced:** "View technical details" is a real `<button>` with `aria-expanded` toggling true/false; per-issue "How to fix" uses native `<details>` (keyboard- and screen-reader-friendly by default).
- **Keyboard-complete with visible focus:** every control — download, disclosures, help link, new assessment — is reachable and operable by keyboard with a visible focus ring.
- **Contrast & scaling:** the calm palette meets AA (the muted amber/blue/green are chosen partly *because* neon fails contrast); text scales with OS settings; the layout reflows to a single column on mobile with comfortable targets.
- **Reduced motion:** the only motion is a small chevron rotation, which honours `prefers-reduced-motion`.
- **Reading order:** DOM order matches visual order (verdict → priorities → help → actions → evidence), so linear/AT navigation follows the intended conclusions-first path.

---

*End of Screen 5 spec. Conclusions first, evidence on request, four questions answered in under ten seconds — and the consulting door opened honestly. No backend code, no prior screens redesigned, per the freeze. Awaiting approval before Screen 6 (PDF Preview).*
