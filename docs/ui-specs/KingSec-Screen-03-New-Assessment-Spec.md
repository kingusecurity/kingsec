# KingSec — Screen 3: New Security Assessment (Design Spec)

| | |
|---|---|
| **Screen** | 3 of 7 — New Security Assessment |
| **Version** | 1.0 (v1 requirements frozen) |
| **Status** | Awaiting founder approval |
| **Audience** | Small businesses, IT admins, consultants, MSPs — **not** pentesters |
| **Design north star** | A first-time user starts a real assessment in **under 30 seconds**, no documentation |
| **Files** | `KingSec-UI-03-New-Assessment.html` (interactive: validation, error, and loading states are live) |

---

## 0. Objective

Make the fastest, simplest way to start a security assessment that still behaves responsibly. Success is measured in seconds-to-start and in whether a non-technical business owner ever feels lost. The entire screen is **two inputs and one button** — everything else is reassurance, not data entry.

---

## 1. Field audit — "does this need to exist in v1?"

Every candidate field was challenged. Only two survived.

| Field | Verdict | Reasoning |
|---|---|---|
| **Website address** | ✅ Keep | The one irreducible input. |
| **Authorization confirmation** | ✅ Keep | Legally and ethically required; you cannot let anyone scan arbitrary targets. One checkbox. |
| Scan depth (quick / standard / deep) | ❌ Cut | A business owner has no basis to choose. One sensible default, hidden. |
| Ports / check categories / intensity | ❌ Cut | Pentester vocabulary; meaningless and intimidating here. |
| Login credentials (authenticated scan) | ❌ Cut | Advanced, rare, and a data-sensitivity liability → V2. |
| Schedule / recurring | ❌ Cut | Belongs to a post-result nudge, not the start form → V2. |
| Assessment name / label | ❌ Cut | Site + date names it automatically. |
| Email / notifications | ❌ Cut | No account; desktop notification handles completion. |
| AI key | ❌ Cut (this screen) | Deferred until after the "aha"; the scan runs without it. |
| Compliance framework (SOC 2 / HIPAA / PCI) | ❌ Cut | Scope creep for v1 → V2. |

**Result:** URL + checkbox. Time-to-start is bounded by how fast someone can type their domain and tick a box — comfortably under 30 seconds.

---

## 2. Layouts

A deliberate decision: this screen uses **one fluid composition**, not three bespoke layouts. A two-field form does not benefit from divergent desktop/tablet/mobile designs — one centered card that reflows is less to build, less to test, less to break, and looks identical (and trustworthy) everywhere. The single card is defined once and adapts by breakpoint.

**Desktop (≥ 1024px).** The card (max-width 480px) floats centered on the calm canvas, vertically and horizontally. The top bar carries only the brand and a single "Cancel" exit — no competing navigation — so attention falls straight down the card: heading → address → what-it-checks → authorization → start. Maximum focus for the primary task.

**Tablet (600–1023px).** Identical centered card; the 480px cap keeps line lengths comfortable with generous margins. No layout change is needed or made — the composition already fits, and consistency is a feature.

**Mobile (< 600px).** The card relaxes to near-full-width with tightened padding (26px), so it reads as a full-screen focused task. Inputs and the button are full-width with touch-comfortable targets; the checkbox row, disclosure, and info line stack naturally in a single column (the card is single-column by design, so it is effectively mobile-first). The "Cancel" affordance stays reachable in the top bar.

```
 Desktop / Tablet                         Mobile (< 600px)
 ┌───────────── top bar ─────────────┐    ┌──── top bar ────┐
 │ KingSec                    Cancel │    │ KingSec  Cancel │
 └───────────────────────────────────┘    └─────────────────┘
                                            ┌───────────────┐
        ┌───────────────────────┐          │ New security  │
        │  New security assess. │          │ assessment    │
        │  Website address      │          │ [ address    ]│
        │  [ yourcompany.com  ✓]│          │ what checks ▸ │
        │  what does it check ▸ │          │ [x] authorized│
        │  [x] I'm authorized   │          │ [   Start    ]│
        │  [   Start assessment]│          │ data stays 🔒 │
        │  data stays on machine│          └───────────────┘
        └───────────────────────┘
```

---

## 3. UX rationale

- **One obvious action.** There is exactly one thing to do: type your website. Nothing competes.
- **Forgiving input.** Paste `https://…`, a `www.`, or a bare domain — it normalizes silently. Users are never punished for formatting.
- **The button can't strand you.** It stays disabled until the two real requirements are met, and (new) once the URL is valid it actively *nudges* the remaining step ("Confirm you're authorized to continue"), so the last action is never a mystery.
- **Expectation-setting, not choice.** "Standard assessment · about 2–4 minutes" tells users what they're committing to without asking them to decide anything.
- **Transparency on demand.** "What does this check?" is collapsed by default — available for the curious, invisible to everyone else.
- **Sub-30-second path:** land → type domain → tick box → Start. No account, no options, no reading.

---

## 4. Trust rationale

*"Would this make a business owner trust KingSec?"*

- **Honest scope gate.** The authorization checkbox reads as care and lawfulness, not bureaucracy — exactly the signal a risk-averse buyer wants.
- **Data-locality claim, placed at the hesitation point.** *Your site's data never leaves your machine* sits right by the Start button — a rare, true, differentiating claim.
- **No manufactured fear, no upsell.** Per our philosophy ("trust is our marketing; honesty is our conversion"), this screen sells nothing. It just gets you moving, competently.
- **Plain language throughout.** Nothing here requires security vocabulary, which itself signals "this tool is for you."

---

## 5. Accessibility considerations

- **Keyboard-complete:** the whole flow (field → checkbox → button) is operable without a mouse; visible focus rings on every control.
- **Errors announced:** the inline error uses `role="alert"` so assistive tech speaks it; it is never conveyed by colour alone (icon + text).
- **Disabled button has a non-colour cue:** the authorization nudge gives a textual reason rather than relying on the greyed state.
- **Targets & text:** touch-comfortable hit areas, 16px input text (prevents mobile zoom), respects OS text scaling.
- **Motion:** the card entrance and the loading spinner honour `prefers-reduced-motion` (spinner slows, entrance disabled).
- **Labels:** the input has a real `<label>`; the checkbox label is fully clickable.

---

## 6. States

**Empty (default).** The pristine form: address field with placeholder `yourcompany.com`, collapsed "what does this check?", unchecked authorization, disabled Start. This *is* the screen's resting state — clean and inviting, nothing to dismiss.

**Validation.**
- *Valid:* a green check appears inside the field once the address is well-formed. Reassurance in real time.
- *Invalid (on blur):* the field turns to the error style and a plain-language message appears — *"That doesn't look like a website address. Try something like yourcompany.com."* — clearing automatically as soon as the input becomes valid or empty. (Live in the HTML.)
- *Authorization nudge:* when the URL is valid but the box is unticked, the checkbox row highlights and its helper text switches to *"Confirm you're authorized to continue,"* making the final step obvious.

**Error (beyond format — documented for implementation).** Distinct, plain-language handling per failure, each recoverable:
- *Unreachable / doesn't resolve:* "We couldn't reach that website. Check the address, or try again." (Ideally caught by a fast pre-check before committing to a multi-minute scan.)
- *No internet:* "KingSec needs a connection to check your site." with retry.
- *Blocked target (guardrail):* if the address resolves to an internal/reserved range or an obviously-out-of-scope target, refuse clearly: "For safety, KingSec can only scan public websites you control." (This is the technical half of the authorization promise.)

**Loading.** On Start, the button becomes a spinner + *"Starting assessment…"* and disables to prevent double-submit — the first beat of the transition into Screen 4, where the calm logo pulse grows into the full scan animation. (Live in the HTML.)

---

## 7. Self-critique — three lenses

**Apple's Head of Product — "protect the 30 seconds."**
Praise: two inputs is the right answer; most teams would have shipped eight. Push: audit every remaining pixel against the speed goal. The "What does this check?" disclosure and the info line are justified (they set expectations and reduce anxiety) — but the copy must stay tight; a single wasted clause is friction. Verdict: keep the structure, keep it collapsed, resist adding a third element ever.

**Cloudflare's Design Lead — "the happy path is easy; robustness is the job."**
Praise: forgiving input and real-time validation are correct. Push: the *error* surface is where this screen lives or dies in the field — unreachable, timeout, and blocked-target must be *distinct* messages, not one generic failure, and the pre-flight reachability check matters so a typo fails in 2 seconds, not after a 3-minute scan. The disabled-button reason (now the nudge) was a real gap — good that it's fixed. Ensure `role="alert"` and focus handling are solid. Verdict: harden the states and the backend guardrails; the UI is doing its half.

**CEO of a cybersecurity consultancy — "does a business owner (and a consultant) trust this?"**
Praise: the careful authorization gate and the data-locality line are exactly the credibility signals that convert in this market, and there's zero salesiness — correct. Push: *"I own this website"* still reads owner-first, but a large slice of our audience are **consultants and MSPs scanning clients' sites** — the "or have permission to test it" wording covers them, but a first-class "on behalf of a client" mode (with stronger verification) is a real V2 need. Verdict: right trust posture for v1; accommodate the consultant case properly later.

**Reconciliation.** Speed (Apple) + robustness (Cloudflare) + trust-and-consultant-fit (CEO) converge cleanly: **keep the two-input form, keep the disabled-button nudge, harden the error states and backend scope guardrails, tighten copy, and defer the consultant "on behalf of" mode to V2.** No conflict requires a redesign.

---

## Developer Notes

*Technical considerations for future implementation (no backend code here).*

- **Input normalization (authoritative in the core, not the UI).** Lowercase, trim, strip scheme/path/query, handle `www.`, convert IDN/Unicode domains to punycode (ASCII), reject whitespace. The client's regex is a *forgiving* pre-filter only; the Service API's `start_assessment` use case owns real validation.
- **Reachability pre-check (recommended).** Before committing to a multi-minute scan, do an async DNS resolution + lightweight HTTP `HEAD` with a short timeout, debounced, non-blocking to typing. Fail typos fast and kindly.
- **Authorization guardrails (backend, non-negotiable).** The checkbox is necessary but not sufficient. The engine must block RFC 1918 / reserved / loopback ranges, cloud metadata IPs (e.g., `169.254.169.254`), and obviously-not-yours patterns, and enforce scope. This is the "responsible by construction" requirement from the security architecture.
- **Wiring to the core.** On submit, the UI calls the Service API `start_assessment(target, context)` → receives a **job id** → navigates to Screen 4 (Running Scan), which polls status/progress. Matches the hexagonal core + job-based Service API we froze — the UI stays a thin wrapper.
- **Double-submit / idempotency.** The loading state disables the button; the start call should carry an idempotency key so retries don't spawn duplicate scans.
- **Privacy & security.** Don't persist the raw URL beyond the assessment record; no secrets in the client; escape any reflected input; rate-limit assessment starts per app instance.
- **Accessibility hooks.** `role="alert"` on the error node; move focus to the field on error; ensure the nudge text is announced.
- **No AI key required here.** Limited mode runs the scan; plain-English guidance (which needs the key) is prompted later per the frozen flow.

---

## Future Enhancements (Version 2+)

*Intentionally postponed to protect the two-input, sub-30-second v1. None ship without explicit approval.*

- **Scan depth** (collapsed "Advanced options": quick vs deep).
- **Authenticated scanning** (credentials / session) for areas behind a login.
- **Scheduled / recurring assessments** (offered as a post-result nudge, not a form field).
- **Consultant / MSP "on behalf of a client" mode** — with stronger ownership verification (DNS TXT or file token) replacing the simple attestation for client sites.
- **Multiple / bulk targets** and **asset groups**.
- **Compliance presets** (SOC 2 / HIPAA / PCI mapping).
- **Non-website targets** (IP ranges, cloud accounts via read-only roles).
- **Saved scan profiles** and **integrations** (Jira / Slack / CI trigger via API).

---

*End of Screen 3 spec. No backend code, no prior screens redesigned, per the freeze. Awaiting approval before Screen 4 (Running Scan).*
