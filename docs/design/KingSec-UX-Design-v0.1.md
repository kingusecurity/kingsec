# KingSec — Product & User Experience Design (v0.1)

| | |
|---|---|
| **Document** | Product / UX / UI Design Specification |
| **Product** | KingSec — local web application (reusable Python core) |
| **Version** | 0.1 (Draft — for review) |
| **Status** | Awaiting founder approval |
| **Design target** | A non-technical business owner ("the CEO") — with notes on the real operator |
| **North-star test** | *A first-time user completes a full assessment and downloads a report without reading any documentation.* |
| **Constraint** | Design only — no code, no images (text wireframes) |

---

## 0. Design brief (read this first)

**Who we are actually designing for — and the tension I resolved.** You asked me to design for "a CEO with no cybersecurity background." But the architecture we agreed on assumes the operator is often an IT generalist. These are different people, and pretending otherwise produces a muddled product. My resolution, which shapes every decision below:

- **The interface is designed to the *lowest* skill bar** — a business owner with zero security knowledge must be able to drive it. If the CEO can use it, the IT person certainly can. Designing "up" from the CEO is safe; designing "down" from an expert is not.
- **The real clicker is often the champion** (an IT contractor, office manager, or the one technical person), acting *for* the CEO. The design serves them without alienating the CEO.
- **The CEO-facing artifact is the PDF report**, not the app. The report is where "explain it to a board / an insurer" happens. It gets as much design care as the app itself — arguably more, because it's the thing that gets forwarded.

**The one guiding decision: this is a *guided flow*, not a dashboard.** The instinct for a "SaaS product" is to build a console — sidebar, many tabs, a dashboard home. For a tool whose entire job is *run one assessment → get one answer → download one report*, that chrome is noise. KingSec v1 is a **single, linear, guided path** with two quiet secondary areas (history, settings). Everything in this document bends toward that. The critique at the end enforces it.

**The product's emotional job.** Security is scary and shameful for non-experts ("what if I'm exposed and look foolish?"). The design must feel **calm, competent, and non-judgmental** — a trusted advisor, not a blaring alarm. This is why the visual language is calm blues and generous whitespace, *not* a wall of red (§11), and why copy is plain and reassuring, never condescending.

---

## 1. Complete user flow

The end-to-end path, first-time user, happy path plus the critical branches:

```
   OPEN APP (localhost)
        │
        ▼
   FIRST RUN?  ──yes──►  WELCOME + ONE-TIME SETUP
        │                 (connect an AI key · plain "why")
        │no                     │  key tested OK
        ▼                       ▼
   ┌─────────────────────────────────────────┐
   │  START AN ASSESSMENT                     │
   │  • enter what to check (your website)    │
   │  • confirm you're allowed to (attest)    │
   │  • [Start]                               │
   └───────────────┬─────────────────────────┘
                   │  input valid + reachable + attested
                   ▼
   RUNNING  (plain-language progress · est. time · reassurance)
        │
        │  finished (fully OR partially)
        ▼
   ┌─────────────────────────────────────────┐
   │  RESULTS                                 │
   │  • Health grade + one-line meaning       │
   │  • "Fix these first" (top 3)             │
   │  • [Download PDF report]                 │
   │  • (disclosure) full findings for techies│
   └───────────────┬─────────────────────────┘
                   │  [Download]
                   ▼
   PDF REPORT  (exec summary → technical appendix)  ──►  DONE
                   │
                   └──►  optional: [Run again later] / share with IT
```

**Branches that matter (designed in §2 and §17):**
- No/invalid AI key → guided fix, cannot start a scan until resolved (graceful, explained).
- Bad/typo domain, or domain won't resolve → validation + suggestion, cannot start.
- Not attested → cannot start (trust/legal gate — see §2 Screen 2).
- Scanner partly fails → **partial results shown honestly**, not a dead end.
- AI enrichment fails (key out of credits, provider down) → **findings still shown, plainly organized, with a "plain-English explanations unavailable — retry" banner.** The scan is never wasted.

---

## 2. Screen-by-screen breakdown

For each screen: **Sees · Clicks · System does · Background · Info shown · Errors · Error handling · Next.** (This is the structure you asked for, applied to the minimal screen set.)

### Screen A — Welcome & one-time setup (first run only)

- **Sees:** A calm welcome ("KingSec checks your business for security weaknesses and tells you what to fix — in plain English"). A single setup step: *Connect an AI assistant.* A plain-English "Why do I need this?" expander. A single field to paste a key, a link to get one, and a **[Test & continue]** button. A reassuring line: *"Your key and your results stay on this computer. Nothing is uploaded to us."*
- **Clicks:** "Why do I need this?" (optional) → pastes key → **[Test & continue]**.
- **System does:** Validates the key by making one tiny, cheap test call; on success, stores it locally (see §17 for how) and advances to Start.
- **Background:** Stores the key in the OS-appropriate secure location; records that first-run is complete; loads default assessment settings.
- **Info shown:** What KingSec does, what a key is (one sentence), the privacy promise, cost expectation ("a full check typically costs a few cents of AI usage").
- **Errors:** Empty key; malformed key; key rejected by provider; provider unreachable (offline).
- **Error handling:** Inline, specific, non-scary. *"That key wasn't accepted by the provider — double-check you copied all of it."* / *"Can't reach the internet — KingSec needs a connection to run checks."* Never a raw provider error string. Offers a **[Try again]** and keeps whatever they typed.
- **Next:** → Start an assessment. (This screen is skipped on every subsequent launch.)

### Screen B — Start an assessment (the true home for returning users)

- **Sees:** One dominant input: *"What should we check?"* with an example placeholder (`yourcompany.com`) and a one-line helper (*"Enter your website or business domain — the part after @ in your email works too."*). Below it: a single, clear **attestation checkbox** — *"I confirm I own this, or I have permission to test it."* — with a short "Why we ask" link. A large **[Start check]** button. Nothing else competing for attention.
- **Clicks:** Types the target → ticks the attestation → **[Start check]**. (Optional: an unobtrusive "Advanced options" link, collapsed by default.)
- **System does:** Validates and normalizes the input (strips `http://`, `www`, paths); checks the target resolves and is reachable; confirms attestation is ticked; then enqueues the assessment job on the Python core and routes to Running.
- **Background:** Calls the core's *start-assessment* use case with the normalized target, a fresh job id, and the (single-user) context; the core hands work to scanner adapters. Records the attestation with a timestamp (accountability).
- **Info shown:** The one input, the attestation, expected duration ("about 5–15 minutes"), and the privacy line repeated subtly.
- **Errors:** Empty/invalid input; obvious typo (`gmail,com`); target won't resolve; target unreachable; **attestation unticked**; a private/reserved address entered (e.g., `192.168.x.x` or `localhost`).
- **Error handling:** *"That doesn't look like a web address — did you mean `gmail.com`?"* / *"We couldn't find that address online — check the spelling."* / **attestation:** the **[Start check]** button stays disabled with a gentle inline note (*"Please confirm you're allowed to test this — here's why"*) rather than an error after the fact. Private-range input → *"That's an internal address. KingSec v1 checks internet-facing assets."* (and a note that internal scanning is a future capability).
- **Next:** → Running.

> **Design + security note (ties to the SRS §17):** For a *local* toolkit the user runs on their own infrastructure and is legally responsible for, a clear **attestation + scope confirmation** is the honest, humane baseline — a cryptographic DNS-ownership challenge would be a terrifying wall for this persona. When KingSec becomes SaaS (where *we* bear liability), stronger verification (DNS TXT / file token / verified cloud role) becomes mandatory. The attestation is designed as a *trust-building* moment ("we take this seriously, and so should you"), not fine print.

### Screen C — Running (the long-wait experience)

- **Sees:** A calm progress screen with the target shown, a progress indicator, an **estimated time remaining**, and a **plain-language current step** that changes as work proceeds: *"Mapping what's visible online… Looking for exposed services… Checking for known weaknesses… Writing your plain-English summary…"* A reassuring line: *"You can leave this running — we'll let you know when it's done."* A subtle **[Cancel]**.
- **Clicks:** Nothing required. Optionally **[Cancel]**, or navigates away (the job continues; §19 notifies on completion).
- **System does:** Polls the core's *get-status* use case for stage + progress + partial findings; updates the plain-language step; on completion routes to Results.
- **Background:** Scanner adapters run (Nmap/Nuclei etc.); findings stream into the core, get normalized/deduped/scored; the AI adapter generates plain-English enrichment near the end.
- **Info shown:** Target, progress, time estimate, human-readable stage, and a "so far we've found N things to review" running count (framed neutrally, not alarmingly).
- **Errors:** A scanner times out or crashes; the whole scan fails to start; the machine goes to sleep / connection drops mid-run; user cancels.
- **Error handling:** A single failed scanner → continue with the rest and mark that check as "couldn't complete" in results (**graceful degradation**, per SRS §29). Total failure → a plain explanation + **[Try again]**, never a stack trace. Connection drop → pause + *"Connection lost — we'll resume when you're back online."* Cancel → confirm, then return to Start with nothing saved.
- **Next:** → Results (full or partial).

### Screen D — Results (where the product lives)

- **Sees, top to bottom (progressive disclosure):**
  1. **Health grade** — a single, honest headline (e.g., a letter grade or 0–100) with a **one-line plain meaning** (*"Needs attention — we found 2 urgent issues"*) and an explicit, small caveat: *"This is a snapshot of today, not a guarantee."*
  2. **"Fix these first"** — the **top 3** issues as cards (structure below). This is the heart of the product.
  3. A single primary action: **[Download PDF report]**.
  4. A quiet disclosure: **[See all findings]** for the technical person — collapsed by default.
- **Each top-3 card shows:** a **plain-English title** (*"Your website can be impersonated by fake copies"* — not *"Missing SPF/DMARC"*); **why it matters in business terms** (*"Attackers could send emails that look like they're from you"*); a **severity chip** (icon + word + colour — never colour alone, §20); **what to do**, in plain steps, **clearly labelled *AI-generated — verify before acting*** (ties to SRS §18); and a soft CTA: **[Share this with your IT provider]**.
- **Clicks:** Expands a card for detail → **[Download PDF report]** → optionally **[See all findings]** → optionally **[Run again]**.
- **System does:** Renders the scored, enriched findings from the core; on download, calls the core's *generate-report* use case and streams back the PDF.
- **Background:** Report renderer composes exec summary + technical appendix from the same finding data; file saved to the user's Downloads.
- **Info shown:** Grade + meaning + caveat; top 3 with plain guidance; count of total findings behind the disclosure; timestamp of the assessment.
- **Errors:** Report generation fails; **AI enrichment failed but scan succeeded**; zero findings; an overwhelming number of findings.
- **Error handling:** Report fail → keep results on screen, show *"Couldn't build the PDF — try again,"* offer retry (the data isn't lost). **AI-enrichment failure → the single most important degradation case:** show findings organized by severity with their raw technical descriptions, under a banner: *"Plain-English explanations couldn't be generated (your AI key may be out of credit) — here are the technical results, and you can retry."* The assessment is **never** wasted. Zero findings → the success/empty state (§18/§15). Too many findings → the top-3 framing already protects the user; the full list is paginated behind the disclosure.
- **Next:** → PDF report (deliverable) → done, or run again later.

### Screen E — The PDF report (the deliverable)

- **Structure (designed as carefully as the app because it gets forwarded to boards and insurers):**
  1. **Cover** — company/target, date, overall grade, KingSec mark.
  2. **Executive summary (one page, no jargon)** — grade, the top 3 in plain English, and a single "what to do next" paragraph. *This is the only page many readers will read.*
  3. **Priorities** — the top issues with business impact + recommended action.
  4. **Full findings (technical appendix)** — for the IT provider: detail, evidence, references.
  5. **About this assessment** — scope, method, the point-in-time caveat, and the "AI-assisted, verify before acting" note.
- **Design intent:** exec-readable first, technically credible second. Clean, authoritative, printable, and unmistakably professional — this document *is* the sales proof that the product is worth paying for.

---

## 3. Navigation map

Deliberately shallow — depth is the enemy of the north-star test.

```
                 ┌───────────────┐
   (first run) ─►│  A. Welcome/  │
                 │    Setup      │
                 └──────┬────────┘
                        ▼
                 ┌───────────────┐        ┌──────────────┐
        ┌───────►│  B. Start      │◄──────┤  History      │  (secondary)
        │        │  (home)        │       │  (past checks)│
        │        └──────┬────────┘        └──────────────┘
        │               ▼                  ┌──────────────┐
        │        ┌───────────────┐         │  Settings     │  (secondary:
        │        │  C. Running    │         │  key, prefs   │   AI key, theme)
        │        └──────┬────────┘         └──────────────┘
        │               ▼
        │        ┌───────────────┐
        └────────┤  D. Results    │──►  E. PDF report (download)
        (run     └───────────────┘
         again)
```

- **Primary spine:** B → C → D → E. That's the whole product.
- **Secondary (one click from B, never in the spine):** History and Settings. They exist; they don't compete.
- **No login, no account, no onboarding tour** — it's a local app; simplicity is free here, and we spend it.

---

## 4. Dashboard layout

**Contrarian position (enforced in the critique): v1 does not have a "dashboard" in the SaaS sense, and shouldn't.** The "home" is Screen B — the Start screen — because the product's job is to *start a check*, not to admire charts. What a naive design would call a dashboard, we split into:

- **Start (home):** one input, one attestation, one button. Calm and empty on purpose.
- **Results:** the grade + top-3 + download (Screen D) — the closest thing to a "dashboard," but scoped to one assessment.
- **History (secondary):** a simple reverse-chronological list of past checks (target, date, grade, "open"). This is where trend/repeat value lives *later*; in v1 it's a plain list, not an analytics surface.

If/when KingSec becomes SaaS with continuous scanning, a real dashboard (trends over time, multiple assets, drift) earns its place. Building it now would violate the single-flow principle and the SRS scope discipline.

---

## 5. Information architecture

The organizing principle is **progressive disclosure driven by decreasing audience size:**

```
Level 1 — EVERYONE (the CEO):   Grade + one-line meaning + "fix these first" (top 3)
Level 2 — THE DOER:             Per-issue "what to do" (plain steps) + "why it matters"
Level 3 — THE TECHNICAL PERSON: Full findings, evidence, references (behind [See all findings])
Level 4 — THE RECORD:           The PDF report (exec summary → technical appendix)
```

- **One primary object:** the *Assessment* (a target + a date + a grade + findings). Everything hangs off it.
- **Findings are ranked, not listed.** The core's contextual risk score (SRS §15/§18) decides the top 3; the rest are demoted behind a disclosure. Ranking *is* the product — an unranked list is the failure mode we're built to avoid.
- **Language is layered too:** plain-English at Level 1–2, technical terms only appear at Level 3+ (and always with a plain gloss on first use).
- **Nothing hidden that a user needs; nothing shown that a user doesn't.** The CEO never has to see a CVE id to act.

---

## 6. Wireframe descriptions (text only)

Compact text wireframes for the spine screens.

**B — Start (home)**
```
┌──────────────────────────────────────────────────────────┐
│  KingSec                                   History  ⚙︎     │
│                                                            │
│                                                            │
│            What should we check?                           │
│      ┌────────────────────────────────────────┐           │
│      │  yourcompany.com                        │           │
│      └────────────────────────────────────────┘           │
│      Enter your website or business domain.                │
│                                                            │
│      ☐  I own this, or I have permission to test it.       │
│         Why we ask →                                       │
│                                                            │
│              ┌───────────────────────┐                     │
│              │      Start check       │  (disabled until   │
│              └───────────────────────┘   valid + ticked)   │
│                                                            │
│      Advanced options ▸                                    │
│                                                            │
│   Your results stay on this computer.                      │
└──────────────────────────────────────────────────────────┘
```

**C — Running**
```
┌──────────────────────────────────────────────────────────┐
│  Checking  yourcompany.com                                 │
│                                                            │
│   ●━━━━━━━━━━━━━━━━━━━━○───────────────  ~ 6 min left      │
│                                                            │
│   Looking for exposed services…                            │
│                                                            │
│   So far, 4 things to review.                              │
│                                                            │
│   You can leave this running — we'll let you know.         │
│                                              [ Cancel ]    │
└──────────────────────────────────────────────────────────┘
```

**D — Results**
```
┌──────────────────────────────────────────────────────────┐
│  Results · yourcompany.com · Today                         │
│                                                            │
│     ┌───────┐   Needs attention                            │
│     │  C    │   We found 2 urgent issues.                  │
│     └───────┘   Snapshot of today, not a guarantee.        │
│                                                            │
│   Fix these first                                          │
│   ┌────────────────────────────────────────────────────┐  │
│   │ ▲ URGENT   Your website can be impersonated         │  │
│   │ Why it matters: attackers could send emails that…   │  │
│   │ What to do (AI-generated — verify): …               │  │
│   │                       [ Share with your IT provider ]│  │
│   └────────────────────────────────────────────────────┘  │
│   ┌────────────────────────────────────────────────────┐  │
│   │ ▲ URGENT   …                                        │  │
│   └────────────────────────────────────────────────────┘  │
│   ┌────────────────────────────────────────────────────┐  │
│   │ ● IMPORTANT …                                       │  │
│   └────────────────────────────────────────────────────┘  │
│                                                            │
│        ┌─────────────────────────┐                         │
│        │   Download PDF report    │                        │
│        └─────────────────────────┘                         │
│                                                            │
│   See all findings (17) ▸                                  │
└──────────────────────────────────────────────────────────┘
```

---

## 7. UX improvements (over a naive first design)

Concrete upgrades, each with the reasoning:

1. **Rank, don't dump.** The naive design shows every finding. Ours shows *the top 3* first — because the entire value proposition is deciding what matters. (IA §5.)
2. **Translate every finding into business language** at Level 1, keep the jargon for Level 3. A CEO acts on "your website can be impersonated," not "SPF record missing."
3. **Attestation as a calm gate, not a legal wall.** Disable the button with a gentle nudge instead of throwing an error after submission.
4. **Never waste a scan.** If AI enrichment fails, degrade to organized technical results rather than showing an error and losing the run. (Ties to SRS §29.)
5. **Long-wait dignity.** Plain-language stages + time estimate + "leave it running" + completion notification, instead of a spinner and silence.
6. **Label AI guidance honestly** ("verify before acting"). Trust is the whole brand; overclaiming AI in a security context is dangerous. (SRS §18.)
7. **The report is a product, not an export.** Exec summary first — because that's what gets read and forwarded.
8. **An honest headline grade.** A single grade is CEO-friendly but risks false comfort; we pair it with a one-line meaning and a point-in-time caveat so it informs without lulling.

---

## 8. UI design principles

1. **Clarity over cleverness.** If a non-expert can't parse it in three seconds, it's wrong.
2. **One primary action per screen.** Every screen has an obvious next step; secondary actions recede.
3. **Calm, not alarm.** Reassuring by default; urgency reserved for genuine urgency, expressed once.
4. **Progressive disclosure.** Show the answer; let detail be pulled, not pushed.
5. **Plain language first, jargon on demand.** Technical terms always arrive with a plain gloss.
6. **Honest by design.** No false reassurance, no overclaimed AI, no hidden failure. Caveats where they matter.
7. **Respect the wait and the failure.** Long operations and partial failures are designed states, not afterthoughts.
8. **Accessible by default** (§20) — not a bolt-on.

---

## 9. Component list

Reusable components (design inventory — deliberately small):

- **AppShell** (minimal top bar: logo, History, Settings)
- **PrimaryButton / SecondaryButton / TextLink**
- **TextField** (with inline validation + helper text)
- **AttestationCheckbox** (checkbox + "why" disclosure)
- **GradeBadge** (the headline grade)
- **SeverityChip** (icon + label + colour — the colourblind-safe severity unit)
- **FindingCard** (title · why-it-matters · severity · what-to-do · CTA), expandable
- **ProgressStepper / ProgressBar** (with plain-language stage + time estimate)
- **Disclosure / Accordion** ("See all findings", "Why we ask", "Advanced options")
- **Banner / InlineAlert** (info · warning · error · degraded-mode)
- **EmptyState** (illustrated-by-text, message + primary action)
- **Toast / Notification** (transient status)
- **HistoryListItem** (target · date · grade · open)
- **ReportPreview / DownloadAction**
- **Modal** (confirm cancel, confirm run-again)

*If a component isn't on this list, question whether v1 needs it.*

---

## 10. Design system (tokens)

Described as design tokens (not code).

- **Spacing scale (8-pt base):** 4, 8, 12, 16, 24, 32, 48, 64. Generous whitespace is a feature — it reads as calm and confident.
- **Radius:** small 6px (inputs, chips), medium 12px (cards), large 20px (primary containers). Soft, approachable, not sharp/aggressive.
- **Elevation:** three levels only — flat (base), subtle card shadow, and modal/overlay shadow. Restraint over drama.
- **Grid:** single-column, centered, comfortable max content width (~640–720px for the flow screens) so nothing feels sprawling or intimidating.
- **Density:** low. This is a consumer-grade tool, not an analyst console.
- **Breakpoints:** designed desktop-first (it's a local app) but must not break on a laptop's smaller window; graceful reflow to a single narrow column.

---

## 11. Color palette

Rationale first: for anxious non-experts, the base palette must signal **trust and calm**, and strong semantic colour must be *reserved* for meaning (severity/status). A wall of red destroys trust. Tokens (hex are design values, not code):

| Token | Value | Use |
|---|---|---|
| **Brand / Primary** | `#2A3F73` (deep trust-blue) | Logo, primary buttons, key accents |
| **Primary hover** | `#22335F` | Interactive states |
| **Accent** | `#3B82F6` | Links, subtle highlights |
| **Background** | `#F7F8FA` | App canvas (soft, not stark white) |
| **Surface** | `#FFFFFF` | Cards, inputs |
| **Text primary** | `#1A2233` | Body/headings |
| **Text secondary** | `#5B6472` | Helper text, captions |
| **Border / Divider** | `#E3E7EE` | Quiet separation |
| **Severity — Critical** | `#C0392B` | *Paired with a filled triangle icon + "URGENT"* |
| **Severity — High** | `#D97706` | *Icon + "HIGH"* |
| **Severity — Medium** | `#B7791F` | *Icon + "IMPORTANT"* |
| **Severity — Low** | `#4B7BB5` | *Icon + "MINOR"* |
| **Severity — Info** | `#6B7280` | *Icon + "INFO"* |
| **Success** | `#2E7D57` | Clean results, confirmations (used sparingly) |
| **Warning (degraded)** | `#B7791F` | The "AI explanations unavailable" banner |

- **Colour is never the only signal.** Every severity pairs colour with a distinct **icon shape** and a **plain word** (§20) — mandatory for colourblind users and simply clearer for everyone.
- **Dark mode:** a considered future addition, not v1. (Cut list, §critique.)

---

## 12. Typography

- **UI + report body: one highly legible humanist sans** (e.g., **Inter**, or a system-safe equivalent). One family keeps the product coherent and reduces decisions.
- **Optional report display face:** a restrained serif for report headings *only* if it reads as more "authoritative document" — otherwise stay single-family for consistency. (This is a taste call to make with a designer; defaulting to single-family is the safe, coherent choice.)
- **Type scale (rem-like ratios, ~1.25):**

| Role | Size | Weight |
|---|---|---|
| Display (grade meaning / screen title) | 28–32px | 600 |
| H1 (section) | 22–24px | 600 |
| H2 | 18–20px | 600 |
| Body | 16px | 400 |
| Helper / caption | 13–14px | 400 |
| Button | 16px | 600 |

- **Legibility rules:** generous line-height (1.5 body), comfortable measure (~60–75 chars), never smaller than 13px anywhere, high contrast (§20). For this audience, *readable* beats *fashionable* every time.

---

## 13. Icons

- **One consistent icon set** (e.g., a clean, friendly line set such as Lucide/Feather-style) — coherence over variety.
- **Severity icons are distinct *shapes*, not just coloured dots:** filled triangle (Urgent), triangle-outline (High), circle (Important), small dash/dot (Minor), "i" (Info) — so severity survives greyscale and colourblindness.
- **Iconography stays literal and calm** — a shield/lock language for security, checkmarks for done, a gentle magnifier for "checking." Avoid aggressive imagery (skulls, flames, sirens); it undercuts the trusted-advisor tone.
- **Icons always pair with text labels** for primary actions and severities — never icon-only for anything consequential.

---

## 14. Animations

Motion is used sparingly and purposefully — to reassure and orient, never to entertain.

- **Screen transitions:** quick, soft fades/slides (~150–200ms). Nothing bouncy or slow.
- **The Running screen is the one place motion earns real work:** a smooth, continuous progress motion and gently rotating plain-language stage messages that make a multi-minute wait feel alive and honest (not a frozen spinner). This is the highest-anxiety moment; calm, competent motion here builds trust.
- **State changes** (finding card expand, banner appear) use subtle height/opacity easing so nothing "pops" jarringly.
- **Grade reveal on Results:** a brief, dignified count-up or fade-in — a small moment of "here's your answer," without gamifying a serious result.
- **Respect `prefers-reduced-motion`** (§20): all non-essential motion is disabled for users who ask for it.

---

## 15. Empty states

- **Before the first check (returning user, no history):** the Start screen *is* the empty state — an inviting input and a one-line "point us at your website to begin." No blank void, no "no data" message.
- **History with nothing in it:** *"Your past checks will appear here. Run your first check to get started."* + a button back to Start.
- **"See all findings" with nothing beyond the top items:** *"That's everything — no other findings."* (Reassuring, not "0 results".)
- **Principle:** an empty state always **explains + invites the next action** and never reads as an error or a dead end.

---

## 16. Loading states

- **The long scan (Screen C)** is the marquee loading state — designed, not a spinner: plain-language stage + time estimate + running count + "leave it running" + completion notification (§19). (Full detail in §2-C and §14.)
- **Short waits** (testing an AI key, generating the PDF): an inline button-level spinner with a plain label (*"Testing your key…"*, *"Building your report…"*) — the button, not the page, shows the wait.
- **Skeletons** for the Results screen while findings render, so it feels instant and structured rather than blank-then-flash.
- **Principle:** never a bare spinner with no words; always tell the user *what* is happening and *roughly how long.*

---

## 17. Error states

Mapped from the flow. Every error is **plain, specific, non-scary, and actionable** — and never leaks a raw technical/stack error (ties directly to SRS §29: verbose errors are both confusing here *and* a bad habit for a security product).

| Situation | What the user sees | Handling |
|---|---|---|
| No / invalid AI key | *"That key wasn't accepted — check you copied all of it."* | Inline on Setup/Settings; keep input; **[Try again]** |
| Offline | *"KingSec needs an internet connection to run checks."* | Block start; retry when back |
| Invalid / typo target | *"That doesn't look like a web address — did you mean `gmail.com`?"* | Inline; suggest correction |
| Target won't resolve | *"We couldn't find that address online — check the spelling."* | Inline; block start |
| Private/internal address | *"That's an internal address; KingSec v1 checks internet-facing assets."* | Explain + note future capability |
| Attestation unticked | Gentle inline note; **[Start]** disabled | Prevent, don't punish |
| One scanner failed | Results shown; that check marked *"couldn't complete"* | **Graceful degradation** — partial results |
| Whole scan failed | *"Something went wrong running the check."* + **[Try again]** | No stack trace; safe message + correlation id for support |
| **AI enrichment failed, scan OK** | Banner: *"Plain-English explanations couldn't be generated (your AI key may be out of credit) — here are the technical results."* + **[Retry explanations]** | **Never waste the scan;** show organized technical findings |
| Report generation failed | Results stay on screen; *"Couldn't build the PDF — try again."* | Data preserved; retry |
| Connection dropped mid-scan | *"Connection lost — we'll resume when you're back online."* | Pause + auto-resume |

**Global rule:** every error names *what happened*, *why (in plain terms)*, and *the one thing to do next* — and offers a support-quotable reference id instead of internals.

---

## 18. Success states

- **Assessment complete, issues found:** the Results screen itself is the success state — *"Here's what we found and what to fix first."* Success here means *clarity*, not celebration.
- **Assessment complete, all clean:** a genuinely reassuring but **honest** state — *"Good news — we didn't find any urgent issues today,"* immediately followed by the point-in-time caveat and a nudge to re-check periodically. **We never imply permanent safety** (that would be dangerous and dishonest for a security tool).
- **Report downloaded:** a brief confirmation toast (*"Report saved to your Downloads"*) + a soft next step (*"Share it with your IT provider"* / *"Run again next month"*).
- **Key connected (first run):** a quiet checkmark and immediate progression — celebrate by *getting out of the way*, not with a modal.
- **Principle:** success is calm and forward-moving; the reward is the answer and the easy next step, not confetti.

---

## 19. Notification system

- **In-app (transient):** toasts for confirmations (report saved), non-blocking warnings (degraded mode), and quick statuses. Auto-dismiss, never stack into noise.
- **In-app (persistent):** banners for states the user must notice and can act on (offline, AI-unavailable) — they stay until resolved.
- **System/OS notification (the important one):** because a scan can run for many minutes and the user is told they can "leave it running," KingSec fires a **desktop notification on completion** (*"Your check of yourcompany.com is ready"*) that deep-links to Results. This closes the long-wait loop and is essential to the "walk away" promise in §2-C.
- **No email/push in v1** (local app, single user) — those arrive with SaaS.
- **Principle:** notify on things the user *waited for* or *must act on*; stay silent otherwise. Notification fatigue is the fastest way to lose trust.

---

## 20. Accessibility considerations

Accessibility is designed in, not retrofitted — and for a *security* product it's also correctness (severity must never depend on colour perception).

- **Colour independence:** every severity/status pairs **colour + icon shape + text label** (§13). The product is fully usable in greyscale and for all forms of colour blindness. *Non-negotiable.*
- **Contrast:** meets WCAG AA (≥4.5:1 body, ≥3:1 large text and meaningful UI). The calm palette (§11) is chosen to satisfy this without shouting.
- **Keyboard:** full keyboard operability — the entire spine (start → results → download) completable without a mouse; visible focus states; logical tab order.
- **Screen readers:** semantic structure, proper labels on inputs and the attestation, meaningful headings, live-region announcements for scan progress and completion, and alt text/labels for all icons.
- **Motion:** honour `prefers-reduced-motion` — disable non-essential animation (§14).
- **Text:** minimum 13px, respects OS text-scaling, ample spacing, plain language (which is itself a cognitive-accessibility feature).
- **Errors:** announced to assistive tech, tied to their field, never conveyed by colour alone.
- **Targets:** comfortably large hit areas for buttons/checkboxes.

---

# ✂️ Self-critique — as the Head of Design at Apple and the CTO of Cloudflare

*Now I put on the harshest hats and cut. The brief was explicit: remove anything unnecessary, and simplify until a first-timer finishes without documentation. A design that survives praise but not scrutiny isn't done.*

**The Apple Head of Design would say: "This is still too much product, and one screen will kill you."**

1. **The AI-key wall on screen one is the single greatest threat to your north-star, and this design under-solves it.** A non-technical CEO who opens the app and is asked to *"paste your OpenAI API key"* will close it. No amount of "Why do I need this?" copy fully saves that. This is the make-or-break UX problem, and honesty demands I flag it as unresolved, not decorated. **Options, in order of preference:** (a) *make the guided key setup exceptional* — a genuinely hand-held, tested, plain-English flow with a 60-second "get a key" walkthrough; (b) ship a **built-in demo/sample assessment** that requires *no* key, so the user experiences the value *before* being asked to set anything up (defer the wall until after the "aha"); (c) longer term, a **managed/bundled AI option** so a key is optional. My recommendation: **(b) + (a)** — let people *see* a finished result first, then set up. Value before friction. *This alone probably determines whether v1 succeeds.*
2. **Kill the multi-step feel. Start is one screen, and it should feel like Google's homepage.** One input, one confirmation, one button. I already pushed this way — go further: the attestation can be a single line under the field, "Advanced options" can be nearly invisible, and there is *nothing else* on the screen. If a first-timer sees more than three elements, we failed.
3. **Delete scan-depth choices from v1 entirely.** A CEO cannot choose between "quick" and "deep" — they don't have the mental model. **Pick one sensible default and hide the rest** behind "Advanced options" that 95% never open. Choice is a tax you're charging a user who came for an answer.
4. **The headline grade is a liability as much as a feature — tighten it or reconsider.** A letter grade invites false comfort ("we got a B, we're fine") or panic ("an F?!"). Keep it *only* because it's scannable — but the *one-line meaning* and the *point-in-time caveat* are doing the real work and must never be optional or de-emphasized. Consider whether "Needs attention / Looking good / Urgent action needed" as words is safer than a letter. **Test this with real non-technical people before committing.**
5. **The "dashboard" and "History" are v1 scope creep in disguise.** You do not need a history list to prove the core loop. **Cut History from the first shippable version** — or reduce it to the barest "here are your past reports" list — and spend that effort on the key-setup and results-clarity problems that actually decide adoption.

**The Cloudflare CTO would say: "Your happy path is fine; your product lives or dies in the failure and trust states — and there, mostly, you've done the right thing, with two holes."**

6. **The AI-degradation path is correct and is your most important non-obvious decision — protect it.** "Scan succeeds, AI fails, show organized technical results anyway" is exactly right; a lesser team would show an error and burn the user's scan (and their AI credits). Keep it, test it deliberately, and make the retry cheap. *This is the difference between a toy and a tool.*
7. **You're honest about AI ("verify before acting") — good, and don't let anyone talk you out of it.** In a security context, a confidently wrong "you're safe" is a genuine harm. The label stays, the human-in-the-loop framing stays. This is both ethics and liability.
8. **Hole: you haven't designed for the scan that *never finishes* or the scanner that hangs.** Real scanners stall. You need a hard **per-assessment timeout** and a "this is taking longer than usual — keep waiting / stop and show what we have" state. Design the *ungraceful* long-run, not just the graceful one.
9. **Hole: the attestation is trust theatre unless you also *technically* refuse obviously-out-of-scope targets.** A checkbox saying "I'm allowed" while the tool will happily scan `pentagon.gov` is not enough. Pair the attestation with **technical guardrails** (block internal/reserved ranges, warn on clearly-not-yours patterns) so the product is responsible *by construction*, not just by promise. (This matters more the moment you go SaaS.)
10. **One family, one icon set, no dark mode, no extra components — you already trended lean; be leaner.** Every component on the §9 list that isn't on the B→C→D→E spine is a candidate for "later." Ship the spine beautifully; add the rest when reality asks.

---

# ✅ The reconciled v1 — what we actually ship first

Applying the critique, here is the minimal product that still delivers the whole value and passes the north-star test:

**Screens (only these):**
1. **A sample result on first open (no key required)** — the user *sees* a finished assessment and report immediately. *(New, from critique #1 — value before friction.)*
2. **Setup** — one guided, tested AI-key step, entered *after* the "aha," with a 60-second "get a key" helper.
3. **Start** — one input, one attestation line, one button. Sensible scan default; everything advanced hidden.
4. **Running** — plain-language progress, time estimate, hard timeout with a "keep waiting / show what we have" fallback, completion notification.
5. **Results** — grade + plain meaning + caveat, **top 3 fixes**, **[Download PDF]**, and a quiet **[See all findings]**. Graceful AI-degradation built in.
6. **The PDF report** — exec summary → technical appendix.

**Cut from v1 (added back later, deliberately):** History/analytics dashboard, dark mode, scan-depth chooser, any component off the spine, and (for now) any AI-provider abstraction beyond the single BYO-key path.

**Kept as non-negotiable:** the AI-degradation fallback, honest AI labelling, the point-in-time caveat, colour-independent severity, the attestation **plus** technical scope guardrails, and the completion notification.

**The test we hold ourselves to:** hand the built app to someone non-technical, say nothing, and watch them go from opening it to a downloaded report. If they get stuck or ask a question, that friction point is the next thing we fix — before anything else.

---

## Open decisions I need from you

1. **The key-friction fix (critique #1):** approve "**sample result first, key after the aha**" as the v1 approach? This is the highest-leverage decision in the whole design.
2. **Headline result format:** letter grade, 0–100, or **words** ("Urgent action needed / Needs attention / Looking good")? I lean words for this persona — but let's test.
3. **v1 scope cut:** agree to **drop History/dashboard** from the first shippable version?
4. **Report branding:** is the PDF **KingSec-branded**, white-label, or both (a paid feature)? This ties to monetization (SRS §20).

---

*End of Product/UX Design v0.1 (Draft). No code and no images produced, per your instruction. Awaiting your approval and the four decisions above before we move to the next stage — which, when you're ready, should be locking the **Service API's use-case surface** (the exact operations and the plain-data shapes that flow between this UI and the Python core), because that contract is what turns this design into something buildable.*
