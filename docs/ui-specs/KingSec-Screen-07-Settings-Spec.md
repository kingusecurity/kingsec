# KingSec — Screen 7: Settings (Design Spec)

| | |
|---|---|
| **Screen** | 7 of 7 — Settings *(completes Version 1)* |
| **Version** | 1.0 (v1 requirements frozen) |
| **Status** | Awaiting founder approval |
| **Mandate** | Software *preferences*, not an admin panel — usable with zero security knowledge |
| **Files** | `KingSec-UI-07-Settings.html` (interactive: theme, toggles, API-key show/hide + connected state) |

---

## 0. Philosophy — preferences, not administration

An "admin panel" is where power users configure a system; **preferences** are where a normal person adjusts how their software behaves. KingSec's Settings is firmly the latter. The test that governed every decision: *could the non-technical business owner from our Welcome screen open this and understand every single option?* If a control needs expert knowledge, it doesn't belong in v1 — it's hidden or deferred. The result is five small, plainly-labelled groups, each row carrying a one-line description in human language.

**V1 scope (exactly what was asked, nothing more):** Appearance (Theme) · AI assistant (Provider + bring-your-own key) · Reports · Privacy · About. No scan tuning, no network config, no logging levels, no advanced anything — those are administration, and they'd betray the whole product's promise.

---

## 1. The one delicate control, handled with care

The **bring-your-own API key** is the single genuine friction point in the entire product — and this screen is where it's made calm. Rather than a bare field, it's wrapped in plain-language reassurance that does three jobs at once: explains *why* (so results can be turned into plain English), reinforces the trust advantage (*your key and data stay on this computer*), and removes the fear of being blocked (*no key? KingSec still works in limited mode*). A "How do I get a key?" link and a live "Connected ✓" state remove the last friction. This is the UX embodiment of the architecture decision we froze — and it's deliberately the most explained control on the page.

---

## 2. Accessibility review

- **Native, labelled controls throughout.** Real `<select>`, checkboxes (styled as switches), buttons, and text inputs — each with a `<label>` or `aria-label` — so everything is keyboard-operable and screen-reader-legible for free.
- **Toggles announce state:** switches are real checkboxes, so assistive tech reads "on/off"; they're not conveyed by colour alone (the knob position changes too).
- **Theme control is a labelled group** (`role="group"`), each option a real button; selection is visible beyond colour (background + weight).
- **Visible focus rings** on every interactive element; the API-key show/hide is a real button with an `aria-label`.
- **Contrast & scaling:** calm palette meets AA; text scales with OS settings; the layout reflows to a single column on mobile with full-width controls.
- **Reduced motion:** the only motion is the toggle/segment transitions, which honour `prefers-reduced-motion`.
- **Plain language is cognitive accessibility:** every row's helper text explains the option without jargon — the same principle that runs through the whole product.

---

## 3. Security review

- **The API key is a secret and must be treated as one.** In production it is stored in the OS secure store / encrypted local storage — **never in plaintext config, never in logs, never transmitted to KingSec**. The field is masked by default; show/hide is local only.
- **Least privilege for the key.** It's used solely for the chosen AI provider's calls, made from the user's machine; KingSec's servers are never in the path.
- **"Clear assessment history" is a real destructive action** — it must require confirmation (a dialog, like the scan-cancel flow) and genuinely purge local data, including any cached findings and generated reports the user chose to remove.
- **No secrets echoed.** The "Connected" state confirms a key is present without ever displaying or transmitting it; validation (a lightweight test call) happens locally against the provider.
- **Input from settings is still input:** business name and report paths are validated/escaped before they land in a generated PDF (they flow into the report template).
- **Updates are integrity-checked.** "Check for updates" must verify signatures before applying anything — a security tool cannot ship an unverified auto-update path.

---

## 4. Privacy review

- **The privacy story is the product's headline trust claim, stated plainly here:** KingSec runs on the user's computer; their sites' data and results never leave the machine. Settings is the right place to make that promise explicit and legible.
- **Telemetry is off by default and honestly scoped.** "Share anonymous usage data" defaults off, and its description is truthful about what it does and does *not* include (never sites, never results). Opt-in, never opt-out.
- **Data ownership & deletion.** The user can clear all local history at will — real control, not a gesture. There's no server-side copy to worry about *because there is no server-side copy.*
- **BYO-key reinforces privacy:** because inference uses the user's own provider account from their machine, KingSec never sees the prompts, the findings, or the site data — a genuine, rare privacy posture we should keep stating.

---

## Developer Notes

*Technical considerations for future implementation (no backend code here).*

- **Settings persist locally** (per the local-app model): a local settings store on the user's machine, read at startup and injected into the core — the core never reads env/config itself (per the frozen hexagonal boundary: config is passed in).
- **API key → OS secure storage.** Use the platform keychain / credential vault (or an encrypted local store), not the plaintext settings file. Surface only presence + validity to the UI.
- **Provider abstraction already exists in the architecture** (the AI-provider port). "AI provider" here just selects which adapter the core uses; adding a provider is an adapter, not a rewrite. "Local model" points the port at a local runtime (e.g., Ollama).
- **Theme:** the control ships in v1; the **Dark palette itself is a V2 deliverable**, so v1 ships Light as default with the control present ("Dark coming soon"), or wires "System" to Light until the dark tokens land. Don't ship a half-built dark theme.
- **"Clear history" and "Check for updates"** are real operations needing confirmation dialogs and (for updates) signature verification, respectively.
- **Report preferences flow into generation:** business name, save path, and "include technical appendix" are read by the report generator (Screen 6) — validate/escape them before templating.
- **No admin surface leaks in.** Keep expert controls out of the UI entirely in v1; if power users need them later, gate behind an explicit "Advanced" section (V2), never on by default.

---

## Version 2 roadmap (intentionally postponed)

*None ship without explicit approval.*

- **Dark theme** (the palette + tokens behind the control that already exists).
- **Advanced options section** (opt-in): scan depth, custom scan profiles, proxy/network settings — quarantined away from the simple defaults.
- **Scheduled assessments & notifications** preferences (ties to the recurring-checks nudge).
- **Team / multi-user & roles** (only relevant once the SaaS layer exists).
- **White-label / branding** controls for consultants and MSPs (logo, colours, report contact) — a Pro flow.
- **Integrations** (Slack / Jira / email) credentials and preferences.
- **Language / localization** selection.
- **Import/export settings** for consultants managing many installs.

---

## Version 1 — design complete

Screen 7 closes the set. The seven core screens (Welcome, Home, New Assessment, Running Scan, Results, PDF Report, Settings) — plus the Home empty state and the all-clear Results state — are designed, on-brand, accessible-by-construction, and honest by design. Every screen answers the one question we set at the start: *would this make a business owner trust KingSec?*

**The through-line held:** trust is the marketing, honesty is the conversion — expressed as radical simplicity, plain language, no fear-selling, no paywalled criticality, milestone-based honesty, and a report good enough to leave the building. **Next phase is implementation, not more design.**

---

*End of Screen 7 spec, and of the Version 1 design phase. No backend code, no prior screens redesigned, per the freeze.*
