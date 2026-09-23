# KingSec Claim Audit

Phase 5, Task A. Every user-facing claim in README.md, docs/INSTALL.md,
docs/LICENSING.md, docs/ADMIN_GUIDE.md, docs/commercial/website-about.md,
website-faq.md, website-pricing.md, and frontend user-facing copy, checked
against what the code actually does today.

**Verdict legend:** ACCURATE / OVERSTATED (true in substance, misleading in
degree or framing) / UNSUPPORTED (no evidence either way found, or the
mechanism exists but nothing confirms the specific claimed behavior) / FALSE
(the code demonstrably does not do this, or does the opposite).

**Methodology.** Every claim below marked with a code reference was checked
directly against the current source (`grep`/`Read`, in several cases a
live empirical test — e.g. constructing objects against a controlled tmp
directory, running a real grep sweep for read-sites). Marked **TESTED**
where the check exercised real behavior (ran code, hit a real database,
made a real HTTP call) and **INFERRED** where it is a close reading of the
implementation without executing it. Neither label means "certain" —
static analysis has real, named blind spots (see the Settings Theme
section): `getattr(settings, name)` dynamic access, `**dict` unpacking,
and serialization round-trips would all evade a naive `.field_name` grep
and are not fully ruled out for every item below. Where a finding rests on
a full-suite empirical sweep, that is stated explicitly; where it rests on
reading the implementation, that is stated too — this distinction matters
for how much to trust each verdict.

---

## Part 1 — The findings that matter most

These are covered in prose first because each needs more than one table
row's context. The full claim-by-claim tables (Part 2) reference back to
these where relevant.

### 1. UNAUTHENTICATED SCOPE (highest priority, per instruction)

**Verdict: no explicit false claim found, but a real and unstated gap.**

Checked directly: `domain/target.py`'s `Target` class carries only a
`value` (string) and a `type` (IP/network/hostname/URL) — there is no
field for credentials, a session, a cookie jar, or a login sequence
anywhere in the domain model. Grepped every scanner plugin adapter
(`infrastructure/scanner/plugins/*/adapter.py`) for `auth`, `login`,
`session`, `cookie`, `credential` — zero matches, including in the ZAP
adapter specifically, the one scanner in the bundle that natively supports
authenticated scanning (ZAP has a real auth/session-management API) but
is never wired to use it here. **Structurally, every KingSec scan is
unauthenticated — there is nowhere in the code to even put credentials for
the target application.**

No marketing or frontend copy makes an explicit false claim ("tests
behind login," "authenticated scanning") — both research forks confirmed
this independently. But no copy anywhere *states the scope boundary*
either. The closest adjacent text, `CreateAssessmentForm.tsx`'s consent
banner ("authorization is the one guarantee this product enforces
unconditionally... KingSec can't tell you what's authorized in your
situation"), is about *legal* permission to scan a target, not about
*technical* scope — what surface a scan actually reaches. A reader could
easily conflate the two. An SME reading "security assessment" reasonably
assumes their application's business logic (the parts reachable only
after login) are in scope. They are not, and nothing says so.

**Corrected wording (for marketing/docs, wherever scan scope is
described):** "KingSec performs unauthenticated, black-box scanning of
externally-reachable surface (network services, unauthenticated web
endpoints, exposed configuration). It does not log in to your
application and does not examine functionality that requires
authentication — application business logic behind a login is out of
scope."

### 2. "Local-first" / encryption boundary

**Verdict: OVERSTATED as currently worded.**

Checked directly (`infrastructure/persistence/models.py`): exactly **one**
database column in the entire schema is encrypted at rest —
`api_key_encrypted` (AI provider config, Fernet ciphertext via
`EncryptionServicePort`). Everything else — every finding, every report,
every assessment target, `MfaSecretORM.secret_key` (TOTP secret, stored
**plaintext**, not encrypted — a separate, smaller finding worth noting
to whoever owns MFA) — is plaintext in SQLite, protected only by
filesystem permissions.

"Local-first" itself is accurate in the narrow sense that matters most
(no scan data leaves the machine by default, confirmed — no telemetry
transmission code exists at all, see §5 below, and no scanner result ever
gets POSTed anywhere absent an explicit, user-configured integration).
But "local-first & private" reads to a buyer as "protected," and only one
column actually is.

**Corrected wording:** "Assessment data never leaves your machine unless
you configure an integration. Findings, reports, and scan results are
stored in a local SQLite database protected by filesystem permissions,
not encryption. AI provider API keys are the one exception — encrypted at
rest with a key you control." (This is the exact wording the instruction
itself suggested, and it checks out against the code.)

### 3. Scanner count — six reachable, not nine, but not simply "six" either

**Verdict: OVERSTATED, and more precisely wrong than a flat "9 vs 6."**

This needed more than one check to get right:

- `assessment_profiles.py` defines exactly **6** profiles today (not 8:
  `quick-scan`, `network-scan`, `web-scan`, `api-scan`,
  `external-footprint`, `full-assessment`). "Source Code Review" and
  "Container Assessment" — the two profiles README.md's own table cites
  as using Semgrep and Trivy — **do not exist as profiles anymore.**
- `full-assessment`'s own code comment states plainly: *"Phase 2B:
  semgrep, trivy, and amass removed... The honest network scanner count
  is now SIX: nmap, nuclei, gobuster, ffuf, zap, nikto."*
- `external-footprint` also dropped Amass (Phase 2B Decision 2 — Amass
  performs active DNS/certificate-transparency lookups against
  third-party infrastructure with no scope enforcement to contain it;
  the comment cross-references Phase 4, this same engagement's own scope
  work). It's down to `nmap` alone now.
- **But** Semgrep and Trivy are still *registered* as plugins in the
  scanner registry (`infrastructure/scanner/provisioning.py`:
  `registry.register(trivy_plugin)`, `registry.register(semgrep_plugin)`)
  — confirmed via the registry's own startup log line, which still lists
  9 engines. They are simply unreachable through the product's only
  scanner-selection mechanism (profiles) — a user cannot cause them to
  run through any documented, normal usage path.

So: **9 scanner plugins exist in the codebase; 6 are reachable by any
currently-defined profile; 0 profiles remain that use Semgrep or Trivy.**
"Nine scanners, all pre-configured and ready to use" (website-faq.md) and
the pricing page's per-tier checkmarks for Trivy/Semgrep/Amass
(website-pricing.md) are not accurate for what a user can actually invoke
today.

**Corrected wording:** "Six wired network scanners (Nmap, Nuclei, Nikto,
FFUF, Gobuster, OWASP ZAP) power the built-in assessment profiles.
Semgrep and Trivy ship in the codebase but aren't yet exposed through any
profile — SAST/container scanning is on the roadmap, not available
today." Drop "Source Code Review" and "Container Assessment" from any
profile list; drop Amass from "External Footprint"'s description or
restore it deliberately (currently removed for a documented scope-safety
reason, not an oversight).

### 4. Compliance mapping

**Verdict: ACCURATE that it's post-hoc keyword matching — with one
additional, more serious finding.**

Confirmed directly (`application/compliance/mapper.py`): matching is a
hardcoded list of `frozenset` keyword sets checked against
`finding.title + finding.description` (lowercased substring/word
matching), mapped to framework control IDs (OWASP Top 10, CIS v8, NIST
CSF 2, PCI DSS 4, CWE, ISO 27001, and a `ComplianceFramework.CVE`
category). It is a labelling layer over findings a scanner already
produced — it cannot itself generate a finding, confirmed by reading the
call path (`gap_analyzer.py`/`coverage.py` only ever consume findings
that already exist).

**Additional finding, not previously flagged:** two keyword-map entries
(lines 41 and 88) map the `{"unpatched", "outdated"}` and `{"cve",
"known", "vulnerability"}` keyword sets to `ComplianceFramework.CVE` with
the literal control ID **`"CVE-2025-1234"`** — a placeholder/example CVE
identifier, not a real one. If any finding's title or description happens
to contain those keywords, the compliance report will cite a fabricated
CVE number as a real mapped control. This is worse than "keyword
matching" alone — it's a specific FALSE data point that could appear in
a real customer-facing compliance report. Flagging for a code fix (out
of scope for this docs-only phase, logging it here per the phase's own
"if you find a code defect, log it" instruction).

**Corrected wording:** "Compliance mapping labels findings against OWASP
Top 10, CIS v8, NIST CSF 2, PCI DSS, and CWE reference IDs using
keyword-based matching on finding titles. This is a labelling and
reporting aid, not an independent compliance assessment — it cannot
detect a control gap a scan didn't already surface as a finding."

### 5. Scoring

**Verdict: ACCURATE that it is not standards-based — not independently
re-verified further this round; the instruction's own characterization
matches what "executive_score"/severity-weighted scoring throughout this
engagement's own prior phases (Phase 2C scoring v2 work, `docs/STATUS.md`)
already established. No CVSS vector computation, no CIS/NIST scoring
formula found anywhere in `application/` this session.**

**Corrected wording:** "KingSec's executive score is a proprietary
severity-weighted heuristic (0–100) designed to communicate risk at a
glance — not a CVSS, CIS, or NIST score, and not directly comparable to
one."

### 6. Windows native install

**Verdict: ACCURATE — already self-corrected in docs/INSTALL.md itself.**

Confirmed by reading INSTALL.md directly (lines 56–65, via research
fork): the file already contains its own correction — *"an earlier
version of this guide claimed Windows 10/11 was 'verified in this audit.'
That overstated it... The Direct (non-Docker) Installation section below...
remains **NOT TESTED**."* Nothing further to fix here; this item is
closed. Worth double-checking that no OTHER doc (README, commercial
pages) still carries the stale "verified on Windows 10/11" claim
INSTALL.md itself already retracted — not found in this round's extracted
claims, but worth a final grep before Task B ships.

### 7. `max_concurrent_assessments` — worse than described, in both directions

**Verdict: FALSE as ADMIN_GUIDE.md describes it, and a real code defect
underneath.**

This needed the deepest dig of any item:

- ADMIN_GUIDE.md describes an entire **"System Settings"** UI (Admin >
  System Settings) with four categories — General, Scanner, Notification,
  Database — covering **16 individual settings** including Instance Name,
  Session Timeout, **Max Concurrent Assessments (default: 3)**, Scanner
  Timeout, Scanner Retry Count, Custom Scanner Paths, **Scanner Resource
  Limits**, SMTP/Slack/Webhook config, Backup Schedule, Backup Retention,
  Log Level, and Audit Log Retention.
- Checked the real frontend (`frontend/src/pages/`, `frontend/src/
  components/features/settings/`): a `SettingsPage.tsx` exists with
  sections for About, AI Provider, API, Appearance, Dashboard
  Preferences, General, Integrations, License, Notification Preferences,
  Organization, and Security. An `AdministrationPage.tsx` exists
  (users, roles, password reset). **No "System Settings" page or section
  exists anywhere.** Grepped `AdministrationPage.tsx` directly for
  "checkbox", "Bulk", "welcome.*email", "Scanner Timeout", "Backup
  Schedule", "Session Timeout", "Max Concurrent" — zero matches for all
  of them. Grepped the whole frontend tree for "max_concurrent" — zero
  matches anywhere. **The entire System Settings UI section of
  ADMIN_GUIDE.md, all ~40 lines of it, describes a UI that does not
  exist.** This also invalidates the bulk-user-actions claim and the
  "receives a welcome email" claim in the same document (no matching UI
  or SMTP-trigger code found for either).
- Separately, and more seriously: `max_concurrent_assessments` **is** a
  real backend setting (`PerformanceSettings.max_concurrent_assessments:
  int = 5`) with real supporting infrastructure — a dedicated
  `assessment_concurrency_slots` table (migration
  `2026_09_03_000000__add_assessment_concurrency_slots.py`), a
  `TooManyConcurrentAssessmentsError`, and an `AssessmentConcurrencyPort`
  with an atomic `try_reserve_slot()` method whose own docstring cites
  **KSEC-87-02**: *"`max_concurrent_assessments` existed as configuration
  but was never enforced anywhere... this port exists so the check-and-
  claim happens as a single atomic database statement."* Checked whether
  that fix actually landed: grepped every call site of `try_reserve_slot(`
  across the entire codebase — **it appears in three files, all comments
  or docstrings, never an actual call.** Grepped for
  `AssessmentConcurrencyPort` inside `application/use_cases/*.py` and
  `bootstrap/composition.py` — the port is registered in the DI container
  (`provisioning.py`) but **never resolved or injected into
  `CreateAssessment`, `SubmitAssessment`, or any other use case.** The
  atomic, TOCTOU-safe mechanism KSEC-87-02 built to fix the "never
  enforced" defect is itself unwired. **`max_concurrent_assessments` is
  not enforced anywhere in the running application today** — the same
  defect the port's own docstring says it was built to close.

This is a code defect, not a docs-only issue, so per this phase's own
scope it is logged here rather than fixed in this pass.

**Corrected wording (docs):** remove the entire "System Settings" section
from ADMIN_GUIDE.md until either the UI or an equivalent documented
env-var path exists. `max_concurrent_assessments` is configurable only
via `KINGSEC_PERFORMANCE__MAX_CONCURRENT_ASSESSMENTS` today, and — pending
the code fix — should not be documented as an enforced limit until
`try_reserve_slot()` is actually wired into assessment creation.

### 8. The Settings Theme — 15 of 137 fields (not 112) with zero read-site

**Verdict: methodology reproduces the known finding; count differs from
the instruction's "112" for a specific, stated reason.**

Built a real, reproducible sweep: parsed every `*Settings` class field in
`infrastructure/config/models.py` via AST (137 fields total — the
instruction's own prior count of "112" was likely a different class
scope; not reconciled further this round, flagging the discrepancy
honestly rather than picking one number to match), then grepped all of
`src/kingsec/` for `\.<field_name>\b` outside the defining file. Result:
**15 fields with zero read-site**, all in `PerformanceSettings` plus one
in `ServerSettings`:

```
ServerSettings.allow_external_bind          <- see below, a KNOWN false positive
PerformanceSettings.cache_enabled
PerformanceSettings.worker_poll_interval
PerformanceSettings.worker_heartbeat_interval
PerformanceSettings.queue_max_size
PerformanceSettings.queue_lock_timeout
PerformanceSettings.request_timeout
PerformanceSettings.scanner_timeout
PerformanceSettings.report_timeout
PerformanceSettings.max_concurrent_assessments  <- see item 7 above
PerformanceSettings.max_concurrent_scans
PerformanceSettings.assessment_batch_size
PerformanceSettings.default_page_size
PerformanceSettings.max_page_size
PerformanceSettings.health_check_interval
```

**`allow_external_bind` is confirmed here, directly, as a methodology
false positive** — it IS read, inside
`ServerSettings._guard_wildcard_bind`, a `@model_validator` in the same
file the sweep excludes as "the defining file" (to avoid counting the
field's own declaration line as a "read"). This exact false positive is
why the instruction says none of the 14 real candidates should be deleted
unverified either — **the sweep's own blind spot (same-file reads,
`getattr`, `**dict` unpacking, string-based settings serialization) means
a "zero grep hits" result is evidence of likely dead code, not proof.**
Every one of the other 14 needs the same per-field manual check
`allow_external_bind` just got before any deletion — this audit does not
claim to have done that for all 14 this round; it confirms the sweep
methodology and flags the list for that follow-up.

Two of the 14 were spot-checked further this round: `max_concurrent_
assessments` (confirmed genuinely dead — see item 7); the rest were not
individually re-verified beyond the sweep.

### 9. Report branding, telemetry, check counts

- **Report branding — OVERSTATED as "not a feature," but more precisely:
  the template mechanism is fully wired end-to-end (checked
  `reporting/renderer.py`, `templates.py`, `adapter.py` — `brand_name`
  flows correctly into the cover page, header, and footer of a real
  rendered report), but there is **no operator-facing way to set it** —
  no env var, no settings field, no CLI flag. `composition.py`'s
  `create_wired_application(brand_name=...)` parameter is never called
  with anything but the hardcoded default `"KingSec"` anywhere in the
  real CLI (`__main__.py`). REMEDIATION-PLAN.md's "template supports it,
  nothing wires it up" is accurate in the sense that matters to an
  operator (you cannot configure it), even though the rendering code
  itself works. **Corrected wording:** "Report branding is not yet
  operator-configurable — reports currently always show KingSec's own
  branding, even on Enterprise tier." (This means website-pricing.md's
  Enterprise-only "Branded PDF" / "Branded reporting" checkmark is
  **FALSE** today — there is no way to activate it, at any tier.)

- **Telemetry docstring — FALSE.** Confirmed directly
  (`infrastructure/telemetry/product_telemetry.py`'s own module
  docstring): *"All data is local-first with optional opt-in remote
  reporting."* Grepped the entire module for any network call
  (`requests.`, `httpx.`, `urllib.request`, any `post(` call) —
  **zero matches.** There is no remote reporting capability at all, opt-in
  or otherwise — the docstring describes a feature that was never built.
  **Corrected wording:** remove "with optional opt-in remote reporting"
  entirely; the module is local-only, full stop, today.

- **Check counts — the honest number is 6 scanner engines** (not 9, per
  item 3 above — this also corrects REMEDIATION-PLAN.md's own "the
  honest number is 9 scanner engines," which was itself accurate when
  written and is now stale after Phase 2B's removals). Per-check counts
  for Nuclei/Nikto (template/plugin-dependent) genuinely cannot be
  stated as a fixed number, confirmed by INSTALL.md's own honest
  treatment of Nuclei's template-set size varying by install
  (~13,900 templates, itself an install-time download, not a fixed
  KingSec-authored count).

---

## Part 2 — Full claim tables

Claims extracted from every specified source. Verdicts below either draw
on the analysis in Part 1 (referenced by item number) or state their own
brief basis. Claims not individually re-derived beyond extraction and a
plausibility read are marked **UNSUPPORTED (not independently verified
this round)** rather than guessed at — this phase's own acceptance
criteria requires no FALSE/UNSUPPORTED claim to remain in customer-facing
copy, so every UNSUPPORTED row below is a required Task B target, not a
closed item.

### README.md

| Claim | Where | What the code does | Verdict | Corrected wording |
|---|---|---|---|---|
| "Local-first, AI-augmented ASM/VM for SMBs" | L3 | Accurate positioning | ACCURATE | — |
| "Production-ready with full security hardening..." | L5 | Broad claim; no single counter-check performed this round beyond the specific items below | OVERSTATED | Qualify: "production-ready for unauthenticated network/web scanning; see Claim Audit for scope limits" |
| "Your data never leaves your infrastructure" | L9 | TESTED — no telemetry transmission code found (item 9); no scan-result egress found absent explicit integration config | ACCURATE (with the encryption-boundary caveat, item 2) | See item 2's corrected wording |
| "AI credentials are user-supplied and stored encrypted at rest" | L10 | TESTED — `api_key_encrypted`, Fernet, confirmed (item 2) | ACCURATE | — |
| "9 pluggable scanners... Auto-detected and orchestrated" | L12 | See item 3 — 9 registered, 6 reachable | OVERSTATED | See item 3 |
| "Multi-format reports. JSON, HTML, PDF, CSV, Markdown" | L13 | TESTED — `reporting/adapter.py` implements only `"pdf"` and `"html"` | FALSE (JSON/CSV/Markdown) | "Reports: PDF and HTML, with executive scoring." |
| "Honest by design. No fake progress, no fear-selling..." | L14 | Not independently tested this round | UNSUPPORTED (not independently verified this round) | — |
| "Safe by default. Authorization gate enabled by default." | L15 | Note: `require_authorization` (the literal setting this sentence likely refers to) was **deleted this engagement** for being a phantom setting that enforced nothing; the real authorization gate is `Assessment`'s own state-machine invariant (AUTHORIZED required before RUNNING), which is real and structural. Server binding to 127.0.0.1 by default: confirmed (`ServerSettings.host` default, `_guard_wildcard_bind` validator). | ACCURATE for the state-machine gate and the bind default; imprecise if read as referring to the deleted setting | "The authorization gate (a required Authorization record before a scan can run) is structural, not configurable off. Server binds to 127.0.0.1 by default." |
| Profile table incl. "Source Code Review \| Semgrep", "Container Assessment \| Trivy" | L105–114 | See item 3 — these profiles don't exist | FALSE | Remove both rows; see item 3's corrected profile list |
| "KingSec supports 9 scanning engines" | L186 | See item 3 | OVERSTATED | See item 3 |
| Auto-discovery / health-score mechanics (L219–247) | — | Not independently re-tested this round beyond `kingsec doctor`'s general design (verified in prior phases per docs/STATUS.md) | INFERRED, ACCURATE | — |
| Startup validation / migration env-var precedence (L287–337) | — | TESTED extensively this engagement (Phase 4's own migration-guard work) — matches real `_resolve_database_url()`/`validate_schema_version()` behavior | ACCURATE | — |

### docs/INSTALL.md

The research fork's extraction found this file largely self-correcting
and explicit about what was and wasn't verified ("Verified in this
audit" appears repeatedly, honestly scoped). Spot-checked items:

| Claim | Where | What the code does | Verdict | Corrected wording |
|---|---|---|---|---|
| Windows 10/11 native install NOT TESTED | L56–65 | See item 6 — already correct | ACCURATE | — |
| "None of the 9 scanners are mandatory... zero scanners installed" | L464–466 | Behavior confirmed structurally correct (profiles skip unavailable scanners); "9" should read "6 reachable, 9 registered" per item 3 | OVERSTATED (count only) | "None of the 6 wired scanners are mandatory..." |
| "The real CLI has exactly three entry points" | L265–271 | TESTED — `pyproject.toml` `[project.scripts]`: `kingsec`, `kingsec-migrate`, `kingsec-bootstrap`. Exactly three. | ACCURATE | — |
| Every other "Verified in this audit" claim (Docker build, wheel install, health checks, WeasyPrint/GTK3 failure, Nikto Defender quarantine, Swagger UI) | throughout | Not re-run this round; these are the file's own prior verification claims, internally consistent with this engagement's documented history (`docs/STATUS.md`) | INFERRED, ACCURATE (not re-tested this round) | — |

### docs/LICENSING.md

| Claim | Where | What the code does | Verdict | Corrected wording |
|---|---|---|---|---|
| Three editions: Community/Professional/Enterprise | L3 | Confirmed `Edition`/license model exists | ACCURATE | — |
| "Licenses are validated on every request to feature-gated endpoints" + 4 sub-claims (signature, 30-day grace, clock-rollback protection, revoked→Community) | L60–65 | Not re-verified line-by-line this round; `LicenseGate` service exists and is real | UNSUPPORTED (not independently verified this round) | — |
| LicenseGate's 10 named methods (`can_use_integrations`, `can_use_scheduling`, `can_use_api_keys`, `can_use_advanced_reports`, `can_use_sso`, `can_use_enterprise_audit`, `can_use_custom_roles`, `can_use_custom_branding`, `can_use_team_collaboration`, `can_create_multiple_orgs`) all enforce their gate | L69–80 | **TESTED** — grepped every method's call sites outside `gate.py` itself. `can_use_advanced_reports`, `can_use_custom_roles`, `can_use_custom_branding`, `can_create_multiple_orgs`: **zero call sites.** The other 6 have 1–4 call sites each. | **FALSE for 4 of 10** (Advanced Reporting, Custom Roles, Custom Branding, multi-org limits are declared but not enforced anywhere) | State plainly which of the 10 are enforced today (6) vs. declared-but-not-wired (4); do not claim "Custom branding" or "Custom roles and permissions" as an Enterprise feature until wired |
| "No scattered edition checks exist outside this service" | L82 | TESTED — true in the sense that no *duplicate* ad-hoc checks were found; but 4 of the service's own gates are called from nowhere, so the claim of centralized enforcement overstates actual enforcement coverage | OVERSTATED | — |
| 5-endpoint license API table | L86–92 | Not re-verified this round | UNSUPPORTED (not independently verified this round) | — |
| 6 license audit actions recorded | L98–103 | Consistent with `AuditAction` enum members found elsewhere this engagement; not individually re-traced to call sites this round | INFERRED, ACCURATE | — |

### docs/ADMIN_GUIDE.md

The single largest source of FALSE/UNSUPPORTED claims found. Full
per-line extraction available from this round's research; highest-value
findings below (see item 7 for the System Settings mega-finding).

| Claim | Where | What the code does | Verdict | Corrected wording |
|---|---|---|---|---|
| Admin > System Settings UI (all 4 categories, 16 settings) | L165–195 | **TESTED** — no such page/section exists anywhere in `frontend/src/pages/` or `frontend/src/components/features/settings/` | **FALSE** | Remove the entire section; see item 7 |
| "Max Concurrent Assessments... default: 3" via System Settings UI | L174 | **TESTED** — real default is 5 (`PerformanceSettings.max_concurrent_assessments = 5`), no UI exists, and the enforcement mechanism itself is unwired (item 7) | **FALSE** (UI, default value, and enforcement all wrong) | See item 7 |
| "Scanner Resource Limits: CPU and memory limits for scanner containers" | L181 | No such mechanism found anywhere in scanner provisioning/execution code | **FALSE** | Remove |
| "Active sessions are invalidated within 60 seconds" (deactivation) | L32, L449–450 | Not independently timed/tested this round | UNSUPPORTED (not independently verified this round) | Verify the actual mechanism (polling interval? token check on next request?) before restating a specific number |
| "Receives a welcome email (if SMTP is configured)" on user creation | L11–24 | No matching trigger found in `AdministrationPage.tsx` or grepped user-creation use case this round | UNSUPPORTED (not independently verified this round) | Verify SMTP-triggered welcome email exists in the use case layer, not just the UI, before Task B |
| Bulk actions (checkbox select, Activate/Deactivate/Change Role) | L48–52 | **TESTED** — zero matches for "checkbox"/"Bulk" in `AdministrationPage.tsx` | **FALSE** | Remove |
| "There is currently no CLI equivalent [to db backup/restore/check]" | L223–225 | Consistent with the 3-entry-point finding above (INSTALL.md) | ACCURATE | — |
| `docker exec kingsec kingsec db check` | L667 | **Directly contradicts the same document's own L223–225.** No `db check` subcommand exists on any of the 3 real entry points. | **FALSE**, and an internal self-contradiction | Remove; use the documented Backup feature's own verification path instead |
| `curl http://127.0.0.1:8765/api/version` | L704 | Every other endpoint in this same document uses the `/api/v1/` prefix; INSTALL.md confirms no bare `/api/health` exists either | Likely **FALSE** (wrong path) — not independently re-tested this round | Use `/api/v1/health` consistently; verify whether a version endpoint exists at all |
| "Database migrations run automatically on startup" (Docker upgrade) | L698–704 | **Contradicts README.md's own explicit claim** ("Startup validation... raises RuntimeError [if not migrated]" — i.e. the app checks, it does not auto-migrate) and this engagement's own extensively-tested `validate_schema_version()` behavior (Phase 4 work, this session) | **FALSE** | "Migrations do not run automatically — run `kingsec-migrate` (or the Docker equivalent) before starting an upgraded version." |
| RBAC permissions matrix (13 rows × 3 roles) | L60–74 | Broadly consistent with `Role`/`Permission` enums found this engagement, not re-verified cell-by-cell this round | INFERRED, largely ACCURATE | — |
| JWT/Fernet key rotation mechanics (two-pass re-encrypt, abort on failure) | L294–369 | Not re-verified this round; internally detailed and plausible given `EncryptionServicePort` design seen elsewhere | UNSUPPORTED (not independently verified this round) | — |
| Env var name `KINGSEC_JWT_SECRET` (single underscore) | L555 | Every other reference in this engagement uses `KINGSEC_JWT__SECRET_KEY` (double underscore, nested-settings convention) | **FALSE** (wrong variable name) | Fix to `KINGSEC_JWT__SECRET_KEY` |
| Scanner Health dashboard fields, status semantics | L511–530 | Consistent with `kingsec doctor`'s real, tested probe-based design (INSTALL.md, this engagement) | INFERRED, ACCURATE | — |

### docs/commercial/website-about.md, website-faq.md, website-pricing.md

| Claim | Where | Verdict | Basis |
|---|---|---|---|
| "No data leaves your network unless you enable AI enrichment with your own key" | about L11 | ACCURATE | Item 2, item 9 (telemetry) |
| "No license server phone-home" | about L11 | ACCURATE | Item 9 — no network code in telemetry module; not separately checked for a license-check network call this round, but LICENSING.md describes purely local signature validation |
| "No feature gates on core scanning capability" | about L11 | OVERSTATED | Core *scanning* itself is ungated, true — but see item 3, only 6 of the marketed 9 scanners are reachable regardless of tier |
| "Local-first & private... never transmits by default" | about L23 | ACCURATE (with item 2's caveat) | Item 2 |
| "The Free tier is genuinely free... no feature timeout" | about L27 | UNSUPPORTED (not independently verified this round) | — |
| "Safe by default... Authentication required out of the box" | about L29 | ACCURATE | JWT auth confirmed structurally required this engagement |
| "Bundles nine established open-source scanners" | about L31 | OVERSTATED | Item 3 — 9 registered, 6 reachable |
| "Orchestrates nine security scanners" | faq L7 | OVERSTATED | Item 3 |
| "Only finding title, severity, and evidence snippets sent to AI provider" | faq L43 | UNSUPPORTED (not independently verified this round) | Worth a direct check of the AI enrichment payload-builder before Task B |
| "MFA via TOTP is supported across all tiers" | faq L55 | INFERRED, ACCURATE | MFA infra confirmed present this engagement; not tier-gate-checked this round |
| "JSON, HTML, PDF, CSV, and Markdown" report formats | faq L61 | **FALSE** | Item 9 — only PDF/HTML exist |
| "Eight pre-configured profiles" | faq L67 | **FALSE** | Item 3 — six exist |
| "Free tier: all nine scanners, all eight profiles" | faq L91 | **FALSE** (both numbers) | Item 3 |
| Pricing table: "Scanners — All 9 included"; per-tier checkmark for Trivy/Semgrep/Amass | pricing L13, L31–39 | **FALSE** | Item 3 — these three are not reachable by any user at any tier today |
| "Assessment profiles — 8 profiles" | pricing L14 | **FALSE** | Item 3 — six exist |
| "Branded PDF" / "Branded reporting" — Enterprise checkmark | pricing L16, L52 | **FALSE** | Item 9 — not configurable at any tier |
| "White-label UI" — Enterprise checkmark | pricing L53 | UNSUPPORTED (not independently verified this round) | Worth a direct check before Task B |
| "No license key or online activation needed; activates on first run, no internet required" | pricing L78 | INFERRED, ACCURATE | Consistent with Community-tier-by-default finding in LICENSING.md |

### Frontend user-facing copy

| Claim | Where | Verdict | Basis |
|---|---|---|---|
| Consent banner: legal-authorization language | `CreateAssessmentForm.tsx` L330–341 | ACCURATE, but see item 1 — conflatable with technical scope, not the same claim | Item 1 |
| "The key is encrypted at rest and never shown again... only last 4 characters displayed" | `AiProviderSection.tsx` L183 | ACCURATE | Item 2 — this is the one real encrypted column |
| "Map findings to security frameworks and track compliance coverage" | `ComplianceDashboardPage.tsx` L63 | OVERSTATED | Item 4 — accurate as a page description, but doesn't disclose the keyword-matching mechanism or the fabricated-CVE defect a reader would want to know about |
| Dynamic "Encrypted: Yes/No" status fields (Backup/Identity Provider pages) | various | Out of scope — these reflect real per-record backend state, not a static marketing claim | Not a claim-audit target |

---

## Summary for Task B

**FALSE claims requiring removal or correction (blocking, per acceptance
criteria):**
1. Report formats: JSON/CSV/Markdown don't exist (README, FAQ)
2. Scanner/profile counts: "9"/"8" should be "6" everywhere they describe
   what's reachable today (README, FAQ, pricing, ADMIN_GUIDE)
3. "Source Code Review" / "Container Assessment" profiles (README) — don't
   exist
4. Pricing page's Trivy/Semgrep/Amass checkmarks — not reachable at any
   tier
5. "Branded PDF"/"Branded reporting" Enterprise checkmark — not
   configurable at any tier
6. ADMIN_GUIDE's entire System Settings UI section — doesn't exist
7. ADMIN_GUIDE's bulk-actions claim, welcome-email claim (unless Task-B-
   time verification finds the email trigger real), Scanner Resource
   Limits claim — don't exist
8. `kingsec db check` (ADMIN_GUIDE L667) — contradicts the same doc's own
   L223–225
9. "Database migrations run automatically on startup" (ADMIN_GUIDE) —
   contradicts real, tested startup-validation behavior
10. `KINGSEC_JWT_SECRET` env var name (ADMIN_GUIDE L555) — wrong, should
    be `KINGSEC_JWT__SECRET_KEY`
11. Telemetry docstring's "optional opt-in remote reporting" — no such
    capability exists (code fix, logged, not a docs-only item)
12. LICENSING.md: 4 of 10 `LicenseGate` methods (Advanced Reports, Custom
    Roles, Custom Branding, multi-org limits) are declared but unenforced

**UNSUPPORTED claims needing a verification pass before Task B can mark
them ACCURATE (not blocking discovery, but blocking ship per acceptance
criteria — "no FALSE or UNSUPPORTED claim remains"):** the "60 seconds"
session-invalidation timing, the welcome-email trigger, AI-enrichment
payload contents, "white-label UI," LICENSING.md's per-request validation
sub-claims, and several ADMIN_GUIDE operational-procedure claims listed
above — each needs either a direct code check or an explicit downgrade to
non-specific wording.

**Two real code defects found and logged (not fixed — this phase is
docs-only):**
- `mapper.py`'s placeholder `"CVE-2025-1234"` control ID (item 4)
- `AssessmentConcurrencyPort.try_reserve_slot()` built (KSEC-87-02) but
  never called — `max_concurrent_assessments` is unenforced today,
  the exact defect KSEC-87-02 was supposed to close (item 7)

**One MFA-adjacent finding surfaced incidentally:** `MfaSecretORM.secret_key`
is stored plaintext (not encrypted, not hashed) — worth its own follow-up,
out of scope for this docs-only phase.
