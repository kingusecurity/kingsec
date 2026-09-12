# KingSec — Remediation Plan

Owner: Abdul Mannan (VantriqSec)
Basis: `docs/PRODUCT-INVENTORY.md` @ `4e24e3b`, plus senior review corrections.
Goal: make KingSec commercially defensible — technically, legally, and in what it claims.

Save this as `docs/REMEDIATION-PLAN.md` in the repo. Each phase below contains a
prompt to paste into Claude Code verbatim. Run phases in order. Do not start a
phase until the previous one's acceptance criteria are met and committed.

---

## Correction to the audit (apply before starting)

**Inventory Risk #5 ("anomalous dependency version pins") is a false positive.**
FastAPI 0.141.1 is a real release (29 July 2026, current latest). Starlette 1.x is
real. The auditing model treated "newer than my training data" as "suspicious."
Strike Risk #5 from the inventory.

Verify yourself once, then move on:

```powershell
uv pip index versions fastapi
uv pip index versions cryptography
uv pip index versions starlette
```

---

## Phase order and rationale

| Phase | Work | Why here |
|---|---|---|
| 0 | Green baseline: 4 failing tests, CLI `--help` | You need a trustworthy signal before changing anything |
| 1 | End-to-end proof run | Nothing yet proves a real scan produces a real report. Also generates the real finding distributions Phase 2 needs |
| 2 | Executive score v2 | Product-blocking. Current score reads 0/100 on any real target |
| 3 | Auth hardening (first-admin) | Unauthenticated privilege acquisition on a security product |
| 4 | Authorization scope control | Legal exposure; gates any licence-based distribution |
| 5 | Truth pass: docs, marketing, SBOM | Misrepresentation risk the moment money changes hands |

Phases 0–2 are what stand between you and a sellable assessment.
Phases 3–5 are what stand between you and selling it safely.

---

## Phase 0 — Green baseline

**Why:** 3,915 pass / 4 fail. A red suite means every later phase is ambiguous —
you can't tell your breakage from the pre-existing breakage. Also, a security
product that ships with failing tests fails its own credibility test the first
time a technical buyer clones the repo.

**Important:** the 4 failures are *not* to be fixed by weakening assertions. They
are real determinism defects in production code that happen to surface as flaky
tests. Fix the production code.

```
PHASE 0 — Green baseline. Branch: fix/phase-0-green-baseline

Scope IN:  the 4 failing tests, CLI argument parsing
Scope OUT: everything else. No refactors. No unrelated file changes.

TASK A — Fix test_list_jobs_newest_first (x2) and test_cancel_pending_job

These fail on tied timestamps. Do NOT fix them by loosening the assertion or
adding sleeps.

Root cause to confirm first: the query orders by a timestamp column alone, so
rows created within the same clock tick have undefined relative order.

Fix in PRODUCTION code:
- Add a deterministic tiebreaker to the ORDER BY (e.g. ORDER BY created_at DESC,
  id DESC). Apply it to every list/pagination query that orders by a timestamp,
  not just the one the test touches — inconsistent pagination is a real bug that
  shows up as duplicated or skipped rows for customers.
- Report every query you changed.

TASK B — Fix test_progressive_lockout_duration

Fails on `assert 60.0 > 60.0` — a duration computed from wall-clock deltas with
insufficient resolution.

Fix in PRODUCTION code:
- Identify where lockout duration is computed. If it uses time.time() or
  datetime.now() deltas, that is the defect: lockout duration must be derived
  from the attempt count (a deterministic function), not measured elapsed time.
- If a clock is genuinely needed, inject it as a dependency (a Callable[[], float]
  parameter defaulting to time.monotonic) so tests can supply a fake clock.
- Do NOT use time.sleep in the test.

This is account-lockout logic. Explain what the code does now, what it will do
after, and confirm the security behaviour is unchanged or stronger — never weaker.

TASK C — CLI argument parsing

`kingsec --help` currently starts the server and binds a port. Add argparse to
the `kingsec` entrypoint:
  --help / -h     print usage and exit 0
  --version       print version and exit 0
  --host, --port  override bind address (default to current behaviour)
Do the same for kingsec-migrate and kingsec-bootstrap if they also lack it.
Default behaviour with no arguments must be identical to today.

ACCEPTANCE (all must be TESTED, paste real command output):
- [ ] uv run pytest -q  → exit 0, 0 failed
- [ ] uv run ruff check .  → exit 0
- [ ] uv run mypy src  → exit 0
- [ ] uv run kingsec --help  → prints usage, exits 0, binds no port
- [ ] uv run kingsec --version  → prints version, exits 0
- [ ] Add a regression test for the ORDER BY tiebreaker that fails against the
      old query and passes against the new one
- [ ] git status + git diff --stat shown before any commit; stage explicit paths

Then update docs/STATUS.md and stop.
```

---

## Phase 1 — End-to-end proof

**Why:** the inventory establishes that no complete assessment has ever been
observed producing a report. Every commercial claim you make rests on this, and
it is currently unevidenced. It also produces the real finding distributions that
Phase 2's scoring model must be calibrated against.

**Safety — read before running:**

- The scan target must be a machine or container **you own**. Use a deliberately
  vulnerable app you run locally (OWASP Juice Shop, DVWA) in Docker on your own
  machine. Do not point this at any third-party host, any shared network, or
  anything on `vantriqsec.com`.
- **Do not use your real `~/.kingsec` data directory.** Point `data_dir` at a
  throwaway path or use a fresh Docker volume. Your existing local state should
  not be touched.
- Confirm both of the above yourself before you run it.

```
PHASE 1 — End-to-end proof. Branch: chore/phase-1-e2e-evidence

Scope IN:  running the product, capturing evidence, writing docs/E2E-EVIDENCE.md
Scope OUT: fixing anything you find. Record defects; do not repair them.

PRECONDITION — confirm with me before running anything:
1. What target am I scanning, and is it local and owned by me?
2. What data_dir will be used, and confirm it is NOT my existing ~/.kingsec

SETUP
- Start a local vulnerable target in Docker on 127.0.0.1 (I will tell you which).
- Verify which scanner binaries are present on this host: nmap, nuclei, nikto,
  ffuf, gobuster, trivy, semgrep, amass, zap. Record present vs absent.
- Start KingSec against an isolated data directory.

RUN
- Register a user, create an assessment against the local target, and execute at
  minimum: Quick Host Scan, Web Application Scan, and Full Assessment (or the
  largest profile the installed binaries support).
- Time each run with a wall clock. Record actual elapsed seconds.
- Generate a PDF and an HTML report for each.

CAPTURE — write docs/E2E-EVIDENCE.md containing:
1. Environment: host OS, Python version, commit SHA, scanner binaries present
   with their versions
2. Target description (generic — no IPs of anything but loopback)
3. Per profile: actual elapsed time vs the code's estimate, exit status, whether
   a report was produced
4. FINDING DISTRIBUTION — this is the most important output. For each run, the
   count of findings at each severity: Critical / High / Medium / Low / Info.
   Present as a table. Phase 2 depends on these numbers.
5. The executive score each run produced
6. Every error, crash, empty section, malformed report element, or parser failure
   observed — as a numbered defect list, with the label TESTED
7. What did NOT work and why

RULES
- If a scanner binary is absent, say so and mark that engine NOT TESTED. Do not
  install anything without asking me first.
- Do not fix defects. This phase produces evidence, not repairs.
- Every claim labelled TESTED must have pasted command output or a real artifact
  behind it.
- Attach or reference the generated report files; do not describe them from memory.

ACCEPTANCE:
- [ ] docs/E2E-EVIDENCE.md exists with a real severity distribution table
- [ ] At least one real PDF report exists and has been opened and inspected
- [ ] Actual run times recorded for at least 3 profiles
- [ ] Defect list produced
- [ ] docs/STATUS.md updated

Then stop.
```

**After this phase, send me `docs/E2E-EVIDENCE.md`.** If a real scan does not
produce a coherent report, the remediation plan changes and Phase 2 waits.

---

## Phase 2 — Executive score v2

**Why:** `100 − Σ(penalty × count)` saturates. Four criticals → 0. Fifty lows → 0.
Any realistic assessment → 0. The consequence is commercial, not cosmetic: a
customer who remediates ten findings and re-runs still sees 0, so the score cannot
demonstrate improvement — which removes the entire reason to buy a second
assessment. This is the defect that blocks your recurring revenue.

### The design (this is the spec — do not let Claude Code invent an alternative)

Multiplicative severity retention. Each finding multiplies the remaining score by
a factor determined by its severity.

```
score = 100 × Π (retention[severity] ^ count[severity])
```

| Severity | Retention factor |
|---|---|
| Critical | 0.72 |
| High | 0.88 |
| Medium | 0.95 |
| Low | 0.985 |
| Informational | 1.00 |

Properties this gives you, and why each one matters:

- **Bounded in (0, 100]** — never saturates, never goes negative
- **Strictly monotonic** — removing any non-informational finding *always* raises
  the score. This is what makes reassessment saleable.
- **Diminishing returns** — the 40th low-severity finding hurts less than the
  first, which matches how risk actually behaves
- **Explainable to a non-expert** — "each critical finding leaves you with 72% of
  your remaining score." No CVSS vocabulary borrowed, no standard implied.

Reference values (use these as the test fixtures):

| Findings | Score |
|---|---|
| none | 100.0 |
| 1 low | 98.5 |
| 10 medium | 59.9 |
| 1 critical | 72.0 |
| 4 critical | 26.9 |
| 50 low | 47.0 |
| 200 low | 4.9 |
| 2 high + 3 medium + 20 low + 5 info | 49.1 |

Bands for the report cover:

| Range | Label |
|---|---|
| 90–100 | Strong |
| 75–89 | Good |
| 50–74 | Fair |
| 25–49 | Weak |
| 0–24 | Critical |

```
PHASE 2 — Executive score v2. Branch: feat/phase-2-executive-score-v2

Scope IN:  domain/report.py scoring, its persistence, its report rendering, tests
Scope OUT: threat-intelligence risk formula (leave it alone), UI redesign

Read docs/E2E-EVIDENCE.md first. The real severity distributions there are your
sanity check: run the new formula against every real distribution recorded and
confirm the resulting scores are spread across the range rather than clustered.

IMPLEMENT

1. Replace compute_executive_score() with a multiplicative retention model:

     score = 100 × Π (retention[severity] ** count[severity])

   Retention table (module-level Final dict, single source of truth):
     CRITICAL 0.72, HIGH 0.88, MEDIUM 0.95, LOW 0.985, INFORMATIONAL 1.0

   - Compute via exp(Σ count × log(retention)) for numerical stability.
   - Round to 1 decimal. Clamp to [0.0, 100.0].
   - Full type hints. Docstring must state plainly that this is a proprietary
     explainable heuristic and explicitly NOT CVSS, CIS, or NIST-derived.

2. Keep the old function, renamed compute_executive_score_v1(), marked deprecated.
   Do not delete it — historical reports must remain reproducible.

3. Add a score_version field ("v1" / "v2") persisted alongside every score, on
   both the report domain object and the ORM model. Write an Alembic migration
   that adds the column and backfills existing rows to "v1". Show me the
   migration before applying it.

4. Add a severity band function mapping score → label:
   90-100 Strong, 75-89 Good, 50-74 Fair, 25-49 Weak, 0-24 Critical.
   Render the label next to the number on the report cover.

TESTS — required
- Parametrised test over this exact table:
    {} → 100.0 | {LOW:1} → 98.5 | {MEDIUM:10} → 59.9 | {CRITICAL:1} → 72.0
    {CRITICAL:4} → 26.9 | {LOW:50} → 47.0 | {LOW:200} → 4.9
    {HIGH:2, MEDIUM:3, LOW:20, INFORMATIONAL:5} → 49.1
- Property test (hypothesis if already a dependency, otherwise a loop):
  removing any single non-informational finding STRICTLY increases the score.
- Informational findings never change the score.
- Score is always within [0.0, 100.0] for counts up to 10,000.
- A v1 report loaded from the DB still reports score_version "v1".

VERIFY AGAINST REAL DATA
Recompute scores for every distribution in docs/E2E-EVIDENCE.md under both v1
and v2. Put the comparison in a table in the PR description and in
docs/STATUS.md. If every v2 score is still clustered at one end, stop and tell
me — the retention constants need retuning and I will supply new ones.

ACCEPTANCE:
- [ ] uv run pytest -q → exit 0
- [ ] ruff + mypy → exit 0
- [ ] All 8 reference values match exactly
- [ ] Monotonicity property test passes
- [ ] Migration shown to me before it was applied
- [ ] v1/v2 comparison table against real E2E data produced
- [ ] A regenerated PDF report shows the new score and band — TESTED, file attached
```

---

## Phase 3 — Auth hardening

**Why:** first-registered-user-becomes-Admin means that on any network-reachable
instance, whoever reaches `/register` first owns the system. On a security
product this is the finding that ends a sales conversation.

```
PHASE 3 — Auth hardening. Branch: fix/phase-3-first-admin

Scope IN:  registration, first-admin bootstrap, related config and tests
Scope OUT: SSO/IdP, RBAC model changes, session handling

INVESTIGATE FIRST, then propose before implementing:
1. Is self-registration enabled by default? Where is that decided?
2. What exactly does kingsec-bootstrap do? Does it already create an admin?
3. What happens today between first startup and first registration on a host
   bound to 0.0.0.0? Describe the exact window.
4. Is there any existing config to disable registration? If MISSING, say so.

Report those four answers with evidence, then STOP and wait for my go-ahead
before writing code.

PROPOSED FIX (confirm with me first):
- Self-registration OFF by default. New setting, secure default.
- The initial admin is created only by kingsec-bootstrap, which requires an
  explicitly supplied credential/token and refuses to run if any user exists.
- If no admin exists and registration is disabled, the app starts, serves a clear
  "run kingsec-bootstrap" state, and does NOT silently grant admin to a caller.
- Audit-log every admin creation.

TESTS:
- Registering the first user when registration is disabled does NOT grant Admin
- kingsec-bootstrap refuses to run when a user already exists
- Existing deployments are not broken: document the upgrade path explicitly

This changes default security behaviour. Explain the migration impact for anyone
already running KingSec before you write a line of code.
```

---

## Phase 4 — Authorization scope control

**Why:** `authorized_by` and `scope` are free text. Any Analyst can point nine
active scanners at any address that parses. That is acceptable while VantriqSec
is the only operator. It is not acceptable the moment you licence the tool to
someone else, and in Pakistan the NCCIA holds exclusive powers over
unauthorized-access offences under PECA.

```
PHASE 4 — Authorization scope control. Branch: feat/phase-4-scope-enforcement

Scope IN:  domain/authorization.py, assessment creation path, config, tests, UI copy
Scope OUT: everything else

DESIGN FIRST — propose before implementing, and wait for my approval.

Requirements:
1. An Authorization becomes a first-class record, not two strings on an
   assessment: authorized_by, authorizing_organization, an explicit target
   specification (CIDR ranges / hostnames / URL prefixes), valid_from,
   valid_until, and a created_by user.
2. Assessment creation must verify the requested target falls INSIDE an active,
   unexpired authorization's target specification. If it does not, refuse — a
   typed AuthorizationScopeError, not a warning.
3. Target matching must handle: IPv4/IPv6 addresses, CIDR ranges, hostnames with
   wildcard subdomains, and URL prefixes. Reject ambiguous input rather than
   guessing.
4. An explicit, admin-only, audit-logged override for the single-operator case
   (VantriqSec's own use) so this does not block internal work — off by default.
5. Every authorization decision written to the audit log with the deciding rule.

TESTS — this is security-critical, so be thorough:
- In-scope target accepted; out-of-scope refused
- Expired authorization refused
- CIDR boundary cases (network address, broadcast, /32, /31)
- Hostname wildcard does not match a parent or sibling domain
- A target that resolves to a different IP than the one authorized — decide and
  document the behaviour explicitly, do not leave it implicit
- Override path is audit-logged and admin-only

DOCUMENTATION:
Update all UI copy and docs. The current frontend text says KingSec cannot tell
you what is authorized. After this phase that is only partly true and the copy
must describe what is now actually enforced — no more, no less.
```

---

## Phase 5 — Truth pass

**Why:** the inventory found that "local-first" is narrower than it sounds,
scoring is not standards-based, and compliance mapping is keyword matching. Your
commercial pages under `docs/commercial/` were read during the audit but never
checked against those findings. Every overstatement becomes a misrepresentation
risk the day someone pays you.

```
PHASE 5 — Truth pass. Branch: docs/phase-5-truth-pass

Scope IN:  documentation, marketing copy, SBOM. NO application code changes.

TASK A — Claim audit
Build docs/CLAIM-AUDIT.md as a table:
  Claim | Where stated | What the code actually does | Verdict | Corrected wording

Source every claim in: README.md, docs/INSTALL.md, docs/LICENSING.md,
docs/ADMIN_GUIDE.md, docs/commercial/website-about.md, website-faq.md,
website-pricing.md, and all frontend user-facing copy.

Verdict is one of: ACCURATE / OVERSTATED / UNSUPPORTED / FALSE.

Pay specific attention to:
- "local-first" — only one DB column is encrypted; findings and reports are
  plaintext in SQLite. State the encryption boundary precisely.
- Any compliance-framework claim — the mapping is post-hoc keyword matching on
  finding titles and cannot produce a finding. It is a labelling layer.
- Any scoring claim — custom heuristic, not CVSS/CIS/NIST.
- Any Windows claim — INSTALL.md says verified on Windows 10/11. Only a Linux
  container on a Windows host was tested. Native Windows install is NOT TESTED.
- Telemetry — the docstring advertises opt-in remote reporting that does not exist.
- Report branding — template supports it, nothing wires it up. Not a feature today.
- Check counts — the honest number is 9 scanner engines. Per-check counts for
  nuclei/nikto/trivy/semgrep depend on third-party template sets and cannot be
  stated.

TASK B — Rewrite the copy
Apply the corrected wording. Aim for claims that are true, specific, and still
sell. "Assessment data never leaves your machine unless you configure an
integration; findings are stored in a local SQLite database protected by
filesystem permissions" is both honest and stronger than a vague "local-first."

TASK C — Dependency licence inventory
- Run a licence scan against the resolved environment (pip-licenses or uv
  equivalent). Do not install anything without asking me first.
- Produce THIRD_PARTY_LICENSES.md listing every package, version, and licence.
- Flag every GPL/AGPL/copyleft package explicitly.
- Generate an SBOM (CycloneDX or SPDX) and commit it.
- Add a CI step that fails on a disallowed licence.
- Separately document the 9 external scanner binaries: KingSec shells out to
  them and does not redistribute them. State the operator's own obligations.

ACCEPTANCE:
- [ ] docs/CLAIM-AUDIT.md with a verdict for every claim found
- [ ] THIRD_PARTY_LICENSES.md + SBOM committed
- [ ] CI licence gate added and TESTED
- [ ] No FALSE or UNSUPPORTED claims remain in customer-facing copy
```

---

## Backlog (after Phase 5)

Track in `docs/PHASES.md`; none of these block revenue.

- Wire up the 4 unenforced licence gates, or delete them
- Make report branding a real configurable feature, or remove the code
- Remove the telemetry docstring's claim, or implement opt-in remote reporting
- Generate a real `pytest --cov` coverage figure
- Test the native Windows install path end to end, or remove it from the docs
- Review the frontend tree — never audited, and it is what the customer sees
- Onboarding: the Docker image ships without scanner binaries, so a fresh install
  finds nothing. Decide between a documented host-install path and bundling —
  bundling inherits those tools' GPL terms, so decide deliberately.

---

## Standing rules for every phase

1. One phase per Claude Code session. No scope creep.
2. Two failed fix attempts → stop, write `docs/BLOCKED.md`, wait.
3. `git status` and `git diff --stat` before every commit. Stage explicit paths.
   Never `git add .`.
4. Every claim labelled TESTED / INFERRED / NOT TESTED / MISSING, with pasted
   command output behind anything marked TESTED.
5. `docs/STATUS.md` updated before the session ends.
6. Any migration, default-behaviour change, or destructive operation gets shown
   to you before it runs.
