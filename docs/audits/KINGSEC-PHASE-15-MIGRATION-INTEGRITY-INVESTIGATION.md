# KINGSEC PHASE 15 — Migration Integrity (Investigation Only)

**Date:** 2026-08-21
**Scope:** Investigation only, per this phase's own explicit instruction. No source changes, no migration changes, no test changes. This report's only artifact is itself.

---

## 1. Baseline, integrity check, and push/CI status

- **Branch:** `main`. **Starting commit:** `24da639` (`docs: add Phase 14 AI provider SSRF report`).
- **`git status`:** clean on all tracked files at the start of this phase; the only untracked items were the accumulating alembic-pollution files (see §2) and pre-existing stray artifacts from earlier manual work, none touched.
- **Push/CI status:** `git status -sb` reported `## main...origin/main [ahead 22]`. **Phases 01–14 remain unpushed to `origin/main`.** This is unchanged from Phase 14's own report and remains, in this phase's own assessment, the largest standing risk in the programme — no independent CI verification of any of the fourteen prior phases' claims has occurred.
- **Leftover-container check:** `docker ps -a` showed no `kingsec` container before the baseline suite ran.
- **Baseline full suite:** confirmed **`tests="2882" errors="0" failures="0" skipped="0"`** via `pytest --junitxml`, matching Phase 14's baseline exactly.
- **Final full suite (re-run at the end, after all investigation activity):** **`tests="2882" errors="0" failures="0" skipped="0"`** — identical to baseline. No deviation. This phase's own diagnostic activity (Docker volume inspection, `git log` searches, one experimental `python -m build --wheel` invocation, one `alembic heads` introspection call) did not leak state into the test suite. This is itself a data point relevant to §2: this session's diagnostics did not touch any persistent database, only ephemeral/read-only inspection.
- No alembic pollution files were committed. `git status` at the end of this phase shows the same clean tracked tree as the start, plus more accumulated untracked pollution (see §2) — a side effect of running the full suite twice, not of anything this phase wrote.

---

## 2. §2 hypothesis result: PARTIALLY CONFIRMED — same underlying mechanism, but two distinct incidents, not one shared file

The hypothesis was that Finding 5 (the stale-volume failure) and Finding 9 (untracked pollution files) might be **the same finding**: a currently-active file-generation process stamping a real database and then having its file deleted out from under it.

**What is confirmed:** the mechanism the hypothesis describes — an autogenerate "no changes" migration being generated, at some point applied/stamped to a real database, and then having its file removed from the repository — is **exactly what produced Finding 5**, verified with direct evidence (§3.1, §3.2).

**What is disproven, stated plainly per the prompt's own instruction not to stretch evidence:** the *currently* accumulating untracked `*__no_changes.py` files (Finding 9, ongoing since at least Phase 08) are **not** the same files, and this session found no evidence they have stamped any real, persistent database. Specifically:

### What generates them
`git grep` for `autogenerate`, `alembic.command`, and `.revision(` outside `alembic/versions/` itself found exactly one source: `tests/integration/test_alembic_migrations.py::TestMigrationAutogenerate::test_autogenerate_on_clean_state_produces_no_changes`. It runs, as a real subprocess (`_run_alembic()`, `python -m alembic ...`, `cwd=_PROJECT_ROOT`):
1. `alembic upgrade head` against a **temporary** SQLite database (`tmp_path / "test.db"`, a pytest fixture, deleted after the test session).
2. `alembic revision --autogenerate -m "no changes"` against that same temp database.

Because the subprocess uses the repository's real `alembic.ini` (only the database URL is overridden via an env var; `script_location` is not), step 2 writes its generated file into the **real, tracked-adjacent** `src/kingsec/alembic/versions/` directory — even though the database it is comparing against is thrown away immediately after. This test's own assertion (`assert "No changes detected" in result.stderr or result.returncode == 0`) is effectively a no-op check: `alembic revision` returns 0 whether or not it wrote a file, so the test has never caught this.

**Confirmed live, during this phase's own baseline suite run:** a new file, `2026_08_21_012918__no_changes.py` (revision `c3a2be21b3a7`, chaining directly onto the prior file's head `9370acb31540`), appeared in the working tree during this phase's own baseline `pytest tests/` run — direct, reproducible, in-session proof of the mechanism, not inference.

### Do they get applied and stamped, or only written to disk?
**Only written to disk.** The target database is `tmp_path`-scoped, created fresh, upgraded to head, then autogenerate runs against it — `alembic revision --autogenerate` does not itself run `upgrade`, so the newly generated revision is never applied to that (or any) database. The temp file is deleted by pytest's fixture teardown at the end of the test. This is confirmed by the full trace above and by the fact that `_register_adapters()`'s test-path default (`validate_migrations=False`, `create_schema()` instead of `alembic upgrade head` — see `bootstrap/composition.py`'s own docstring) means the vast majority of this suite's 2,882 tests never invoke real Alembic upgrade/stamp logic at all; only `test_alembic_migrations.py`'s own tests do, and only against ephemeral databases.

### Is `fa44a8933db0` among the current 36–38 files, or among any generated-and-deleted this session?
**No**, on both counts, confirmed by direct grep of every currently-existing `*__no_changes.py` file's `revision`/`down_revision` fields (none match) and by this session generating exactly one new file (`c3a2be21b3a7`) during its own test runs, unrelated to `fa44a8933db0`.

**Conclusion:** Finding 9 (the ongoing file pollution) and Finding 5 (the stale-volume stamp) share a root **mechanism** — careless handling of autogenerate "no changes" migrations — but Finding 5 is a **historical, already-crystallized incident from July 2026** (§3.2), fully explained by git archaeology, not a currently-recurring instance of the same files. The currently-accumulating pollution has not, as far as this session could determine, stranded any additional volume. Move to §3, as instructed for a hypothesis that is not fully confirmed.

---

## 3.1 Stale volume forensics

Recovered and inspected the failing state directly rather than reasoning about it.

**Method:** `docker run --rm -v kingsec-data:/data python:3.12-slim python3 -c "..."`, reading `kingsec.db` (the SQLite file inside the pre-existing `kingsec-data` volume, confirmed present via `docker volume ls`) directly with the standard library `sqlite3` module — no container startup needed to observe the state.

**Result, verbatim:**
```
alembic_version table contents: [('fa44a8933db0',)]
all tables: ['alembic_version', 'api_keys', 'assessments', 'assets', 'audit_entries',
'audit_events', 'evidence', 'findings', 'mfa_recovery_codes', 'mfa_secrets',
'notifications', 'recommendations', 'reports', 'revoked_tokens', 'scan_findings',
'scan_jobs', 'scan_reports', 'scan_results', 'schedules', 'sessions', 'users']
```
**The volume is stamped with exactly `fa44a8933db0`** — confirmed directly, not inferred. 20 data tables plus `alembic_version` (21 total).

**Where the committed chain breaks:** confirmed via `alembic heads` (run against the real, current `alembic.ini`): the current tracked chain has exactly one head, `c3a2be21b3a7` (as of this report; it advances by one on every full-suite run per §2). `fa44a8933db0` does not appear anywhere in it (§3.2). The chain breaks **immediately** — `fa44a8933db0` is not a node reachable from, or leading to, any revision alembic currently knows about at all; there is no partial match, no nearby revision to bridge from within the current graph.

**Schema comparison — decisive for §3.4:** the current, up-to-date schema (`tests/integration/test_alembic_migrations.py::EXPECTED_TABLES`) has **50 tables**. The stale volume has **20**. Missing: `organizations`, `teams`, `team_memberships`, `organization_memberships`, `licenses`, `playbooks`, `workers`, `job_queue_entries`, `job_leases`, `dead_letter_entries`, `identity_providers`, `sso_sessions`, `account_links`, `account_lockouts`, `threat_feeds`, `monitor_rules`, `monitor_events`, `monitor_alerts`, `asset_relationships`, `asset_tags`, `asset_technologies`, `asset_history`, `exposures`, `exposure_history`, `cve_entries`, `copilot_conversations`, `execution_history`, `investigation_notes`, `org_activity_events`, `plugin_sdk_manifests`, `ai_provider_config` — roughly 30 tables' worth of subsequent, legitimate feature development this volume predates entirely.

---

## 4. §3.2 provenance of `fa44a8933db0` — verbatim

`git log --all -S 'fa44a8933db0'` (pickaxe search, entire history, all refs):
```
4747d6c docs: add Phase 13 architecture boundary CI gate clearance report
02ded31 docs: add Phase 11 dependency vulnerability remediation report
6097460 build: prepare KingSec for commercial deployment and packaging
60bb527 feat: implement findings, reports, and administration modules
a967df4 feat(frontend): complete Phases 1 and 2 (scaffold, design system, and UI foundation)
```
The first two are this programme's own prior audit reports quoting the error message verbatim (Phase 11, Phase 13) — not code. The remaining three are real product history, examined individually:

**`a967df4`** (2026-07-24, tagged `frontend-v0.2.0`) — **adds** `src/kingsec/alembic/versions/2026_07_23_225151__no_changes.py`:
```
"""no changes

Revision ID: fa44a8933db0
Revises: c5982f21123b
Create Date: 2026-07-23 22:51:51.586156
"""
...
revision: str = 'fa44a8933db0'
down_revision: str | None = 'c5982f21123b'
```
This is the **origin**: `fa44a8933db0` was, at this point, a genuinely committed Alembic revision.

**`60bb527`** (2026-07-26, tagged `v1.2.0`) — adds `2026_07_25_031537__no_changes.py`, chaining forward: `down_revision = 'fa44a8933db0'` (revision `0363a63e0698`).

**`6097460`** (2026-07-27, tagged `v1.1.0`) — titled "build: prepare KingSec for commercial deployment and packaging" — **deletes 47 committed `*__no_changes.py` files in one commit** (`47 files changed, 1616 deletions(-)`), including both files above. This was a deliberate, wholesale cleanup of an accumulation of committed autogenerate pollution generated over roughly 2026-07-23 through 2026-07-27 (the same `test_autogenerate_...` mechanism identified in §2, except at that point in the project's history these were being *committed* rather than left untracked — the current untracked-and-accumulating pattern is itself, in a sense, a regression from a state where someone once cared enough to delete them).

**Does `fa44a8933db0`'s parent (`c5982f21123b`) still exist in the current tracked chain?** No — confirmed via direct grep of every currently-tracked `versions/*.py` file. It is not among the 47 files this session could directly enumerate as deleted by `6097460` either (that search only found files whose *content* changed the literal string `fa44a8933db0`); it was very likely one of the other ~45 files removed in the same commit, part of the same abandoned chain, but this session did not individually verify each of the 47 by name — see §9.

**Answer to the framing question:** `fa44a8933db0` was **committed and later removed** — not never-committed. This is a history problem, and per the prompt's own framing ("a deleted-but-once-committed revision is a history problem with a known bridge"), a bridge is at least conceptually possible — but see §6 for why it is not straightforward in practice given the schema drift found in §3.1.

---

## 5. §3.3 real-user reachability, and the resulting corrected severity

Two separate questions, both answered directly.

### Does the shipped image run `alembic upgrade head` at startup, and only that?
**Yes**, confirmed by reading the complete, 29-line source of `src/kingsec/_migrate.py` (the `kingsec-migrate` console-script entry point the Dockerfile's `CMD` invokes): it constructs the packaged `alembic.ini` path and runs exactly `python -m alembic -c <path> upgrade head` as a subprocess, nothing else. No revision-generation code path exists in the shipped runtime. `Dockerfile`'s `CMD ["sh", "-c", "kingsec-migrate && python -m kingsec"]` means a non-zero exit from this step (which "Can't locate revision" produces) **aborts the entire container start** — `python -m kingsec` never runs. This is a hard, total startup failure for any database in this state, not a degraded mode — confirmed by inspecting `_migrate.py`'s `sys.exit(run_migrations())` and the shell `&&` chaining; no repair/recovery logic exists anywhere in `startup_validator.py` (grepped for `repair`/`stamp`/`Can't locate`, no matches).

### Is there any path in the shipped artifact that generates a revision at runtime?
**No** for the runtime container — confirmed above. **But the *build* process is a different, and more concerning, story**, discovered empirically this session and not previously examined by any prior phase:

`pyproject.toml`'s `[tool.hatch.build.targets.wheel]` section contains:
```toml
include = ["src/kingsec/alembic/alembic.ini", "src/kingsec/alembic/script.py.mako", "src/kingsec/alembic/versions/*.py"]
```
This is a **filesystem glob**, evaluated at build time against whatever files physically exist — it has no awareness of git tracking status. The Dockerfile's builder stage does `COPY src/ ./src/` (an unfiltered, raw copy of the entire `src/` tree from the build host) before running `python -m build --wheel`. **Verified empirically this session**: running `python -m build --wheel` directly against this session's own (polluted, 68-file) working tree produced a wheel containing **all 68 `versions/*.py` files — the 31 legitimately tracked ones and all 37 untracked pollution files present on disk at build time**, confirmed by unzipping the built wheel and diffing its contents against `git ls-files`. Zero tracked files were missing from the wheel; all 37 untracked files were present.

**This means the shipped artifact's own `versions/` directory is not deterministic — it depends on what happens to be sitting in the builder's working tree at build time**, not on the committed repository state. Every prior phase's own Docker-verification builds in this programme (Phases 09–14) were built from this same, continuously-polluting working tree, and per this finding, likely shipped a different, non-reproducible set of extra `no_changes.py` files each time.

### Corrected severity
**Not zero, and not "purely a development artifact" — but the blast radius is currently zero because there are no customers, and the mechanism is fully specific to a build pipeline that does not currently enforce a clean checkout.** Neither extreme (retire the finding entirely per Option C, or leave it unconditionally High per the status quo) is fully supported by the evidence:

- The stale `kingsec-data` volume itself is a fossil of internal development (July 2026, pre-release, matching this project's own "no customers yet" status) — its specific occurrence has zero customer blast radius today, confirmed.
- But the **mechanism that produced it — an uncontrolled build process baking in whatever untracked migration files exist on the build machine — is live, current, and unmitigated**, confirmed by this session's own wheel build. It is not hypothetical: it is the same class of event that produced the current stale volume, and nothing in the current `Dockerfile`/`pyproject.toml`/CI process prevents it from happening again to a real release the moment there is a customer.

Corrected rating: **High is still the right severity, but the finding it should attach to has shifted** — from "an existing stale volume needs a bridge" (narrow, already-inert) to **"the release/build pipeline has no safeguard against baking non-reproducible, untracked migration state into a shipped artifact"** (live, structural, and exactly what created the original incident). This is stated as a finding, not fixed, per §0.

---

## 6. §3.4 bridge feasibility

**Is a bridge needed for the *existing* stale volume specifically?** Given §3.1's schema comparison (20 tables vs. the current 50), a "bridge" in the sense of "teach Alembic to walk from `fa44a8933db0` to today's head" is not available — the revision chain alembic would need to traverse was deleted wholesale in `6097460` and does not exist in any committed form to replay. The only two technically possible repairs for *this specific volume*:

1. **Blind stamp-to-head** (`alembic stamp head` without running the intervening migrations): **actively dangerous**, not merely incomplete. It would mark the database as fully up to date while it is actually missing ~30 tables' worth of schema. Every feature depending on those tables would fail with `no such table` at the point of use, not a migration error at startup — trading a loud, obvious startup failure for a silent, delayed one. Not recommended under any option.
2. **Manual schema catch-up**: run (or hand-reconstruct) the ~30 tables' worth of legitimate schema changes this volume is missing, then stamp to head. This is realistically equivalent to re-deriving a custom one-off migration path specific to this exact historical divergence point — significant, bespoke effort for a volume with no evidence of containing data worth preserving (20 tables of what appears to be early development/test data, not identified as anyone's production data).

**Is a bridge needed for a *hypothetical future* customer stuck in an analogous state?** This is the more important question and depends entirely on §5's structural finding: if the build-pipeline non-determinism is left unfixed, a future customer's install could, in principle, hit an analogous (though likely much less severe, since it would only involve one or two stray revisions rather than 47) stranding. A genuine, general-purpose bridge mechanism (e.g., a startup-time "can't locate revision — here is how to recover" diagnostic, or a documented manual stamp-repair procedure) is a real engineering option, but its cost is only justifiable once Option A/B/C (§7) resolves what KingSec actually commits to supporting.

---

## 7. §4 — Decision inputs: Options A / B / C

Presented without a chosen recommendation, per this phase's explicit instruction.

### Option A — Unsupported: upgrades require a clean volume
**What it means:** Document plainly (deployment docs) that in-place upgrade is not supported; recommend/require a fresh volume for any version change. Close Finding 5 as won't-fix for the existing stale volume.
**Blast radius:** Zero today (no customers). Going forward: any future customer who upgrades in place and hits a migration mismatch gets an unrecoverable, undocumented failure unless the docs are actually read first — a real support-burden risk once there are customers, proportional to how often schema changes actually break forward-compatibility (unknown — not measured this session).
**Effort:** Low — documentation only.
**Forward commitment:** None beyond maintaining the documentation. Does **not** address §5's structural build-pipeline non-determinism — a customer's *first* install could still, in principle, receive a non-reproducible `versions/` set if the release build isn't from a clean tree, which is a separate risk this option does not touch.

### Option B — Supported with a repair path
**What it means:** Commit to in-place upgrade working, build (a) a stamp-repair mechanism for the specific stranding pattern found here, and/or (b) a startup-time diagnostic that detects an unrecognized `alembic_version` stamp and surfaces actionable recovery guidance instead of a bare Alembic traceback.
**Blast radius:** Reduces future support burden if upgrades are common; but see §6 — a *correct* repair requires verifying actual schema state, not just re-stamping, which is nontrivial to automate safely and was not something this session found any existing infrastructure for.
**Effort:** Medium-to-high, and open-ended: the "repair" cost scales with how far divergent a stranded database's real schema is from any known revision, which is not knowable in general ahead of time. The one concrete instance in this repo (fa44a8933db0, 30 missing tables) is squarely at the expensive end.
**Forward commitment:** Ongoing — every future migration would need to consider "what does this do to a database stranded at some historical stamp," a maintenance burden that compounds over time. Does not, by itself, fix §5's build-pipeline non-determinism, which is the mechanism that would keep producing new instances of this problem to repair.

### Option C — Not a product issue at all
**What it means:** If the existing stale volume is accepted as a pure development artifact (confirmed, §5 — it is, for this specific instance) with no path to any current customer, retire Finding 5 as originally scoped (a bridge for *this volume*) and instead scope the real, live risk — §5's build/packaging non-determinism (Finding 9's downstream consequence) — as its own, more precisely targeted finding.
**Blast radius:** For the existing volume: zero, confirmed. For the underlying mechanism: **not zero** — this option is only fully correct if it is paired with actually fixing Finding 9's build-time inclusion behavior (the `pyproject.toml` glob + raw `COPY src/` combination), which is what would prevent recurrence. Choosing C without also committing to fixing that mechanism would be closing the finding on evidence that only supports closing *half* of it.
**Effort:** Low for the retirement itself (a documentation/tracking change); the real cost is whatever Phase 16 scopes for fixing Finding 9 properly (excluding untracked files from the wheel `include` glob, or enforcing a clean checkout in the build process — not fixed here, per §0).
**Forward commitment:** Commits the product to treating "no in-place upgrade before this point" as an accepted, permanent fact for any pre-audit-programme installation, while committing engineering effort instead to making *future* builds reproducible — arguably the highest-leverage use of effort among all three options, since it fixes the cause rather than managing one historical symptom.

---

## 8. Diagnostic scripts, verbatim, with real output

All scripts below were run from throwaway locations (the job scratch directory) or as one-off inline commands; none were added to `tests/` or `src/`.

**Script 1 — alembic revision-graph parser** (`phase15_alembic_graph.py`, run via `python <script> ` from the repo root):
```python
import re
import glob

files = glob.glob("src/kingsec/alembic/versions/*.py")
revs = {}
for f in files:
    if f.endswith("__init__.py"):
        continue
    text = open(f, encoding="utf-8").read()
    m_rev = re.search(r'^revision:\s*str\s*=\s*[\'"]([a-f0-9]+)[\'"]', text, re.M)
    m_down = re.search(r'^down_revision:.*?=\s*[\'"]([a-f0-9]+)[\'"]', text, re.M)
    if m_rev:
        revs[m_rev.group(1)] = (f, m_down.group(1) if m_down else None)

all_revs = set(revs.keys())
down_revs = {d for _, d in revs.values() if d}
heads = all_revs - down_revs
print("Total revision files parsed:", len(revs))
print("Heads (never referenced as down_revision by any file on disk):")
for h in sorted(heads):
    print(" ", h, "->", revs[h][0])
print("fa44a8933db0 appears as a revision id?", "fa44a8933db0" in revs)
print("fa44a8933db0 appears as a down_revision anywhere?", "fa44a8933db0" in down_revs)
```
Real output (against this session's working tree, 59 files parsed at that point):
```
Total revision files parsed: 59
Heads (never referenced as down_revision by any file on disk):
  c3a2be21b3a7 -> src/kingsec/alembic/versions\2026_08_21_012918__no_changes.py
  ccddeeff0011 -> src/kingsec/alembic/versions\2026_07_28_200000__add_attack_surface.py
fa44a8933db0 appears as a revision id? False
fa44a8933db0 appears as a down_revision anywhere? False
```
**Known limitation, disclosed:** the `ccddeeff0011` "head" was a **false positive** — this script's single-value regex does not handle a `down_revision` expressed as a tuple (a merge revision). Corrected against the authoritative source in Script 3 below.

**Script 2 — stale volume `alembic_version` read** (inline, not a file — a single Docker-mounted Python invocation):
```bash
docker run --rm -v kingsec-data:/data python:3.12-slim python3 -c "
import sqlite3
conn = sqlite3.connect('/data/kingsec.db')
cur = conn.cursor()
cur.execute('SELECT version_num FROM alembic_version')
print('alembic_version table contents:', cur.fetchall())
cur.execute('SELECT name FROM sqlite_master WHERE type=\"table\" ORDER BY name')
print('all tables:', [r[0] for r in cur.fetchall()])
conn.close()
"
```
Real output:
```
alembic_version table contents: [('fa44a8933db0',)]
all tables: ['alembic_version', 'api_keys', 'assessments', 'assets', 'audit_entries', 'audit_events', 'evidence', 'findings', 'mfa_recovery_codes', 'mfa_secrets', 'notifications', 'recommendations', 'reports', 'revoked_tokens', 'scan_findings', 'scan_jobs', 'scan_reports', 'scan_results', 'schedules', 'sessions', 'users']
```

**Script 3 — authoritative head check** (real Alembic CLI, not a custom parser):
```bash
cd src/kingsec/alembic && python -m alembic -c alembic.ini heads
```
Real output:
```
c3a2be21b3a7 (head)
```
Confirms exactly one head; corrects Script 1's false-positive second head.

**Script 4 — wheel-packaging empirical check** (`phase15_wheel_check.py`):
```python
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
names = sorted(
    n.split("kingsec/alembic/versions/")[-1]
    for n in z.namelist() if "alembic/versions/" in n and n.endswith(".py")
)
print("count of versions/*.py files packaged in wheel:", len(names))
for n in names:
    print(n)
```
Run via `python -m build --wheel --outdir=<scratch>` (mirroring the Dockerfile builder stage exactly) followed by the script above and a `comm -23` diff against `git ls-files`. Real output:
```
count of versions/*.py files packaged in wheel: 68
```
followed by a diff showing **37 of the 68 packaged files were untracked** (`comm -23 <wheel list> <git ls-files list>` → 37 lines, all `*__no_changes.py`), and a reverse-diff (`comm -13`) confirming **0** tracked files were missing from the wheel — i.e. all 31 tracked files plus all 37 untracked pollution files present at build time were packaged.

---

## 9. What could not be determined, and why — labeled UNKNOWN

- **UNKNOWN: the exact identity of all 47 files deleted in commit `6097460`, individually.** This session confirmed the two files directly linked to the literal string `fa44a8933db0` (via `-S` pickaxe) and confirmed the commit's full diffstat (47 files, 1616 deletions), but did not individually cross-reference all 47 filenames against `fa44a8933db0`'s own revision chain to build the complete original graph. Not required for this phase's core question (the volume's stamp and its provenance are both directly confirmed) but would be needed for anyone attempting Option B's "manual schema catch-up" repair.
- **UNKNOWN: whether the `kingsec-data-phase09` and `kingsec-data-phase12` volumes** (found alongside `kingsec-data` via `docker volume ls`, both left over from this programme's own earlier verification work) carry the same or a different stamp. Not inspected this session — out of scope for the specific finding, but worth noting they exist and were not cleaned up.
- **UNKNOWN: whether any real, external KingSec installation has ever existed outside this development environment.** This report relies on the prompt's own framing ("pre-release, no customers") as ground truth; it was not independently re-verified this session since it is a product/business fact, not something git history or the filesystem can confirm or deny.
- **UNKNOWN: how frequently schema-breaking (as opposed to no-op) migrations occur in this project's normal development cadence** — relevant to Option A's real support-burden estimate, and not measured this session.

---

## 10. Recommended Phase 16 scope

Two candidates, following directly from what this investigation found:

1. **Fix the build-pipeline non-determinism identified in §5** — the `pyproject.toml` `include = [..., "src/kingsec/alembic/versions/*.py"]` glob combined with the Dockerfile's unfiltered `COPY src/ ./src/` is what makes shipped artifacts non-reproducible with respect to the working tree's untracked pollution. This is the live mechanism behind both Finding 9 and (historically) Finding 5, and per §7's Option C reasoning, fixing it is the only choice among the three options that actually prevents recurrence rather than just documenting or repairing after the fact. This is very likely also the correct, final fix for Finding 9 itself (stop shipping what git doesn't track), closing two findings' worth of standing debt in one phase.
2. **Push Phases 01–15 to `origin/main`.** Restated from Phase 14, unchanged: twenty-two commits and fifteen phases of local-only verification remain the single largest unverified assumption in this entire programme.

Phase 14 §5's residual credential-exfiltration risk (a `base_url` pointing at a public attacker-controlled host still receives the real API key) is restated here as still open and out of scope for this phase, per §5 of the Phase 15 prompt.
