# KingSec Phase 20 — CI Pipeline End-to-End

**Date:** 2026-08-21
**Scope:** Close the Linux/Windows mypy divergence Phase 19 §8 found, then drive
CI through every subsequent gate — none of which had ever executed there —
to a full, passing, end-to-end pipeline run.

---

## 1. Baseline, Integrity Check, Starting CI State, Pollution Count

- **Branch:** `main`, starting commit `c797f35` (Phase 19's report commit),
  even with `origin/main`.
- **`git status` at start:** clean except pre-existing, unrelated untracked
  files (`docker-build-log.txt`, `docs/audits/KINGSEC-PHASE-09-*.md`,
  `docs/audits/dead-button-audit*.md`, `kingsec-image.tar`,
  `rebuild-frontend.ps1`) — none touched by this phase.
- **Leftover-container check:** none.
- **Starting CI run:** `32487127974` (Phase 19's report push) —
  `Lint (Ruff)` ✅, `Types (mypy)` ❌ on all three Python versions (identical
  errors to Phase 19 §8.3), `Frontend Quality Gates` ✅. Recorded as the
  starting position per §7's instruction; not re-triaged, since Phase 19
  already fully diagnosed it.
- **Full suite before any change:** 2887 passed, 0 failures, 0 skipped,
  179.6s — matches Phase 19's baseline.
- **Pollution count at start:** 0 (`git status --porcelain
  src/kingsec/alembic/versions/`).
- **Pollution count at end:** 0, re-checked after every local full-suite run
  in this phase.
- **Commits pushed:** all four rounds below, `c797f35..34d214d`. Committed
  before every Docker verification step, per the standing Phase 17 §7
  reminder.

---

## 2. §2 Platform-Divergence Decision

**Chosen: pin `platform = "linux"` in `[tool.mypy]`.**

Alternatives considered and rejected:

- **Check both platforms locally** (two invocations or a documented second
  command): rejected. It relies on developer discipline that has already
  failed twice in this programme (the ruff tracked-files convention, Phase
  18; the implicit host-platform mypy check, Phase 19) — an unenforced habit
  is exactly the failure mode this phase exists to close. It also has real,
  demonstrated cost: empirically, checking a `sys.platform`-guarded branch
  under *both* configured platforms requires every branch to independently
  satisfy `warn_unreachable` under each platform — verified directly (a
  minimal probe checked under `--platform win32` flagged the post-`if`
  code as unreachable, which `--platform linux` did not), so dual-platform
  cleanliness is genuine, ongoing maintenance work, not a one-time cost.
- **Leave it, fix only the five errors:** rejected. This is the "cheapest
  now" option the prompt itself names as producing the next surprise — it
  does nothing to prevent a *third* file from drifting the same way.

**What is no longer covered:** `licensing/parser.py`'s `if sys.platform ==
"win32":` branch (the Windows registry `MachineGuid` lookup used as one
input to the machine-fingerprint hash) is now unreachable-and-skipped by
mypy under the pinned config — on *every* platform, including a literal
Windows machine running this same config, since `platform=` overrides the
host OS mypy actually runs on. Verified empirically: a probe file checked
with `--platform linux` produced zero errors for a `winreg`-using branch
that `--platform win32` type-checks fully. This branch is not dead code —
`compute_machine_id()`'s docstring and the surrounding license-binding
feature imply real, non-container installs are a supported use case — but
it is now checked by nothing in this project's own tooling. If native
Windows support is ever formalized, a dedicated Windows-targeted mypy job
would need to be added to CI to restore coverage for exactly this branch;
until then, changes to it should get manual review with that in mind.

---

## 3. §3.1 `winreg` Fix, Including Windows Runtime Verification

`src/kingsec/infrastructure/licensing/parser.py`, `compute_machine_id()`:
restructured from a bare `try: import winreg ... except (ImportError,
OSError, FileNotFoundError):` to an explicit `if sys.platform == "win32":`
guard around the import and a narrower `try: ... except OSError:` around
just the registry calls (`FileNotFoundError` is already an `OSError`
subclass, so it was redundant in the original tuple; `ImportError` is no
longer reachable once the platform check gates the import itself).

**Why this approach over the alternatives named in the prompt:** a scoped
per-module mypy override (`[[tool.mypy.overrides]]` excluding this one
module from strict checking) was rejected — it would silence *all* type
errors in the file, not just the platform-specific ones, a much blunter
instrument than necessary. The `sys.platform` guard is what mypy's own
documentation names as the mechanism for exactly this situation, and it is
the same technique this fix relies on at the config level (§2).

**Windows runtime verification, on this real Windows machine:**
```
registry MachineGuid: 37cf38fc-1879-4d3b-8ec8-9a66640dd2b9
expected (with registry guid): 81ede3ab87ac45a7a64f9c45ccee1d3ded0f226bb5e9346e4ad8718549669f8b
actual from compute_machine_id():  81ede3ab87ac45a7a64f9c45ccee1d3ded0f226bb5e9346e4ad8718549669f8b
CONFIRMED: winreg branch executed and its value is incorporated into the fingerprint
```
Computed the expected SHA-256 by hand (hostname + MAC + the registry's own
`MachineGuid`, read independently via a separate `winreg` call) and
confirmed it matches `compute_machine_id()`'s actual output exactly — the
restructured code still reads the real registry value and folds it into the
fingerprint identically to before.

---

## 4. §3.2 `sandbox.py` Fix, Per-Platform mypy Behavior

Empirically checked `resource.getrusage(...)` under both platforms (isolated
probe file, this project's own strict settings applied via `pyproject.toml`
auto-discovery):

| Platform | Result |
|---|---|
| `--platform linux` | `error: Unused "type: ignore" comment [unused-ignore]` — `resource` resolves fully typed, nothing to suppress |
| `--platform win32` | Clean — the ignore is consumed (a real, suppressed error exists; typeshed's `resource` stub is unavailable/restricted there) |

Under the platform now pinned as canonical (`linux`), the ignore comment
has nothing left to suppress, so it was removed. This is not a bare
"blindly remove it" — the platform-conditional behavior was verified
directly first, and the resulting single-platform config makes "clean under
the canonical platform" the correct, unambiguous target rather than trying
to satisfy two simultaneously.

---

## 5. §4 CI Triage, Round by Round

All run IDs, all steps, quoted from `gh run view --log-failed` /
`gh run view <id>` verbatim where noted.

### Round 0 — starting position (§1)
Run `32487127974`. `Lint (Ruff)` ✅, `Types (mypy)` ❌ ×3, `Frontend` ✅.
Not a round produced by this phase; recorded for continuity only.

### Round 1 — after the mypy/platform fix (commits `2db0831`, `dd0cc24`)
Run `32488065550`.

| Job | Lint | Types | Arch | Bandit | pip-audit | pytest |
|---|---|---|---|---|---|---|
| 3.11 | ✅ | ✅ | ✅ | ✅ | ❌ | — |
| 3.12 | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| 3.13 | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |

**mypy now passes on all three versions** — confirms §2/§3's fix works in
CI, not just locally. Four new gates executed for the first time ever
(import-linter, Bandit, pip-audit, pytest).

- **3.11 pip-audit**, verbatim: `Found 2 known vulnerabilities in 1
  package` — `setuptools 79.0.1`, `PYSEC-2026-3447`, fixed in `83.0.0`.
  Not reproduced on 3.12/3.13 — a per-Python-version-image difference in
  the pre-bundled `setuptools`, not flakiness.
- **3.12/3.13 pytest**, verbatim: `3 failed, 2884 passed, 66 warnings in
  108.14s` —
  `TestNonZeroExitAllThreeSurfaces::test_message_reaches_all_three_surfaces`,
  `TestTwoModesDistinguishableAcrossAllSurfaces::test_binary_absent_and_nonzero_exit_differ_on_every_surface`,
  `TestStartupValidator::test_check_database_with_existing_db`.

### Round 2 — after the three round-1 fixes (commits `8247ff0`, `dc46cb8`, `a7e00ad`)
Run `32488936473`.

| Job | Lint | Types | Arch | Bandit | pip-audit | pytest |
|---|---|---|---|---|---|---|
| 3.11 | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| 3.12 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ **(full job green)** |
| 3.13 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ **(full job green)** |

**First fully green jobs in the programme's history** (3.12, 3.13, every
step including `Upload coverage`). 3.11's `setuptools` fix worked
(pip-audit now clean there too), but pytest surfaced two *new* failures:
`TestStartupValidator::test_check_python_version_passes`,
`TestStartupValidator::test_validate_all_returns_report` — both
`AssertionError: assert False is True`, only on 3.11.

### Round 3 — after the Python-version-floor fix (commit `34d214d`)
Run `32489403962`.

| Job | Result |
|---|---|
| Quality Gates (3.11) | ✅ **all steps** |
| Quality Gates (3.12) | ✅ **all steps** |
| Quality Gates (3.13) | ✅ **all steps** |
| Frontend Quality Gates | ✅ **all steps** |

**Every job, every step, all green.** This is the first complete,
end-to-end CI pipeline pass in the programme's history.

No round in this phase "revealed nothing" — every push surfaced at least
one new, previously-invisible finding, consistent with §0.8's framing that
iteration was expected, not scope creep.

---

## 6. Every Linux-Only Test Failure — Broken Test or Broken Code

### 6.1 `test_message_reaches_all_three_surfaces` / `test_binary_absent_and_nonzero_exit_differ_on_every_surface` — **broken test**

`_run_nonzero_exit()` (`tests/integration/adapters/inbound/web/test_failure_mode_messages_surfaces.py`)
injected a `FakeRunner` intending full isolation from real subprocess
execution, but left `NmapSettings()` at its default `binary_path="nmap"`.
`NmapPlugin.is_available()` (`infrastructure/scanner/plugins/nmap/adapter.py:75-82`)
checks that via a *real* `shutil.which(binary)` call before the injected
runner is ever reached — an environment probe the test's own fixture setup
never controlled. On this dev machine, real `nmap.exe` is on `PATH`
(confirmed: `which nmap` resolves), so the test happened to reach the fake
runner and exercise its intended nonzero-exit path. On CI's clean Ubuntu
runners — no scanner binaries installed at all, the already-out-of-scope
Finding 6 — `is_available()` returns `False` before the fake runner is ever
called, collapsing "nonzero exit" into "binary absent."

**Not the code's fault**: `is_available()`'s real `shutil.which()` check is
correct, intentional production behavior — you should not report a scanner
"available" if its binary genuinely isn't installed. The test's isolation
was incomplete. **Fix:** `binary_path="python"` — guaranteed present (it's
running the test), and the *same* sentinel this codebase already uses for
this exact purpose in `test_adapter.py`, `test_nmap_plugin.py`, and
`test_nuclei_plugin.py`. This test file was the one place that didn't
follow the established pattern. No `skipif` used or needed.

### 6.2 `test_check_database_with_existing_db` — **broken code**

`StartupValidator.check_database()` ran `SELECT 1` — a constant literal
that never reads a page — against a file containing garbage bytes, to
decide whether it's a real, accessible SQLite database. Whether that
statement alone triggers SQLite's file-header validation turns out to
depend on the linked SQLite version's own eagerness, not on any explicit
validation logic in the code:
```
sqlite3.sqlite_version: 3.50.4   (this dev machine)
SELECT 1 against garbage bytes: raises "file is not a database"
```
— but CI's Python 3.12/3.13 (different bundled SQLite build) silently
returned a row and reported `passed=True, message='Database accessible
(0.0 MB)'`. **This is a real code defect**, not a test artifact: the health
check's actual reliability was accidental, riding on an unspecified,
version-dependent side effect rather than genuine validation. **Fix:**
query `SELECT count(*) FROM sqlite_master` instead — reading the schema
catalog forces a real page read on every SQLite version, verified directly
against both a garbage file (now reliably raises) and a real database
(query still succeeds normally). No `skipif` used or needed — the fix
makes the check correct everywhere, which is what a startup health check
claiming "verify database is accessible" should have done from the start.

### 6.3 `test_check_python_version_passes` / `test_validate_all_returns_report` — **broken code**

`StartupValidator.check_python_version()` hardcoded a `(3, 12)` floor,
contradicting two other explicit, deliberate project artifacts:
`pyproject.toml`'s `requires-python = ">=3.11"` and the CI matrix's own
`["3.11", "3.12", "3.13"]`. This was invisible until this phase because
pytest had never run under Python 3.11 in CI before (Round 2), and this
dev machine's `.venv` is Python 3.14 (>= 3.12), so the check always
silently passed locally regardless of whether its floor was correct.
Confirmed nothing in the codebase actually needs 3.12: every other gate
and 2885 other tests already ran clean under 3.11 in the same CI run, and
a grep for PEP 695 `type X = ...` syntax (3.12+-only) found none. **Fix:**
corrected the floor to `(3, 11)`, matching what the project declares and
tests. The two tests were correct as written (they assert "the running,
supported interpreter passes this check," not any specific version) — the
validator was wrong. No `skipif` used or needed.

---

## 7. `pip-audit` — CI Result vs. the Local Finding

**Phase 11's characterization, confirmed exactly by this phase**: local
`pip-audit` findings (`mcp` via a globally-installed `semgrep`, `pip` the
machine's own, `pypdf2` an orphan absent from `pyproject.toml`) were
environment noise, not project findings. **CI's authoritative result**,
after the one genuine fix this phase made (`setuptools` upgrade in the
workflow):
```
No known vulnerabilities found
```
on all three Python versions. The one *real* CI-only finding this phase
uncovered — `setuptools 79.0.1`, `PYSEC-2026-3447` on the 3.11 runner
image specifically — was fixed at the workflow level (`python -m pip
install --upgrade pip setuptools`) and confirmed clean in Round 2 onward.
Local `pip-audit` remains not a valid signal for this project, exactly as
Phase 11 and this phase's own §4 prediction stated; the workflow-installed,
clean-environment run is the only one that matters going forward.

---

## 8. Final Gate Results, Local and CI Side by Side

| Gate | Local (this dev machine) | CI (all 3 Python versions) |
|---|---|---|
| Lint (Ruff) | `ruff check .` — all checks passed | ✅ pass |
| Types (mypy) | `mypy src` — no issues, 585 files | ✅ pass |
| Architecture (import-linter) | `lint-imports` — 3 kept, 0 broken | ✅ pass — identical: 3 kept, 0 broken |
| Security (Bandit) | `bandit -q -r src` — 0 issues | ✅ pass — identical, only nosec-parsing warnings on both |
| Security (pip-audit) | Historically noisy/invalid (Phase 11) | ✅ pass — "No known vulnerabilities found" |
| Test (pytest) | 2887 passed, 0 failed, 0 skipped | ✅ 2887 passed, identical, on all 3 versions |

**Local and CI now agree on every gate** — the exact outcome §5's
verification requirement names.

---

## 9. Suite Counts, Local and CI

- **Local:** 2887 passed, 0 failures, 0 skipped (unchanged from Phase 19's
  baseline — no tests added or removed this phase, only two tests fixed
  and two production files corrected).
- **CI, all three Python versions:** `2887 passed` — identical to local, on
  3.11, 3.12, and 3.13 alike (Round 3 verbatim: `2887 passed, 3 warnings in
  109.73s` / `2887 passed, 3 warnings in 114.10s` / `2887 passed, 67
  warnings in 116.73s`). **No difference between local and CI counts** —
  this is itself the finding: every one of the 2887 tests, including Phase
  19's three atomicity regression tests, now runs and passes on the
  platform the product actually ships on, for the first time.

---

## 10. Docker Rebuild, Startup, and Fresh Volume Stamp

**Build:** `docker compose build --progress=plain` against the fully pushed
working tree (`34d214d`): `Image kingsec:2.0.0 Built`.

**Startup, fresh volume:** a new named volume (`kingsec-data-phase20`), all
three required secrets generated fresh (`KINGSEC_SECRETS__ENCRYPTION_KEY`,
`KINGSEC_JWT__SECRET_KEY`, `KINGSEC_SECRETS__API_KEY_PEPPER` — this
environment has no defaults for them, per the standing memory note), started
against the freshly built image.

**Migration log, full chain to head:**
```
INFO:alembic.runtime.migration:Running upgrade d1e2f3a4b5c6 -> 91969658a556, rename stale indexes to match models.py
```
Same head as Phase 19 — this phase made no migration changes, so this is a
regression check, not new ground.

**Health:** Docker's own `HEALTHCHECK` reported `Up 13 seconds (healthy)`;
the access log recorded `GET /api/v1/health` → `status_code=200`.

**Fresh volume's `alembic_version` and index state**, read directly via a
throwaway `python:3.12-slim` container mounting the same volume:
```
alembic_version: [('91969658a556',)]
account_links indexes: ['ix_account_links_provider_id', 'ix_account_links_provider_user',
  'ix_account_links_user_id', 'sqlite_autoindex_account_links_1', 'sqlite_autoindex_account_links_2']
sso_sessions indexes: ['ix_sso_sessions_provider_id', 'ix_sso_sessions_user_id',
  'sqlite_autoindex_sso_sessions_1']
```
Identical to Phase 19's fresh-volume result — confirms Phase 19's atomicity
fix and Phase 20's changes coexist cleanly in the shipped container image.

**Teardown:** container and volume both removed; confirmed via `docker ps -a`
and `docker volume ls` that neither remains, and nothing is left listening
on port 8765.

---

## 11. Files Changed and Commit Hashes

| Commit | Files | Summary |
|---|---|---|
| `2db0831` | `pyproject.toml`, `src/kingsec/infrastructure/licensing/parser.py` | Pin `platform = "linux"`; restructure `winreg` usage with `sys.platform` narrowing |
| `dd0cc24` | `src/kingsec/infrastructure/plugin/sandbox.py` | Drop the now-genuinely-unused `type: ignore` |
| `8247ff0` | `tests/integration/adapters/inbound/web/test_failure_mode_messages_surfaces.py` | Pin `binary_path="python"` for deterministic nonzero-exit fixture |
| `dc46cb8` | `src/kingsec/infrastructure/startup/startup_validator.py` | `check_database()`: force a real page read (`sqlite_master` count) |
| `a7e00ad` | `.github/workflows/ci.yml` | Upgrade `setuptools` alongside `pip` in the install step |
| `34d214d` | `src/kingsec/infrastructure/startup/startup_validator.py` | `check_python_version()`: correct the floor to `(3, 11)` |

All pushed to `origin/main` (`c797f35..34d214d`).

---

## 12. What This Phase Does NOT Fix

- **Finding 5's product decision** (Option A/B/C, Phase 15 §7) — still the
  product owner's.
- **Phase 18 §4's two missing indexes** (`asset_history.timestamp`,
  `exposures.severity`) — still awaiting a product-owner decision.
- **The runtime engine's transaction semantics** (Phase 19 §4.2) — still
  reported only, reachable solely via `create_all()` on a fresh database.
- **Windows-only type coverage for `licensing/parser.py`'s `winreg`
  branch** (§2) — a new, explicit gap this phase's own fix introduces;
  documented, not closed.
- Findings 6, 7, 8 (no scanner binaries in the image — directly responsible
  for §6.1's failure surfacing at all; IP-vs-URL target type; `.env`
  friction).
- Phase 11's carried observation about scanner-binary version guidance
  (distinct from the `pip`/`setuptools` finding this phase did fix).
- Phase 12's carried observation (`diagnostics.py`'s hardcoded probe).
- Phase 14 §5's residual credential-exfiltration risk — still open.
- Phase 16's two carried notes (builder-stage `.git` layer;
  `_skip_empty_autogenerate_revision` in production `env.py`).
- Frontend work — `Frontend Quality Gates` passed throughout this phase
  without needing any changes.
- No refactor beyond what a specific, observed CI failure demanded — every
  change in §11 traces directly to a verbatim log line.

---

## 13. Recommended Phase 21 Scope

1. **Decide the native-Windows support question explicitly.** §2's fix
   left `licensing/parser.py`'s `winreg` branch completely unchecked by
   mypy. If Windows-native (non-container) deployment is a real, ongoing
   target, a dedicated Windows mypy job in CI would close that gap
   properly; if it isn't, the branch (and the machine-binding feature's
   scope) deserves an explicit decision rather than silent, unchecked
   code.
2. **Coverage upload was skipped by prior rounds' failures** — now that
   Round 3 is fully green, confirm `codecov/codecov-action` is actually
   receiving and publishing coverage from all three Python versions, not
   just succeeding as a no-op step.
3. Continue carrying forward Finding 5, the two missing indexes, and the
   other explicitly out-of-scope items from §12 until a product-owner
   decision or a dedicated phase addresses them.
