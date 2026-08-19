# KingSec Phase 12 — CI Gate Clearance, Part 1: Bandit and Mypy

**Date:** 2026-08-20
**Branch:** `main`
**Starting commit:** `02ded31` (Phase 11's close — one commit ahead of the prompt's stated `bc68c5d`, the extra commit being Phase 11's own report, made after the prompt was drafted)
**Ending commits:** `681e59e` (bandit), `9c697cb` (mypy)

## 1. Baseline and Phase 01–11 integrity check

`git branch --show-current`: `main`. `git log -1 --oneline` at the start of this phase: `02ded31 docs: add Phase 11 dependency vulnerability remediation report`. All 12 prior commits confirmed present via `git log --oneline`.

**Leftover-container check** (required by §6, after Phase 10 §1 and Phase 11 §1 both hit `test_collect_health_status_unreachable` failing spuriously because `diagnostics.py:91` probes `127.0.0.1:8765`): `docker ps -a` returned **zero containers** at the start of this phase. Confirmed clean.

`git status --porcelain` showed the working tree exactly as Phase 11 left it: the Phase 09 report (still untracked, never committed — carried forward unchanged), the 5 known orphan files, and 23 untracked alembic pollution files.

**Full backend suite before any change:** `tests="2854" errors="0" failures="0" skipped="0"` — exactly matching the required Phase 11 baseline.

## 2. Live re-run of bandit and mypy

**`bandit -q -r src`, live**: 16 findings, at the exact same locations Phase 09 recorded. **One discrepancy in Phase 09's own summary table, not in the underlying findings**: Phase 09's table listed B310 at "8" locations, but its own listed location string (`playbooks/actions.py:214, siem_service.py:106/137/168, ticketing_service.py:105/129/151, webhook_service.py:95, monitoring/diagnostics.py:93`) enumerates 9 distinct locations (1+3+3+1+1). The live re-run confirms **9** B310 findings, not 8 — Phase 09's count column undercounted by one; every individual location it listed was correct. Total finding count (16) was accurate either way. No other drift.

**`mypy` at project scope, live**: 17 errors in 8 files, matching Phase 09's file list and total count exactly (`upgrade_service.py`, `scanner_installer.py`, `monitoring/diagnostics.py`, `use_cases/backup.py`, `threat_intelligence_routes.py`, `copilot_routes.py`, `ai_routes.py`, `bootstrap/composition.py`). Line numbers differed slightly from any prior capture only because Phase 08–11's own edits to some of these files shifted line numbers incidentally — not a sign of new errors.

## 3. Bandit: per-finding table

| Finding | Location(s) | Determination | What was done |
|---|---|---|---|
| B310 (×9) | `playbooks/actions.py:214`, `siem_service.py:106/137/168`, `ticketing_service.py:105/129/151`, `webhook_service.py:95` | **Real defect** — see §4 | Fixed structurally: switched to `open_validated()` (siem/ticketing/webhook) or a duplicated `_NoRedirectHandler` (playbooks/actions.py), both of which refuse HTTP redirects after validating. The flagged `urlopen()` call no longer exists at these lines — bandit reports zero findings here now, not a suppression. |
| B310 (×1) | `monitoring/diagnostics.py:93` (pre-fix line number) | **False positive** | `url` is a hardcoded literal (`"http://127.0.0.1:8765/api/v1/health"`) probing this same process's own health endpoint — no operator, user, or stored value reaches it. Suppressed: `# nosec B310` with inline justification. |
| B404 (×1) | `scanner_discovery.py:16` | **Justified suppression** — see §4 | `# nosec B404` on the import line. |
| B603 (×2) | `scanner_discovery.py:343/389` (pre-fix line numbers) | **Justified suppression** — see §4 | `# nosec B603` on each `subprocess.run(` call. |
| B110 (×2) | `extended_adapter.py:101`, `middleware/performance.py:114` | **Real defect** | Both were genuine swallowed exceptions with zero trace. Fixed: replaced `except Exception: pass` with `except Exception as exc: _logger.warning(...)`, matching this codebase's existing best-effort-logging pattern (used throughout `submit_assessment.py`, `generate_report.py`, etc.). |
| B106 (×1) | `jit_provisioning.py:58` | **False positive** — see §5 | Suppressed: `# nosec B106` with inline justification (verified, not assumed). |
| B405 (×1) | `nmap_parser.py:22` | **False positive** — see §5 | Suppressed: `# nosec B405` with inline justification (verified, not assumed). |

**Final: `bandit -q -r src` exits 0, zero findings** (was 16).

## 4. §2.1 — SSRF analysis in full

Every one of the 9 B310 locations was traced individually before any fix, per the prompt's own three questions (URL provenance, scheme validation, internal/link-local blocking):

**`siem_service.py` (Splunk HEC, Sentinel, Elastic), `ticketing_service.py` (Jira, GitHub, GitLab), `webhook_service.py` (generic/Slack/Teams/Discord webhooks), `playbooks/actions.py` (custom webhook action)** — all 8 destination URLs come from **operator-configured settings** (`IntegrationSettings` fields) or a **stored playbook action config** (`config.get("url")`, set when an operator authors a playbook). Every one of these 8 call sites **already called `validate_url()`/`URLValidationPort.validate()` before opening the connection** — confirmed by direct inspection, not assumed. `url_validator.py`'s `validate_url()` (`infrastructure/notifications/url_validator.py`) is a real, comprehensive SSRF filter: scheme allowlist (`http`/`https` only — blocks `file://`, `gopher://`, etc.), then real DNS resolution via `socket.getaddrinfo()` followed by IP-range blocking covering loopback, RFC 1918 private ranges, link-local, multicast, reserved, and unspecified addresses, for both IPv4 and IPv6.

**The gap: `urlopen()`'s default opener follows HTTP redirects automatically.** `validate_url()` only validates the *initial* URL. A destination that legitimately passes validation (a real, external, non-private address) — or one that starts safe and is later compromised, or one an attacker can influence to respond with a redirect — could return an HTTP 3xx response whose `Location` header points at an internal address (the canonical example: a cloud metadata endpoint at `169.254.169.254`, itself in the already-blocked link-local range, but never re-checked because the redirect is followed *after* validation already passed). This is exactly the "Is there any allowlist, or any block on internal/link-local address ranges? ... Is there a redirect to one reachable?" question the prompt named explicitly. **Confirmed as a real, structural gap, not a hypothetical**: `urllib.request.urlopen()`'s default `OpenerDirector` includes an `HTTPRedirectHandler` that follows redirects (up to a cap) with zero re-validation.

**The fix:** `url_validator.py` gained `open_validated(req, *, timeout, allowlist=None)` — calls `validate_url()` on `req.full_url`, then opens through a new `_NO_REDIRECT_OPENER` (an `OpenerDirector` built with a `_NoRedirectHandler` subclass whose `redirect_request()` unconditionally raises `SSRFError` instead of following). All 7 infrastructure-layer call sites (siem×3, ticketing×3, webhook×1) now call `open_validated()` instead of `validate_url()` + `urlopen()` separately. `playbooks/actions.py` (application layer, cannot import `kingsec.infrastructure` per this codebase's existing hexagonal boundary — confirmed via `URLValidationPort`'s own docstring) gets a **duplicated**, functionally-identical `_NoRedirectHandler` defined locally in that module, used via its own `_NO_REDIRECT_OPENER.open(req, ...)` inside the same `try`/`except UnsafeURLError` block that already wraps `self._url_validator.validate(url)`.

**Why refuse outright rather than re-validate the redirect target?** Every one of these 8 calls is a one-shot POST (or, for the read-heavy paths, still a single fixed API call) to a specific, already-known API endpoint (Splunk's HEC ingest URL, GitHub's issues API, a configured webhook URL, etc.) — none has any legitimate reason to be redirected at all. Refusing outright is simpler, has no gap of its own (re-validating each hop would need to also cap the number of hops, handle the redirect chain's own timing, etc.), and fails loud (a `RuntimeError`/failed delivery record an operator will see) rather than silently succeeding against a moved destination.

**`monitoring/diagnostics.py`'s urlopen is different in character, confirmed**, exactly as the prompt anticipated: `url = "http://127.0.0.1:8765/api/v1/health"` is a hardcoded string literal, not read from any settings object, request, or database record. There is no attacker-controlled input this specific call could ever route through. Suppressed with justification, not fixed with `open_validated()` — the redirect-refusal fix wouldn't add anything meaningful here (nothing legitimate could ever make this URL redirect anywhere, since it targets this same process).

## 5. §2.4 — B106 and B405 verdicts

**B106 (`jit_provisioning.py:58`, `password_hash="__sso__placeholder__"`): confirmed false positive, verified rather than assumed.** Traced the only consumer of `User.password_hash`: `Argon2PasswordHasher.verify()` (`infrastructure/auth/password_hasher.py:47-51`) checks `password_hash.startswith("$argon2")` or `.startswith("pbkdf2:")` before attempting any real verification, and returns `False` unconditionally for any other format. `"__sso__placeholder__"` matches neither prefix, so **no password an attacker could ever submit would authenticate an SSO-provisioned user through the local login path** — a hard, structural, format-based rejection, not a weakened credential or a timing-attack-vulnerable comparison. This is exactly the check the prompt asked to verify before treating the finding as low-severity, and it holds.

**B405 (`nmap_parser.py:22`, `import xml.etree.ElementTree as ET`): confirmed false positive, verified rather than assumed.** The flagged import sits inside an `if TYPE_CHECKING:` block, which is always `False` at runtime — this import statement never executes. The real runtime parser, in the paired `else:` branch, is `defusedxml.ElementTree` — confirmed installed (`pyproject.toml: defusedxml>=0.7.1,<1`) and confirmed importable (`python -c "import defusedxml"` succeeds, version 0.7.1). The module's own docstring already stated this design explicitly before this phase touched anything. Bandit's static blacklist rule pattern-matches the literal import text without understanding `TYPE_CHECKING` guards, so it flags dead code as if it were live. **This is not an XXE exposure**: the actual XML parser used at runtime to process Nmap's scan output already has entity-expansion/XXE protection via `defusedxml`.

## 6. Mypy: the `unreachable` finding

**`scanner_installer.py`, `get_commands_for_current_platform()`** (originally reported at line 415, an `elif`-chain fallback `return ()`).

**Investigation:** `Platform = Literal["windows", "linux", "macos"]` (`scanner_installer.py:16`) — a closed, 3-value type. `detect_platform() -> Platform` (`scanner_installer.py:70-76`) is exhaustive **by construction**: it checks `"win" in sys.platform` and `"linux" in sys.platform`, and its final statement is an *unconditional* `return "macos"` — meaning every possible `sys.platform` string maps to one of exactly the 3 `Platform` literal values, with no way to produce a 4th value. `get_commands_for_current_platform()` then checked `platform == "windows"`, `elif platform == "linux"`, `elif platform == "macos"`, followed by a fallback `return ()`. Since the type checker can prove all 3 possible `Platform` values were already handled by the three explicit branches, the code path reaching the trailing `return ()` is provably unreachable.

**Verdict: dead code, not a disabled check and not a logic error.** There is no 4th platform this function silently fails to handle — `Platform`'s own definition and `detect_platform()`'s own exhaustive fallback jointly guarantee that. This is not a security-relevant path (platform-specific install-command selection for the scanner-installer helper feature, not an authorization or validation gate), and investigation confirmed no case is being silently skipped.

**Fix:** restructured the final `elif platform == "macos": return guide.macos` + trailing dead `return ()` into a plain `else: return guide.macos` — identical runtime behavior for all 3 platform values, zero unreachable statements, and the `else` branch's own comment documents the exhaustiveness reasoning inline so a future reader doesn't need to re-derive it.

## 7. Mypy: remaining errors, per file, and how each was resolved

| File | Error(s) | Resolution |
|---|---|---|
| `ai_routes.py` | 5× `unused-ignore` (`# type: ignore[assignment]` on `request: Request` parameters) | Removed — stale leftovers suppressing nothing today. Confirmed no real error was hiding underneath any of the 5 (mypy reported only "unused", never a paired real error, unlike `backup.py`'s case below). |
| `ai_routes.py:136` | `no-any-return` | `_resolve()` returns `Any` by design (generic DI helper). Annotated the intermediate local (`ai: AIQueryPort = _resolve(...)`) so mypy checks against `AIQueryPort.health()`'s own declared `dict[str, Any]` return type instead of accepting `Any` unchecked. |
| `threat_intelligence_routes.py:21,26` | `no-any-return` ×2 | Same pattern: `app.resolve(X)` returns `Any`; annotated `service: ThreatIntelligenceService = ...` / `generator: ThreatReportGenerator = ...` before returning. |
| `copilot_routes.py:25,30,35` | `no-any-return` ×3 | Same pattern, 3 call sites (`CopilotService`, `InvestigationNotesService`, `CopilotExportService`). |
| `upgrade_service.py:269` | `no-any-return` | `json.loads()` returns `Any`; the function declares `-> dict[str, Any]`. Added a real `isinstance(loaded, dict)` check before returning, falling back to `{}` otherwise — this also closes a latent bug: a corrupted or unexpectedly-shaped manifest file would previously have been returned as if it were a `dict` (lying to every caller) instead of degrading safely. |
| `monitoring/diagnostics.py` | `no-any-return` | Same `json.loads()` pattern as `upgrade_service.py`; same fix (`isinstance(parsed, dict)` check, with a descriptive fallback message for the non-dict case). |
| `use_cases/backup.py:740` | `unused-ignore` + `call-overload` | **A real bug hiding underneath a mismatched error-code tag.** The comment read `# type: ignore[arg-type]`, but the actual error mypy raises here is `[call-overload]` (`int()` called with a bare `object`-typed argument, which matches none of `int`'s overload signatures) — mypy correctly identifies that the `[arg-type]` tag doesn't cover the `[call-overload]` error actually occurring, so it reports the ignore as unused *while still surfacing the real error*. Fixed with a genuine `isinstance(raw_downtime, str \| int \| float)` narrowing before calling `int()`, falling back to the existing value otherwise. At runtime, the *old* code would have raised an unhandled `TypeError` for any `kwargs["estimated_downtime_minutes"]` value that wasn't already int-coercible (e.g. a dict) — confirmed via the new regression test in §8, and confirmed there was zero prior test coverage of this field at all. |
| `bootstrap/composition.py:1831` | `misc` (cannot infer type of lambda) | `lambda c, _db=db_check: SystemHealthMonitor(db_check=_db)` used a default-argument closure-capture idiom that is only necessary to avoid Python's late-binding-closure bug *inside a loop* — `db_check` here is a single, stable local variable, not a loop variable, so the idiom was unnecessary and was confusing mypy's inference against `register_factory`'s `Callable[[Container], T]` signature. Simplified to `lambda c: SystemHealthMonitor(db_check=db_check)`, matching the plain one-parameter lambdas already used by the sibling registrations immediately below it. |

**Final: `mypy` at project scope reports `Success: no issues found in 589 source files`** (was 17 errors in 8 files).

## 8. Tests added for behavioral changes

Per §4's instruction, tests were added only where a fix changed observable behavior — not for pure type-annotation or dead-code-removal fixes (`scanner_installer.py`'s `unreachable` fix, the `ai_routes.py`/`threat_intelligence_routes.py`/`copilot_routes.py` no-any-return annotations, and `composition.py`'s lambda simplification are all behavior-preserving by construction, confirmed by the unchanged full-suite count around each).

**Bandit fixes (6 new tests, committed in `681e59e`):**

| File | Test(s) | Proves |
|---|---|---|
| `tests/unit/infrastructure/test_url_validator.py` | `TestOpenValidatedRefusesRedirects` (2 tests) | `open_validated()` refuses a real HTTP 302 from a real local server, even when the initial URL is allowlisted — both to a loopback target and to a "public-looking" one, proving the refusal is unconditional. |
| `tests/unit/application/test_playbook_actions.py` | `test_redirect_is_refused_not_followed` (1 test, + 1 existing test's mock target corrected — see below) | The application layer's own duplicated `_NoRedirectHandler` genuinely works, exercised against a real local redirecting server, not a mocked exception. |
| `tests/unit/infrastructure/ai/test_extended_adapter.py` | `TestAuditRequestBestEffort` (2 tests) | The audit-write failure is logged (not silently swallowed) when the audit publisher raises, and confirms the no-audit-configured case remains a silent no-op (unchanged behavior). |
| `tests/unit/infrastructure/test_performance_middleware.py` | `test_caching_failure_is_logged_not_silently_swallowed` (1 test) | The caching-failure path logs a warning and still returns a response, calling `dispatch()` directly with a stub `call_next` (a real FastAPI/TestClient round-trip double-consumes a `StreamingResponse.body_iterator`, which raises the same error a second time from framework code the middleware never touches — not a useful way to isolate this specific `try`/`except`). |

**A pre-existing test required a deliberate, documented fix, not a silent patch**, per ground rule #4: `test_playbook_actions.py::test_allowed_url_proceeds_to_send` patched `urllib.request.urlopen`, which `_handle_webhook` no longer calls directly after this phase's fix (it now opens through the module-level `_NO_REDIRECT_OPENER`). Confirmed live before fixing: leaving the stale patch target in place made the test fall through to a **real network call** to `example.com`, which returned a genuine `405 Method Not Allowed` and failed the assertion — not a passing-for-the-wrong-reason mock, an actually-broken test. Fixed by patching `_NO_REDIRECT_OPENER.open` instead, with a comment explaining why the target changed.

**Mypy fix (2 new tests, committed in `9c697cb`):**

| File | Test(s) | Proves |
|---|---|---|
| `tests/unit/application/test_backup_use_cases.py` | `test_update_downtime_from_string`, `test_update_downtime_unparseable_falls_back_to_existing` | The `call-overload` fix's real behavioral change: a string value still coerces correctly (`"45"` → `45`), and a value that isn't `str`/`int`/`float` (e.g. a nested dict from a malformed request) now falls back to the existing value instead of the old code's unhandled `TypeError` crash. |

## 9. Gate results after

| Gate | Command | Result |
|---|---|---|
| bandit | `bandit -q -r src` | **Exit 0, 0 findings** (was 16) |
| mypy | `mypy` (project scope) | **`Success: no issues found in 589 source files`** (was 17 errors in 8 files) |
| ruff | `git ls-files '*.py' \| xargs ruff check` | **`All checks passed!`** |
| Full backend suite | `pytest` | **`tests="2862" errors="0" failures="0" skipped="0"`** (2854 baseline + 8 new: 6 bandit + 2 mypy) |

## 10. Docker rebuild and startup result

**Build:** `docker compose build` — succeeded, no cache (full rebuild). New image ID `771809757879`, `kingsec:2.0.0`, 115MB content size. Build log confirms `cryptography-50.0.0` (Phase 11's fix, still correctly present) among the installed packages.

**Startup:** started a fresh container against a new, dedicated volume (`kingsec-data-phase12`) to get a clean read independent of any prior phase's volume state (Phase 09's own `kingsec-data` volume is still known to hit the pre-existing, out-of-scope Finding 5 migration incompatibility, unrelated to this phase). Result:

```
$ docker ps --filter name=kingsec-phase12-check --format "table {{.Status}}\t{{.Ports}}"
STATUS                    PORTS
Up 11 seconds (healthy)   127.0.0.1:8765->8765/tcp

$ curl -s http://127.0.0.1:8765/api/v1/health
{"status":"ok"}
```

Container logs show a clean migration run (`alembic` applying cleanly from base to head) and a clean application boot with all 9 scanner engines registered, zero errors or warnings. The container was stopped and removed immediately after this check (per Phase 10 §1's and Phase 11 §1's established lesson: a leftover container on `127.0.0.1:8765` would spuriously fail `test_collect_health_status_unreachable` in any subsequent phase's baseline run) — confirmed via `docker ps -a` showing no KingSec containers remaining afterward (only the unrelated `buildx_buildkit_default` builder container, which is build infrastructure, not a KingSec application container).

## 11. Files changed and commit hashes

**Bandit commit `681e59e`** (15 files): `application/idp/jit_provisioning.py`, `application/playbooks/actions.py`, `application/scanner_discovery.py`, `infrastructure/ai/extended_adapter.py`, `infrastructure/integrations/{siem_service,ticketing_service,webhook_service}.py`, `infrastructure/middleware/performance.py`, `infrastructure/monitoring/diagnostics.py`, `infrastructure/notifications/url_validator.py`, `infrastructure/scanner/nmap_parser.py`, plus 4 test files (`test_playbook_actions.py`, `test_extended_adapter.py`, `test_performance_middleware.py`, `test_url_validator.py`).

**Mypy commit `9c697cb`** (9 files): `adapters/inbound/web/{ai_routes,copilot_routes,threat_intelligence_routes}.py`, `application/scanner_installer.py`, `application/use_cases/backup.py`, `bootstrap/composition.py`, `infrastructure/monitoring/diagnostics.py` (a second, separate edit on top of the bandit commit's own change to this same file), `infrastructure/upgrade/upgrade_service.py`, `tests/unit/application/test_backup_use_cases.py`.

No file was deleted. No test was weakened, skipped, or silently patched — the one pre-existing test requiring a fix (§8) is documented, not silently changed.

## 12. What this phase does NOT fix

- **`import-linter`** (Phase 09 Finding 1) — held for Phase 13 as an architectural change (introducing a port to decouple `ai_provider_routes.py` from `kingsec.infrastructure.ai.*`), per this phase's own explicit scoping.
- **Phase 09 Finding 5** (cross-version migration incompatibility, High) — **still open, still awaiting a product decision** on whether in-place upgrade from 1.0.0 is a supported path at all. Restated per instruction; not investigated or touched this phase.
- Phase 09 Findings 6, 7, 8 (no scanner binaries in the shipped image, IP-vs-URL target type gap, `.env` first-run friction) — product/packaging decisions, untouched.
- Finding 9 (alembic test pollution) — now at 23+ untracked files (growing with every full-suite run this session added more), counted, not fixed.
- Phase 11's two carried observations — the unpinned `pip>=26.1.2` in the Dockerfile, and the absence of documented minimum-safe-version guidance for operator-supplied scanner binaries — recorded again here, not fixed.
- Frontend work, including Phase 10 §4's long-qualified-headline observation on `ReportsPage.tsx`.
- Any refactor beyond what a specific gate finding demanded — e.g., `execution_routes.py`'s and other pre-existing files' broader design were not touched even though this phase's investigation passed through adjacent code.

## 13. Whether the branch is now pushable

**Bandit and mypy no longer block CI.** Both gates that this phase targeted are now genuinely clean, not suppressed-to-pass: `bandit -q -r src` exits 0 with zero findings, and `mypy` reports zero errors across the entire configured project scope. `ruff check` on tracked files remains clean (was already passing before this phase). The full backend suite passes at 2862/0.

**`import-linter` remains the one known blocker**, exactly as Phase 09 first found and this phase's own §5/§12 restate: one broken contract, `kingsec.adapters.inbound.web.ai_provider_routes` importing `kingsec.infrastructure.ai.{client,providers,errors}` directly, in violation of the hexagonal layering contract. This is deliberately not touched here — the prompt scoped it out explicitly for Phase 13, since the correct fix (introducing a port) is an architectural change deserving its own design step, not lint cleanup bundled alongside bandit/mypy work.

**Conclusion: not yet pushable as CI-green, but the remaining gap is now down to exactly one gate, with a known fix already scoped for the next phase.** Two of the three static-analysis gates that have never run in this codebase's history (Phase 09 §3) are now genuinely clean. `pip-audit` (Phase 11) and `ruff` were already clean. `import-linter` is the sole remaining item standing between this branch and a passing CI run.

## The principle this phase served

Sixteen bandit findings and seventeen mypy errors sat between eleven phases of security work and a second pair of eyes. Working through each one individually — rather than suppressing the list — found a real SSRF gap (redirect-following bypassing already-in-place validation across every operator-configured outbound integration this product has), a real type-checking bug hiding under a mismatched `# type: ignore` tag, two genuinely swallowed exceptions, and confirmed two bandit findings as false positives only after actually tracing the code, not assuming. The two gates this phase owned are now clean because the underlying code is actually correct, not because the gates were told to stop looking.
