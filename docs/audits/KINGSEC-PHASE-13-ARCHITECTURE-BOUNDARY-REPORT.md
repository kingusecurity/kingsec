# KINGSEC PHASE 13 — CI Gate Clearance, Part 2: Architecture Boundary

**Date:** 2026-08-20
**Scope:** Resolve the sole remaining `lint-imports` contract violation identified in Phase 09 and confirmed in Phase 12 (`ai_provider_routes.py` importing infrastructure directly), and evaluate the SSRF-control duplication Phase 12 introduced as a side effect of that same boundary rule.

---

## 1. Baseline and integrity

- **Branch:** local working branch, no feature branch switch performed (consistent with Phases 09–12).
- **Starting commit:** `d18747b` (`docs: add Phase 12 CI gate clearance report`).
- **`git status` at start:** clean on all tracked files relevant to this phase; the only untracked items were pre-existing alembic-pollution files (`src/kingsec/alembic/versions/*__no_changes.py`, 34 files as of this phase — see §7) and stray artifacts from prior manual Docker/frontend work (`docker-build-log.txt`, `kingsec-image.tar`, `rebuild-frontend.ps1`, two `dead-button-audit*.md` files, and an already-written `KINGSEC-PHASE-09-CONSOLIDATION-VERIFICATION-REPORT.md`) — none of these are touched or committed by this phase.
- **Leftover-container check:** `docker ps -a` showed no `kingsec` container running or stopped before the baseline suite ran. This check has been required since Phase 10 because `diagnostics.py:91`'s hardcoded `http://127.0.0.1:8765/api/v1/health` probe causes `test_collect_health_status_unreachable` to fail spuriously if anything is listening on that port.
- **Full suite before any change:** confirmed against the Phase 12 baseline of 2,862 passed, 0 failed (re-verified via the same full-suite run methodology used later in §10; no discrepancy found).

## 2. §3.1 — The import-linter contract, verbatim

From `pyproject.toml`:

```toml
[tool.importlinter]
root_package = "kingsec"
include_external_packages = true
exclude_type_checking_imports = true

[[tool.importlinter.contracts]]
name = "Hexagonal layering (dependencies point inward only)"
type = "layers"
layers = [
  "kingsec.adapters | kingsec.infrastructure",
  "kingsec.application",
  "kingsec.domain",
]

[[tool.importlinter.contracts]]
name = "Domain is pure (no frameworks, no outer layers)"
type = "forbidden"
source_modules = ["kingsec.domain"]
forbidden_modules = [
  "fastapi", "uvicorn", "httpx", "pydantic", "sqlite3",
  "kingsec.application", "kingsec.adapters", "kingsec.infrastructure",
]

[[tool.importlinter.contracts]]
name = "Application knows domain only (defines ports, imports no adapters)"
type = "forbidden"
source_modules = ["kingsec.application"]
forbidden_modules = [
  "fastapi", "uvicorn", "httpx", "sqlite3",
  "kingsec.adapters", "kingsec.infrastructure",
]
```

Three contracts total. The `layers` contract's `"kingsec.adapters | kingsec.infrastructure"` entry makes `adapters` and `infrastructure` **siblings** — neither may import the other, both may only depend inward on `application` → `domain`. This is exactly the rule `ai_provider_routes.py` (an adapter) broke by importing `kingsec.infrastructure.ai.*` directly.

**Pre-existing exceptions:** `grep -n "ignore_imports" pyproject.toml` returns zero matches. There is no prior workaround for this or any other violation — the contract has never been relaxed.

`tests/` sits outside `root_package = "kingsec"`, so the contract does not apply to test files, consistent with every prior phase's understanding.

## 3. §3.2 — Per-import trace in `ai_provider_routes.py`

Pre-refactor imports and their exact usage:

| Import | Names used | Where (pre-refactor line) | Usage kind |
|---|---|---|---|
| `kingsec.infrastructure.ai.client` | `AIClient` | `test_ai_provider_config()`, ~L226 | Instantiation — one throwaway client per test-connection call, closed in a `finally` |
| `kingsec.infrastructure.ai.errors` | `AIError` | `save_ai_provider_config()` ~L148, `test_ai_provider_config()` ~L197 | Exception-catch — narrows a `try` around provider resolution / the network call |
| `kingsec.infrastructure.ai.providers` | `default_model_for`, `resolve_provider` | `get_ai_provider_config()` (×3 call sites), `save_ai_provider_config()`, `test_ai_provider_config()` | Function calls — `resolve_provider` returns a `ProviderConfig` strategy object later used for `build_endpoint`/`build_headers`/`build_payload`/`extract_text`; `default_model_for` is a pure lookup |

**The `errors` question, answered specifically:** `AIError` (in `infrastructure/ai/errors.py`) is defined as `class AIError(ExternalServiceError):` — it is already a subclass of the shared-kernel `kingsec.shared.errors.ExternalServiceError` (`src/kingsec/shared/errors/exceptions.py`). The sibling route file `ai_routes.py` already imports `ExternalServiceError` from `kingsec.shared.errors` safely (shared kernel, not infrastructure) and catches it in four places. Nothing else in these call sites raises `ExternalServiceError` directly, so catching the parent type instead of `AIError` is behaviorally identical — **no exception-translation layer was needed**, only a swapped import.

## 4. §3.3/§3.4 — Existing pattern and pre-existing port check

**Existing pattern cited:** `ai_routes.py` already depends on `kingsec.application.ai.ports.AIQueryPort` (an application-layer ABC) rather than importing infrastructure directly, resolving it via `Application.resolve()` — the same `container.register_factory`/`register_instance` DI pattern used throughout `bootstrap/composition.py`. This is the model the fix conforms to, the same discipline as Phase 01 reusing `require_admin` exactly as `secret_routes.py` did.

**Does `AIQueryPort` already serve the need?** No. `AIQueryPort.generate`/`chat`/`health` operate against the **currently-configured** provider, resolved internally via `AIConfigResolver.resolve()`, which takes no override arguments. `ai_provider_routes.py`'s `/test` endpoint has a fundamentally different requirement: test **arbitrary, not-yet-saved candidate credentials** (provider name, API key, model, base URL) supplied directly in the request body, which `AIConfigResolver` never sees. Forcing this through `AIQueryPort` would require either adding override parameters that only one caller needs, or resolving a fake "configuration" through a path built for a different purpose. This is a genuinely different capability, not a modest extension — justifying a new, narrowly-scoped port (`AIProviderTestPort`) rather than distorting `AIQueryPort`.

## 5. Pre-refactor test coverage — stated honestly

`tests/integration/adapters/inbound/web/test_ai_provider_routes.py` (pre-Phase-13) had 7 tests covering `GET`/`PUT` config precedence, key masking, and the keep-existing-key-on-omit semantics thoroughly. The `/test` endpoint — the exact code this phase moves behind a port — had **exactly one test**, `test_unsupported_provider_fails_without_any_network_call`, covering only the pre-check path. The real outbound-HTTP-call logic (`AIClient.post_json` → provider strategy → response parsing) had **zero automated coverage**; the file's own prior docstring stated this was "deliberately NOT mocked... live-verified manually" instead.

**Characterization tests added** (`TestTestConnectionAgainstRealServer`, 3 tests, using a real local `ThreadingHTTPServer` shaped like Anthropic's `/v1/messages` endpoint — matching this codebase's established real-server-over-mock pattern from `tests/integration/ai/conftest.py`):

- `test_successful_connection` — asserts 200, `success: true`, correct endpoint path (`/v1/messages`), correct `x-api-key` header, and that the API key is never echoed in the response.
- `test_failed_connection_reports_failure_without_500` — a 401 from the stub server produces `success: false` with no 500, and exactly one `ai_provider_test_failed` audit entry.
- `test_default_model_used_when_body_omits_one` — confirms the request body sent to the provider uses `default_model_for("anthropic")` when the caller's request omits `model`.

All 3 confirmed passing **before** the refactor (against the original inline `AIClient`/`resolve_provider` code), establishing the pre-refactor behavioral baseline this phase is required to preserve.

## 6. Design chosen, alternatives considered

**Chosen:** a new `AIProviderTestPort` (application layer, `application/ports/outbound/ai_provider_test.py`) with three methods — `validate_provider`, `default_model_for`, `test_connection` — implemented by a new `AIProviderTester` (infrastructure layer, `infrastructure/ai/provider_tester.py`) that wraps the exact same `resolve_provider`/`default_model_for`/`AIClient` code that used to live inline in the route. Registered as a stateless singleton via `container.register_instance(AIProviderTestPort, AIProviderTester())` in `bootstrap/composition.py`'s `_register_ai_services()`, matching the exact pattern already used for `container.register_instance(URLValidationPort, SSRFURLValidator())`.

**Alternatives considered and rejected:**
- *Extend `AIQueryPort`* — rejected per §4: a different capability (arbitrary candidate credentials vs. the currently-configured provider), not a natural extension.
- *Move the whole strategy/client mechanism into the application layer* — rejected: this would relocate genuinely infrastructural concerns (HTTP client pooling, wire-format construction) across the hexagonal boundary in the wrong direction; the port/adapter split keeps the application layer's port abstract and the wire-level detail in infrastructure, where it already lived.
- *Use `register_factory` instead of `register_instance`* — rejected: `AIProviderTester` has zero constructor dependencies and holds no per-request state, so a factory closure would add indirection with no benefit; `register_instance` is the existing convention for exactly this shape (`SSRFURLValidator`).

## 7. Fix implemented

Two independent changes, matching §1 (contract violation) and §2 (duplication evaluation).

### 7a. New files

**`src/kingsec/application/ports/outbound/ai_provider_test.py`** (new) — `AIProviderTestPort` ABC, three abstract methods as designed in §6.

**`src/kingsec/infrastructure/ai/provider_tester.py`** (new) — `AIProviderTester(AIProviderTestPort)`, reusing `resolve_provider`/`default_model_for` (`providers.py`) and `AIClient` (`client.py`) unchanged.

### 7b. `ai_provider_routes.py` and `composition.py`

```diff
--- a/src/kingsec/adapters/inbound/web/ai_provider_routes.py
+++ b/src/kingsec/adapters/inbound/web/ai_provider_routes.py
@@
+from kingsec.application.ports.outbound.ai_provider_test import AIProviderTestPort
 from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
 from kingsec.domain.audit import AuditAction, AuditEntry
-from kingsec.infrastructure.ai.client import AIClient
-from kingsec.infrastructure.ai.errors import AIError
-from kingsec.infrastructure.ai.providers import default_model_for, resolve_provider
+from kingsec.shared.errors import ExternalServiceError
@@ get_ai_provider_config
+    tester: AIProviderTestPort = _resolve(request, AIProviderTestPort)
     ...
-            "effective_model": record.model or default_model_for(record.provider),
+            "effective_model": record.model or tester.default_model_for(record.provider),
     ...
-        effective_model == default_model_for("anthropic")
+        effective_model == tester.default_model_for("anthropic")
     ...
-        effective_model = default_model_for(env_settings.provider)
+        effective_model = tester.default_model_for(env_settings.provider)
@@ save_ai_provider_config
+    tester: AIProviderTestPort = _resolve(request, AIProviderTestPort)
     try:
-        resolve_provider(body.provider)
-    except AIError:
+        tester.validate_provider(body.provider)
+    except ExternalServiceError:
         raise HTTPException(status_code=400, detail=f"Unsupported AI provider: {body.provider!r}") from None
@@ test_ai_provider_config
+    tester: AIProviderTestPort = _resolve(request, AIProviderTestPort)
     try:
-        provider = resolve_provider(body.provider)
-    except AIError as exc:
+        tester.validate_provider(body.provider)
+    except ExternalServiceError as exc:
         return {"success": False, "message": str(exc)}
-    model = body.model or default_model_for(body.provider)
-    base_url = body.base_url or provider.default_base_url
-    client = AIClient(timeout=15, retry_count=0, retry_delay=0, verify_ssl=True)
     try:
-        url = provider.build_endpoint(base_url, model)
-        headers = provider.build_headers(body.api_key)
-        payload = provider.build_payload(...)
-        provider.extract_text(client.post_json(url, headers, payload))
-    except AIError as exc:
+        provider_name = tester.test_connection(body.provider, body.api_key, body.model, body.base_url)
+    except ExternalServiceError as exc:
         audit.record(AuditEntry(action=AuditAction.AI_PROVIDER_TEST_FAILED, ...))
         return {"success": False, "message": str(exc)}
-    finally:
-        client.close()
-    return {"success": True, "message": f"Connected to {provider.name} successfully."}
+    return {"success": True, "message": f"Connected to {provider_name} successfully."}
```

```diff
--- a/src/kingsec/bootstrap/composition.py
+++ b/src/kingsec/bootstrap/composition.py
@@ _register_ai_services
+    from kingsec.application.ports.outbound.ai_provider_test import AIProviderTestPort
+    from kingsec.infrastructure.ai.provider_tester import AIProviderTester
     ...
+    # Stateless (no per-call config resolution) - a fresh instance costs
+    # nothing and needs no other resolved dependency, unlike AIQueryPort.
+    container.register_instance(AIProviderTestPort, AIProviderTester())
```

No route signature, status code, response shape, or auth dependency changed. `require_admin` on the router is untouched, per the constraint that this phase does not touch authorization.

## 8. §2 evaluation — duplication unified

Phase 12 §4 had introduced `_NoRedirectHandler` inside `application/playbooks/actions.py`, duplicating the identically-named, functionally identical class in `infrastructure/notifications/url_validator.py`, because at the time the application layer had no port exposing "validate and open, refusing redirects" as a single operation.

**Determination: unification was the correct, proportionate fix.** `URLValidationPort` gained one new abstract method:

```python
@abstractmethod
def open(self, url: str, *, method: str = "GET", data: bytes | None = None,
         headers: dict[str, str] | None = None, timeout: float) -> None:
    """Validate `url`, then perform the HTTP request, refusing any redirect."""
```

`SSRFURLValidator.open()` implements it by building a `urllib.request.Request` and delegating to the already-existing `open_validated()` helper (unchanged, from Phase 12), translating `SSRFError` → `UnsafeURLError` exactly like `validate()` already does.

`playbooks/actions.py`'s `_handle_webhook` was rewritten to call `self._url_validator.open(url, method="POST", data=data, headers={...}, timeout=30)` directly. The entire `_NoRedirectHandler` class and `_NO_REDIRECT_OPENER` module attribute, and the now-unused `import urllib.request`, were **deleted** from the application layer. There are now exactly **one** implementation of the redirect-refusal control, not two.

This was not disproportionate: the new method is 9 lines of signature/docstring in the port plus a 10-line delegating implementation, and it let a duplicated security-relevant class be deleted outright rather than merely deprecated.

## 9. Tests

**New:**
- `tests/unit/infrastructure/test_url_validator.py::TestSSRFURLValidator` (4 tests) — `validate()`/`open()` translate `SSRFError`→`UnsafeURLError`, `validate()` allows a real public URL, `open()` refuses a redirect through the unified path (using the real local `redirecting_server` fixture).
- `tests/integration/adapters/inbound/web/test_ai_provider_routes.py::TestTestConnectionAgainstRealServer` (3 tests) — see §5.

**Modified, with individual justification (existing tests, no new assertions added, only re-targeted to the new API surface):**
- `tests/unit/application/test_playbook_actions.py` — `_AllowingValidator`/`_BlockingValidator` stubs now implement `open()` in addition to `validate()` (required because `ActionExecutor` now calls `open()`, not `validate()` + a module-level opener). `test_allowed_url_proceeds_to_send` now asserts against `validator.opened[...]` instead of patching a now-deleted `_NO_REDIRECT_OPENER` attribute. `test_redirect_is_refused_not_followed` (Phase 12's own regression test) now exercises the **real** `SSRFURLValidator` instead of a stub, proving the unified path genuinely refuses a redirect end-to-end from `ActionExecutor`'s perspective — a strictly stronger test than before, still asserting the same outcome (redirect refused, `RuntimeError` raised).
- `tests/integration/adapters/inbound/web/test_ai_provider_routes.py::_build_app()` — the hand-rolled `_StubApp.resolve()` DI stub needed a new branch (`if service_type is AIProviderTestPort: return tester`) to know about the new port; this is test-fixture plumbing, not a behavioral-assertion change. Confirmed the necessity of this change by first observing all 10 tests fail with `ValueError: Unknown service: AIProviderTestPort` before adding it, and all 10 pass after — isolating it as a fixture gap, not a regression in route behavior.

No test had its assertions weakened, removed, or its expected outcome changed. Phase 12's `test_redirect_is_refused_not_followed` continues to pass, now against the unified implementation.

## 10. Verification — all gates

| Gate | Command | Result |
|---|---|---|
| import-linter | `lint-imports` | **3 kept, 0 broken.** "Analyzed 707 files, 3785 dependencies." Contract file **not edited** — verified via `git diff pyproject.toml` showing no changes. |
| bandit | `bandit -q -r src` | 0 findings (no `Issue:` lines; only benign `nosec`/test-name-in-comment parser warnings, pre-existing and unrelated to this phase's files) |
| mypy | `mypy src` | `Success: no issues found in 585 source files` |
| ruff (tracked files) | `git ls-files '*.py' \| xargs ruff check` | All checks passed. (`ruff check .` against the untracked tree reports 123 errors, all inside untracked `alembic/versions/*__no_changes.py` pollution files — see §12/§13; zero errors outside that directory, zero in any file this phase touched.) |
| Full backend suite | `pytest tests/` | **2,869 passed, 0 failed** — the Phase 12 baseline of 2,862 plus 7 tests added this phase (4 in `test_url_validator.py`'s new `TestSSRFURLValidator` class, 3 in `test_ai_provider_routes.py`'s new `TestTestConnectionAgainstRealServer` class). Confirmed by counting result characters directly (2,869 `.`, zero `F`/`E`) after the process exited 0, since the interactive summary line was not captured cleanly in the first (colorized) run. |

**If the contract was edited in any way:** it was not. `pyproject.toml`'s `[tool.importlinter]` section is byte-for-byte identical to the copy recorded in §2 of this report, confirmed by `git status` showing `pyproject.toml` as unmodified throughout this phase.

## 11. Docker rebuild, startup, and AI-provider-route verification

- `docker compose build` → succeeded, produced `kingsec:2.0.0`.
- Started against a **fresh, phase-13-specific volume** (`kingsec-data-phase13`, not the pre-existing `kingsec-data` default volume) via `docker run`, matching the compose file's port/env/health-check/security configuration.
  - Note: an initial attempt against the pre-existing default `kingsec-data` volume failed to reach a healthy state (`Can't locate revision identified by 'fa44a8933db0'` on every alembic run). This is a stale-migration-stamp symptom consistent with Phase 09 Finding 5 (cross-version migration, still open — see §13) and was **not** investigated further or fixed, per this phase's explicit scope; a fresh volume was used instead to get a clean read, following this programme's established Docker-testing convention.
- On the fresh volume: container reached a running state immediately, `ai adapter registered provider=anthropic` logged at startup, `GET /api/v1/health` returned 200 on the first attempt.
- Live-verified all three AI provider routes through the real running container, as an authenticated admin user (first-registered user, auto-provisioned Admin):
  - `GET /api/v1/settings/ai-provider` → 200, correct env-sourced shape.
  - `PUT .../ai-provider` with an unsupported provider → 400.
  - `PUT .../ai-provider` with a real provider/key → `{"status": "saved", ...}`; subsequent `GET` showed `source: "database"`, masked key `********7777`.
  - `POST .../ai-provider/test` with an invalid Anthropic key → real network call to `api.anthropic.com`, returned `{"success": false, "message": "[KS-EXT-001] AI authentication failed"}` — no 500, confirming `ExternalServiceError` propagates correctly through the new port to the route's existing catch block.
  - `POST .../ai-provider/test` with an unsupported provider → `{"success": false, "message": "...unsupported AI provider..."}`, and confirmed via container logs that **no** `ai_provider_test_failed` audit entry was recorded for this case (matching pre-refactor behavior — unsupported-provider failures are not audited).
  - Container logs confirmed exactly the expected audit entries: one `ai_provider_test_failed` (from the bad-key test) and one `ai_provider_configured` (from the successful save) — both `success` flags correct.
- Verification container and its dedicated volume were stopped and removed afterward (`docker stop`/`rm kingsec-phase13`, `docker volume rm kingsec-data-phase13`); confirmed nothing left listening on port 8765.

This confirms the refactor works correctly through real container startup and real DI registration, not just the unit-level `_StubApp` fixture.

## 12. Files changed and commits

| File | Change |
|---|---|
| `src/kingsec/application/ports/outbound/url_validation.py` | +`open()` abstract method |
| `src/kingsec/infrastructure/notifications/url_validator.py` | +`SSRFURLValidator.open()` |
| `src/kingsec/application/playbooks/actions.py` | −`_NoRedirectHandler`/`_NO_REDIRECT_OPENER`, `_handle_webhook` now calls `open()` |
| `tests/unit/infrastructure/test_url_validator.py` | +`TestSSRFURLValidator` (4 tests) |
| `tests/unit/application/test_playbook_actions.py` | stub validators + redirect test updated |
| `src/kingsec/application/ports/outbound/ai_provider_test.py` | new — `AIProviderTestPort` |
| `src/kingsec/infrastructure/ai/provider_tester.py` | new — `AIProviderTester` |
| `src/kingsec/bootstrap/composition.py` | +DI registration for `AIProviderTestPort` |
| `src/kingsec/adapters/inbound/web/ai_provider_routes.py` | infrastructure imports removed, depends on port only |
| `tests/integration/adapters/inbound/web/test_ai_provider_routes.py` | +`TestTestConnectionAgainstRealServer` (3 tests), DI stub extended |

Committed as two logical units, per this programme's established convention:
1. SSRF-control unification (§8): `url_validation.py`, `url_validator.py`, `playbooks/actions.py`, both test files touching that surface.
2. Architecture-boundary fix (§1/§4/§7): the two new port/adapter files, `composition.py`, `ai_provider_routes.py`, its test file.
3. This report.

Commit hashes are recorded in the repository log at the time of this phase's commits (see `git log`); not duplicated here to avoid staleness if amended.

## 13. What this phase does NOT fix

- **Finding 5 (cross-version migration, High, still open)** — restated, not fixed. The stale-volume symptom observed in §11 (`Can't locate revision identified by 'fa44a8933db0'` against the pre-existing default `kingsec-data` volume) is consistent with this finding and was worked around (fresh volume), not investigated or resolved.
- **Findings 6/7/8** — product/packaging decisions, out of scope, not revisited.
- **Finding 9 (alembic pollution)** — counted, not fixed. As of this phase, **34** untracked `src/kingsec/alembic/versions/*__no_changes.py` files exist in the working tree (up from the count recorded in earlier phases), none committed.
- **Phase 11's carried observations** — unpinned `pip>=26.1.2`, no documented minimum-safe-version guidance for scanner binaries. Not addressed.
- **Phase 12's carried observation** — `diagnostics.py`'s hardcoded `127.0.0.1:8765` probe. Not addressed; the leftover-container check remains a required manual step before every full-suite run.
- **Newly observed, not fixed (new finding, disclosed):** `test_ai_provider_config()` (the `/test` endpoint) never calls URL/SSRF validation on the user-submitted `base_url` before `AIProviderTester.test_connection()` uses it to build the outbound request. This is admin-gated (`require_admin`), which limits severity relative to the SIEM/webhook SSRF gaps Phase 12 fixed (those were reachable by lower-privileged actors), but it remains a real gap: an admin-supplied `base_url` reaches a live outbound HTTP call with no SSRF check anywhere in the path. Not fixed in this phase — fixing it would mean adding a `URLValidationPort` call inside `AIProviderTester.test_connection()`, which changes network-call preconditions and is exactly the kind of "behavioral change" this phase's §4 constraints (preserve BYO-key handling exactly, no behavioral change beyond the boundary fix) rule out unilaterally. Flagged here for a future phase.
- **Frontend work** — untouched, out of scope.
- **Any refactor beyond this one contract violation and the §2 evaluation** — no other route, port, or layer was touched.

## 14. Is the branch CI-green and pushable?

| Gate | Status |
|---|---|
| `lint-imports` | ✅ 3/3 contracts kept, 0 violations, contract unedited |
| `bandit -q -r src` | ✅ 0 findings |
| `mypy` | ✅ Success, 585 files, 0 issues |
| `ruff check` (tracked files) | ✅ all checks passed |
| Full backend suite | ✅ 2,869 passed, 0 failed |
| Docker build | ✅ builds cleanly |
| Docker startup (fresh volume) | ✅ healthy, AI provider routes verified live |

All CI gates this programme has been driving toward — the ones Phase 09 through Phase 13 exist to clear — are now green on this working tree. This was explicitly the last of them: the `lint-imports` architecture-boundary violation was the sole remaining blocker identified in Phase 09 and reconfirmed in Phase 12. With it resolved without any contract edit, and every other gate independently re-verified in this same phase, the branch is CI-green by every gate this program checks and is pushable, contingent on nothing else having drifted between this report and the actual push (recommend re-running `lint-imports` and the full suite once more immediately before pushing, as a final sanity check — cheap insurance given how much this phase's credibility rests on the contract being genuinely, not superficially, satisfied).

Open, disclosed, not-yet-fixed items remain (Finding 5, alembic pollution, the new admin-`/test`-endpoint SSRF gap) — none of them block CI as currently configured, since CI does not check for stale migration stamps, repo cleanliness of untracked files, or SSRF coverage of this specific endpoint. They are correctness/security debt, not gate failures, and are listed in §13 for whoever picks up the next phase.
