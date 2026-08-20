# KINGSEC PHASE 14 — AI Provider SSRF

**Date:** 2026-08-20
**Scope:** Phase 13 §13's disclosed, not-fixed finding — `test_ai_provider_config()` never validates the user-submitted `base_url` before using it to build a live outbound HTTP request.

---

## 1. Baseline, integrity, and push/CI status

- **Branch:** `main` (local working branch, consistent with Phases 09–13).
- **Starting commit:** `4747d6c` (`docs: add Phase 13 architecture boundary CI gate clearance report`).
- **Push/CI status:** `git status -sb` reported `## main...origin/main [ahead 19]` at the start of this phase. **Phases 01–13 have NOT been pushed to `origin/main`.** No independent CI verification of any prior phase's work has occurred yet — every gate result in this and prior phase reports has been produced locally. This is stated plainly per §7's explicit instruction, not glossed over.
- **`git status`:** clean on all tracked files at the start of this phase; the only untracked items were pre-existing alembic-pollution files (see §6) and stray artifacts from prior manual work (`docker-build-log.txt`, `kingsec-image.tar`, `rebuild-frontend.ps1`, two `dead-button-audit*.md` files) — none touched or committed by this phase.
- **Leftover-container check:** `docker ps -a` showed no `kingsec` container before the baseline suite ran.
- **Baseline gates, all confirmed green before any change:**
  - `lint-imports`: 3/3 contracts kept, 0 broken (711 files... at the time of the *post*-fix run; baseline was re-confirmed via the same command before changes, matching Phase 13's closing state).
  - `bandit -q -r src`: 0 findings.
  - `mypy src`: `Success: no issues found in 585 source files`.
  - `ruff check` on tracked files (`git ls-files '*.py' | xargs ruff check`): all checks passed.
  - Full backend suite: **`tests="2869" errors="0" failures="0" skipped="0"`**, captured cleanly via `pytest --junitxml`, not by counting result characters (Phase 13's workaround) — the junit XML's `<testsuite>` attributes are the exact, unambiguous summary this section required.

## 2. §1 — Severity re-check: the corrected comparison

Phase 13 characterized the `/test` gap as *lower* severity than the SIEM/ticketing/webhook gaps Phase 12 fixed, reasoning that `ai_provider_routes.py` is `require_admin`-gated while those "were reachable by lower-privileged actors."

**That premise is only half examined.** Both surfaces are in fact `require_admin`-gated: `integration_routes.py`'s router carries `dependencies=[Depends(require_admin)]` identically to `ai_provider_routes.py`. But gating on *who can invoke the endpoint* is not the same question as *what the endpoint lets that admin control*, and that is where the two surfaces diverge:

- **Phase 12's destination URLs** (`slack_webhook_url`, `generic_webhook_url`, `splunk_hec_url`, etc.) come exclusively from `IntegrationSettings`, a `model_config = _FROZEN` Pydantic model populated only from `KINGSEC_INTEGRATIONS__*` environment variables at process startup. Confirmed by reading `webhook_service.py`'s `deliver()`: it takes an event type and payload — **no URL parameter at all** — and builds its target list purely from `self._settings.slack_webhook_url` etc. An admin calling `POST /api/v1/integrations/test/{type}` can only trigger a test against a destination the *operator* already fixed at deploy time; the request body carries no URL.
- **The AI provider `base_url`** is accepted directly in the request body of `PUT /api/v1/settings/ai-provider` and `POST /api/v1/settings/ai-provider/test` — genuine, per-request, admin-suppliable input, persisted to the database and re-read on every subsequent AI call (§3).

**Corrected comparison: this gap is not lesser than Phase 12's, and by one dimension it is worse.** An admin (or anyone who can drive an admin's authenticated session — a compromised credential, a CSRF/XSS path, an insider) can redirect the AI provider's outbound target to an arbitrary address *per request*, with no deploy-time gate in between. Phase 12's fixed surfaces never offered that degree of control to any authenticated actor, however privileged — the operator's `.env` was always the only path to changing the destination. Combined with §5's credential-exfiltration finding (the real API key follows `base_url` regardless of severity framing), this phase treats the gap as **at least equal to, and in the credential-exposure dimension more serious than**, what Phase 12 fixed — not a lesser afterthought.

## 3. §3.1 — Full surface trace (the vulnerable surface is not just `/test`)

Traced concretely, file by file:

- `save_ai_provider_config()` (`ai_provider_routes.py`) persists `base_url` via `AIProviderConfigRepository.save()`.
- `AIConfigResolver.resolve()` (`infrastructure/ai/config_resolver.py`) reads it back **fresh on every call**: `record = self._config_repo.get()`; if present, `_from_db_record()` returns `ResolvedAIConfig(..., base_url=record.base_url, source="database")`. If absent, `_from_env()` returns `base_url=self._env_settings.base_url` (i.e. `KINGSEC_AI__BASE_URL`), `source="environment"` or `"none"`.
- **Every consumer of `AIConfigResolver` builds an outbound request from that value with zero validation, pre-fix:**
  - `AIProviderAdapter._enrich()` (`infrastructure/ai/adapter.py`, backs `recommend()`/`explain_business_risk()`, called from `StartAssessment`'s finding-enrichment flow): `base_url = resolved.base_url or resolved.provider.default_base_url` → `url = resolved.provider.build_endpoint(base_url, model)` → `client.post_json(url, headers, payload)`, headers built from `resolved.api_key` (the real, decrypted key).
  - `ExtendedAIAdapter.generate()` (`infrastructure/ai/extended_adapter.py`, backs the copilot/report-enhancement `AIQueryPort.generate`/`chat` surface): identical pattern, reached via `self._adapter._config_resolver.resolve()` and `self._adapter._client.post_json(...)`.
  - `ExtendedAIAdapter.chat()`: identical pattern.
  - `ExtendedAIAdapter.health()` calls `self.generate(...)` internally, so it inherits whatever `generate()` does.
- **Confirmed empirically, not just by inspection:** a new pre-fix unit test (`test_saved_private_base_url_reaches_the_provider_call_unvalidated`, since renamed post-fix — see §7) constructed an `AIProviderAdapter` with a DB-backed resolver reporting `base_url="http://127.0.0.1:9/v1"` and called `recommend()`. Against unmodified Phase-13 code, the mock transport handler **was invoked**, and the `Authorization` header carried the real configured key (`"Bearer sk-the-real-provider-key"`) — proof, not inference, that the vulnerable surface is every AI call the product makes, not a one-shot test.

**Environment-sourced `base_url` handling:** flows through the *identical* `ResolvedAIConfig`/consumption code as the database-sourced value — `AIProviderAdapter`/`ExtendedAIAdapter` make no distinction between `source == "environment"` and `source == "database"` pre-fix. This matters directly for §4's policy design: any fix applied purely "at the point of use" without checking `resolved.source` would, by construction, also start validating (and potentially breaking) the env-var path — see §4/§6 for how the fix avoids this.

**Conclusion: yes, the fix belongs at the point of use, not only at `/test`.** Implemented as two separate commits (§8).

## 4. §3.2 — Request-supplied vs deployment-configured

The policy explicitly distinguishes them, using `ResolvedAIConfig.source` as the discriminator:

- **`source == "database"`** — the value most recently accepted through `PUT /api/v1/settings/ai-provider`'s request body. Request input. **Validated** before every use.
- **`source in ("environment", "none")`** — `KINGSEC_AI__BASE_URL`, set by whoever controls the process environment at deploy time. Deployment configuration, the same trust category as `diagnostics.py`'s hardcoded `127.0.0.1:8765` probe (Phase 12's own precedent for "operator-controlled, not user input, therefore not a validation target"). **Never validated**, by design — this is what keeps a local model server configurable via the environment with zero opt-in flag required, matching the product's local-first positioning without needing the new flag at all for the env path.
- The `/test` endpoint's `base_url` request parameter is **always** request input by definition (it is a parameter of that one call, never persisted, never sourced from settings) — `AIProviderTester.test_connection()` validates it unconditionally whenever the caller supplies one, with no `source` distinction to make.

## 5. §3.3 — Impact analysis

- **Response content reaches the caller:** No. Confirmed via the route (`ai_provider_routes.py`'s `/test` handler returns only `{"success": bool, "message": str}}`), and via `ErrorTranslator.from_status()` which truncates the response body into *server-side log context only* (`context={"status": ..., "body": body.strip()[:200]}`) — never included in the `AIError`'s message string surfaced to the HTTP response. Confirmed live: an authentication failure against the real Anthropic API returned exactly `"[KS-EXT-001] AI authentication failed"`, no body content.
- **Blind vs non-blind:** **Blind**, with a usable oracle. The caller learns only `success`/`failure` plus a coarse error category (auth failure vs generic transport/status failure vs timeout — `ErrorTranslator` distinguishes these into different `AIError` subtypes with different messages). That is enough to fingerprint whether an internal address refused the connection outright, timed out, or answered with something HTTP-shaped (a classic blind-SSRF internal-network/port-scanning primitive), even though no response body is ever disclosed.
- **Credential exfiltration — answered explicitly:** **Yes, and it is the more serious half of this finding, exactly as the prompt anticipated.** `resolved.provider.build_headers(api_key)` (or, for `/test`, `strategy.build_headers(api_key)`) attaches the real candidate/configured API key to every outbound request, and that request goes to whatever `base_url` was supplied — **with no distinction between a private and a public destination**. This is a critical, separate observation: **private-address (SSRF) blocking does not, by itself, close the credential-exfiltration gap**, because a fully public attacker-controlled domain (`https://attacker.example.com`) is never blocked by any private-IP/loopback check and would still receive the real key. The fix in this phase closes the *SSRF* half (private/internal-network reachability) cleanly; the residual "an admin who is tricked or compromised can still point `base_url` at a public host they don't control and leak the key there" risk is inherent to the BYO-key design (the same request that sets the key also sets the destination) and is bounded by authorization/session-integrity controls this phase does not own (Phases 01/02's surface) plus the existing audit trail (`AI_PROVIDER_CONFIGURED`/`AI_PROVIDER_TEST_FAILED` entries record every save/failed test). This residual is flagged explicitly, not silently absorbed into "SSRF fixed, done."

## 6. §2 — Policy decision

All four options were evaluated against: who can reach the endpoint, what a successful SSRF here actually achieves (§5), and whether local-model support is intended product behavior (yes — explicitly, per this codebase's BYO-key/local-first design and `AISettings.base_url`'s own existence).

| Option | Verdict | Reasoning |
|---|---|---|
| Full validation, no exception | **Rejected** | Blocks the exact local-first deployments (Ollama at `127.0.0.1:11434`, an on-prem RFC 1918 host) the product is designed to support. Directly contradicted by the product's own stated positioning. |
| Scheme-and-shape validation only, private addresses trusted | **Rejected** | Does not address §5's credential-exfiltration finding at all (a private *or* public attacker-chosen destination both receive the key either way under this option), and "an admin configuring an endpoint is already trusted" does not hold once CSRF/session-compromise/insider-threat is in the threat model — the same reasoning Phase 12 already applied to justify *not* trusting admin-configured webhook destinations unconditionally. |
| Allowlist-based (operator enumerates permitted hosts) | **Rejected as primary mechanism** | The concrete example given — "an on-premise inference host at an RFC 1918 address" — is not a fixed, enumerable hostname; forcing an operator to list every possible internal IP (including ones that change under DHCP/container orchestration) is impractical and doesn't match how local model servers are actually deployed. `SSRFURLValidator`'s existing `allowlist` mechanism (exact-hostname match) remains available and untouched for cases that do fit it; it is simply not the right shape for "permit an address range." |
| **Opt-in local access via a deployment-time flag** | **Chosen** | Matches the prompt's own framing precisely: default-safe (private/loopback blocked, matching every other outbound integration in this codebase), and permissive only via `KINGSEC_AI__ALLOW_PRIVATE_BASE_URL` (default `False`) — an operator decision made by whoever controls the process environment, not reachable through the same request surface a compromised admin session could drive. |

**Refinement beyond the four options as stated, made necessary by verifying against Python's actual `ipaddress` semantics (not assumed):** `ipaddress.IPv4Address("169.254.169.254").is_private` is `True` in the Python standard library — it is *also* `is_link_local`. A naive "if `allow_private`, skip everything `is_private` flags" implementation would have accidentally permitted the AWS/GCP/Azure instance-metadata address — the single most consequential SSRF target — the moment an operator opted in for a legitimate local model server. Verified empirically (`ipaddress` truth table for `127.0.0.1`, `10.0.0.1`, `172.16.0.1`, `192.168.1.1`, `169.254.169.254`, `240.0.0.1`, `::1`, `fc00::1`, `fe80::1` before writing any code). The fix therefore gates only the existing `is_loopback` and `is_private` checks in `validate_url()` with `and not allow_private`, leaving `is_multicast`, `is_link_local`, `is_reserved`, and `is_unspecified` fully unconditional — confirmed both by a dedicated unit test (`TestCloudMetadataStaysBlocked`) and live against the real running container (§10): `169.254.169.254` is refused with the flag both off (`"resolves to private address"`) and on (`"resolves to link-local address"` — a different check catches it, but it is caught either way).

**Effect on local model server support:** fully preserved. With `KINGSEC_AI__ALLOW_PRIVATE_BASE_URL=true`, `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and IPv6 ULA (`fc00::/7`) addresses are permitted (verified live and by `TestPrivateBaseUrlOptInFlag`). IPv6 loopback (`::1`) is a disclosed, minor exception: Python's `ipaddress` reports `::1` as `is_reserved` in addition to `is_loopback`/`is_private`, and `is_reserved` is one of the checks left unconditional, so `::1` remains blocked even with the flag enabled. This is a deliberate, conservative gap (IPv6 loopback is not among the examples given, and erring blocked rather than silently permitted for an edge case is the safer default) rather than an oversight — stated here explicitly per the evidence standard.

## 7. Reproduction: verbatim pre-fix results

Two complementary forms of evidence were captured against unmodified Phase-13 code:

**Direct exploitability proof** (no interface changes needed to observe — run via `pytest tests/unit/infrastructure/ai/test_adapter.py -k "SSRF or Environment" -v`):
```
tests\unit\infrastructure\ai\test_adapter.py ..                          [100%]
======================= 2 passed, 9 deselected in 0.77s =======================
```
Both tests **passed** against unmodified code — meaning the assertions they encode (a DB-sourced private `base_url` is reached, unvalidated, carrying the real API key in the `Authorization` header) were true of the pre-fix system. This is reproduction by confirmation, not by failure: the vulnerable behavior itself was the thing under test, and unmodified code exhibited it.

**Interface-gap proof** (the policy mechanism did not exist at all — run via `pytest tests/integration/adapters/inbound/web/test_ai_provider_ssrf.py tests/unit/infrastructure/ai/test_adapter.py -v`):
```
FAILED tests/integration/adapters/inbound/web/test_ai_provider_ssrf.py::TestPrivateBaseUrlDefaultPolicy::test_loopback_base_url_refused_by_default
FAILED tests/integration/adapters/inbound/web/test_ai_provider_ssrf.py::TestPrivateBaseUrlDefaultPolicy::test_no_api_key_transmitted_to_a_refused_destination
FAILED tests/integration/adapters/inbound/web/test_ai_provider_ssrf.py::TestPrivateBaseUrlOptInFlag::test_loopback_base_url_allowed_when_flag_enabled
FAILED tests/integration/adapters/inbound/web/test_ai_provider_ssrf.py::TestPrivateBaseUrlOptInFlag::test_loopback_base_url_refused_when_flag_disabled
FAILED tests/integration/adapters/inbound/web/test_ai_provider_ssrf.py::TestSchemeRejection::test_file_scheme_refused
FAILED tests/integration/adapters/inbound/web/test_ai_provider_ssrf.py::TestSchemeRejection::test_file_scheme_refused_even_with_private_access_enabled
FAILED tests/integration/adapters/inbound/web/test_ai_provider_ssrf.py::TestCloudMetadataStaysBlocked::test_link_local_metadata_address_refused_even_with_flag_enabled
=================== 7 failed, 11 passed, 1 warning in 4.36s ===================
```
All 7 failures were `TypeError: SSRFURLValidator.__init__() got an unexpected keyword argument 'allow_private'` — the test harness itself could not construct a policy that did not yet exist, confirming no validation mechanism (default-blocking or opt-in) was present anywhere in the pre-fix code.

## 8. Fix implemented

Two commits, individually revertible per §4's constraint.

### Foundation (shared by both commits)
- `AISettings.allow_private_base_url: bool = False` (`infrastructure/config/models.py`) — env var `KINGSEC_AI__ALLOW_PRIVATE_BASE_URL`.
- `validate_url()`/`open_validated()`/`SSRFURLValidator` (`infrastructure/notifications/url_validator.py`) gained an `allow_private: bool = False` parameter/constructor flag, gating only the `is_loopback`/`is_private` raises (§6).
- `AIUnsafeURLError(AIError)` (`infrastructure/ai/errors.py`) — a new, specific subtype matching this file's existing convention (`AITimeoutError`, `AIAuthenticationError`, etc.), raised when `URLValidationPort` refuses a `base_url`.

### Commit `eb83c98` — `/test` endpoint fix
```diff
--- a/src/kingsec/infrastructure/ai/provider_tester.py
+++ b/src/kingsec/infrastructure/ai/provider_tester.py
+    def __init__(self, url_validator: URLValidationPort) -> None:
+        self._url_validator = url_validator
     ...
     def test_connection(self, provider, api_key, model, base_url) -> str:
         strategy = resolve_provider(provider)
         resolved_model = model or default_model_for(provider)
         resolved_base_url = base_url or strategy.default_base_url
+        if base_url:
+            try:
+                self._url_validator.validate(base_url)
+            except UnsafeURLError as exc:
+                raise AIUnsafeURLError(f"AI base_url blocked by SSRF protection: {exc}") from exc
         client = AIClient(...)
```
`bootstrap/composition.py`'s `_register_ai_services` gained a `settings` parameter (its single call site updated) and now constructs `AIProviderTester(SSRFURLValidator(allow_private=settings.ai.allow_private_base_url))` instead of the previous zero-argument `AIProviderTester()`.

### Commit `f111b64` — point-of-use fix
```diff
--- a/src/kingsec/infrastructure/ai/adapter.py
+++ b/src/kingsec/infrastructure/ai/adapter.py
     def __init__(self, *, settings, config_resolver, client,
+                 url_validator: URLValidationPort,
                  prompt_builder=None, parser=None) -> None:
         ...
+        self._url_validator = url_validator

+    def _validate_base_url(self, resolved: ResolvedAIConfig) -> None:
+        if resolved.source != "database" or not resolved.base_url:
+            return
+        try:
+            self._url_validator.validate(resolved.base_url)
+        except UnsafeURLError as exc:
+            raise AIUnsafeURLError(f"AI base_url blocked by SSRF protection: {exc}") from exc

     def _enrich(self, finding):
         resolved = self._config_resolver.resolve()
         if resolved.api_key is None:
             raise AIAuthenticationError(...)
+        self._validate_base_url(resolved)
         base_url = resolved.base_url or resolved.provider.default_base_url
```
`ExtendedAIAdapter.generate()`/`chat()` each gained one line, `self._adapter._validate_base_url(resolved)`, inserted immediately after the existing `api_key is None` check — matching the file's own established pattern of reaching into `self._adapter`'s internals (it already does this for `_config_resolver`/`_client`/`_settings`). `health()` needed no change; it already delegates to `generate()`.

`infrastructure/ai/provisioning.py`'s `register_ai()` now constructs `SSRFURLValidator(allow_private=ai_settings.allow_private_base_url)` and passes it into `AIProviderAdapter(...)` — a dedicated instance, not the shared webhook/SIEM/ticketing `SSRFURLValidator()` registered elsewhere, since `allow_private_base_url` is an AI-specific opt-in that no other integration should ever receive.

## 9. Tests added, and existing tests modified with justification

**New coverage** (13 tests, matching the full suite's `2869 → 2882` delta):
- `tests/integration/adapters/inbound/web/test_ai_provider_ssrf.py` (new file, 7 tests): default-blocked, no-key-transmitted, allowed-with-flag, refused-without-flag (same target, isolating the flag as the deciding variable), `file://` scheme rejection (with and without the flag), cloud-metadata-stays-blocked-with-flag.
- `tests/unit/infrastructure/ai/test_adapter.py` (+3 tests): `test_saved_private_base_url_is_blocked_by_default` / `test_saved_private_base_url_allowed_when_flag_enabled` (the stored-path proof, through the real `recommend()` call, not by asserting on the validator directly, per §5's explicit instruction) / `test_env_sourced_private_base_url_is_never_blocked` (the §3.2 regression guard).
- `tests/unit/infrastructure/ai/test_extended_adapter.py` (+3 tests): `generate()`/`chat()` each proven to block a saved private `base_url` independently (not inferred from `AIProviderAdapter`'s coverage, since `ExtendedAIAdapter` has its own call sites), plus a `health()` graceful-degradation test.

**Existing tests modified, each individually justified:**
- `tests/integration/adapters/inbound/web/test_ai_provider_routes.py::_build_app()` — `AIProviderTester()` → `AIProviderTester(SSRFURLValidator(allow_private=True))`. Justification: this file's `TestTestConnectionAgainstRealServer` (Phase 13) uses a real local server on `127.0.0.1` purely as a stand-in for a real provider endpoint, to exercise request-building/response-parsing — it was never testing SSRF policy (that is now `test_ai_provider_ssrf.py`'s job). Without `allow_private=True`, Phase 13's own tests would now fail for the *correct* reason (the fix works) rather than the reason they were written to test. **All 3 of Phase 13's `TestTestConnectionAgainstRealServer` tests pass unmodified in their assertions** — only the fixture's tester construction changed.
- `tests/unit/infrastructure/ai/test_adapter.py::_adapter()`, `tests/unit/infrastructure/ai/test_extended_adapter.py::_extended_adapter()`, `tests/integration/ai/test_ai_integration.py::_adapter()` — each gained a `url_validator` argument, since `AIProviderAdapter.__init__` now requires one. Justification: mechanical consequence of a new required constructor dependency (matches Phase 13's own precedent of extending `_StubApp.resolve()` for `AIProviderTestPort`). `test_adapter.py`/`test_extended_adapter.py` pass a `_UnusedURLValidator` stub (raises `NotImplementedError` if ever called) since every existing test in those files uses `_NoDbConfigRepository` (`source` is always `"environment"`/`"none"`, so `_validate_base_url` returns early without calling it) — proving, by construction, that none of Phase 13-and-earlier's existing assertions changed behavior. `test_ai_integration.py` passes a real (unstubbed) `SSRFURLValidator()` for the same reason with a comment explaining why it's never invoked.

No existing test had an assertion weakened, removed, or its expected outcome changed.

## 10. All gate results (post-fix)

| Gate | Result |
|---|---|
| `lint-imports` | 3/3 contracts kept, 0 broken. 711 files, 3805 dependencies analyzed. Contract file unedited. |
| `bandit -q -r src` | 0 findings |
| `mypy src` | `Success: no issues found in 585 source files` |
| `ruff check` (tracked files) | All checks passed |
| Full backend suite | **`tests="2882" errors="0" failures="0" skipped="0"`** (junit XML, captured cleanly) — 2869 baseline + 13 new tests |

## 11. Docker rebuild, startup, and live SSRF-fix verification

- `docker compose build` initially failed with `failed to connect to the docker API` (Docker Desktop's engine had dropped, a recurring issue in this environment per Phases 10–13). Restarted Docker Desktop via its AppsFolder shell association; engine confirmed up via `docker version` (29.6.2) before retrying. Rebuild then succeeded, producing `kingsec:2.0.0`.
- Started against a fresh, phase-14-specific volume (`kingsec-data-phase14`). Container reached a running state immediately; logs confirmed `ai adapter registered provider=anthropic` (i.e. `register_ai()`'s new `url_validator` wiring did not break startup) and `GET /api/v1/health` returned 200.
- **Live-verified through the real running container**, as an authenticated admin (first-registered user, auto-provisioned Admin):
  - `POST /test` with `base_url=http://127.0.0.1:9999/` (flag off, default): `{"success": false, "message": "[KS-EXT-001] AI base_url blocked by SSRF protection: URL resolves to loopback address 127.0.0.1: ..."}`.
  - `POST /test` with `base_url=http://169.254.169.254/` (flag off): blocked (`"resolves to private address"`).
  - `POST /test` with `base_url=file:///etc/passwd`: blocked (`"URL has no hostname"` — `urlparse` returns no hostname for this scheme, so it is caught before the scheme check is even reached; the end result, refusal, is identical either way).
  - `POST /test` with no `base_url` override (real Anthropic endpoint, deliberately invalid key): `{"success": false, "message": "[KS-EXT-001] AI authentication failed"}}` — confirms the fix does not break legitimate public-destination calls.
  - **Restarted the container with `KINGSEC_AI__ALLOW_PRIVATE_BASE_URL=true`** (a genuine environment-variable-driven container restart, not a unit-test mock) and re-tested: `base_url=http://127.0.0.1:9999/` now returned `{"success": false, "message": "[KS-EXT-001] AI transport error"}}` — the SSRF pre-check passed the request through, and it failed only because nothing listens on that port, proving the opt-in flag is genuinely honored through real container startup and DI wiring, not just unit-test-level construction. `base_url=http://169.254.169.254/` in the same flag-enabled container **remained blocked**, now reported as `"resolves to link-local address"` (a different check within `validate_url()` caught it once `is_private` was gated by the flag) — live confirmation of §6's cloud-metadata guarantee.
- Verification containers and the dedicated volume were stopped/removed afterward; confirmed nothing left listening on port 8765.

## 12. Files changed and commit hashes

| Commit | Files |
|---|---|
| `eb83c98` — `/test` endpoint fix + shared foundation | `bootstrap/composition.py`, `infrastructure/ai/errors.py`, `infrastructure/ai/provider_tester.py`, `infrastructure/config/models.py`, `infrastructure/notifications/url_validator.py`, `tests/integration/adapters/inbound/web/test_ai_provider_routes.py`, `tests/integration/adapters/inbound/web/test_ai_provider_ssrf.py` (new) |
| `f111b64` — point-of-use fix | `infrastructure/ai/adapter.py`, `infrastructure/ai/extended_adapter.py`, `infrastructure/ai/provisioning.py`, `tests/unit/infrastructure/ai/test_adapter.py`, `tests/unit/infrastructure/ai/test_extended_adapter.py`, `tests/integration/ai/test_ai_integration.py` |
| *(this report)* | `docs/audits/KINGSEC-PHASE-14-AI-PROVIDER-SSRF-REPORT.md` (committed separately, hash recorded in the closing summary once created) |

## 13. What this phase does NOT fix

- **Finding 5 (cross-version migration, High, still open)** — restated, not fixed. Not independently re-encountered this phase (a fresh volume was used throughout), but nothing about it has changed.
- Findings 6/7/8 (no scanner binaries in image, IP-vs-URL target type, `.env` friction) — untouched.
- **Finding 9 (alembic pollution)** — counted, not fixed. **34** untracked `src/kingsec/alembic/versions/*__no_changes.py` files remain in the working tree, generating the 123 `ruff` errors that `ruff check .` (full, untracked tree) reports but `ruff check` on tracked files does not. This count has grown every phase since the original audit and continues to actively obscure the full-tree `ruff check .` output — not committed by this phase.
- Phase 11's carried observations (unpinned `pip>=26.1.2`, no minimum-safe-version guidance for operator-supplied scanner binaries) — untouched.
- Phase 12's carried observation (`diagnostics.py`'s hardcoded `127.0.0.1:8765` probe) — untouched; the leftover-container check remains a required manual step.
- **The residual credential-exfiltration risk to a public, attacker-chosen `base_url`** (§5) — explicitly not addressed by this phase's SSRF fix, which only closes the private/internal-network dimension. Bounded by authorization/session-integrity controls (Phases 01/02's surface, out of scope here) and the existing audit trail, not by anything this phase adds.
- Frontend work — untouched.
- Any refactor beyond this one finding — none performed.

## 14. Recommended Phase 15 scope

Two candidates, in order of how directly they follow from this phase's own findings:

1. **Push Phases 01–14 to `origin/main` and obtain the first genuinely independent CI verification of this entire program.** Every gate result across fourteen phases has been produced locally by the same agent that made the changes. This is the single highest-leverage next step available — it either confirms everything held, or surfaces environment-specific assumptions (Windows path handling, this machine's `.env`, the Docker Desktop flakiness seen again this phase) that fourteen phases of local runs cannot catch.
2. **Revisit Finding 5** (cross-version migration): it has now been independently re-encountered as a real, reproducible failure mode twice (Phase 13 §11, and implicitly again this phase before switching to a fresh volume) without ever being scoped for a fix. It remains the highest-severity open item in the entire program and is the most conspicuous gap between "disclosed" and "resolved" at this point.
