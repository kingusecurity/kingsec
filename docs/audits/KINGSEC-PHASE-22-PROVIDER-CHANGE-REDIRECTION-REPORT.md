# KingSec Phase 22 — Provider-Change Credential Redirection

**Date:** 2026-08-21
**Scope:** Determine whether Phase 21's guard, which compares `base_url`
fields, has a gap for `provider` changes that shift the effective
destination without ever changing the `base_url` field itself.

---

## 1. Baseline, Integrity Check, CI Status, Pollution Count

- **Branch:** `main`, starting commit `237d4f4` (Phase 21's report commit),
  even with `origin/main`.
- **`git status` at start:** clean except pre-existing, unrelated untracked
  files (`docker-build-log.txt`, `docs/audits/KINGSEC-PHASE-09-*.md`,
  `docs/audits/dead-button-audit*.md`, `kingsec-image.tar`,
  `rebuild-frontend.ps1`) — none touched by this phase.
- **Leftover-container check:** none.
- **Starting CI run:** `32493027435` — all four jobs green (Quality Gates
  3.11/3.12/3.13, Frontend), matching Phase 21's closing state.
- **Full suite before any change:** 2896 passed, 0 failures, 0 skipped,
  177.4s.
- **Pollution count:** 0 at start, 0 at end (`git status --porcelain
  src/kingsec/alembic/versions/`) — this phase touches no migrations.

---

## 2. §2 Determination — Real, Confirmed Impact (Third-Party Vendor / Fixed Local Endpoint, Not Attacker-Controlled)

### 2.1 The provider set and every `default_base_url`

`provider` is a **free string**, not a closed enum: `AISettings.provider:
str = "anthropic"` (`config/models.py:167`) and
`SaveAIProviderConfigBody.provider: str = Field(..., min_length=1)`
(`ai_provider_routes.py`). It is constrained only at *validation* time via
`resolve_provider()`'s dict lookup (`providers.py:178-187`), which raises
`AIError` for any name not in the registry — `save_ai_provider_config()`
calls `tester.validate_provider(body.provider)` and returns `400` for an
unsupported name before any of this phase's logic runs.

`providers.py`'s registry (`_PROVIDER_FACTORIES`, lines 165-175) has
**exactly nine entries, every one a hardcoded string literal**:

| Provider name(s) | `default_base_url` |
|---|---|
| `openai` | `https://api.openai.com/v1` |
| `openrouter` | `https://openrouter.ai/api/v1` |
| `glm` | `https://open.bigmodel.cn/api/paas/v4` |
| `anthropic`, `claude` | `https://api.anthropic.com` |
| `gemini` | `https://generativelanguage.googleapis.com` |
| `ollama` | `http://localhost:11434/v1` |
| `lm_studio`, `lmstudio` | `http://localhost:1234/v1` |

**There is no "custom"/generic entry, and no entry reads from an
environment variable or resolves to `None`.** But two entries —
`ollama` and `lm_studio`/`lmstudio` — *are* the dangerous case §2.1 asked
about in a specific sense: their hardcoded default is a **loopback
address**, not a cloud vendor. This is not attacker-controlled (an admin
cannot make `provider="ollama"` resolve anywhere other than
`localhost:11434` — that mapping is a code-level constant, not
request-influenced), but it is qualitatively different from "wrong
vendor": a real key could be sent to whatever local service happens to be
listening on that port, deployment-dependent and outside the code's
control.

### 2.2 Impact rating

**Stated plainly, per §2.2's own framing:** every possible destination a
`provider`-only change can produce is a fixed, hardcoded, non-request-
influenced endpoint. **This is not attacker-controlled exfiltration** — no
value derived from user/admin input can steer the destination to an
arbitrary URL through this path (that remains blocked by Phase 21's
`base_url`-comparison guard). It is a genuine confidentiality event of the
class §2.2 names explicitly: "an Anthropic key gets POSTed to OpenAI's
API... the key is disclosed to a third party who should not have it, and
it will appear in that vendor's request logs" — with one qualification
this codebase's own registry adds: for two of the nine provider names, the
"third party" is not a cloud vendor but whatever is listening on
`localhost:11434` or `localhost:1234` in the deployment environment. **Not
inflated to Phase 21's severity (no attacker ever receives the key through
this path), and not dismissed as harmless (a real credential still leaves
its intended destination without the actor moving it ever re-proving they
possess it).**

### 2.3 Env-path reachability

Confirmed clean separation, established in Phase 21 §2.1 and re-verified
here: `AIConfigResolver.resolve()` (`config_resolver.py:59-64`) is
strictly exclusive — `if record is not None: return
self._from_db_record(record); return self._from_env()`. A database record
(the only thing `save_ai_provider_config()` can affect) never combines
with `KINGSEC_AI__BASE_URL` or any other environment-sourced value; a
`provider` change cannot make an env-configured `base_url` pair with a
database-stored key. **The env path is not reachable via this vector.**

### 2.4 Reproduction, verbatim

Direct reproduction against the actual resolver logic (not just the
guard's absence), before touching any test file:

```
BEFORE: provider='anthropic' base_url=None
AFTER save: provider='ollama' base_url=None key preserved=True
RESOLVED: provider='ollama' api_key='sk-ant-the-real-secret-key' base_url=None
EFFECTIVE DESTINATION the real key would be sent to: http://localhost:11434/v1
```

Formal test reproduction (written first, run against unmodified code,
`tests/integration/adapters/inbound/web/test_ai_provider_provider_change_redirection.py`):

```
_ TestProviderOnlyChangeCannotRedirectAStoredKey.test_provider_only_save_is_rejected_when_a_key_is_already_stored _

        resp = client.put("/api/v1/settings/ai-provider", json={"provider": "ollama"})
>       assert resp.status_code == 400, (...)
E       AssertionError: expected the provider-only change to be refused, got 200: {"status":"saved","provider":"ollama"}

_ TestProviderOnlyChangeCannotRedirectAStoredKey.test_resolved_destination_unchanged_when_the_save_is_refused _

        effective_destination = resolved.base_url or resolve_provider(resolved.provider.name).default_base_url
>       assert effective_destination == resolve_provider("anthropic").default_base_url
E       AssertionError: assert 'http://localhost:11434/v1' == 'https://api.anthropic.com'

_ TestRefusalMessageDoesNotLeak.test_provider_change_refusal_leaks_no_secret_or_internal_detail _

        resp = client.put("/api/v1/settings/ai-provider", json={"provider": "ollama"})
>       assert resp.status_code == 400
E       assert 200 == 400

3 failed, 4 passed, 1 warning in 4.02s
```

**This does not meet §2's bar for closing without a fix** ("provider
changes are rejected without a key by some other path, or... `default_base_url`
is `None` for every provider and a `base_url` is always required") — the
destination genuinely changes, and does so meaningfully for two of nine
providers. **Proceeding to §3.**

---

## 3. §3 Approach Chosen

**Chosen: compare resolved destinations, not raw fields.** Added
`effective_base_url(provider, base_url) -> str` (`providers.py`) —
`base_url or resolve_provider(provider).default_base_url` — and extended
Phase 21's guard to compare `effective_base_url(new) !=
effective_base_url(existing)` instead of `body.base_url !=
existing.base_url`.

**Alternative rejected**: adding `provider` to the existing raw-field
condition (`body.provider != existing.provider or body.base_url !=
existing.base_url`) — simpler, but exactly the narrower option §3 itself
warned would "leave the same class of gap open if another
destination-affecting field is ever added," and it would also produce
false positives the resolved-destination comparison avoids (e.g.
re-submitting the *same* provider with an explicit `base_url` that
happens to equal that provider's own default would trip a raw-field
comparison but not a resolved-destination one).

**Layering correction during implementation**: the first attempt imported
`providers.py` (infrastructure) directly into `ai_provider_routes.py`
(adapter) — `lint-imports` caught this immediately: "`kingsec.adapters` is
not allowed to import `kingsec.infrastructure`" (Hexagonal layering
contract). This is exactly the kind of duplication-avoidance-gone-wrong
Phase 13 §2 would flag from the other direction. Corrected by adding
`effective_base_url()` to the **already-injected** `AIProviderTestPort`
(`application/ports/outbound/ai_provider_test.py`) — the route already
depends on `tester: AIProviderTestPort` for `validate_provider()` — and
implementing it in `AIProviderTester`
(`infrastructure/ai/provider_tester.py`), which delegates to the same
`providers.py` function. No new port, no new wiring, and the
architecture boundary `lint-imports` enforces stays intact.

**Constraints honored:**
- Legitimate provider switching still works: a fresh key alongside a
  `provider` change bypasses the guard (`not body.api_key` is false) —
  `test_provider_change_with_a_fresh_key_is_allowed` proves this end to
  end, including the real destination receiving the real new key.
- Phase 21's 9 tests pass unmodified (§6).
- Phase 14's 7 SSRF tests pass unmodified (§6); local model server support
  untouched — this fix only affects the *save-time redirect guard*, never
  `URLValidationPort`/`SSRFURLValidator` or the opt-in flag.
- No change to key storage, encryption, or masking. No change to
  authorization.
- Refusal message: generic, names no internal hostname (`localhost` and
  `11434` explicitly asserted absent in `TestRefusalMessageDoesNotLeak`),
  no raw `str(exc)`.

---

## 4. Fix Implemented

`src/kingsec/infrastructure/ai/providers.py` — new function:
```python
def effective_base_url(provider: str, base_url: str | None) -> str:
    return base_url or resolve_provider(provider).default_base_url
```

`src/kingsec/application/ports/outbound/ai_provider_test.py` — new
abstract method on `AIProviderTestPort`:
```python
@abstractmethod
def effective_base_url(self, provider: str, base_url: str | None) -> str: ...
```

`src/kingsec/infrastructure/ai/provider_tester.py` — implementation:
```python
def effective_base_url(self, provider: str, base_url: str | None) -> str:
    return _effective_base_url(provider, base_url)
```

`src/kingsec/adapters/inbound/web/ai_provider_routes.py`,
`save_ai_provider_config()` — the guard, extended:
```python
if (
    existing is not None
    and existing.api_key_encrypted is not None
    and not body.api_key
    and tester.effective_base_url(body.provider, body.base_url)
    != tester.effective_base_url(existing.provider, existing.base_url)
):
    raise HTTPException(
        status_code=400,
        detail="Changing the AI provider or base_url requires re-supplying api_key - "
        "the previously saved key is never sent to a new destination automatically.",
    )
```

This is a strict extension of Phase 21's condition: when `provider` is
unchanged, comparing resolved destinations is equivalent to comparing
`base_url` directly in every case Phase 21's own 9 tests exercise (verified
in §6) — the four-condition shape (`existing is not None`,
`existing.api_key_encrypted is not None`, `not body.api_key`, destination
differs) is unchanged; only the *destination differs* clause now accounts
for `provider` too.

---

## 5. Tests Added

New file:
`tests/integration/adapters/inbound/web/test_ai_provider_provider_change_redirection.py`
(7 tests, all passing post-fix):

- `test_provider_only_save_is_rejected_when_a_key_is_already_stored` — the
  §1 shape, primary reproduction.
- `test_resolved_destination_unchanged_when_the_save_is_refused` — asserts
  on the resolved destination directly, not the guard's absence.
- `test_concrete_impact_if_a_poisoned_record_ever_reached_the_database` —
  Phase 21's `test_concrete_impact_...` pattern: seeds the repository
  directly and drives the real runtime AI path, confirming a real key
  reaches a real stub server standing in for a redirected destination.
- `test_provider_change_with_a_fresh_key_is_allowed` — the normal
  workflow, must not regress: a fresh key alongside a `provider` change
  succeeds end to end, real destination receives the real new key.
- `test_no_op_save_still_works` — provider unchanged, `base_url`
  unchanged, no key: a routine model-only update.
- `test_first_time_save_with_provider_and_no_key_still_works` — nothing to
  protect yet.
- `TestRefusalMessageDoesNotLeak` — the new refusal message contains no
  secret, no `localhost`/port, no traceback.

**Confirmed unmodified and still passing:** Phase 21's 9 tests
(`test_ai_provider_credential_exfiltration.py`), Phase 14's 7 SSRF tests
(`test_ai_provider_ssrf.py`), `test_ai_provider_routes.py` (10),
`tests/integration/ai/` (5) — 31 tests total, run together with this
phase's 7 new ones (38 passed).

---

## 6. Gate Results and Suite Counts

| Gate | Result |
|---|---|
| `ruff check .` | All checks passed |
| `mypy src` | Success, no issues, 585 source files |
| `lint-imports` | Contracts: 3 kept, 0 broken (confirmed the layering violation caught and fixed, §3) |
| `bandit -q -r src` | 0 issues |
| Full suite (local) | **2903 passed, 0 failures, 0 skipped**, 177.4s (2896 baseline + 7 new) |

---

## 7. CI Result After Push, Step by Step

Push `237d4f4..baaba03`, run `32494897371`:

| Job | Result |
|---|---|
| Quality Gates (3.11) | ✅ all steps, 3m10s |
| Quality Gates (3.12) | ✅ all steps, 2m24s |
| Quality Gates (3.13) | ✅ all steps, 3m5s |
| Frontend Quality Gates | ✅ all steps, 1m57s |

**Phase 20/21's full green pipeline holds — no regression.** CI pytest
count, verbatim (3.11): `2903 passed, 3 warnings in 113.64s` — identical to
local.

---

## 8. Docker Rebuild, Startup, and Live Verification

**Build:** `docker compose build --progress=plain` against the fully pushed
working tree (`baaba03`): `Image kingsec:2.0.0 Built`.

**Startup, fresh volume:** a new named volume (`kingsec-data-phase22`), all
three required secrets generated fresh. Docker's own `HEALTHCHECK`
reported `Up 15 seconds (healthy)`.

**Live verification, following Phase 21 §9's exact method** — a valid
admin JWT minted inside the container's own process using its real
`KINGSEC_JWT__SECRET_KEY`, used via `docker exec` + `urllib.request`
against the real running app on `http://127.0.0.1:8765`:

```
=== PUT real key (anthropic) ===
(200, {'status': 'saved', 'provider': 'anthropic'})

=== GET (should show masked only, base_url None) ===
(200, {'provider': 'anthropic', ..., 'base_url': None,
       'api_key_masked': '********-key', 'source': 'database',
       'updated_at': '2026-08-21T15:03:17.463564+00:00'})

=== PUT provider-only change to ollama (should be 400) ===
(400, {'detail': 'Changing the AI provider or base_url requires
        re-supplying api_key - the previously saved key is never sent
        to a new destination automatically.'})

=== GET again (record must be unchanged) ===
(200, {'provider': 'anthropic', ..., 'base_url': None,
       'api_key_masked': '********-key', 'source': 'database',
       'updated_at': '2026-08-21T15:03:17.463564+00:00'})
record unchanged: True
```

The fix behaves identically in the real, containerized deployment: a real
key was saved for `anthropic`, `GET` never exposed more than the masked
last four characters, the provider-only redirect attempt to `ollama` (one
of the two providers with a hardcoded loopback default, per §2.1) was
refused with the exact message, and the record — including its
`updated_at` timestamp — is byte-identical before and after the refused
attempt.

**Migration stamp**, read directly via a throwaway `python:3.12-slim`
container: `alembic_version: [('91969658a556',)]` — unchanged from Phase
19/20/21 (this phase makes no migration changes).

**Teardown:** container and volume both removed; confirmed via `docker
ps -a` and `docker volume ls` that neither remains.

---

## 9. Files Changed and Commit Hashes

| Commit | Files | Summary |
|---|---|---|
| `b331658` | `src/kingsec/infrastructure/ai/providers.py` | New `effective_base_url()` helper |
| `756efd5` | `src/kingsec/application/ports/outbound/ai_provider_test.py`, `src/kingsec/infrastructure/ai/provider_tester.py`, `src/kingsec/adapters/inbound/web/ai_provider_routes.py` | The fix: extend Phase 21's guard to compare resolved destinations via the port |
| `baaba03` | `tests/integration/adapters/inbound/web/test_ai_provider_provider_change_redirection.py` | 7 new tests |
| (this commit) | `docs/audits/KINGSEC-PHASE-22-PROVIDER-CHANGE-REDIRECTION-REPORT.md` | This report |

---

## 10. What This Phase Does NOT Fix

- **Finding 5's product decision** (Option A/B/C, Phase 15 §7) — open
  since Phase 09.
- **Phase 18 §4's two missing indexes** — evidenced as accidental,
  awaiting a decision.
- **Phase 19 §4.2** — runtime engine's pysqlite DDL behavior; reachable
  only via `create_all()`.
- **Phase 20 §2's coverage gap** — `licensing/parser.py`'s `win32` branch
  type-checked by nothing.
- Findings 6, 7, 8 (no scanner binaries in the image; IP-vs-URL target
  type; `.env` friction).
- Phase 11's carried observations (unpinned `pip>=26.1.2`; no
  minimum-safe-version guidance for operator-supplied scanner binaries).
- Phase 12's carried observation (`diagnostics.py`'s hardcoded probe).
- Phase 16's two carried notes (builder-stage `.git` layer;
  `_skip_empty_autogenerate_revision` in production `env.py`).
- Frontend work (Phase 03 §10's missing `isFailed` branch, Phase 10 §4's
  long headline).

---

## 11. Recommended Phase 23 Scope, and Security-Finding Status

**No known security finding remains open.** Tracing the audit chain this
programme has carried since Phase 09: Finding 5 (Phase 15, a product
decision, not a vulnerability), the two missing indexes (Phase 18,
evidenced accidental, a product decision), the migration atomicity defect
(Phase 19, fixed), the CI pipeline never validating any of it (Phase 20,
fixed), the AI credential base_url redirect (Phase 21, fixed), and this
phase's provider-change variant of the same class (fixed) — every item
that was ever characterized as an actual vulnerability rather than a
product decision or packaging/tooling gap has been closed. This is worth
recording plainly rather than glossing: **the vulnerability-remediation
chain that began at Phase 01 has no open item as of this report.**

What remains (§10's list) is administrative: two product-owner decisions
this programme has correctly declined to make unilaterally across many
phases, one explicit technical decision (native-Windows mypy coverage),
and a set of long-carried, low-urgency observations that have not grown in
scope or risk. Recommended for Phase 23: a single pass to either close or
formally accept each remaining carried item, rather than continuing to
pass them along individually with no change in status.
