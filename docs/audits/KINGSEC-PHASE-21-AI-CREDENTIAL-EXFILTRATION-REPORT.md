# KingSec Phase 21 — AI Credential Exfiltration

**Date:** 2026-08-21
**Scope:** Determine whether Phase 14 §5's open finding — SSRF blocking does
not protect a stored AI credential from being sent to a newly-chosen
destination — is a real vulnerability, and close it if so.

---

## 1. Baseline, Integrity Check, CI Status, Pollution Count

- **Branch:** `main`, starting commit `53fbb30` (Phase 20's report commit),
  even with `origin/main`.
- **`git status` at start:** clean except pre-existing, unrelated untracked
  files (`docker-build-log.txt`, `docs/audits/KINGSEC-PHASE-09-*.md`,
  `docs/audits/dead-button-audit*.md`, `kingsec-image.tar`,
  `rebuild-frontend.ps1`) — none touched by this phase.
- **Leftover-container check:** none.
- **Starting CI run:** `32490198171` — all four jobs green (Quality Gates
  3.11/3.12/3.13, Frontend), matching Phase 20's closing state exactly.
- **Full suite before any change:** 2887 passed, 0 failures, 0 skipped,
  170.6s.
- **Pollution count:** 0 at start, 0 at end (`git status --porcelain
  src/kingsec/alembic/versions/`) — this phase touches no migrations.

---

## 2. §2 Determination — The Vector Is Real (Confirmed)

### 2.1 Which credential does each outbound path use?

**`/test` endpoint** (`ai_provider_routes.py:81-87`,
`TestAIProviderConfigBody`): `api_key: str = Field(..., min_length=1)` — a
**required, non-nullable** field. Pydantic rejects any request omitting it
with `422` before the route body ever executes
(`provider_tester.py:40-46`'s `test_connection()` also takes `api_key` as a
plain required positional argument with no stored-key fallback anywhere in
its body). **The exact combination §2.1 named — `base_url` supplied,
`api_key` omitted — cannot occur at `/test`.** Confirmed directly:
`TestBaseUrlOnlyChangeIsRejectedAtTestEndpoint::test_test_endpoint_requires_api_key`
asserts the `422`.

**Runtime AI paths** (`adapter.py:130-153`, `AIProviderAdapter._enrich()`):
`resolved = self._config_resolver.resolve()` reads `api_key` and
`base_url` **together, from the same database row**
(`config_resolver.py:66-89`, `_from_db_record()`). `self._validate_base_url(resolved)`
(`adapter.py:76-93`) validates only for SSRF (`URLValidationPort`, private/
loopback/link-local/metadata addresses) — a public, attacker-chosen domain
passes this by design, exactly as Phase 14 §5 stated. Confirmed.

### 2.2 Can `base_url` be updated independently of `api_key`? Yes — the real vector.

`ai_provider_routes.py:152-171` (pre-fix), `save_ai_provider_config()`:
```python
key_changed = bool(body.api_key)
if body.api_key:
    api_key_encrypted = encryption.encrypt(body.api_key)
else:
    existing = repo.get()
    api_key_encrypted = existing.api_key_encrypted if existing is not None else None
repo.save(AIProviderConfigRecord(..., api_key_encrypted=api_key_encrypted, base_url=body.base_url, ...))
```
`api_key` has explicit "keep the existing encrypted value if omitted" logic.
**`base_url` has no such preservation** — it is written directly from the
request body every time, with no comparison against what is already
stored. An admin can submit `{"provider": "anthropic", "base_url":
"<attacker>"}`, omitting `api_key` entirely (it is optional on save,
`SaveAIProviderConfigBody.api_key: str | None = Field(default=None, ...)`),
and the previously-stored encrypted key is silently re-persisted alongside
the new destination. The next real AI call resolves both from the same row
(§2.1) and sends the real key to the attacker's `base_url`. **This is the
genuine, cross-actor vector** — genuine because the actor who chooses the
destination (whoever submits this save) need never have known the
plaintext key (§2.3) to redirect it. Confirmed directly by reproduction
(§3).

### 2.3 Authorization and key readability

Both `/test` and the save route require `require_admin`
(`ai_provider_routes.py:46-50`, `router = APIRouter(...,
dependencies=[Depends(require_admin)])`). `GET` never returns the plaintext
key: `get_ai_provider_config()` returns only `api_key_masked` via `_mask()`
(last 4 characters, `ai_provider_routes.py:61-66`), matching the module's
own documented security property ("The plaintext API key is never returned
in any response after the request that set it"). **This is what makes the
finding real rather than self-exfiltration**: an admin who can only ever
see the masked last-4 gains the full plaintext key by redirecting it to a
server they control — a genuine escalation from "can configure AI
settings" to "can read a secret administratively hidden from them," not
"can send my own key wherever I want."

**Determination: the vector is real, via §2.2. §2.1's specific sub-question
is answered negatively (already safe) and required no fix.**

---

## 3. Reproduction, Verbatim

Written first, run against unmodified code
(`tests/integration/adapters/inbound/web/test_ai_provider_credential_exfiltration.py`).
Both failures are the exact vulnerability shape; five other tests in the
same file passed unmodified (the "not an attack" cases: fresh key + new
`base_url` together, first-time save with no prior key, unchanged
`base_url`, the `/test`-endpoint negative, and a direct-repository proof
that the runtime path *does* send a real key to a real destination when
the database row says to — the concrete stakes, decoupled from the guard).

```
_ TestBaseUrlOnlyChangeCannotRedirectAStoredKey.test_base_url_only_save_is_rejected_when_a_key_is_already_stored _

        # A second save changes only base_url - no api_key in the body.
        resp = client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "base_url": attacker_url},
        )
>       assert resp.status_code == 400, (
            f"expected the base_url-only change to be refused, got {resp.status_code}: {resp.text}"
        )
E       AssertionError: expected the base_url-only change to be refused, got 200: {"status":"saved","provider":"anthropic"}
E       assert 200 == 400

_ TestRefusalMessageDoesNotLeak.test_refusal_message_contains_no_stored_secret_or_internal_detail _

        client.put("/api/v1/settings/ai-provider", json={"provider": "anthropic", "api_key": "sk-ant-the-secret"})
        resp = client.put("/api/v1/settings/ai-provider", json={"provider": "anthropic", "base_url": attacker_url})
    
>       assert resp.status_code == 400
E       assert 200 == 400

2 failed, 5 passed, 1 warning in 5.91s
```

---

## 4. §3 Approach Chosen

**Chosen: never transmit a stored key to a newly-specified destination —
require `api_key` to be re-supplied whenever `base_url` actually changes.**

Alternatives considered and rejected:

- **Provider-domain allowlist**: rejected. Doesn't work for local model
  servers (Ollama, LM Studio, vLLM have no "official" domain by
  definition), adds ongoing maintenance (Azure OpenAI's per-tenant
  hostnames), and doesn't address the actual mechanism — the vector isn't
  "which host," it's "who supplied the key that's about to be sent there."
  A request naming a legitimate provider with a legitimate-*looking* host
  the admin doesn't actually control would still pass an allowlist keyed
  on provider name.
- **Custom-endpoint acknowledgement** (a deployment-time opt-in flag,
  mirroring `KINGSEC_AI__ALLOW_PRIVATE_BASE_URL`): rejected as the primary
  control. Phase 14's flag exists to gate *private-address* destinations,
  a narrow, unusual case. Public custom endpoints (a customer's own
  proxy, a self-hosted gateway) are core to "bring your own AI provider" -
  gating *all* base_url changes behind a deployment flag would break that
  legitimate workflow for every operator who hasn't set an env var, for a
  problem that isn't actually about which destinations are allowed.
- **Audit and alert**: adopted as a complement, not the sole control,
  exactly as the prompt itself characterizes it. Phase 13 §11's audit
  entry (`AI_PROVIDER_CONFIGURED`) already fires on every save, but its
  metadata never included `base_url` — a real gap: even the audit trail
  couldn't previously answer "what did they change it to." Added
  `base_url` to the entry's `metadata` (§5) alongside the primary fix.

**Local model server support preserved:** the fix only blocks a `base_url`
change when it arrives *without* a fresh `api_key`. Any request that
supplies both — the exact shape a legitimate Ollama/LM Studio setup
submits from the Settings UI — is completely unaffected; a first-time save
(nothing to protect yet) and an unchanged `base_url` are unaffected too.
`TestLocalModelServerStillWorks` proves both the allowed and (still)
refused shape of Phase 14's own opt-in flag end-to-end through this exact
save path, with a real `SSRFURLValidator`, not a stub.

**Constraints honored:** no change to how keys are stored, encrypted, or
masked; no change to authorization (`require_admin` untouched on both
routes); `URLValidationPort` reused as-is (`SSRFURLValidator` in the new
local-model-server tests) — no new validation mechanism introduced.

---

## 5. Fix Implemented

`src/kingsec/adapters/inbound/web/ai_provider_routes.py`,
`save_ai_provider_config()`:

```python
existing = repo.get()

if (
    existing is not None
    and existing.api_key_encrypted is not None
    and body.base_url != existing.base_url
    and not body.api_key
):
    raise HTTPException(
        status_code=400,
        detail="Changing base_url requires re-supplying api_key - "
        "the previously saved key is never sent to a new destination automatically.",
    )
```

placed before the existing key-preservation logic (which now reuses the
same `existing` lookup rather than fetching it a second time). The guard
fires only when all four conditions hold: a real key is already stored,
`base_url` in the request differs from what's stored, and no fresh key
accompanies the change. A first-time save (`existing is None`), an
unchanged `base_url`, or a save that supplies a new key alongside the new
`base_url` all bypass it untouched.

The audit entry's `metadata` gained one field:
```python
metadata={"provider": body.provider, "key_changed": key_changed, "base_url": body.base_url},
```
`base_url` is not a secret (unlike `api_key`), so recording it in full
closes the forensic gap noted in §3's evaluation without any leak-safety
concern.

---

## 6. Tests Added, Existing Tests Modified

New file:
`tests/integration/adapters/inbound/web/test_ai_provider_credential_exfiltration.py`
(9 tests, all passing post-fix):

- `TestBaseUrlOnlyChangeCannotRedirectAStoredKey` (5 tests): the primary
  reproduction (`test_base_url_only_save_is_rejected_when_a_key_is_already_stored`),
  the concrete-impact proof via a direct repository seed
  (`test_concrete_impact_if_a_poisoned_record_ever_reached_the_database` —
  proves the runtime path *would* send the real key if the database ever
  held that shape, independent of whether the save-time guard holds, per
  Phase 14 §5's "assert on what the stub server actually received"
  standard), and three "not an attack" cases (fresh key + new base_url
  together; first-time save with no prior key; unchanged base_url).
- `TestLocalModelServerStillWorks` (2 tests): real `SSRFURLValidator`,
  proves the allowed and still-refused shape of Phase 14's opt-in flag
  survive this fix, through the save route end to end.
- `TestBaseUrlOnlyChangeIsRejectedAtTestEndpoint` (1 test): confirms §2.1's
  negative directly (`422` from Pydantic) rather than leaving it as an
  inference.
- `TestRefusalMessageDoesNotLeak` (1 test): the new `400` detail message
  contains neither the stored secret nor a raw traceback.

**No existing test was modified or weakened.** Ran unmodified and
confirmed still passing: `test_ai_provider_ssrf.py` (7/7, Phase 14's SSRF
suite), `test_ai_provider_routes.py` (10/10), `tests/integration/ai/`
(5/5, the real-HTTP-server AI integration tests).

---

## 7. Gate Results and Suite Counts

| Gate | Result |
|---|---|
| `ruff check .` | All checks passed |
| `mypy src` | Success, no issues, 585 source files |
| `lint-imports` | Contracts: 3 kept, 0 broken |
| `bandit -q -r src` | 0 issues |
| Full suite (local) | **2896 passed, 0 failures, 0 skipped**, 172.7s (2887 baseline + 9 new) |

---

## 8. CI Result After Push, Step by Step

Push `53fbb30..14b6c62`, run `32492147095`:

| Job | Result |
|---|---|
| Quality Gates (3.11) | ✅ all steps, 2m45s |
| Quality Gates (3.12) | ✅ all steps, 3m6s |
| Quality Gates (3.13) | ✅ all steps, 2m42s |
| Frontend Quality Gates | ✅ all steps, 1m58s |

**Phase 20's full green pipeline holds — no regression.** CI pytest count,
verbatim (3.11): `2896 passed, 3 warnings in 104.95s` — identical to local.

---

## 9. Docker Rebuild, Startup, and Live AI Provider Route Verification

**Build:** `docker compose build --progress=plain` against the fully pushed
working tree (`14b6c62`): `Image kingsec:2.0.0 Built`.

**Startup, fresh volume:** a new named volume (`kingsec-data-phase21`), all
three required secrets generated fresh (no defaults exist in this
environment). Docker's own `HEALTHCHECK` reported `Up 14 seconds
(healthy)`; the access log recorded `GET /api/v1/health` → `200`.

**Live verification against the real running container** — no test
doubles, no stubbed auth: a valid admin JWT was minted inside the
container's own process using the real `KINGSEC_JWT__SECRET_KEY` it was
started with (the same HS256/claims shape `JWTTokenService.create_access_token()`
produces — `sub`, `username`, `role: "admin"`, `iss: "kingsec"`), then used
to call the live HTTP API via `docker exec` + `urllib.request` against
`http://127.0.0.1:8765`:

```
=== PUT real key ===
(200, {'status': 'saved', 'provider': 'anthropic'})

=== GET (should show masked only) ===
(200, {'provider': 'anthropic', ..., 'base_url': None,
       'api_key_masked': '********-key', 'source': 'database', ...})

=== PUT base_url-only change (should be 400) ===
(400, {'detail': 'Changing base_url requires re-supplying api_key - the
        previously saved key is never sent to a new destination automatically.'})

=== GET again (base_url must be unchanged) ===
(200, {'provider': 'anthropic', ..., 'base_url': None,
       'api_key_masked': '********-key', 'source': 'database',
       'updated_at': '2026-08-21T14:34:23.270579+00:00'})  # identical to the first GET - the refused save never persisted anything
```

The fix behaves identically in the real, containerized deployment as it
does in the test suite: the real key was saved, `GET` never exposed more
than the masked last four characters, the base_url-only redirect attempt
was refused with the exact message, and the record's `updated_at`
timestamp (and everything else) is byte-identical before and after the
refused attempt — proof it never touched the stored record at all.

**Migration stamp**, read directly via a throwaway `python:3.12-slim`
container mounting the same volume: `alembic_version: [('91969658a556',)]`
— identical to Phase 19/20 (this phase makes no migration changes).

**Teardown:** container and volume both removed; confirmed via `docker
ps -a` and `docker volume ls` that neither remains.

---

## 10. Files Changed and Commit Hashes

| Commit | Files | Summary |
|---|---|---|
| `b3f4cb3` | `src/kingsec/adapters/inbound/web/ai_provider_routes.py` | The fix: require `api_key` re-supply on `base_url` change; record `base_url` in the audit entry |
| `14b6c62` | `tests/integration/adapters/inbound/web/test_ai_provider_credential_exfiltration.py` | 9 new tests |
| (this commit) | `docs/audits/KINGSEC-PHASE-21-AI-CREDENTIAL-EXFILTRATION-REPORT.md` | This report |

---

## 11. What This Phase Does NOT Fix

- **Finding 5's product decision** (Option A/B/C, Phase 15 §7) — still the
  product owner's, open since Phase 09.
- **Phase 18 §4's two missing indexes** (`asset_history.timestamp`,
  `exposures.severity`) — still awaiting a product-owner decision.
- **Phase 19 §4.2** — the runtime engine shares the pysqlite DDL defect;
  reachable only via `create_all()` on a fresh database.
- **Phase 20 §2's coverage gap** — `licensing/parser.py`'s `win32` branch
  is still type-checked by nothing on any platform.
- Findings 6, 7, 8 (no scanner binaries in the image; IP-vs-URL target
  type; `.env` friction).
- Phase 11's carried observations (unpinned `pip>=26.1.2`; no minimum-
  safe-version guidance for operator-supplied scanner binaries).
- Phase 12's carried observation (`diagnostics.py`'s hardcoded probe).
- Phase 16's two carried notes (builder-stage `.git` layer;
  `_skip_empty_autogenerate_revision` in production `env.py`).
- Frontend work (Phase 03 §10's missing `isFailed` branch, Phase 10 §4's
  long headline).

---

## 12. Recommended Phase 22 Scope

Per this phase's own §1, this closes "the last item in the audit chain
that is an actual vulnerability rather than a product decision or a
packaging gap." What remains in §11's carried list is, by that same
framing, administrative rather than security-remediation work:

1. **Phase 20 §2's `win32` mypy coverage gap** — the one item on the
   carried list with an open technical decision attached (native-Windows
   support: real ongoing target, or not). Worth resolving explicitly
   rather than leaving indefinitely carried, since it's a decision, not
   more investigation.
2. **Finding 5's product decision** (Phase 15 §7, open since Phase 09) and
   **Phase 18 §4's two missing indexes** — both are product-owner
   decisions this programme has correctly declined to make unilaterally
   across many phases now; if there's no path to a decision, that's worth
   surfacing on its own.
3. The remaining items (Findings 6/7/8, Phase 11's pip/scanner-binary
   observations, Phase 12's diagnostics probe, Phase 16's two notes,
   frontend work) are all long-carried, low-urgency, and none has grown
   in scope or risk across the phases that have passed them along - a
   single phase to either close or formally accept each, rather than
   continuing to carry them one at a time, may be more efficient than
   further individual investigation.
