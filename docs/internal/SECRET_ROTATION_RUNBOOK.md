# KingSec — JWT Secret & API-Key Pepper Rotation Runbook

> **Status:** MANUAL ACTION REQUIRED
> **Scope:** `KINGSEC_JWT__SECRET_KEY`, `KINGSEC_SECRETS__API_KEY_PEPPER`
> **Created:** Phase 88 (KSEC-88-01); updated Phase 89 (KSEC-89-01)

**What has and hasn't been verified by an automated coding session, at a
glance:**

- **TESTED by the coding session:** the consequences described in §2
  (single-secret sign/verify, HMAC-only pepper verification), the
  production placeholder/length guard (§2.3), that `.env` remains
  untracked and unmodified, and that neither secret's value appears
  anywhere in source control.
- **OPERATOR ACTION REQUIRED (cannot be performed or verified by a coding
  session):** generating and installing the actual new values (§3 Steps
  1-2), the maintenance-window restart (§3 Step 4), and the live
  new-token-accepted/old-token-rejected verification (§3 Step 5) — these
  require a running production deployment and real credentials that this
  runbook, by design, never touches.

---

## 1. Why this is manual

KingSec has no automated secret-rotation mechanism for these two values.
`docs/internal/PRODUCTION_RELEASE_CHECKLIST.md` already documents this
plainly: "No secrets rotation mechanism | Manual rotation | v1.2". The
`RotateSecrets` use case (`application/use_cases/rotate_secrets.py`)
rotates the **encryption key** (`KINGSEC_SECRETS__ENCRYPTION_KEY`) used to
re-encrypt values already stored through `SecretProviderPort` — it has no
relationship to either secret in this runbook. There is no other
established mechanism to build on. Deployment is a single Docker Compose
service (`docker-compose.yml`) that reads both values from `.env` via
`env_file:` — there is no Vault, no Docker secret, no KMS integration to
route rotation through.

## 2. What each secret does, and what changing it breaks

### 2.1 `KINGSEC_JWT__SECRET_KEY`

`JWTTokenService` (`infrastructure/auth/jwt_service.py`) loads this value
**once**, at construction, into a single `self._secret` used to both
`jwt.encode()` every new token and `jwt.decode()` every incoming token.
There is no key ID (`kid`), no dual-secret/grace-period support, and no
per-token key versioning anywhere in the codebase.

**Consequence: rotating this value invalidates every currently-issued
access token, refresh token, and MFA-pending token, immediately and
without exception.** The moment the new secret is loaded, every token
signed under the old secret fails `jwt.decode()`'s signature check on its
very next use — every logged-in user and every session gets a `401` and
must log in again. There is no graceful transition; this is a hard cutover
by design of the current implementation, not a bug.

### 2.2 `KINGSEC_SECRETS__API_KEY_PEPPER`

`HmacApiKeyHasher` (`infrastructure/auth/api_key_hasher.py`) hashes an API
key as `HMAC-SHA256(pepper, plaintext_key)`. Verification recomputes the
same HMAC with the **currently configured** pepper and compares it to the
hash stored at issuance time (`infrastructure/persistence/api_key_repository.py`).
There is no legacy-pepper fallback list (unlike the encryption service's
own `KINGSEC_SECRETS__LEGACY_ENCRYPTION_KEYS` mechanism).

**Consequence: rotating this value invalidates every previously-issued API
key, immediately and permanently.** No plaintext API key is ever stored
anywhere (only its HMAC), so there is no way to re-hash existing keys
under a new pepper — every API client must be issued a brand-new key
after rotation.

### 2.3 Startup guard already in place

`Settings._guard_default_secrets_in_production` (`infrastructure/config/settings.py`)
already refuses to start in `production` if either value is still the
literal placeholder `DEFAULT_SECRET_PLACEHOLDER`, or shorter than 32
bytes — this only catches "never configured" or "too short," not "should
be rotated on a schedule." Phase 89 added a direct test proving this guard
fires in `production` for both conditions
(`tests/unit/infrastructure/test_config_security.py::TestProductionSecretGuardRejectsPlaceholder`) —
TESTED by that coding session, using only the public placeholder constant
and synthetic values, never a real secret. The generation commands in
§3 Step 1 already produce values well above the 32-byte minimum.

## 3. Rotation procedure

This is a hard cutover for both secrets — there is no partial/rolling
option with the current implementation. Perform both together during a
planned maintenance window; performing only one leaves the other's blast
radius (see §2) as a needless, disconnected second outage later.

### Step 1 — Generate the new values (do this on the deployment host, not in chat/tickets/logs)

```bash
# New JWT secret key (min 32 bytes recommended)
python -c "import secrets; print(secrets.token_hex(32))"

# New API-key pepper
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Do not paste the output into a ticket, chat message, commit, or this
runbook. Pipe it directly into your secret store or `.env` editor.

**Avoiding accidental exposure (shell history, logs, CI output):**
- Do not pass either value as a literal command-line argument (e.g.
  `export KINGSEC_JWT__SECRET_KEY=abc123...`) — most shells record this in
  history (`~/.bash_history`, `~/.zsh_history`) by default, and process
  listings (`ps aux`) can briefly expose command-line arguments to other
  users on the same host. Prefer piping generator output directly into an
  editor or secret store, as shown above, so the value never appears as a
  literal argument.
- If rotation is ever scripted through CI, ensure the value is masked/
  registered as a CI secret (not a plain pipeline variable) so it cannot
  appear in build logs or console output.
- Do not include either value in a commit message, PR description, issue,
  or this runbook — everything in this document is written to remain
  accurate with placeholder/example text only, never a real value.

### Step 2 — Update the deployment environment

Edit the production `.env` file in place (the file `docker-compose.yml`'s
`env_file:` directive reads) and replace the values of:

```
KINGSEC_JWT__SECRET_KEY=<new value>
KINGSEC_SECRETS__API_KEY_PEPPER=<new value>
```

Do not commit `.env` — it is gitignored (`.gitignore` lines 22-23) and
must stay that way.

### Step 3 — Notify stakeholders before restarting

Because this is a hard cutover (§2), every active session and every API
integration breaks at the moment of restart:

- Notify users that they will need to log in again.
- Notify every API-key holder that their existing key will stop
  authenticating and they will need a newly-issued key (via whatever
  admin/API-key-management flow already exists in the product — this
  runbook does not change how keys are issued, only that existing ones
  stop working).

### Step 4 — Restart/redeploy

```bash
docker compose up -d --force-recreate kingsec
```

`kingsec-migrate` runs automatically as part of the container's `CMD`
(see `Dockerfile`) before the app starts — no separate migration step is
needed for a secret rotation (neither secret has a corresponding schema).

### Step 5 — Verify the new configuration without printing secrets

Do **not** `cat .env`, `echo $KINGSEC_JWT__SECRET_KEY`, or print either
value at any point. Verify indirectly instead:

1. **Startup succeeded**: `docker compose logs kingsec --tail 50` shows
   normal startup log lines and no `ValueError` about
   `KINGSEC_JWT__SECRET_KEY`/`KINGSEC_SECRETS__API_KEY_PEPPER` still being
   the default placeholder or too short (the existing
   `_guard_default_secrets_in_production` check, §2.3, would raise and
   crash startup if the new value were accidentally left as the
   placeholder, empty, or under 32 bytes).
2. **JWT rotation took effect**: log in with a test account through the
   real login endpoint and confirm a **new** access token is issued and
   accepted by an authenticated request. Separately, confirm a token
   captured **before** the restart is now rejected with `401` — this
   proves the old secret is no longer accepted, not just that a new one
   works.
3. **Pepper rotation took effect**: issue a **new** API key through the
   normal API-key-issuance flow and confirm it authenticates. Separately,
   confirm an API key issued **before** the restart now fails
   authentication — same reasoning as above.
4. **Health check**: `curl http://127.0.0.1:8765/api/v1/health` (or the
   configured healthcheck the container already runs) returns healthy.

None of the above requires reading or printing either secret's value.

## 4. Rollback considerations

There is no safe rollback that avoids a second cutover: reverting `.env`
to the old values and restarting again will re-invalidate every token and
API key issued *during* the rotation window (i.e., anyone who logged in
or received a new API key between Step 4 and the rollback loses that
session/key too). Only roll back if the new secrets themselves are wrong
(e.g., generation error, wrong variable) — not as a way to "undo" the
invalidation, which cannot be undone either direction.

## 5. Future: could this become a graceful (non-cutover) rotation?

Phase 89 (KSEC-89-06) analysis only — nothing below is implemented, and
this section does not change §1-4's current, hard-cutover procedure.

**JWT — key IDs (`kid`) + current-key/previous-key verification.**
`JWTTokenService` would need to: (1) embed a `kid` claim (identifying
which secret signed the token) in every newly-issued token; (2) hold both
the current and previous secret in memory, keyed by `kid`; (3) on verify,
look up the secret by the token's own `kid` instead of assuming a single
global secret. This is the same shape already proven in this codebase for
the encryption service's `KINGSEC_SECRETS__LEGACY_ENCRYPTION_KEYS` list —
not a new pattern, just not yet applied to JWT signing. Retirement of the
previous key would be controlled by time (once every token signed under
it has expired — bounded by `refresh_token_expire_days`, currently up to
90 days) rather than an immediate hard cutover.

**API-key pepper — a genuinely harder problem.** Unlike JWTs (short-lived,
naturally expire), API keys are long-lived by design and only their HMAC
is ever stored — there is no plaintext to re-hash under a new pepper after
the fact. A dual-pepper transition would require verifying against *both*
the current and previous pepper's HMAC on every request (cheap: two HMAC
computations, not a KDF) until every key is naturally rotated or an
operator forces re-issuance — but every previously-issued key would need
to remain valid under the *previous* pepper indefinitely, or until
deliberately expired, since there is no way to know which keys are still
in active use. This is more operationally complex than the JWT case: it
trades "all keys break at once" for "old peppers must be retained and
checked indefinitely, growing the attack surface of the old pepper rather
than eliminating it on a schedule."

**Operational implications of building either mechanism:** both require
changes to how secrets are supplied (a list/history of peppers instead of
one value, a `kid`-to-secret map instead of one value) — a schema change
to `SecretsSettings`/`JWTSettings`, not just an operator procedure change.
Both also require a policy decision this repository does not currently
have an answer to: how long does a "previous" key/pepper stay valid before
it must be purged, and who is responsible for enforcing that. Building
this without deciding that policy first would just move the hard-cutover
problem from "immediate" to "eventually, at an undefined time" — arguably
worse, since it would look successful at rotation time and fail silently
later. This is why Phase 89 does not implement either mechanism: the
policy question is a product/security decision, not a coding one.

## 6. Status

Per Phase 88 (KSEC-88-01), reconfirmed Phase 89 (KSEC-89-01): rotation was
**NOT PERFORMED** — this is correct and expected, not a gap. The mandate in
both phases was explicitly to investigate the token/key lifecycle and
keep this runbook actionable, without touching real secret values or
forcing an operator-facing outage as a side effect of an automated
coding session. Classification: **MANUAL ACTION REQUIRED**.
