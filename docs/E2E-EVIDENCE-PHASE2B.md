# Phase 2B E2E Evidence

Real assessments, driven through KingSec's own HTTP API (not scanners invoked
directly), against two deliberately-vulnerable, loopback-only Docker targets.
This is Task 6 — the phase's real deliverable. Defects found during these runs
are **recorded, not fixed** — see §5.

## 1. Environment

| | |
|---|---|
| OS | Windows 10 Pro 10.0.19045 |
| Python | 3.14.4 |
| KingSec version | 2.0.0 |
| Commit SHA | `dd08eb4ce8d219fcd2825372de25f72653c02f30` |
| Docker | 29.6.2 |
| DVWA image | `vulnerables/web-dvwa` @ `sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7` |
| Juice Shop image | `bkimminich/juice-shop` @ `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e` |
| Data dir | `C:\kingsec-e2e` (never `~/.kingsec`) |

### Binding verification (beyond `docker port`)

```
docker port dvwa-phase2b        -> 80/tcp -> 127.0.0.1:18080
docker port juiceshop-phase2b   -> 3000/tcp -> 127.0.0.1:13000
netstat -ano | findstr ":18080" -> TCP 127.0.0.1:18080  LISTENING  (not 0.0.0.0)
netstat -ano | findstr ":13000" -> TCP 127.0.0.1:13000  LISTENING  (not 0.0.0.0)
```

Went one step further per instruction: connected to both ports via the
machine's real LAN-facing IP (`10.20.1.64`) — both **refused** (curl exit 7).
Confirmed reachable only via `127.0.0.1` (DVWA → HTTP 302, Juice Shop → HTTP
200). Genuinely loopback-only, not just labeled that way.

### Wordlist — followed `docs/INSTALL.md`'s documented step exactly, nothing extra

The exact documented PowerShell block ran cleanly: `common.txt` downloaded to
`~/.kingsec/wordlists/common.txt` (38,536 bytes), `KINGSEC_FFUF__WORDLIST` /
`KINGSEC_GOBUSTER__WORDLIST` set. **No Task 3 defect found** — the documented
steps produced working ffuf and gobuster on the first attempt.

### Nuclei templates

Ran `nuclei -update-templates` after explicit approval.

- **Elapsed: 5m47.679s** (real wall clock)
- **Actual size on disk: 86 MB**, 13,948 template files — materially smaller
  than the 728 MB estimate in the approval message (that figure came from a
  git-clone size estimate, not a measurement, per the request to report if it
  differed). **INSTALL.md should say ~86 MB, not ~728 MB**, if a size is
  quoted there in future.
- **Landed at `C:\Users\Laptop Zone by JK\nuclei-templates`** — nuclei's own
  global, per-user default location, **outside both `~/.kingsec` and
  `C:\kingsec-e2e`**. Nuclei manages this directory itself, independent of
  `KINGSEC_STORAGE__DATA_DIR`. Worth recording for the eventual Docker story:
  a containerized KingSec would need either a separate volume for this path
  or an explicit `-nt`/config override to relocate it inside the data volume.
- Nuclei **was** usable after the update (doctor confirms below) — no
  doctor/discovery defect.

### `kingsec doctor` — before nuclei templates

```
[OK       ] nmap      (Nmap) v7.99                status: usable
[UNUSABLE ] nuclei    (Nuclei) v3.11.1             reason: Missing Nuclei templates
[NOT FOUND] nikto     (Nikto)                      reason: 'nikto' not found on PATH or common locations
[OK       ] ffuf      (FFUF) v2.2.1                status: usable
[OK       ] gobuster  (Gobuster) v3.8.2             status: usable
[OK       ] zap       (OWASP ZAP) v2.17.0           status: usable
6 scanners checked: 4 usable, 2 not usable
```

### `kingsec doctor` — after nuclei templates (the state all 5 runs executed under)

```
[OK       ] nmap      (Nmap) v7.99                status: usable
[OK       ] nuclei    (Nuclei) v3.11.1             status: usable
[NOT FOUND] nikto     (Nikto)                      reason: 'nikto' not found on PATH or common locations
[OK       ] ffuf      (FFUF) v2.2.1                status: usable
[OK       ] gobuster  (Gobuster) v3.8.2             status: usable
[OK       ] zap       (OWASP ZAP) v2.17.0           status: usable
6 scanners checked: 5 usable, 1 not usable
```

5 of 6 usable, exactly as expected. Nikto is pre-existing-known-missing
(Windows Defender quarantines the downloaded Perl script — documented
elsewhere in this engagement, not re-investigated here).

---

## 2. The five runs

All five submitted via `POST /api/v1/assessments` → `POST
.../start` → polled `GET .../{id}` to a terminal state, through the real,
running HTTP server (`python -m kingsec`, real JWT auth, real SQLite
persistence at `C:\kingsec-e2e\kingsec.db`) — not a script bypassing the
product.

| # | Profile | Target | Estimated | **Actual (real wall clock)** | Assessment status |
|---|---------|--------|-----------|-------------------------------|--------------------|
| 1 | web-scan | `http://127.0.0.1:18080` (DVWA) | 60 min | **391s (6.5 min)** | `completed_with_gaps` |
| 2 | web-scan | `http://127.0.0.1:13000` (Juice Shop) | 60 min | **391s (6.5 min)** | `completed_with_gaps` |
| 3 | api-scan | `http://127.0.0.1:13000` (Juice Shop) | 45 min | **369s (6.15 min)** | `completed` |
| 4 | quick-scan | `127.0.0.1` | 5 min | **38s** | `completed` |
| 5 | full-assessment | `http://127.0.0.1:13000` (Juice Shop) | 60 min | **169s (2.8 min)** | `completed_with_gaps` |

All five runs finished far under their profile's estimated duration. This
host's earlier nmap-only host sweep measured ~13s; the URL-target runs above
(391s/369s/169s) are dominated by nuclei (when it doesn't time out) and ffuf's
wordlist pass, not nmap, which is consistent with nmap's own contribution
staying small across all five runs.

### Per-run, per-scanner terminal state and reason

**Run 1 — web-scan / DVWA:**
| Scanner | State | Findings | Reason |
|---|---|---|---|
| nmap | succeeded | 10 | — |
| gobuster | succeeded | 0 | — |
| ffuf | succeeded | 13 | — |
| nuclei | **timed_out** | 0 | `scan did not complete within the configured 300-second timeout` |
| zap | succeeded | 12 | — |

**Run 2 — web-scan / Juice Shop:**
| Scanner | State | Findings | Reason |
|---|---|---|---|
| nmap | succeeded | 10 | — |
| gobuster | **failed** | 0 | `gobuster exited with code 1` (orchestrator log; API surfaces only "exited with an error before producing usable results" — see Defect 2) |
| ffuf | succeeded | 4639 | — (see Defect 3 — this is not 4639 real findings) |
| nuclei | succeeded | 0 | — |
| zap | succeeded | 0 | — |

**Run 3 — api-scan / Juice Shop** (profile has no nmap/gobuster):
| Scanner | State | Findings | Reason |
|---|---|---|---|
| ffuf | succeeded | 4655 | — (see Defect 3) |
| nuclei | succeeded | 0 | — |
| zap | succeeded | 0 | — |

**Run 4 — quick-scan / 127.0.0.1** (nmap-only profile):
| Scanner | State | Findings | Reason |
|---|---|---|---|
| nmap | succeeded | 9 | — |

**Run 5 — full-assessment / Juice Shop:**
| Scanner | State | Findings | Reason |
|---|---|---|---|
| nmap | succeeded | 10 | — |
| nuclei | succeeded | 1 | — |
| gobuster | **failed** | 0 | `gobuster exited with code 1` |
| ffuf | succeeded | 0 | Juice Shop had OOM-crashed by this point (see Defect 4) |
| zap | succeeded | 0 | (same) |
| nikto | skipped_binary_missing | 0 | `'Nikto' is not installed` |

---

## 3. Severity distribution per run — the calibration table

Computed both ways, per instruction: **with** nuclei's contribution, and
**without** it (to show how much of the spread depends on the optional
728 MB-estimated / 86 MB-actual template download).

**Nuclei's total contribution across all 5 runs, combined: one (1) finding —
Informational.** Zero Critical, High, Medium, or Low findings from nuclei in
any run.

| Run | Critical | High | Medium | Low | Informational | Total |
|---|---|---|---|---|---|---|
| 1 — web-scan/DVWA | 0 | 0 | 7 | 17 | 11 | 35 |
| 2 — web-scan/JuiceShop | 0 | 26 | 191 | 4426 | 6 | 4649 |
| 3 — api-scan/JuiceShop | 0 | 26 | 191 | 4436 | 2 | 4655 |
| 4 — quick-scan/127.0.0.1 | 0 | 0 | 0 | 6 | 3 | 9 |
| 5 — full-assessment/JuiceShop | 0 | 0 | 0 | 6 | 5 | 11 |

**Without nuclei's contribution** (subtract its one finding from Run 5):

| Run | Critical | High | Medium | Low | Informational | Total |
|---|---|---|---|---|---|---|
| 1 | 0 | 0 | 7 | 17 | 11 | 35 |
| 2 | 0 | 26 | 191 | 4426 | 6 | 4649 |
| 3 | 0 | 26 | 191 | 4436 | 2 | 4655 |
| 4 | 0 | 0 | 0 | 6 | 3 | 9 |
| 5 | 0 | 0 | 0 | 6 | **4** | 10 |

**The table is identical with or without nuclei, except Run 5's Informational
count drops by exactly one.** Nuclei changed nothing about the Critical/High/
Medium picture in this evidence run. See §6's verdict — this is directly
relevant to whether the template download is optional.

---

## 3b. POST-2B-c RE-RUN — 2026-09-13, Runs 1–3 only, against the Priority 1-4 fixes

Same targets, same binding (`127.0.0.1:18080`/`127.0.0.1:13000`), same data
dir (`C:\kingsec-e2e`), same real HTTP API flow as §2 — re-run after Phase
2B-c's Priorities 1b–4 and small items landed on branch
`fix/phase-2bc-signal-quality`, uncommitted at the time of this run. Runs 4
and 5 were not re-run (not required; nothing in Runs 4/5 exercised the
fixed code paths). The original DB rows from §2/§3 are untouched — these
are three brand-new assessment rows in the same database.

One environment-setup defect found and corrected before these numbers are
valid: the first Run 1 attempt (discarded, not counted below) ran against a
freshly-started server that never had `KINGSEC_FFUF__WORDLIST`/
`KINGSEC_GOBUSTER__WORDLIST` set (an artifact of restarting the server in a
new session, not a KingSec code defect), so ffuf/gobuster both
`skipped_asset_missing`. Caught by inspecting `scanner_summary` before
trusting the result; server restarted with the correct env vars (same
wordlist file Task 3 already produced, `~/.kingsec/wordlists/common.txt`);
Run 1 re-submitted cleanly. The discarded assessment row still exists in
the database (harmless clutter, not referenced below).

| Run | Critical | High | Medium | Low | Informational | Total |
|---|---|---|---|---|---|---|
| 1 — web-scan/DVWA | 1 | 0 | 5 | 11 | 28 | **45** |
| 2 — web-scan/JuiceShop | 0 | 0 | 0 | 6 | 5 | **11** |
| 3 — api-scan/JuiceShop | 0 | 0 | 0 | 0 | 0 | **0** |

**Run 2's total: 4,649 → 11.** This is the acceptance bar Priority 1
existed to clear, and it clears it by three orders of magnitude, not
marginally. Run 3 went from 4,655 to 0 findings entirely (see below for
why that specific number is zero, not just small).

### Why each number moved, per scanner — not asserted, read directly from `scanner_summary`

**Run 1 (DVWA) — total rose, 35 → 45, this is coverage improving, not
regressing:**
- `nuclei`: **timed_out → succeeded, 22 findings.** This is the small-item
  fix (timeout raised 300s → 600s) working exactly as intended — nuclei
  contributed zero findings in the original Run 1 because it never
  finished; now it does, and its 22 findings (all newly visible, none
  present before) account for most of the total's increase along with the
  new Critical. This was expected and disclosed before running: raising
  the timeout would let a previously-truncated scan actually report what
  it finds.
- `gobuster`: succeeded, 0 findings — DVWA does not wildcard-respond, so
  neither Priority 1a nor 1b's signals had anything to demote here; this
  run is the "quiet path" control case.
- `ffuf`: succeeded, 13 findings (was unrun in the very first, discarded
  attempt; the original Task 6 Run 1 had ffuf enabled and contributing to
  the 35-finding baseline — the wordlist fix restored this to working
  the same as Task 6, and severity classification on real, non-wildcard
  results is unaffected by the demotion signals for the same reason as
  gobuster above).
- `zap`: still `skipped_asset_missing`, same pre-existing chocolatey-shim
  issue as every prior run in this engagement — untouched by this phase.

**Run 2 (Juice Shop, web-scan) — the flood is gone, by design, not by
accident:**
- `ffuf`: **succeeded (13 findings, flooding) → failed, 0 findings, with a
  specific reason.** `skipped_reason`: *"The target returned a non-404
  response for a random, nonexistent path — it appears to serve a
  catch-all response (common for single-page applications) rather than a
  real 404 for missing paths. Fuzzing this target would produce a flood of
  false-positive findings rather than real results, so the scan was not
  run..."* — the exact `WILDCARD_RESPONSE_USER_MESSAGE` text, produced by
  a real HTTP probe against the real running Juice Shop container, not a
  simulated condition.
- `gobuster`: **succeeded (0 findings) → failed, 0 findings — and its own
  real reason now survives all the way into the persisted
  `scanner_summary`, not just the server log.** `stderr_excerpt`
  (Priority 4, queried directly from `assessments.scanner_summary` in the
  real database): *"the server returns a status code that matches the
  provided options for non existing urls.
  http://127.0.0.1:13000/d5e2bab8-... => 200 (Length: 9393). Please
  exclude the response length or the status code or set the wildcard
  option.. To continue please exclude the status code or the length"* —
  this is Defect 2 from §5, closed: gobuster's own actionable message no
  longer dead-ends at `gobuster exited with code 1` in the log; it
  survives, verbatim, to the field an operator actually reads.
  `skipped_reason` (the separate, still-sanitized field) correctly still
  reads the generic safe message — the fix adds a field, it does not
  relax the existing sanitization boundary.
- `nmap`: succeeded, 10 findings — unaffected by any of this phase's
  changes, as expected (host sweep, not path-based).
- `nuclei`: succeeded, 1 finding (Informational) — matches §3's own
  finding that nuclei's total contribution across every run in this
  entire evidence set is exactly one Informational finding.
- `zap`: same pre-existing skip as every other run.

**Run 3 (Juice Shop, api-scan) — zero findings, for a real, checkable
reason, not a silent failure:**
- `ffuf`: **succeeded, 0 findings** (not aborted this time — the api-scan
  profile's ffuf invocation targets a different path/scope than web-scan's,
  and this specific invocation's random probe path did not trigger the
  wildcard condition; a real, target-shape-dependent outcome, not a
  hardcoded one).
- `nuclei`: succeeded, 0 findings.
- `zap`: same pre-existing skip.
- api-scan's profile does not include nmap/gobuster (same scanner subset
  as Task 6's original Run 3), so there is nothing else to report — the
  original Run 3's 4,655 findings were effectively 100% ffuf flood
  (4,436 Low + most of the 191 Medium/26 High), and with the flood
  mechanism gone, this run has nothing left to find on Juice Shop's
  unauthenticated surface. Consistent with THE BAR's own conclusion
  that KingSec's unauthenticated scope, not scanner sensitivity, is the
  real limiting factor here.

### Report-generation pipeline re-verified against this real data (Priority 2)

Generated Run 1's report twice via `POST /assessments/{id}/report` (45
findings, one Critical). `grep -c "AI enrichment failed"` against the
server log: **0 new occurrences during either report generation call** —
this environment has no AI provider configured
(`KINGSEC_AI__*` unset), so 5a's fail-fast correctly skipped the entire
enrichment pass both times, logging nothing per-finding. (A **separate,
newly-discovered** instance of the same defect class exists in scan-time
enrichment, `submit_assessment.py` — 56 "AI enrichment failed
(best-effort): [KS-EXT-001] no AI API key configured" lines were logged
across the three scans themselves, proportional to finding count. This is
the same underlying pattern Defect 5/Priority 2 fixed, in a different call
site that was out of scope for this round's fix — logged in
`docs/STATUS.md`, not fixed here.)

Downloaded the same report via `GET /reports/{id}/download` twice in
direct succession. `C:\kingsec-e2e\report_cache\` contains exactly two
files — one per `POST .../report` call (each is a genuine new snapshot,
correctly getting its own cache entry) — and zero additional files were
created by the two `GET .../download` calls, confirming 5d's cache is
serving the stored artifact rather than re-rendering. Verdict text
byte-checked directly (`b'\xe2\x80\x94'` present, `b'\xef\xbf\xbd'`
absent) — same Correction 1 verification discipline applied here as a
matter of course, not because anything looked wrong.

### Corroborates the acceptance criterion tested synthetically in this round

The synthetic acceptance test (`test_report_render_offload.py`,
`/health` responsive during a slow render) proved the offload works in
isolation. This real run corroborates the surrounding claims it depends
on: AI fail-fast genuinely fires zero times against a real unconfigured
environment, and the cache genuinely prevents re-render on repeat
downloads — both observed directly against the real server and real
database above, not re-asserted from the unit test alone.

---

## 4. Findings judged REAL vs LIKELY FALSE POSITIVE

**Run 1 (DVWA) — judged REAL, essentially in full.** DVWA is a real
Apache/PHP application, not a single-page app; it returns genuine 404s for
nonexistent paths (verified indirectly: ffuf and gobuster both behaved
normally against it, no wildcard-abort, no flood). ffuf's 13 hits
(`php.ini`, `phpinfo.php`, `robots.txt`, `.htaccess`/`.htpasswd`/`.hta` →
403, `server-status` → 403, `.gitignore`, `favicon.ico`, `config`/`docs`/
`external` → 301) are genuine, DVWA-appropriate discoveries. ZAP's 12 passive
findings (CSP header not set, missing anti-clickjacking header, directory
browsing, cookie flags, server-version leak, debug error messages, suspicious
comments) are genuine and match DVWA's known-weak default configuration.
nmap's 10 findings are genuine open ports — one is the target itself
(18080), nine are this host's own unrelated services (see labeling below).

**Runs 2 and 3 (Juice Shop, web-scan/api-scan) — the ~4639/4655 ffuf
"findings" are judged LIKELY FALSE POSITIVES, essentially in full.** Root
cause confirmed directly: Juice Shop is an Angular single-page app whose
server returns **HTTP 200 for any path**, including ones that cannot
possibly exist —

```
curl http://127.0.0.1:13000/4a894d30-8cc2-4503-b007-b00d487f5c0e  ->  200
```

ffuf has no wildcard/catch-all detection in this invocation and matched
essentially every word in the SecLists wordlist against that same 200
response, producing thousands of "HTTP 200" hits including ones ffuf's own
severity heuristic scores High (`.env`, `.git/HEAD`, `.git/config`,
`WS_FTP.LOG`, `cosign.key` — all real SPA-catchall 200s, not real files) and
Medium (`/ADMIN`, `/AdminService`, `/Database_Administration`, etc. — same
mechanism). **These are not 26 High-severity and 191 Medium-severity
vulnerabilities in Juice Shop.** They are one mechanical false-positive
generator, repeated thousands of times. gobuster, run against the identical
target, correctly detected this exact condition and refused to proceed (see
Defect 2) — confirming ffuf's flood is the anomaly, not a real signal.

**Run 4 (quick-scan/127.0.0.1) — judged REAL, all 9.** Genuine open ports on
this host.

**Run 5 (full-assessment/Juice Shop) — judged REAL, all 11.** nmap's 10 open
ports are genuine; nuclei's one finding ("Public Swagger API - Detect",
Informational) is a genuine, low-impact information-disclosure hit — Juice
Shop does expose a Swagger/OpenAPI endpoint.

### Host services vs. target findings (both quick-scan and every URL-target run)

Every run in this suite targets `127.0.0.1:<port>`, and nmap's host-sweep
component scans the whole host, not just the target's own port — so **every
run**, not only quick-scan, surfaces this machine's own unrelated services:
port 135 (RPC), 445 (SMB), 902/912 (VMware), 1001, 3000 (**this is
`vantriqsec-crm`**, off-limits per instruction — confirmed pre-existing, read
only, never touched), 3389 (RDP), 5357 (WSDAPI), 5678 (**this is
`vantriqsec-n8n`**, off-limits, confirmed pre-existing, read only, never
touched). **Labeled here as HOST SERVICES, not target findings, in every run
they appear in** — not only Run 4 as originally flagged, since the same
nmap-host-sweep mechanism fires on every URL target that resolves to
127.0.0.1 too. This is worth flagging to Phase 2C beyond the original Run-4-
specific instruction: any severity/count aggregation across these runs must
exclude these ports uniformly or it will double-count the same nine host
services in every run's totals.

---

## 5. Defects found — numbered, TESTED, with evidence. NOT fixed.

### Defect 1 — nuclei's 300s default timeout is insufficient against DVWA

Run 1's nuclei invocation hit the orchestrator's 300-second timeout and
contributed zero findings, while the identical nuclei binary/template set
completed successfully (though with 0 findings) against Juice Shop in Runs
2, 3, and 5. Evidence: `scanner_summary` for Run 1 —
`{"scanner_id":"nuclei","status":"timed_out","skipped_reason":"...scan did
not complete within the configured 300-second timeout..."}`. Not
investigated further (not chased per instruction) — recorded as found.

### Defect 2 — gobuster's own actionable error is discarded; only a generic failure surfaces

Gobuster failed twice, identically, against Juice Shop (Runs 2 and 5).
Reproduced directly, manually, against a live target:

```
gobuster dir -u http://127.0.0.1:13000 -w common.txt
-> the server returns a status code that matches the provided options for
   non existing urls. http://127.0.0.1:13000/4a894d30-... => 200
   (Length: 9393). Please exclude the response length or the status code
   or set the wildcard option.. To continue please exclude the status
   code or the length
```

This is gobuster's own wildcard-detection safety feature working correctly
and telling the operator exactly what to do. KingSec's orchestrator log
records only `gobuster exited with code 1`, and the assessment API surfaces
only `"gobuster exited with an error before producing usable results. Check
the scanner's configuration or try again."` — gobuster's specific,
actionable diagnostic is captured nowhere in the persisted record. This is
the same "silent failure" defect class named repeatedly elsewhere in this
engagement (docs/STATUS.md), here on the read side of a scanner's own
stderr rather than a version probe.

### Defect 3 — ffuf has no wildcard-response detection; floods false positives against SPA targets

See §4. Confirmed root cause (a random nonexistent path returns HTTP 200)
and confirmed by direct comparison with gobuster, which detects and safely
aborts on the identical condition ffuf does not check for at all. Produced
4639 and 4655 "findings" in two independent runs against the same target —
this is fully reproducible, not a one-off.

### Defect 4 — Juice Shop's container OOM-crashed twice, reproducibly, coincident with ffuf's flood

```
docker logs juiceshop-phase2b
-> FATAL ERROR: Ineffective mark-compacts near heap limit
   Allocation failed - JavaScript heap out of memory
docker ps -a -> Exited (139)
```

Happened after Run 2 (web-scan: nmap+gobuster+ffuf+nuclei+zap) and again
after Run 3 (api-scan: ffuf+nuclei+zap only). **ffuf is the only scanner
common to both runs that preceded a crash** — nmap and gobuster were not
even part of Run 3. This is not necessarily a KingSec code defect (the
target's own default Node heap limit is the proximate cause), but it is a
real, reproducible operational finding: an unthrottled ffuf wordlist scan
against a resource-constrained target can crash it mid-assessment, with no
apparent request-rate limiting on KingSec's side. Restarted the container
each time (a test-fixture restart, not `docker rm`) so subsequent runs
scanned a live target.

### Defect 5 — a single large report render can freeze the entire server for every user

Generating/downloading the report for Run 2 or Run 3 (4649/4655 findings)
made the running KingSec server **completely unresponsive to every other
request, including the unrelated `/health` endpoint**, for 2+ minutes
(confirmed repeatedly: `curl -m 5 /health` → connection refused/timeout,
while the process's CPU time stayed flat between checks — blocked, not
busy-looping). Server log evidence:

```
grep -c "no AI API key configured" kingsec_server.log
-> 14043
```

Fourteen thousand and forty-three individual, per-finding AI
business-risk-explanation attempts were logged for a single report render,
each failing with `[KS-EXT-001] no AI API key configured` — there is no
fail-fast check that skips the entire enrichment pass when no key is
configured; every finding pays the cost individually. This entire pass
appears to run synchronously inside the request handler with nothing yielded
back to the event loop, so it blocks the whole (single-worker) server.
Separately: the `/reports/{id}/download` endpoint re-renders the PDF from
scratch on every call rather than serving the already-generated artifact —
confirmed via the log showing `"report rendered"` / `"report generated"` a
second time for an assessment whose report had already been generated and
saved minutes earlier. Recovered by killing and restarting the server
process; no scan data was lost (all persisted in `C:\kingsec-e2e\kingsec.db`).
This is unrelated to Task 5B's Priority 2 scanner-subprocess guard — that
guard is specifically for the scanner subprocess tree and worked correctly
throughout every run in this evidence set (no scan ever exceeded its
timeout) — this is a distinct hang in the HTTP report-rendering path.

### Defect 6 — RETRACTED. Not a product defect; was my own capture-path artifact.

Originally recorded as em-dash characters corrupting to U+FFFD in the
persisted data. **Verified and wrong — corrected here, per instruction.**

Read the finding title directly from SQLite with an explicit UTF-8
connection, bypassing any shell/PowerShell redirect entirely:

```python
conn = sqlite3.connect('file:C:/kingsec-e2e/kingsec.db?mode=ro', uri=True)
title = cur.execute("SELECT title FROM findings WHERE id = ?", (...,)).fetchone()[0]
repr(title)  ->  'HTTP 403 — http://127.0.0.1:18080/.htaccess'
```

The em-dash decodes and re-encodes correctly, round-tripping through
UTF-8 with no loss. Also checked the raw bytes of the original
`curl`-written JSON file on disk (never touched by Python or a terminal):
the em-dash's three-byte UTF-8 sequence is intact there too, byte for
byte. **The database, the API response, and the file on disk were
correct UTF-8 the entire time.** The corruption I originally reported was
introduced only when I `print()`ed the decoded string through this
Windows host's shell for my own inspection — a console-codepage
artifact of my own diagnostic process, not KingSec's. No product code
touched; nothing to fix.

---

## 6. Did nmap scan DVWA's port 18080 when given the URL?

**Yes — confirmed two independent ways, not just asserted.**

1. **Direct database read** (`assessments.scanner_summary`, read-only,
   bypassing any report-rendering path):
   ```
   asmt-c2c0be...  nmap  port_specification =
     "nmap's own default port sweep + explicit port 18080"
   ```
2. **The real finding list**: `Open port 18080/tcp` (Low) appears in Run 1's
   findings, alongside this host's own unrelated services.
3. **The regenerated PDF's own Limitations section** (extracted text, exact):
   > "Nmap's port scan of this target covered: nmap's own default port sweep
   > + explicit port 18080. This is not every possible port — a service
   > running on a port outside that coverage would not have been seen by
   > this assessment."

Phase 1's worst finding — nmap silently never scanning the URL's own port —
is fixed and this run proves it against a real target, not a unit test.

## 7. `port_specification` per run, and how it rendered

| Run | `port_specification` (as persisted) |
|---|---|
| 1 — web-scan/DVWA | `nmap's own default port sweep + explicit port 18080` |
| 2 — web-scan/JuiceShop | `nmap's own default port sweep + explicit port 13000` |
| 3 — api-scan/JuiceShop | *(no nmap in this profile — field absent, correctly)* |
| 4 — quick-scan/127.0.0.1 | `nmap's own default port selection (no explicit port added)` — correct: a bare IP target has no explicit URL port to add |
| 5 — full-assessment/JuiceShop | `nmap's own default port sweep + explicit port 13000` |

Run 1's rendering in the actual PDF is quoted verbatim in §6 above — the
disclosure sentence renders exactly as designed, naming the real port
covered and stating plainly what was not covered.

## 8. Regenerated PDF for the best run

**Run 1 (web-scan / DVWA)** chosen as the best run: no target crash, no
server hang, no scanner failures beyond nuclei's timeout (itself
transparently disclosed via `COMPLETED_WITH_GAPS`), genuine multi-scanner
findings spanning Medium/Low/Informational, and a real, correct
port-coverage disclosure.

- **Generated** via `POST /api/v1/assessments/{id}/report`, **downloaded**
  via `GET /api/v1/reports/{id}/download` through the real running server.
- **Opened and inspected** (text extracted and read, not just a byte-count
  check): 27 pages, coherent Executive Summary → Risk Prioritization →
  per-finding detail → Scanner Coverage → Limitations → Conclusion
  structure. Verdict text: *"Incomplete assessment — 4 of 5 scanners ran;
  findings are partial. 1 scanner(s) did not complete (Nuclei) — see Scanner
  Coverage for details. Among the scanners that completed, Moderate issues
  were found."* Overall Risk Score 31.0/100, explicitly labeled "based on 4
  of 5 scanners... not a posture score."
- **Path**: `C:\kingsec-e2e\phase2b-run1-webscan-dvwa-report.pdf`
  (123,211 bytes).

---

## THE BAR

**Numerically met, substantively not.** Runs 2 and 3 do contain High (26)
and Medium (191) findings. Per §4, those are essentially entirely Defect 3's
false-positive flood, not genuine vulnerability detection — confirmed by
direct root-cause reproduction, not inference. **Excluding that noise, the
real, defensible severity ceiling across all five runs is Medium** — Run 1's
seven genuine Medium findings (a missing CSP header, a missing
anti-clickjacking header, directory browsing enabled, and three `403`s on
sensitive config paths). None of these are exploitation-level findings; they
are configuration/hygiene issues.

**Neither DVWA's nor Juice Shop's actual headline vulnerabilities — SQL
injection, XSS, broken authentication, insecure deserialization, the things
both applications are deliberately built to demonstrate — were detected by
any of the five runs. The primary reason is structural, not a scanner
weakness: KingSec has no concept of authentication.** DVWA requires
database setup and an admin/password login before any of its
vulnerability modules become reachable — nearly every one of its famous
vulnerabilities lives behind that login. Juice Shop's flaws are
concentrated in authenticated API interactions, not its public-facing
pages. An unauthenticated scanner does not fail to find these — it never
reaches the surface they live on; it sees a login page (DVWA) or an SPA
shell serving the same response to everything (Juice Shop — the same
mechanism behind Defect 3). **This is a scope boundary of what KingSec
currently performs — unauthenticated, external assessment — not a defect
in ZAP's or nuclei's detection quality.** Two secondary, real factors
compound it: ZAP is invoked in passive-only mode (`-quickurl`, no active
attack payloads — see the Task 5/5B work), and nuclei contributed one
Informational finding across all five runs combined, because its
template library is weighted toward CVE/technology-fingerprint detection
rather than either app's intentionally-coded business-logic flaws. Even
with active-mode ZAP and full nuclei coverage, though, authentication
would still gate access to most of what these apps are famous for — the
scope boundary is the primary limiter here, not scan depth.

**Answering the specific question directly: nuclei templates are NOT the
path to Critical/High findings here.** The High/Medium findings that exist
came entirely from ffuf's false-positive flood (Defect 3), not from nuclei.
Making the 86 MB template download the default does not, on this evidence,
buy any real severity signal — Phase 2C should not treat it as load-bearing
for finding real Critical/High issues, and should not calibrate against
Runs 2/3's raw severity counts without first excluding Defect 3's noise.

**Say this plainly, as instructed: the scanners are not yet finding the
vulnerabilities these two deliberately-vulnerable applications are famous
for.** What this run demonstrates working end-to-end — real scan execution,
real timeout/coverage disclosure, real port-scope disclosure, real
persistence, real report generation for normally-sized results — is
genuine and substantial progress. But the product does not yet detect
SQLi/XSS/broken-auth-class vulnerabilities against either target, and that
gap should be named directly rather than obscured by the numerically-present
but substantively-hollow High/Medium counts in Runs 2 and 3.

### Phase 5 CLAIM AUDIT — high priority

KingSec performs **unauthenticated, external** security assessment. An SME
buyer hearing "security assessment" will reasonably assume their
application's business logic — what a logged-in user, or an attacker with
stolen or guessed credentials, can do — is in scope. It is not, today. This
run is direct, reproducible evidence of that gap (two applications
deliberately built around post-login/authenticated-API vulnerabilities,
zero of them found by five real runs) — state it as plainly to a customer
as it is stated here, before a sales conversation implies otherwise.

**Roadmap capability, logged here for that same audit:** credentialed /
authenticated scanning — accepting a login flow or session token as part
of target configuration, so ZAP/nuclei/ffuf's scope can extend past a
login page — is not built and not scheduled. Recording it as a real, named
gap rather than an implicit one.
