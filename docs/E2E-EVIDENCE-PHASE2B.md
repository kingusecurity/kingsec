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

### Defect 6 — em-dash characters in finding titles are corrupted to U+FFFD in the persisted data itself

```python
json.load(open("run_1...json"))["findings"][10]["title"]
-> 'HTTP 403 \ufffd http://127.0.0.1:18080/.htaccess'
```

Confirmed at the Python-decoded-JSON level (not a terminal-rendering
artifact) — the intended em-dash (`—`) between the HTTP status and URL in
KingSec's own generated finding titles is replaced with the Unicode
replacement character in the actual API response and, by extension, the
persisted `findings` data. Present across every run's findings that use this
title format. Root cause not investigated (a non-UTF-8 codec somewhere in
the finding-title construction or capture path is the likely candidate, not
confirmed) — recorded as found, not chased.

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
any of the five runs.** Two structural reasons, both visible in this
evidence: ZAP is invoked in **passive-only** mode (`-quickurl`, no active
attack payloads — see the Task 5/5B work), and **nuclei contributed one
Informational finding across all five runs combined**, not because its
templates are broken, but because nuclei's library is weighted toward
CVE/technology-fingerprint detection, which does not line up with either
app's intentionally-coded business-logic flaws.

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
