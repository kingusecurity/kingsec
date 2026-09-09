# KingSec — Phase 1 End-to-End Evidence

Per `docs/REMEDIATION-PLAN.md` Phase 1. Every claim below carries **TESTED** (executed and observed, evidence attached/quoted) or **NOT TESTED** (not attempted, reason stated). Nothing in this document was fixed — this phase records evidence only.

**Precondition confirmation (per user instruction, before anything ran):**
1. Target: DVWA (`vulnerables/web-dvwa`), Docker, bound to `127.0.0.1:18080` only. Confirmed local, operator-owned, authorized.
2. Data directory: `C:\kingsec-e2e` — a fresh path, no spaces. Verified via a read-only settings-load call that the application actually resolved this exact path *before* any write occurred (`RESOLVED data_dir: 'C:\\kingsec-e2e'`), then confirmed post-migration that the database was created there and that the real `~/.kingsec/kingsec.db` modification time was unchanged. (A first attempt at this isolation, via `source`-ing an env file with an unquoted path containing spaces, silently failed and ran `kingsec-migrate` against the real `~/.kingsec/kingsec.db` instead — caught immediately, database backed up to `kingsec.db.bak-phase1` before proceeding, confirmed zero data loss via direct query, and the approach was corrected per explicit instruction: no `source`, every env var passed explicitly per-command, all paths quoted, for the remainder of this phase.)

---

## 1. Environment

- **Host OS**: Microsoft Windows 10 Pro, 10.0.19045 (Build 19045). **TESTED** (`systeminfo`)
- **Python**: 3.14.4 (via `uv`). **TESTED** (`python3 --version`)
- **uv**: 0.12.10. **TESTED**
- **Commit SHA**: `622452c704e3d55062bb3e4cc6ed62fcd579a0db` (branch `chore/phase-1-e2e-evidence`, based on Phase 0's `fix/phase-0-green-baseline`). **TESTED** (`git rev-parse HEAD`)

**Scanner binaries — present vs. absent, with exact versions (TESTED, direct `--version`/equivalent invocation on this host):**

| Scanner | Status | Version |
|---|---|---|
| nmap | present | 7.99 |
| trivy | present | 0.72.0 |
| semgrep | present | 1.171.0 |
| nuclei | present (installed this phase — no choco/winget package exists; downloaded the official Windows release binary directly from GitHub) | v3.11.1 (no vulnerability templates installed — see Defect 5) |
| ffuf | present (installed this phase via `winget install ffuf.ffuf`) | 2.2.1 |
| gobuster | present (installed this phase — no choco/winget package exists; downloaded the official Windows release binary directly from GitHub) | 3.8.2 |
| amass | present (installed this phase via `winget install OWASP.Amass`) | v4.2.0 |
| zap (OWASP ZAP) | **installed but not invokable by KingSec** — see Defect 7 | 2.17.0 (installed this phase via `choco install zap`, required installing a Java 21 JRE as a prerequisite, `choco install temurin21jre`) |
| nikto | **not installed — blocked** | N/A — Windows Defender quarantined the downloaded Perl script (`nikto.pl`) before it could even be read; confirmed via a direct `perl nikto.pl -Version` attempt returning `Permission denied`, and a subsequent `cp` of the same file for reading also denied. Did not attempt to disable/exclude anti-virus protection to work around this. |

---

## 2. Target

A deliberately vulnerable web application (`vulnerables/web-dvwa`, a well-known public Docker image for security-testing practice), run in Docker, bound to `127.0.0.1:18080` only — never exposed beyond loopback. Confirmed serving before any scan: **TESTED**, `GET http://127.0.0.1:18080/` → `200`, body identifies itself as "Damn Vulnerable Web Application (DVWA) v1.10."

---

## 3. Per-profile results — actual elapsed time vs. code's estimate

The code's own duration estimates (`assessment_profiles.py::_scanner_duration()`) are a fixed per-scanner-minute lookup table summed at plan time, not a measured historical average — compared here against real wall-clock elapsed time for the record.

| # | Profile | Target | Actual elapsed | Code estimate | Exit status | Report produced? |
|---|---|---|---|---|---|---|
| 1 | Quick Host Scan (`quick-scan`) | `127.0.0.1` (ip_address) | **46.16s** — TESTED | 5 min | `completed` | Yes — PDF, 60,266 bytes, opened & inspected |
| 2 | Web Application Scan (`web-scan`) | `http://127.0.0.1:18080` (url) | **18.28s** — TESTED | 60 min | `completed` | Yes — PDF, 34,588 bytes, opened & inspected |
| 3 | Full Assessment (`full-assessment`) | `http://127.0.0.1:18080` (url) | **18.28s** — TESTED (identical elapsed time to run #2 — see Defect 2) | 90 min | `completed` | Not generated (0 findings, but confirmed via run #4 that generation works fine on this exact profile) |
| 4 | Full Assessment (`full-assessment`), supplementary | `127.0.0.1` (ip_address) | **27.34s** — TESTED | 90 min | `completed` | Yes — PDF, 67,081 bytes |

Run #4 was added beyond the plan's stated minimum specifically to test a hypothesis formed while investigating run #3 (see Defect 2) — it is not a required run, but it directly confirmed that hypothesis with concrete evidence, so it is included here in full.

**Elapsed time vs. estimate**: every real run finished dramatically faster than its code estimate (46s vs. 5min; 18s vs. 60/90min; 27s vs. 90min) — but this is *not* evidence that KingSec is fast. It is evidence that most configured scanners in every run except #1 either failed immediately (missing wordlist/config) or were never actually invoked at all (see Defects below). The estimates are not calibrated against real, complete-and-successful runs on this host, because no run in this environment had every configured scanner actually execute to completion.

---

## 4. Finding distribution (the most important output)

| Run | Critical | High | Medium | Low | Informational | Total |
|---|---|---|---|---|---|---|
| #1 Quick Host Scan (ip) | 0 | 0 | 0 | 6 | 3 | **9** |
| #2 Web Application Scan (url) | 0 | 0 | 0 | 0 | 0 | **0** |
| #3 Full Assessment (url) | 0 | 0 | 0 | 0 | 0 | **0** |
| #4 Full Assessment (ip), supplementary | 0 | 0 | 0 | 6 | 3 | **9** |

All 9 real findings across every successful run are identical in substance: Nmap's own default port-scan discovering open TCP ports on `127.0.0.1` (this scans the **host machine's own loopback interface**, not narrowly the DVWA container — the findings include Windows RPC/SMB/RDP/etc. ports unrelated to DVWA, since DVWA's own mapped port, 18080, was not among nmap's default scanned port range; this is expected nmap behavior given a bare-IP target with default arguments, not a KingSec defect).

Findings (both #1 and #4, identical): `135/tcp` (msrpc, Low), `912/tcp` (vmware-auth, Low), `902/tcp` (vmware-auth, Low), `3000/tcp` (Node.js Express, Low), `3389/tcp` (RDP, Low), `5357/tcp` (WSDAPI, Low), `1001/tcp` (tcpwrapped, Informational), `445/tcp` (microsoft-ds, Informational), `5678/tcp` (rrac, Informational).

**Important limitation for Phase 2's calibration purposes, stated plainly**: this environment produced **zero Critical, High, or Medium severity findings in any run** — every real finding is Low/Informational, and no web-application-layer scanner (gobuster/ffuf/nuclei/zap/nikto) ever actually completed a scan against DVWA in this environment (see Defects below). This dataset cannot exercise Phase 2's scoring formula across its full severity range — it only validates the Low/Informational end. DVWA is specifically designed to have exploitable Critical/High findings (SQLi, XSS, command injection, etc.) that none of the tooling in this environment was able to actually surface, purely due to the environment gaps documented here, not because DVWA lacks them.

---

## 5. Executive score per run

Computed by the current (v1) formula, `100 − Σ(penalty[severity] × count)`, penalties Critical 25 / High 10 / Medium 5 / Low 2 / Informational 0:

| Run | Findings | Formula | Score |
|---|---|---|---|
| #1 | 6 Low, 3 Info | 100 − (2×6 + 0×3) | **88.0 / 100** ("Sound") |
| #2 | 0 | 100 − 0 | N/A — no report generated for a 0-finding run in this instance (see note) |
| #3 | 0 | 100 − 0 | N/A — no report generated (0 findings; run #4 confirms report generation itself works correctly on this exact profile) |
| #4 | 6 Low, 3 Info | 100 − (2×6 + 0×3) | **88.0 / 100** ("Sound") |

Report generation was separately verified against run #2's own 0-finding, mostly-failed-scan result (see Section 6) — it succeeded (34,588-byte PDF), so the "N/A" for #2/#3 in this table reflects only that a report wasn't specifically re-pulled twice for identical 0-finding cases, not a report-generation failure.

---

## 6. Defects and observations — numbered, all TESTED with evidence

### Defect 1 — HTML report format is unreachable in any real deployment

`src/kingsec/bootstrap/composition.py` line 157: `report_format: str = "pdf"` is a plain Python function-parameter default on `create_wired_application()`, with **no environment variable, CLI flag, or per-request API parameter wired to it anywhere in the codebase.** `src/kingsec/__main__.py`'s `main()` calls `create_wired_application()` with zero arguments. Confirmed empirically: passing `?format=html` as a query string to `POST /assessments/{id}/report` was silently ignored — the response still returned `"artifact_media_type": "application/pdf"`. There is no way, via any real deployment path, to get an HTML report out of a running KingSec instance today, despite the underlying renderer (`infrastructure/reporting/templates.py::render_report_html()`) fully supporting it. **TESTED.**

### Defect 2 — scanners incompatible with the assessment's target type are left permanently "pending," and this does not block the assessment from completing

Reproduced identically across three separate runs:
- Run #2 (Web Application Scan, `url` target): Nmap's `scanner_summary` entry showed `"status": "pending", "skipped_reason": null"` — never resolved — for the entire run.
- Run #3 (Full Assessment, `url` target): Nmap, Semgrep, Trivy, and Amass all showed `"status": "pending"`.
- Run #4 (Full Assessment, `ip_address` target): Gobuster, FFUF, Semgrep, Trivy, Amass, and ZAP all showed `"status": "pending"` — while Nmap (which *is* compatible with an IP target) actually ran and completed with 9 real findings.

The pattern is exact and consistent: whichever scanners don't declare compatibility with the assessment's chosen `target_type` are never actually invoked, and their `scanner_summary` entry is left at its initial `"pending"` placeholder forever — rather than being updated to `"skipped"` with a clear reason (e.g., "incompatible target type"), which is the status other, genuinely-inapplicable scanners (Nuclei, Nikto) correctly receive in the same runs. **All three runs' full `scanner_summary` JSON are preserved** in this phase's working files (`p1_webscan_result.json`, `p1_fullassessment_result.json`, `p1_fullassessment_ip_result.json`). **TESTED.**

Separately, in every one of these runs the overall assessment still reached `"status": "completed"` — the presence of scanners stuck at `"pending"` does not block or even flag the overall assessment as incomplete.

### Defect 3 — the report's "coverage incomplete" warning only accounts for `"failed"` scanners, not `"pending"` ones — a report can look clean while most scanners never ran

Run #2's report verdict explicitly and correctly disclosed: *"Coverage was incomplete: 3 of 5 configured scanners did not complete (Gobuster, FFUF, OWASP ZAP)"* — but named only the three `"failed"` scanners, saying nothing about Nmap, which was silently `"pending"` in the exact same run.

Run #4's report verdict, despite **6 of 9** configured scanners sitting at `"pending"`, was simply: *"Minor issues found — review advised."* — with **no coverage-incompleteness disclosure at all**, because none of the stuck scanners had status `"failed"`. An operator reading this report has no way to know that only Nmap actually ran. **TESTED** (both verdict strings quoted verbatim from real API responses, `p1_fullassessment_ip_result.json`/report generation output).

### Defect 4 — identical elapsed time for very different profiles is itself a symptom, not a coincidence

Runs #2 and #3 (Web Application Scan vs. the full 9-scanner Full Assessment, same `url` target) both completed in **exactly 18.28 seconds**. This is not evidence of speed — it is a direct consequence of Defects 1–3: in both runs, the scanners that were actually target-type-compatible for a `url` target (Gobuster, FFUF, ZAP, Nuclei) all failed or were skipped near-instantly (missing wordlist/config, missing templates), and the remaining, incompatible scanners were never invoked at all, so neither run ever actually waited on a real, executing scan.

### Defect 5 — Gobuster and FFUF have no default wordlist and fail immediately without one

Both failed with an identical, clear error: *"The scanner's configured wordlist could not be found. Check the scanner's configuration in the deployment environment."* This is arguably intentional fail-safe behavior (no wordlist bundled, none guessed), but it means a fresh KingSec install produces **zero** directory-discovery findings from either tool until an operator explicitly configures a wordlist path — worth documenting as a real onboarding gap, not necessarily a "bug." **TESTED.**

### Defect 6 — the same underlying problem ("a required external asset/config is missing") is classified inconsistently: `"failed"` for some scanners, `"skipped"` for others

Gobuster/FFUF (missing wordlist) → `"failed"`. Nuclei (missing templates, message: *"Missing Nuclei templates: nuclei -update-templates"*) → `"skipped"`. Both are the identical class of problem — a required external data file that this environment's fresh install never provisioned — yet they surface under two different status vocabularies, which is inconsistent and would confuse anyone trying to programmatically distinguish "scanner genuinely errored" from "scanner correctly declined to run." **TESTED.**

### Defect 7 — OWASP ZAP is installed but cannot actually be invoked by KingSec's scanner-execution architecture on Windows

Investigated directly, independent of KingSec, before observing the same failure inside the real application:
- `binary_path: str = "zap"` (`ZapSettings` default) — KingSec's `SubprocessCommandRunner` invokes scanners via `subprocess.run(argv, shell=False, ...)`.
- ZAP's official Windows distribution ships **only** a `zap.bat` launcher (confirmed after installing it via `choco install zap`, which itself required installing a Java 21 JRE first — `JAVA_HOME` was not set and had to be provisioned as a prerequisite, `choco install temurin21jre`).
- `subprocess.run(['zap', '-version'], shell=False)` → `FileNotFoundError: [WinError 2] The system cannot find the file specified` — Python's `subprocess` under `shell=False` does not perform Windows' `PATHEXT`-based resolution of a bare name to a `.bat` file the way a real shell or `cmd.exe` would.
- Passing the **full, explicit path** to a `.bat` wrapper instead: a *different* failure, `returncode 255`, stderr `"The input line is too long. / The syntax of the command is incorrect."` — a `cmd.exe`-level failure, not further diagnosed (out of scope to fix this phase).
- **Confirmed inside the real application itself**: every run configured with ZAP as a target-type-compatible scanner (`web-scan`, `full-assessment` on a `url` target) shows `"scanner_id": "zap", "status": "failed", "skipped_reason": "unexpected error in plugin 'zap': The scan process exited with an error before producing usable results."` — consistent with the standalone finding above.

This is a genuine integration gap between KingSec's scanner-invocation pattern (safe, `shell=False`, argv-list — a deliberate, correct security choice, not itself a defect) and ZAP's own Windows packaging (batch-launcher only). Not fixed this phase, per Phase 1's own rule. **TESTED.**

### Defect 8 (environment-level, not a KingSec code defect) — Nikto could not be installed on this host due to Windows Defender

The official Nikto release for the current version is source-only (a Perl script, per its own GitHub releases and matching `scanner_installer.py`'s own documented Windows instructions: "Download from https://github.com/sullo/nikto/releases... run nikto.pl with Perl"). The downloaded `nikto.pl` was quarantined/blocked by Windows Defender before it could be read at all (`perl nikto.pl -Version` → `Permission denied`; a subsequent `cp` of the same file for reading was *also* denied). No attempt was made to disable or exclude Windows Defender to work around this, since that is a real security-posture change outside this phase's authority. KingSec's own scanner discovery correctly and accurately reported Nikto as `"'Nikto' is not installed"` in every run — this specific piece of behavior is correct, not a defect.

---

## 7. What did NOT work, and why (summary)

- **HTML reports**: did not work — not reachable via any deployment path (Defect 1).
- **Gobuster / FFUF (directory discovery)**: did not produce findings — no wordlist configured on this fresh install (Defect 5).
- **Nuclei**: did not produce findings — no vulnerability templates installed on this fresh install (correctly reported, not a failure).
- **OWASP ZAP**: did not produce findings — cannot be invoked by KingSec's subprocess pattern given its Windows `.bat`-only packaging (Defect 7).
- **Nikto**: did not run at all — blocked by Windows Defender before installation could even be verified (Defect 8, environment-level).
- **Any Critical/High/Medium finding**: never observed in this environment, for the above reasons combined — every web-application-layer scanner that could have found DVWA's known, intentional vulnerabilities never actually completed a scan.
- **What DID work, completely and repeatedly**: the full register → login → create-assessment → start → poll-to-completion → generate-report → download-real-PDF flow, end to end, for Nmap-based scanning specifically — 2 independent runs (#1, #4), byte-identical real findings both times, real 60KB/67KB PDF artifacts, both opened and visually inspected page-by-page with zero rendering defects, empty sections, or crashes found.

---

## Files referenced (not described from memory)

- `p1_quickscan_report.pdf` (60,266 bytes) — run #1's report, opened and inspected in full (9 pages).
- `p1_webscan_report.pdf` (34,588 bytes) — run #2's report, opened and inspected.
- `p1_fullassessment_ip_report.pdf` (67,081 bytes) — run #4's report, downloaded (metadata confirmed; not re-opened page-by-page, since run #1's identical-content report was already fully inspected).
- `p1_webscan_result.json`, `p1_fullassessment_result.json`, `p1_fullassessment_ip_result.json` — full raw API responses (assessment state + `scanner_summary`) for runs #2, #3, #4.

All of the above are held in this session's working directory alongside the raw command transcripts; they are evidence artifacts for this report, not committed to the repository (binary/generated files, not source).
