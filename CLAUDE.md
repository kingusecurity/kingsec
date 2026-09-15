# CLAUDE.md

Project-specific standing rules for AI-assisted work in this repository. These apply regardless of which phase or prompt is currently active.

## Docker safety

Never run `docker rm`, `docker stop`, `docker prune`, or `docker volume rm` without explicit approval for that specific action. `vantriqsec-crm` and `vantriqsec-n8n` on this host are production services and are strictly off limits — never target them, never include them in a broader cleanup command, never stop them "just to check" something.

Test/verification containers (e.g. a DVWA target) must be created with an explicit, memorable name and torn down only via an explicit, individually-approved command — never as a side effect of a broader cleanup, environment reset, or "let me just clear this out" action. `dvwa-phase2a` was removed at some point during Phase 2A with no record of what removed it or when; that must not be possible again. If a container you expect to be running is missing, say so plainly and ask before assuming it needs to be recreated or that its absence is harmless.

## Cross-checking reported numbers

Any number stated in a report (counts, percentages, timings, pass/fail totals) must be cross-checked against every other document that states the same figure before the report is sent — not just re-derived from whatever code or fixture produced it this time. The Phase 2A scanner count (a regression test asserting "3 of 9 succeed" alongside `docs/E2E-EVIDENCE.md` and a live re-verification both independently showing "1 of 9") was fabricated in a test fixture and passed every automated gate (pytest, ruff, mypy) without complaint — the fixture was internally self-consistent, so nothing caught it automatically. Only comparing the number against another document that stated the same real-world fact caught it. Automated gates passing is not evidence a stated number is correct; check it against independent sources before it goes in a report.

## Environment and data isolation

- Pass environment variables explicitly on the same command line as the command itself; never `source` an env file. Quote every path. (An unquoted path containing spaces silently dropped an isolation override in Phase 1 and caused an unauthorized write to the real `~/.kingsec`.)
- Never write to `~/.kingsec`. Verification work uses an isolated data directory, and the resolved path must be proven before any write happens — printed by the running application itself, not just assumed from a variable that was set.

## Migrations and destructive operations

- Show the full text of any Alembic migration, schema change, or default-behavior change before applying it, and never apply one to a real database without explicit, separate approval.
- Install nothing — no packages, binaries, or tools — without asking first.

## Git

- Never `git add .` or `git add -A`. Run `git status --short` and `git diff --stat` first, show both, then stage explicit paths only. Write professional commit messages. Changes unrelated to the work just approved get their own separate commit.

## Verification honesty

- Label every claim TESTED / INFERRED / NOT TESTED / MISSING. A claim marked TESTED needs real command output or a real artifact behind it, not an assumption that it would pass.
- "No fix needed" is ambiguous on its own — say "no further fix needed at this point in this investigation" instead, so it can never be read as a claim about the code's entire history.
- Never substitute a stub, fake, or double for a component the real one could be wired to instead. When a test genuinely must fake something, fake the narrowest possible seam and state in the test which seam is fake and why. (A stub plugin registry let a scanner "succeed" against a target type it can never actually support in production, and that fabricated number passed every automated gate undetected.)
- Any conclusion carried over from before a context reset is UNVERIFIED. Re-check it in the current session before reporting it as done. Never report "already correct, no changes needed" about work from an earlier context. (Phase 2A's FIX 6 was reported this way and was false — it had only ever touched `action_required` and a headline caveat, never the report's score, band, or gauge, which is exactly why the same defect reproduced itself on the report's own page 2 and needed a separate follow-up fix.)
- A test that constructs its own input by hand-setting a field (`dataclasses.replace(obj, field=correct_value)`) only verifies what happens *downstream* of that field being correct — it can never catch a defect in *how that field gets derived* from real upstream data, because it never exercises the derivation path at all. When a field is meant to be computed from other data, test the computation, not just the consumer of an already-correct value; construct the input the way the real defective case actually arises, not via the shortest path to a passing assertion. Same shape as Phase 2A's `_FakeRegistry` fabrication. (Phase 2C Step 2's `test_completed_with_gaps_zero_findings_keeps_partial_coverage_label` hand-set `assessment_status=COMPLETED_WITH_GAPS` and correctly proved the band-selection logic honors that field — but `Report.from_assessment()` derives `assessment_status` as a straight passthrough of `assessment.status`, never cross-checked against `assessment.scanner_summary`'s actual success count, so a real assessment with a stale/wrong status sailed straight past every test and rendered "100.0 / 100, No Findings — Coverage Limited" for a run where zero scanners succeeded.)

## Session discipline

- One phase per session. Stop cleanly at the end of it; never continue straight into the next phase on the same pass.
- After two failed attempts at the same fix, stop and write `docs/BLOCKED.md`: what was tried, actual vs. expected output, and the top two hypotheses for what's actually wrong.
- Read `docs/STATUS.md` first, at the start of every session. Update it again before the session ends.
- If context resets mid-phase, re-read `docs/STATUS.md` and this file before resuming any work. (A mid-phase context reset in Phase 2A led to a status-decision block being rewritten in a way that silently dropped a previously-documented invariant.)
