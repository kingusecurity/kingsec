# CLAUDE.md

Project-specific standing rules for AI-assisted work in this repository. These apply regardless of which phase or prompt is currently active.

## Docker safety

Never run `docker rm`, `docker stop`, `docker prune`, or `docker volume rm` without explicit approval for that specific action. `vantriqsec-crm` and `vantriqsec-n8n` on this host are production services and are strictly off limits — never target them, never include them in a broader cleanup command, never stop them "just to check" something.

Test/verification containers (e.g. a DVWA target) must be created with an explicit, memorable name and torn down only via an explicit, individually-approved command — never as a side effect of a broader cleanup, environment reset, or "let me just clear this out" action. `dvwa-phase2a` was removed at some point during Phase 2A with no record of what removed it or when; that must not be possible again. If a container you expect to be running is missing, say so plainly and ask before assuming it needs to be recreated or that its absence is harmless.

## Cross-checking reported numbers

Any number stated in a report (counts, percentages, timings, pass/fail totals) must be cross-checked against every other document that states the same figure before the report is sent — not just re-derived from whatever code or fixture produced it this time. The Phase 2A scanner count (a regression test asserting "3 of 9 succeed" alongside `docs/E2E-EVIDENCE.md` and a live re-verification both independently showing "1 of 9") was fabricated in a test fixture and passed every automated gate (pytest, ruff, mypy) without complaint — the fixture was internally self-consistent, so nothing caught it automatically. Only comparing the number against another document that stated the same real-world fact caught it. Automated gates passing is not evidence a stated number is correct; check it against independent sources before it goes in a report.
