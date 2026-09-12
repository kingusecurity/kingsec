# Scanner Licensing Risk — Investigation Only

**Status:** Investigation only, per explicit instruction. No code changes in this
document. Six scanners, cited from each project's own license text (fetched
directly from the project's own repository/site, not a third-party summary),
with a verdict per scanner.

**The one fact that determines every verdict below:** KingSec never bundles,
vendors, or ships any scanner binary or its data files. Confirmed by reading
`infrastructure/config/models.py`: every `*Settings.binary_path` defaults to a
bare command name (`"nmap"`, `"nikto"`, `"nuclei"`, `"ffuf"`, `"gobuster"`,
`"zap"`), resolved against the operator's own `PATH` via `shutil.which()` in
each plugin's `is_available()` — never a path inside KingSec's own source tree
or Docker image. Confirmed by reading the `Dockerfile`: it contains no
reference to any of the six scanner names — nothing is installed into the
image. `nuclei.py`'s `templates_dir` defaults to `None` ("let the scanner use
its own default set" — its own docstring), and the equivalent is true for
ffuf/gobuster wordlists (already logged separately in `docs/STATUS.md`'s
Correction 4 discussion) — KingSec ships no scanner data files either.

Every scanner is invoked the same way: the operator installs it themselves,
KingSec shells out to it as an external subprocess via its documented CLI,
and reads back structured output (XML/JSON) it never modifies. This is the
"arm's-length external tool invocation" pattern already established for nmap
this session (the exact reason `nmap_default_ports.py` was rebuilt from
scratch rather than copying `nmap-services` — see `docs/STATUS.md`'s Decision
4 correction). Every verdict below assumes this pattern continues to hold; if
it stops holding for any one scanner (KingSec starts bundling that scanner's
binary or data files in an installer/Docker image), that scanner's verdict
must be re-evaluated, not assumed to still be CLEAR.

---

## 1. nmap — NPSL (Nmap Public Source License)

**Source:** `https://nmap.org/npsl/` (project's own license page).

**Key terms (quoted/paraphrased from the page):** grounded in GPLv2 with
additional terms. Explicitly states a goal to "prohibit redistribution and
use of Nmap within proprietary hardware and software products" — a company
wanting to embed Nmap in a commercial product must obtain a separate **Nmap
OEM license**. The standard NPSL is the free/public one; the OEM license is
the paid commercial-embedding path.

**How KingSec interacts with it:** KingSec does not embed, redistribute, or
bundle the nmap binary — the operator installs their own copy. This was the
exact question this session already investigated in depth for
`nmap_default_ports.py` (the `nmap-services` frequency-data file): NPSL
covers Nmap's own source and data files, not an external program that merely
invokes the already-installed `nmap` binary via its command-line interface
and reads its output. KingSec's own 61-port list was rebuilt from scratch
using only public IANA documentation specifically to keep zero NPSL-licensed
material in KingSec's source tree — see `docs/STATUS.md`'s Decision 4
correction.

**Verdict: CLEAR**, conditioned on KingSec continuing to (a) never bundle the
`nmap` binary or any of its data files (`nmap-services`, NSE scripts, etc.)
into KingSec's own source, installer, or Docker image, and (b) never require
KingSec's own commercial license to cover use of the operator's separately-
installed nmap. Both conditions hold today. If KingSec ever ships nmap
bundled (e.g., baking it into a Docker image or installer for convenience),
that specific change would need an Nmap OEM license and should trigger a
NEEDS LEGAL REVIEW re-evaluation before shipping — not assumed clear by
extension of this verdict.

---

## 2. nuclei — MIT

**Source:** `https://raw.githubusercontent.com/projectdiscovery/nuclei/main/LICENSE.md`
(project's own LICENSE file).

**Key terms (quoted):** standard MIT license — "the rights to use, copy,
modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software," conditioned only on including the copyright/license notice in
copies. No restriction on commercial use, embedding, or bundling.

**Templates:** nuclei's vulnerability-detection templates live in a separate
repository, `projectdiscovery/nuclei-templates`, under its own license — also
checked directly: `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/LICENSE.md`,
also MIT, same terms.

**How KingSec interacts with it:** `NucleiSettings.templates_dir` defaults to
`None`, letting nuclei use its own bundled/updated template set — KingSec
ships no templates of its own. Even if it did, MIT permits it.

**Verdict: CLEAR.** MIT is fully permissive for commercial use, redistribution,
and bundling, for both the nuclei binary and its templates. No condition
attached — this is the one scanner where even bundling would not create risk.

---

## 3. nikto — GPLv3 (code) + separately-licensed database files

**Source:** `https://raw.githubusercontent.com/sullo/nikto/master/COPYING`
(project's own COPYING file, confirmed GPLv3 — the repository's README states
"you can redistribute it and/or modify it under the terms of the GNU General
Public License version 3"). The database-file restriction is stated directly
in the project's own repository documentation and confirmed via web search
against `cirt.net` (the project maintainer's own site): Nikto's database
files (its web-test signatures) are **not** GPL-licensed — they "may only be
distributed as part of the official Nikto package or installer, for use
exclusively with Nikto," and reuse elsewhere requires a separate commercial
license from CIRT, Inc.

**How KingSec interacts with it:** KingSec invokes the operator's own
separately-installed `nikto` binary as an external subprocess (`binary_path`
default `"nikto"`, PATH-resolved) and parses its output. KingSec does not
link against nikto's code, does not embed or modify it, and does not extract
or reuse its database files independently of the Nikto package itself.

**Verdict: CLEAR, but on a judgment call, not a bright line — flag for
awareness rather than treat as settled law.** The standard GPL interpretation
(the FSF's own long-stated position) is that invoking a separate GPL program
via its documented, arm's-length command-line interface — not linking against
its code, not distributing it — does not make the calling program a
"derivative work" subject to the GPL. Under that interpretation KingSec's own
source is not GPL-encumbered by shelling out to nikto. This is the same
reasoning that clears nmap's NPSL (which is explicitly GPLv2-based) above.
The database-file restriction is separately satisfied as long as KingSec
never bundles or reuses Nikto's database files outside of the operator's own
official Nikto installation — which it does not do today (no database files
are read, copied, or shipped by KingSec; nikto reads its own database files
itself, the same "tool reads its own data" pattern as nmap's port sweep).
**NEEDS LEGAL REVIEW before any packaging change** that would bundle the
nikto binary/database files into a KingSec installer or Docker image, or any
change that reuses nikto's database content independently of invoking nikto
itself.

---

## 4. ffuf — MIT

**Source:** `https://github.com/ffuf/ffuf` → `LICENSE` (project's own file,
confirmed MIT via the repository).

**Key terms:** standard MIT — "released under MIT license," permitting use,
modification, distribution, and sale in commercial products, conditioned
only on retaining the copyright/license notice.

**How KingSec interacts with it:** external subprocess invocation only
(`binary_path` default `"ffuf"`); KingSec supplies a wordlist path via
config but does not bundle a wordlist of its own.

**Verdict: CLEAR.** Fully permissive; no condition beyond attribution, which
is irrelevant here since KingSec doesn't redistribute ffuf's own source.

---

## 5. gobuster — Apache License 2.0

**Source:** `https://raw.githubusercontent.com/OJ/gobuster/master/LICENSE`
(project's own LICENSE file, confirmed Apache-2.0).

**Key terms (quoted):** grants a "perpetual, worldwide, non-exclusive,
no-charge, royalty-free, irrevocable copyright license" to use, reproduce,
and create derivative works, including commercially. Requires only that
modified files carry a notice of modification and that original
copyright/attribution notices be retained if gobuster's own code/NOTICE file
is redistributed.

**How KingSec interacts with it:** external subprocess invocation only
(`binary_path` default `"gobuster"`); no gobuster source is redistributed by
KingSec, so the attribution/NOTICE requirement never triggers.

**Verdict: CLEAR.** Apache-2.0 is commercial-friendly and permits proprietary
use; the only obligations concern redistributing gobuster's own source,
which KingSec does not do.

---

## 6. OWASP ZAP — Apache License 2.0

**Source:** `https://raw.githubusercontent.com/zaproxy/zaproxy/main/LICENSE`
(project's own LICENSE file, confirmed Apache-2.0).

**Key terms:** identical Apache-2.0 terms as gobuster above — permissive,
commercial-use-friendly, obligations only apply when redistributing ZAP's
own source/modified files.

**How KingSec interacts with it:** external subprocess invocation only
(`binary_path` default `"zap"`); no ZAP source is redistributed by KingSec.

**Verdict: CLEAR.** Same reasoning as gobuster.

---

## Summary table

| Scanner | License | Verdict | Condition |
|---|---|---|---|
| nmap | NPSL (GPLv2-based) | CLEAR | Never bundle the nmap binary or its data files |
| nuclei (+ templates) | MIT | CLEAR | None |
| nikto | GPLv3 + proprietary DB files | CLEAR (judgment call) | Never bundle nikto's binary/DB files; keep to arm's-length subprocess invocation; re-review before any packaging change |
| ffuf | MIT | CLEAR | None |
| gobuster | Apache-2.0 | CLEAR | None |
| OWASP ZAP | Apache-2.0 | CLEAR | None |

Two scanners (nmap, nikto) carry a real but currently-satisfied condition
tied to KingSec's packaging model rather than a permanent, unconditional
clearance — both should be re-checked specifically if KingSec's distribution
model ever changes to bundle scanner binaries or data (a Docker image that
installs scanners into the same image, an all-in-one installer, etc.).
