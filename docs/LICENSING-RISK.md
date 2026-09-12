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

**This "non-bundling" fact does NOT settle every scanner's verdict on its
own** — it answers the redistribution question but not necessarily the
*use* question. nmap's entry below is the case where that distinction
matters: the NPSL prohibits "redistribution **and use**" within a
proprietary product, and non-bundling only addresses the first half.

---

## 1. nmap — NPSL (Nmap Public Source License)

**CORRECTION (this round):** the first version of this entry verdicted nmap
CLEAR-conditioned-on-never-bundling. That answers only the redistribution
half of the question and was wrong to present as a full clearance. Rewritten
below to NEEDS LEGAL REVIEW, per the same standard applied to nikto's entry
— this scanner matters more than nikto's, since it is the only one that
works in every profile.

**Source:** `https://nmap.org/npsl/` (project's own license page) and
`https://nmap.org/oem/` (project's own OEM licensing page).

**The exact clause that changes the analysis:** the NPSL's stated goal is to
"**prohibit redistribution and use of Nmap within proprietary hardware and
software products**" (`https://nmap.org/npsl/`, emphasis added — the
original entry quoted this same sentence but only acted on the
"redistribution" half). "Use," not only "redistribution," is named as
prohibited within a proprietary product absent an OEM license.

**The OEM page's own description of what it covers:** `https://nmap.org/oem/`
states Nmap's *recommended* integration approach for a proprietary product is
exactly KingSec's own design — "install Nmap on the end-user system using
the silent-install feature and then have your application execute Nmap when
needed, requesting XML formatted results (-oX) which you would then parse
with any XML parser" — and then adds: "the license also allows other
integration approaches, such as **parsing of Nmap's normal output format**,
processing Nmap data files directly, or even integrating Nmap source code
into your application." That sentence is on the OEM page, describing what
the **paid** OEM license permits — not the free NPSL. KingSec's own nmap
adapter does precisely this: invokes an operator-installed `nmap` binary via
subprocess and parses its XML output (`-oX -`, piped to `parse_nmap_xml()`).

**The unresolved question, stated explicitly:** does a commercial product
that invokes an operator-installed nmap binary and parses its XML output
constitute "use... within a proprietary software product" under the NPSL —
triggering the OEM license requirement even though KingSec never
redistributes the nmap binary itself? The prior version of this entry
treated "we don't bundle/redistribute nmap" as sufficient to clear the whole
question; the NPSL's own wording (prohibiting use, not only redistribution)
and the OEM page's own listing of XML-parsing among the integration
approaches it describes do not support treating that as settled.

**This cannot be resolved by reading code or licenses further.** Both
source documents have now been read directly and quoted above; the
remaining ambiguity is a legal interpretation question (what "use... within
a proprietary... product" means for an arm's-length subprocess invocation
with no code linking, no redistribution, and no bundled data), not a
factual one this investigation can close by more reading. It needs either
Nmap's own answer or independent legal counsel.

**Verdict: NEEDS LEGAL REVIEW.** Not CLEAR, not blocked — open. KingSec does
not currently redistribute or bundle the nmap binary or its data files (that
much remains true and unconditionally good), but that fact does not resolve
whether invoking-and-parsing itself requires an OEM license. Do not treat
this as CLEAR by extension of the redistribution analysis.

**Draft email to Nmap sales, NOT SENT — Abdul sends it if he chooses to:**

> To: sales@nmap.com
> Subject: OEM license question — commercial product invoking Nmap via subprocess, parsing XML output
>
> Hello,
>
> We're building a commercial security-assessment product (KingSec) that
> uses Nmap as one of several external scanning tools. I want to check
> whether our integration model requires an Nmap OEM license before we
> ship it commercially.
>
> Our model, factually:
> - We do not bundle, redistribute, or ship the Nmap binary or any of its
>   data files with our product.
> - The operator installs Nmap themselves, separately, on their own system.
> - Our product invokes that operator-installed `nmap` binary via a
>   subprocess call (passing `-oX -` for XML output) and parses the XML
>   output our product receives back.
> - We do not link against Nmap's source code, modify Nmap, or
>   redistribute Nmap's own data files (e.g. `nmap-services`, NSE scripts).
>
> Your OEM page (nmap.org/oem) describes "parsing of Nmap's normal output
> format" as one of the integration approaches your license covers, and
> the NPSL states a goal of prohibiting "redistribution and use of Nmap
> within proprietary hardware and software products." We want to confirm
> whether our model — invoking an operator-installed Nmap binary and
> parsing its output, with no redistribution or bundling on our part —
> requires an Nmap OEM license, or whether it falls outside what the NPSL
> restricts.
>
> Happy to answer any follow-up questions about our architecture.
>
> Thank you,
> Abdul Mannan
> KingSec

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
| nmap | NPSL (GPLv2-based) | **NEEDS LEGAL REVIEW** | Unresolved: does invoke-and-parse-XML constitute "use... within a proprietary software product" under the NPSL, independent of never bundling/redistributing? Needs Nmap's own answer or counsel — see the draft email above. |
| nuclei (+ templates) | MIT | CLEAR | None |
| nikto | GPLv3 + proprietary DB files | CLEAR (judgment call) | Never bundle nikto's binary/DB files; keep to arm's-length subprocess invocation; re-review before any packaging change |
| ffuf | MIT | CLEAR | None |
| gobuster | Apache-2.0 | CLEAR | None |
| OWASP ZAP | Apache-2.0 | CLEAR | None |

**nmap is the one scanner this table cannot mark CLEAR without an outside
answer**, and it is the highest-stakes of the six precisely because it is
the only scanner that works in every profile — a NEEDS LEGAL REVIEW verdict
here is a real, load-bearing open item, not a formality. nikto carries a
real but currently-satisfied condition tied to KingSec's packaging model
(never bundle its binary/DB files) — that one should be re-checked
specifically if KingSec's distribution model ever changes to bundle scanner
binaries or data (a Docker image that installs scanners into the same
image, an all-in-one installer, etc.). nmap's open question is different in
kind: it does not resolve itself even under KingSec's current, unchanged
packaging model — it needs a real answer from Nmap or counsel regardless of
whether anything about KingSec's distribution changes.
