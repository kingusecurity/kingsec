# Scope Authorization

> **DRAFT — NOT LEGAL ADVICE. REQUIRES REVIEW BY QUALIFIED COUNSEL.**
> This is a technically accurate starting point for a lawyer to work from,
> not a substitute for one. Every clause below is cross-referenced to the
> exact place KingSec enforces or discloses it, so a reviewer can verify
> the document describes the real system rather than an aspiration. Do
> not present this to a client, or rely on it, until it has been reviewed
> and adapted by counsel for your jurisdiction and engagement terms.

This document is the **paper** authorization a client signs before
VantriqSec runs a KingSec assessment against their systems. It is not
the same thing as the in-product `AuthorizationGrant` — the signed copy
of this document is the source record; the in-product grant is how
KingSec technically enforces what this document authorizes. The person
entering the grant into KingSec should copy its fields directly from a
fully executed copy of this document, not from a verbal description of
it.

---

## 1. Authorizing Party

| Field | Value |
|---|---|
| Full name of person authorizing | ______________________ |
| Title / role at the organization | ______________________ |
| Authorizing organization (legal entity name) | ______________________ |
| Basis of authority to authorize this assessment on the organization's behalf (e.g. system owner, officer of the company, documented delegation) | ______________________ |
| Signature | ______________________ |
| Date | ______________________ |

**Why this exists:** `AuthorizationGrant` (`src/kingsec/domain/authorization_grant.py`)
carries `authorized_by` and `authorizing_organization` as separate,
required, non-empty fields (`AuthorizationGrant.__post_init__`) — the
product itself distinguishes *who* authorized a scan from *which
organization* stands behind that authorization, and refuses to create a
grant missing either. This section is where those two facts get their
first, human-signed source. `created_by` is a third, separate field on
the same object — the KingSec operator who enters the grant into the
system — and may be a different person from the signer above; it is not
a substitute for their signature.

---

## 2. Target Specification

Fill in **exactly one** row, using the same precision you intend the
grant to have. State the form explicitly — a URL does not implicitly
authorize the host or network it happens to sit on (see Section 4).

| Form | Value (fill in the one that applies) |
|---|---|
| IP address (single host) | ______________________ |
| CIDR network range | ______________________ |
| Exact hostname | ______________________ |
| Wildcard hostname (covers subdomains only, never the bare domain) | ______________________ |
| URL prefix (covers that path and everything beneath it; a bare `/` covers the whole host:port) | ______________________ |

**Why this exists:** these are the five real shapes
`TargetSpecificationType` (`src/kingsec/domain/authorization_grant.py`)
accepts — `IP_ADDRESS`, `NETWORK`, `HOSTNAME`, `WILDCARD_HOSTNAME`,
`URL_PREFIX` — and no others; the product validates whatever is entered
against the same format rules `Target` itself uses
(`TargetSpecification._validate_format()`), so a malformed value here
is rejected by the system, not silently accepted. `covers_target()`
(same file) is the exact function that later checks a requested scan
target's value against whichever row is filled in here — never DNS
resolution, only a literal comparison of what both sides were given, so
what you write here should be the literal value you intend, not
something you expect a hostname to resolve to.

---

## 3. Validity Window

| Field | Value |
|---|---|
| Valid from (date/time, with timezone) | ______________________ |
| Valid until (date/time, with timezone) | ______________________ |

**Why this exists:** `AuthorizationGrant.valid_from` / `valid_until`
(`src/kingsec/domain/authorization_grant.py`) are required,
timezone-aware fields, and the product rejects a grant whose
`valid_until` is not strictly after `valid_from`
(`AuthorizationGrant.__post_init__`). `AuthorizationGrant.is_active(at)`
is the exact function that checks whether "now" falls inside this
window (and that the grant hasn't been separately revoked via
`revoked_at`) before any scan is allowed to proceed — a scan requested
outside this window, or after revocation, is not a scan KingSec will
run regardless of what target it names.

---

## 4. Surface Tiers — what authorizing this target actually authorizes

**This is the single most important clause in this document.**

Authorizing a specific URL is **not** the same as authorizing the host
that URL sits on. Some scanning tools respect the exact scope you give
them; others do not, by design, because of how they work:

- Tools that respect the target's own path exactly, and go no further
  (e.g. FFUF, Gobuster): authorizing a URL authorizes exactly that path
  and nothing beyond it on that host.
- Tools that touch the whole host:port once they start, regardless of
  which path was given (e.g. Nikto, Nuclei, OWASP ZAP): authorizing a
  URL on that host authorizes everything reachable on that port, not
  just the specific path named.
- Tools that sweep the **entire host**, independent of any port named
  in the target (e.g. Nmap's port-discovery sweep): authorizing a URL
  or a single port does **not** authorize a full-host port sweep. A
  separate, explicit host-level authorization (an IP address, network,
  or bare hostname row in Section 2 — never a URL-prefix row) is
  required before this kind of scan may run against that host.

**You must state, deliberately, which of these you are authorizing.**
Checking only a URL-prefix row in Section 2 does not authorize a
host-wide scan of the server behind it, even if that server happens to
be entirely under your control.

☐ I authorize **only** what the Section 2 target specification
  literally covers, at the narrowest of the three levels above.

☐ I additionally authorize a full-host scan (port discovery/sweep) of
  the host underlying the Section 2 target. If checked, the Section 2
  target specification must itself be host-level (IP address, network,
  or bare hostname) — not a URL prefix.

**Why this exists:** this clause exists because of a real defect found
and fixed in this product ("Blocking 1" — the docstring on
`satisfies_tier()`, `src/kingsec/domain/authorization_grant.py`): a
grant's coverage of a target's own declared value is not the same
question as whether it covers what a scanner's real invocation actually
touches once it runs. `ScannerSurfaceTier`
(`src/kingsec/domain/scanner.py`) is the product's own three-level
model of exactly the distinction drawn above (`HOST_PORT_PATH`,
`HOST_PORT_ANY_PATH`, `HOST_ANY_PORT`), derived from each scanner
plugin's own capability declaration, never a hand-maintained table.
`effective_scan_surface()` and `find_covering()`
(`src/kingsec/application/authorization_scope.py`) are the functions
`CreateAssessment` actually calls before a scan is allowed to start —
`satisfies_tier()` explicitly refuses a URL-scoped grant for a
host-wide scan ("a URL-scoped grant does not license a host-wide,
any-port scan — a separate host-level grant is required"). This
document's checkbox pair mirrors that real enforcement rule exactly, so
what the client agrees to on paper and what the product will actually
allow never diverge.

---

## 5. What This Authorization Does Not Cover

Signing this document, and the checkboxes in Section 4, authorize scanning
only the exact target named in Section 2, at the surface extent selected
in Section 4. They do **not** authorize:

- **Any other host.** If the target is a device on a live network (a home
  Wi-Fi network, a corporate LAN, a virtual machine bridged onto either),
  this authorization does not extend to the router, any other device on
  that network, or any host merely *reachable from* the named target.
  Each additional host requires its own Section 2 target specification
  and its own signed authorization — proximity on the same network is
  not authorization.
- **Denial-of-service, resource-exhaustion, or availability-impacting
  testing** of any kind, against the named target or any other system.
- **Physical access, social engineering, or testing against personnel.**
- **Retention or disclosure of any data or credentials** incidentally
  encountered beyond what is necessary to report a finding.
- **Scanning outside the Section 3 validity window**, or after the grant
  recording this authorization has been revoked.
- **A full-host scan**, unless the second checkbox in Section 4 is
  selected *and* Section 2 names a host-level target — the first
  checkbox alone does not imply the second.

**Why this exists:** `AuthorizationGrant.covers_target()` and
`satisfies_tier()` (`src/kingsec/domain/authorization_grant.py`) compare a
scan target against the *literal* value entered in Section 2 — never a
subnet, never a DNS resolution, never "anything nearby." The product has
no concept of authorization-by-network-adjacency; this section exists so
the paper document is equally explicit about it, especially where the
named target is a virtual machine bridged onto a real network alongside
devices the signer may not own or control.

---

## 6. Scope Boundary — unauthenticated, external assessment only

KingSec performs **unauthenticated** external assessment. It examines
what's reachable without logging in — open ports and services, missing
security headers, outdated software, and application-layer issues an
unauthenticated visitor could find. It has no mechanism to log in to
your application, so anything that only exists behind
authentication — business-logic flaws, authorization bugs between
roles, anything reachable only once signed in — is out of scope for
this assessment, regardless of what target is named in Section 2. A
clean report means no unauthenticated issues were found; it does not
mean the assessed system has no vulnerabilities behind its login
screen.

**Why this exists:** this is the client-facing scope statement
KingSec already publishes (`docs/commercial/website-faq.md`,
`docs/commercial/website-home.md`, `docs/commercial/website-pricing.md`
— all rewritten in the Phase 5 truth-pass to state this claim precisely
and verifiably). On the product side, every rendered report discloses
the same boundary on its own Scope at a Glance and Limitations
sections, from a single source of truth
(`_AUTHENTICATION_SCOPE_SHORT`, `src/kingsec/infrastructure/reporting/templates.py`) —
this clause exists so the paper authorization and the delivered report
say exactly the same thing, not two independently worded versions that
could drift apart.

---

## 7. What KingSec Will Actually Do

This assessment may run some or all of the following six scanners,
depending on the assessment profile selected and which are compatible
with the target named in Section 2:

| Scanner | What it does |
|---|---|
| Nmap | Discovers open network ports and running services. |
| Nuclei | Tests for known vulnerability patterns using community-maintained templates. |
| Nikto | Checks web servers for common misconfigurations and known issues. |
| FFUF | Discovers hidden files, directories, and parameters via automated guessing. |
| Gobuster | Discovers hidden files, directories, and parameters via automated guessing. |
| OWASP ZAP | Actively and passively tests the web application for common vulnerability classes. |

**Why this exists, and why the wording matches:** this table is the
same six scanners and the same plain-language descriptions
(`_SCANNER_DESCRIPTIONS`, `src/kingsec/infrastructure/reporting/templates.py`)
the delivered report's own Methodology section
(`_methodology()`, same file, Phase 6 Task 5) uses to describe what ran —
deliberately the same wording in both places, not a second,
independently maintained copy that could say something different from
what the report itself discloses after the fact.

---

## 8. Rate Limiting

Scanning tools in this assessment operate under request-rate limits by
default, not at full unthrottled speed:

| Scanner | Default rate limit |
|---|---|
| Nuclei | 150 requests/second |
| FFUF | 40 requests/second |
| Gobuster | 100ms delay between requests (~10 requests/second) |

**These limits are a politeness and safety control, not a security
guarantee.** A real attacker targeting the same system would not be
bound by them, and could probe at a far higher rate, from multiple
sources simultaneously, and without regard for whether the target
system remains stable under the load. This assessment's rate limiting
tells you nothing about how the assessed system would behave under an
actual attack's request volume.

**Why this exists:** these are the real, currently-shipped default
values (`NucleiSettings.rate_limit`, `FfufSettings.rate_limit_per_second`,
`GobusterSettings.delay_ms` — `src/kingsec/infrastructure/config/models.py`),
each independently operator-configurable via its own environment
variable. They exist because of a real, reproducible operational defect
found in this product: "Defect 4" (`docs/E2E-EVIDENCE-PHASE2B.md`) — an
unthrottled FFUF wordlist scan crashed a real, resource-constrained
target twice, reproducibly, with a JavaScript heap-out-of-memory error,
before any request-rate limiting existed on KingSec's side. FFUF's and
Gobuster's defaults above are the fix that followed that defect (Phase
2B-c Priority 3, tagged as such in the source); Nuclei's own rate limit
is a separate, general-purpose politeness control on the same settings
class, not tied to that specific incident. Each scanner's actual applied
rate limit is recorded per scan
(`ScannerRunSummary.rate_limit_description`) and disclosed in every
delivered report's Limitations section — so what this document promises
and what the report discloses after the fact are the same claim.

---

## 9. Not a Penetration Test

The client acknowledges that this assessment is **automated
vulnerability scanning**, not a manual penetration test. It does not
include manual exploitation, social engineering, physical security
testing, business-logic analysis, or a human tester's judgment about
which findings are genuinely exploitable in the assessed system's
actual context. Findings should be triaged by qualified personnel
before being treated as confirmed vulnerabilities; some may be false
positives, and the assessment's absence of findings in any category is
not proof of the absence of risk in that category.

---

## 10. Signatures

By signing below, the client confirms they have read and understood
Sections 1–9 above, and specifically the surface-tier checkboxes in
Section 4 and the exclusions in Section 5.

| | |
|---|---|
| Client signature | ______________________ |
| Client name (printed) | ______________________ |
| Date | ______________________ |

**VantriqSec countersignature.** By countersigning below, the VantriqSec
representative confirms the scope, target, validity window, and
surface-tier authorization above have been reviewed, match what will be
entered into KingSec as the `AuthorizationGrant` (see the closing note
below), and that the assessment will be conducted strictly within these
terms — no scan surface beyond what Section 4 checked, no target beyond
what Section 2 named.

| | |
|---|---|
| VantriqSec representative (signature) | ______________________ |
| VantriqSec representative (printed name) | ______________________ |
| Title / role | ______________________ |
| Date | ______________________ |

Upon execution, the fields in Sections 1–3 above should be entered into
KingSec as a real `AuthorizationGrant` before any assessment against
the Section 2 target is created. The grant's `id` should be recorded
alongside the retained signed copy of this document for audit purposes.
