# Frequently Asked Questions

## Verification boundary

- **INFERRED (2026-10-07):** answers below were checked against current source
  and configuration.
- **NOT TESTED (2026-10-07):** no fresh install or live scan of the current
  working tree has been completed in this session.
- **NOT TESTED:** the current native Windows installer has not been validated
  on a Windows host.

## Product scope

### What is KingSec?

KingSec is a local-first security assessment orchestrator and reporting tool.
It coordinates compatible open-source scanners and turns their output into an
authorization-linked posture report for systems you are permitted to assess.

### Is it a penetration test?

No. The network and web profiles perform an unauthenticated, external
first-pass assessment. They do not log in to applications, test business logic
between user roles, run a SOC, or replace a human-led penetration test.

### Does a clean report mean the target is secure?

No. It means no findings were reported by the scanners that completed within
the scope shown. Always read the scanner outcomes and coverage limitations.
`completed_with_gaps` explicitly means coverage was incomplete.

### Is KingSec commercially available?

Do not infer an offer, price, support commitment, or production-readiness
guarantee from this repository. VantriqSec is preparing a services-led
assessment offering; commercial terms and availability require a separate,
current agreement.

## Privacy and connectivity

### Does assessment data leave the KingSec server?

KingSec stores its own assessment records and reports locally by default.
External tools can still make network requests as part of their operation:
scanners contact the authorized target, Amass can query third-party DNS and
certificate-transparency sources, scanner databases/templates may update over
the network, and configured AI or integration providers receive the data sent
to them. Review every enabled scanner and integration before use.

### Can KingSec run offline?

The application and previously installed scanner data can operate without a
cloud account. Some scanner modes, database/template updates, domain
enumeration sources, AI providers, and external integrations require network
access.

## Installation

### Which scanners does KingSec support?

The profile registry can drive Nmap, Nuclei, Nikto, FFUF, Gobuster, OWASP ZAP,
Semgrep, Trivy, and Amass. They are external dependencies and are not bundled
into the base Docker image.

### What happens when a scanner is missing?

A missing required scanner or asset blocks its profile during planning. A
missing optional scanner is recorded as a coverage gap. KingSec does not turn a
missing scanner into a successful zero-finding result.

### Why can Docker not see a scanner installed on my host?

Containers do not inherit host executables. Add the required scanners and
assets to a derived KingSec image, or run KingSec from source in the same host
environment as the scanners.

### Can I run KingSec on Windows?

The Docker Desktop Linux-container path has historical evidence in this
repository. A PowerShell source installer exists, but its current revision is
not yet validated on a native Windows host. HTML reports avoid the GTK runtime;
native PDF output requires the documented GTK setup.

### Is there a published Docker image or PyPI package?

The current installation guides assume a repository checkout and a locally
built Docker image or source install. Do not rely on an unverified public image
or `pip install kingsec` workflow.

## Accounts and authorization

### How do I create the first administrator?

Run `kingsec-bootstrap` in the same environment and against the same data
directory as the server. The first self-registered user never becomes Admin;
self-registration is disabled by default and, when enabled, creates Viewers.

### Why must I create an authorization grant?

KingSec checks scope before persisting an assessment. An Admin records a
time-bounded grant for the permitted target; Analysts can inspect coverage but
cannot authorize their own work.

### Why does domain enumeration need a different grant?

Enumerating a domain reaches beyond one hostname. The `domain-enumeration`
profile therefore requires a `domain` target and an exact `domain` grant. A
hostname or wildcard-hostname grant is deliberately insufficient.

### What are source and container targets?

`source_path` is an absolute path visible to the KingSec server.
`container_image` is an OCI/Docker image reference reachable from the KingSec
runtime. Both require purpose-built profiles and exact matching grant types;
they are not encoded as hostnames.

## Assessments and reports

### How do I create a first assessment?

Bootstrap an Admin, confirm a compatible scanner is usable, create an active
authorization grant, choose a compatible profile/target in **New Assessment**,
review the plan and grant coverage, save the assessment, and then start it from
its detail page. Creation and execution are separate actions.

### Which report formats are supported?

HTML and PDF. JSON, CSV, and Markdown report export are not supported delivery
formats in the current core report path.

### Why was no report generated for a failed run?

KingSec refuses to produce a posture report when no scanner completed
successfully. This avoids presenting an empty scan as evidence of a clean
target.

### What does the executive score mean?

It is a summary derived from the findings collected in that assessment. It is
not meaningful without the report's scanner outcomes and coverage disclosure,
and it is not a certification or compliance attestation.

## Security and operations

### How are passwords stored?

The production composition uses Argon2id. Passwords are never stored in plain
text.

### Does KingSec provide HTTPS directly?

The default server is loopback HTTP. For network access, place it behind a TLS
reverse proxy and preserve the safe host binding until that proxy and access
controls are ready.

### How do I update the database schema?

Use `kingsec-migrate` from the installed environment. The Docker container runs
it before server startup. Back up important data and review release-specific
migration guidance before upgrading an existing deployment.

### Where do I get more help?

- [QUICK_START.md](QUICK_START.md) for the first authorized assessment
- [INSTALL.md](INSTALL.md) for deployment
- [SCANNER_GUIDE.md](SCANNER_GUIDE.md) for scanner prerequisites
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for diagnosis
- [API_REFERENCE.md](API_REFERENCE.md) or the running `/docs` page for API use
- GitHub issues: https://github.com/kingusecurity/kingsec/issues
