# KingSec User Guide

KingSec is a local-first security assessment orchestrator. It coordinates
compatible external scanners, records authorization, preserves evidence, and
turns scanner output into HTML or PDF posture reports. It is not a penetration
test, SOC, SIEM, EDR, or proof that a target is secure.

## Verification boundary

- **INFERRED (2026-10-07):** this guide was cross-checked against the current
  domain model, profile registry, FastAPI routes, and frontend routes/forms.
- **NOT TESTED (2026-10-07):** the current working tree has not completed a
  fresh browser walkthrough or live scanner run.
- **MISSING from the base Docker image:** scanner executables. Install scanners
  in the same runtime as KingSec before expecting a profile to run.

See [QUICK_START.md](QUICK_START.md) for installation and first-run steps.

## Accounts and roles

KingSec has three application roles:

| Role | Core assessment access |
|---|---|
| Viewer | View permitted assessments, findings, reports, and scanner status |
| Analyst | Viewer access plus create/start/cancel assessments and inspect grants |
| Admin | Analyst access plus create/revoke grants and administer the instance |

The first administrator is created with `kingsec-bootstrap`. Self-registration
is disabled by default; when enabled, every self-registered account starts as a
Viewer, including the first one.

Passwords are 8–128 characters and require at least one uppercase letter, one
lowercase letter, and one digit. Passwords are stored with Argon2id. Accounts
can also use TOTP MFA and recovery codes.

If the login response says MFA is required, complete the TOTP or recovery-code
step before expecting an access token. Do not treat the pending MFA token as an
authenticated session.

## Before every assessment

Confirm all four conditions before creating a run:

1. You own the target or have explicit permission to assess it.
2. An Admin has created an active authorization grant for the real scope.
3. The selected profile accepts the target type.
4. Its required scanners and assets are reported usable in **Monitor** /
   **Scanner Health**.

KingSec's network and web profiles are unauthenticated. They do not log in to
the target application and cannot evaluate business logic or controls that are
only reachable after authentication.

## Target types

Choose the type that describes the resource, not one that merely accepts a
similar-looking string:

| Target type | Use it for | Important boundary |
|---|---|---|
| `ip_address` | One IPv4 or IPv6 address | Not a CIDR range |
| `hostname` | One host name | Does not authorize domain-wide enumeration |
| `url` | One HTTP/HTTPS URL | Embedded credentials are rejected |
| `network` | A CIDR network | Authorize the entire intended network |
| `domain` | DNS-domain enumeration | Requires an explicit `domain` grant |
| `source_path` | An absolute source-tree path | Path is on the KingSec server, not the browser computer |
| `container_image` | An OCI/Docker image reference | Image must be reachable by Trivy in KingSec's runtime |

Source paths and container images are exact resources for authorization
purposes. Domain enumeration may query external DNS and certificate-
transparency sources even though KingSec stores its own assessment data
locally.

## Assessment profiles

Profiles express assessment intent and select scanners with compatible target
types.

| Profile | ID | Target types | Scanner plan |
|---|---|---|---|
| Quick Host Scan | `quick-scan` | IP, hostname | Nmap (required) |
| Network Assessment | `network-scan` | Network, IP, hostname | Nmap (required), Nuclei |
| Web Application Scan | `web-scan` | URL | Nmap, Gobuster, FFUF, Nuclei, ZAP |
| API Assessment | `api-scan` | URL | FFUF, Nuclei, ZAP |
| External Footprint Mapping | `external-footprint` | Hostname, IP | Nmap (required) |
| Full Assessment | `full-assessment` | IP, hostname, URL | Nmap, Nuclei, Gobuster, FFUF, ZAP, Nikto |
| Source Code Assessment | `code-review` | Absolute source path | Semgrep and Trivy (required) |
| Container Image Assessment | `container-scan` | Container image | Trivy (required) |
| Domain Enumeration | `domain-enumeration` | DNS domain | Amass (required) |

The execution-plan preview is authoritative at runtime. A required unavailable
scanner blocks creation/start rather than producing a misleading clean result.
An optional unavailable scanner is recorded as a coverage gap.

Profile duration values shown by the application are estimates, not service-
level commitments. Target responsiveness, selected scanners, assets, network
conditions, and timeouts can materially change actual duration.

## Authorization grants

Open **Authorization Grants** before creating an assessment.

- Admins can create and revoke grants.
- Analysts can list grants and preview whether a target/profile combination is
  covered.
- A grant contains the authorizer, authorizing organization, target
  specification, validity window, creator, and optional revocation time.

The new-assessment form uses the same coverage logic as final submission. A
green preview means active grants cover the effective scanner surfaces at that
moment; it does not replace a signed authorization document or engagement
record.

Use the narrowest accurate grant. For example, grant one IP rather than a CIDR
when only that host is authorized, and use a URL prefix when authorization is
limited to part of an application. Domain enumeration requires the explicit
`domain` specification type. `source_path` and `container_image` grants must
exactly match the target value.

## Create and run an assessment

1. Open **Assessments** and choose **New Assessment**.
2. Choose a profile.
3. Choose its compatible target type and enter the target.
4. Record who authorized the work and a concise audit-trail scope.
5. Review authorization coverage and generate the execution plan.
6. Resolve every blocking message.
7. Create the assessment.
8. Open its detail page and choose **Start Assessment**.

Creation and execution are separate deliberate actions. Saving an assessment
does not send traffic to the target.

While a run is active, the detail page shows overall and per-scanner progress.
Progress is operational status, not a guarantee that a scanner is finding or
will find vulnerabilities.

## Understand assessment status

| Status | Meaning |
|---|---|
| `draft` | Created but not yet authorized |
| `authorized` | Authorized and saved, ready to be started |
| `running` | Scanner execution is active |
| `completed` | Every planned scanner succeeded |
| `completed_with_gaps` | At least one scanner succeeded and at least one scanner was skipped, failed, or timed out |
| `failed` | The run did not produce a successful scanner result |
| `cancelled` | Execution was cancelled |

Always read the scanner summary. `completed_with_gaps` is a partial-coverage
result, not a synonym for complete. A scanner marked skipped, failed, or timed
out did not establish that its part of the target is clean.

## Review findings

The **Findings** page provides permitted findings across assessments; an
assessment detail page keeps the same results in their run context. Use the
finding detail view to inspect:

- title, severity, status, and affected asset when the scanner supplied one;
- scanner evidence;
- remediation guidance and references; and
- the source assessment and its coverage.

Severities are `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFORMATIONAL`.
Finding workflow statuses are `OPEN`, `CONFIRMED`, `FALSE_POSITIVE`, and
`REMEDIATED`.

Scanner findings require human review. Confirm the affected asset and evidence
before prioritizing remediation, and mark a result false positive only after
verification. KingSec does not fabricate a CVE identifier when the scanner did
not provide one.

## Generate and use reports

Generate a report from a completed assessment, then access it from the
assessment or **Reports** page. Supported delivery formats are:

- HTML
- PDF

The report includes findings, severity counts, evidence and remediation,
executive scoring, scanner outcomes, and coverage limitations. A score is a
summary of the data collected; read it together with the coverage disclosure.
When all scanners fail, KingSec refuses to produce a security-posture report
from an empty run.

PDF output uses WeasyPrint and native rendering libraries. The Docker runtime
contains them; a native Windows installation can use HTML or install the GTK
runtime described in [INSTALL.md](INSTALL.md).

## Scanner readiness

Scanner discovery reports whether each executable is installed, its detected
version, required assets, and whether it is usable. Discovery never installs or
changes scanner software.

Common supporting assets include Nuclei templates, FFUF/Gobuster wordlists,
and Trivy's vulnerability database. An executable can be present but unusable
when a required asset is missing.

In Docker, install scanners inside a derived KingSec image. A scanner installed
only on the host is invisible to the container. For source installations,
install it on the KingSec server and ensure the KingSec process can resolve it
on `PATH` or through the applicable configured binary path.

See [SCANNER_GUIDE.md](SCANNER_GUIDE.md) for scanner-specific guidance.

## Interpretation boundaries

- Only scan systems covered by current authorization.
- Do not interpret zero findings as proof of security.
- Do not call a KingSec assessment a penetration test.
- Network and web profiles are unauthenticated and external in scope.
- Local source and container profiles analyze resources accessible to the
  KingSec runtime; they do not remotely retrieve arbitrary private source.
- Domain enumeration can extend beyond a single host and therefore uses a
  distinct target and grant type.
- Review and securely distribute reports: they can contain sensitive target,
  service, and vulnerability information.

## Troubleshooting

| Problem | Check |
|---|---|
| Login page redirects to bootstrap | Run `kingsec-bootstrap` against the same data directory as the server. |
| Registration is refused | Self-registration is disabled by default; contact an Admin or change the explicit security setting. |
| Profile cannot proceed | Review required scanner, asset, and target-compatibility messages in the execution plan. |
| Authorization preview is incomplete | Have an Admin create the correct active grant; verify its type, value, and validity window. |
| Run ends `completed_with_gaps` | Inspect every scanner outcome and coverage note. |
| Report is unavailable | Confirm the assessment has usable results and check the configured HTML/PDF runtime. |
| Docker cannot see a host scanner | Add the scanner to a derived image; containers do not inherit host executables. |

For deployment troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
For endpoint payloads, see [API_REFERENCE.md](API_REFERENCE.md) or the running
instance's `/docs` page.
