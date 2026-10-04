# KingSec v1.1.0 — Pricing

> **Note:** The prices below are placeholders for demonstration and planning purposes. They do not represent final or current pricing. Contact kingusecurity@gmail.com for the latest information.

**KingSec performs unauthenticated external assessment.** It scans what's reachable without logging in — it does not authenticate to your application, so functionality and logic flaws that only exist behind a login are not examined by any tier. A clean result says nothing about what sits behind authentication. See "What KingSec Assesses" below before you buy.

---

## Tier Overview

| | Free | Professional | Enterprise |
|---|---|---|---|
| **Price** | $0 | $49 / month | Custom |
| **Users** | Up to 3 | Up to 25 | Unlimited |
| **Scanners** | All 6 included | All 6 included | All 6 + custom plugin integration |
| **Assessment profiles** | 6 profiles | 6 profiles | 6 profiles |
| **AI enrichment** | — | BYO-Key | BYO-Key + private model |
| **Reports** | HTML | HTML + PDF | HTML + PDF |
| **Scheduled assessments** | Up to 5 | Unlimited | Unlimited |
| **MFA/TOTP** | ✓ | ✓ | ✓ |
| **RBAC** | — | ✓ | ✓ |
| **Teams** | — | Up to 5 | Unlimited |
| **Audit logging** | — | ✓ | ✓ |
| **API access** | Read-only | Read + write | Full |
| **Support** | Community (GitHub) | Email + GitHub | Dedicated SLA |

---

## Feature Comparison

| Feature | Free | Professional | Enterprise |
|---|---|---|---|
| Nmap scanning | ✓ | ✓ | ✓ |
| Nuclei scanning | ✓ | ✓ | ✓ |
| Nikto scanning | ✓ | ✓ | ✓ |
| FFUF fuzzing | ✓ | ✓ | ✓ |
| Gobuster enumeration | ✓ | ✓ | ✓ |
| OWASP ZAP scanning | ✓ | ✓ | ✓ |
| AI remediation guidance | — | BYO-Key | BYO-Key |
| AI severity explanation | — | BYO-Key | BYO-Key |
| Report formats | HTML | HTML + PDF | HTML + PDF |
| Scheduled assessments | 5 max | Unlimited | Unlimited |
| Custom scanner plugin integration (code-level, via our services team) | — | — | ✓ |
| JWT authentication | ✓ | ✓ | ✓ |
| Role-based access control | — | ✓ | ✓ |
| MFA / TOTP | ✓ | ✓ | ✓ |
| Team management | — | ✓ | ✓ |
| Audit log | — | ✓ | ✓ |
| API tokens | Read-only | Read + write | Full |
| Priority support | — | — | ✓ |
| On-prem deployment | ✓ | ✓ | ✓ |
| Docker / pip install | ✓ | ✓ | ✓ |

*Not currently offered at any tier: PDF/report branding (the template supports it internally, but there is no way to configure it yet), a white-label UI, custom assessment profiles, and JSON/CSV/Markdown report export. Trivy, Semgrep, and Amass ship in the codebase as registered scanner plugins but are not reachable through any of the 6 assessment profiles today — they are not part of what you're buying at any tier until that changes.*

---

## What "Free" Means

The Free tier is fully functional for individual use and small teams. You get all six scanners, all six assessment profiles, and unlimited local storage of findings. No time limits. No feature holds. The only limitations are on team size, scheduled assessment count, and RBAC — features that primarily benefit larger organizations.

---

## What KingSec Assesses

KingSec performs **unauthenticated** external security assessment: it examines what's reachable without a login — open ports and services, missing security headers, outdated software versions, and application-layer issues an unauthenticated visitor could find (injection points, exposed paths, misconfigured TLS, and similar). It does not have a mechanism to log in to your application, so anything that only exists behind authentication — business-logic flaws, authorization bugs between user roles, anything reachable only once signed in — is not in scope for any assessment, at any tier. A clean report means no unauthenticated issues were found; it does not mean your application is free of vulnerabilities behind its login screen.

---

## FAQ

**Q: Is the Free tier really free?**
A: Yes. No trial period, no credit card required, no feature timeout.

**Q: What do I need to pay for beyond the software?**
A: If you use AI enrichment, you pay your AI provider (OpenAI, Anthropic, etc.) directly for API usage. KingSec does not charge a markup on AI requests.

**Q: Can I switch tiers later?**
A: Yes. Upgrade or downgrade at any time. All your data and assessments are preserved.

**Q: Do I need a license key or online activation?**
A: No. KingSec activates on first run with no internet connection required.

---

**Version:** 1.1.0  
**Author:** Abdul Mannan  
**Contact:** kingusecurity@gmail.com  
**GitHub:** https://github.com/kingusecurity/kingsec
