# KingSec v1.1.0 — Home

---

## Hero Section

**Headline:** Your Infrastructure. Your Data. Your AI.

**Subheadline:** KingSec is a local-first, AI-augmented attack surface management and vulnerability prioritization platform designed for small and medium businesses. Run it on your own hardware, bring your own AI key, and keep your findings private by default.

**CTA:** `docker run -p 127.0.0.1:8765:8765 kingusecurity/kingsec`

---

## Problem / Solution

**The Problem**

SMBs face the same threat landscape as large enterprises but lack the security teams, tooling budgets, and time to manage it. Existing solutions are either SaaS-only (sending your scan data to a third party), prohibitively expensive, or require significant manual orchestration across dozens of standalone tools.

**The Solution**

KingSec unifies six industry-standard security scanners under a single, local-first platform with a built-in React frontend. It runs entirely on your machine — no telemetry, no cloud dependency, no data leaving your network. AI enrichment is optional, bring-your-own-key, and fully transparent. You get actionable, prioritized findings without the overhead of an enterprise-grade SOC.

**What it doesn't do:** KingSec performs unauthenticated external assessment. It examines what's reachable without logging in — it has no mechanism to authenticate to your application, so anything behind a login screen is out of scope. A clean result tells you nothing about what's behind authentication.

---

## Key Features

- **Local-first & private** — All scanning, processing, and storage happens on your infrastructure. No data is sent to external services unless you explicitly configure an AI provider with your own key.
- **Six scanners, one interface** — Nmap, Nuclei, Nikto, FFUF, Gobuster, and OWASP ZAP are orchestrated through a unified assessment engine. Results are correlated and deduplicated automatically.
- **AI-enriched findings** — Connect your own OpenAI, Anthropic, or compatible API key to receive natural-language remediation guidance, severity explanations, and context-aware recommendations. The AI augments — it never replaces — the scanner results.
- **Role-based access control** — JWT-authenticated with RBAC and optional MFA/TOTP. Users, teams, and permissions are managed through the Settings panel.
- **Six assessment profiles** — From a five-minute Quick Host Scan to a 90-minute Full Assessment, pre-configured profiles match common workflows so you don't need to build a scan from scratch.
- **HTML and PDF reporting** — Reports are available on demand or scheduled.

---

## Scanner Framework

KingSec ships with a plugin-based scanner architecture. Each scanner runs as an isolated process; results are parsed, normalized, and merged into a unified findings database. Scanners are added via a documented plugin interface, independent of the orchestration core.

| Scanner | Category | Typical Use |
|---|---|---|
| Nmap | Network discovery | Host and port enumeration |
| Nuclei | Vulnerability scanning | Template-based vulnerability detection |
| Nikto | Web server scanning | Web server misconfiguration and known issues |
| FFUF | Web fuzzing | Directory and parameter discovery |
| Gobuster | Directory/ DNS busting | Subdomain and path enumeration |
| OWASP ZAP | Web application | Active and passive web application scanning |

Trivy, Semgrep, and Amass are also built as scanner plugins in the codebase, but none of the six assessment profiles currently schedule them — they're not part of a live assessment today.

---

## Call to Action

Ready to run your first assessment?

```
docker pull kingusecurity/kingsec
docker run -p 127.0.0.1:8765:8765 kingusecurity/kingsec
```

Then open `http://127.0.0.1:8765` in your browser.

**Version:** 1.1.0  
**Author:** Abdul Mannan  
**Contact:** kingusecurity@gmail.com  
**GitHub:** https://github.com/kingusecurity/kingsec
