# KingSec v1.1.0 — Frequently Asked Questions (Website Edition)

---

### 1. What is KingSec?

KingSec is a local-first, AI-augmented attack surface management (ASM) and vulnerability prioritization platform for small and medium businesses. It orchestrates six security scanners under a single interface, runs on your own infrastructure, and keeps your data private by default.

---

### 2. What does KingSec actually assess?

KingSec performs **unauthenticated** external assessment. It examines what's reachable without logging in — open ports and services, missing security headers, outdated software, and application-layer issues an unauthenticated visitor could find. It has no mechanism to log in to your application, so anything that only exists behind authentication — business-logic flaws, authorization bugs between roles, anything reachable only once signed in — is out of scope for every assessment, at every tier. A clean report means no unauthenticated issues were found; it does not mean your application has no vulnerabilities behind its login screen.

---

### 3. What does "local-first" mean?

Assessment data never leaves your machine unless you configure an integration. Findings and reports are stored in a local SQLite database protected by your filesystem's own permissions — not separately encrypted (one configuration value, your AI provider API key, is encrypted at rest; everything else relies on filesystem access control). The only network traffic KingSec sends on its own is optional AI enrichment, which sends finding data (title, severity, description, and evidence snippets — redacted before sending) to an AI provider of your choice using your own API key.

---

### 4. How is this different from SaaS vulnerability scanners?

SaaS scanners require you to upload your scan targets and findings to a third-party cloud. KingSec runs entirely on your hardware. You control the data, the schedule, and the AI integration. There is no per-asset license fee, no data residency concern, and no internet requirement for core functionality.

---

### 5. Do I need an internet connection?

Core scanning and assessment management work fully offline. You only need internet access to download the Docker image or pip package, and optionally to use AI enrichment (if configured).

---

### 6. Which scanners are included?

Six scanners are bundled and reachable through every assessment profile: Nmap, Nuclei, Nikto, FFUF, Gobuster, and OWASP ZAP. All are pre-configured and ready to use. (Trivy, Semgrep, and Amass exist in the codebase as registered plugins but aren't wired into any current assessment profile — they're not part of a live assessment today.)

---

### 7. Can I add my own scanners?

The scanner framework is plugin-based, and the Enterprise tier includes custom scanner plugin integration through our services team — this is a code-level integration (implementing our scanner plugin interface), not a self-serve UI toggle. For Free and Professional tiers, the six bundled scanners are available.

---

### 8. How does the AI enrichment work?

You provide your own API key from OpenAI, Anthropic, or a compatible provider. When findings are generated, you can optionally request AI-powered analysis, which includes remediation guidance, severity explanation, and context-aware recommendations. Finding title, severity, description, and evidence snippets are sent to the AI provider, redacted before sending.

---

### 9. Is my data sent to the AI provider if I don't enable AI?

No. AI enrichment is off by default. No data is sent to any third party unless you explicitly configure an AI provider and enable enrichment.

---

### 10. What authentication options are available?

KingSec supports JWT-based authentication with configurable token expiration. Role-based access control (RBAC) with Admin, Analyst, and Viewer roles is available in the Professional and Enterprise tiers. MFA via TOTP is supported across all tiers.

---

### 11. What reporting formats are supported?

HTML and PDF.

---

### 12. What are the assessment profiles?

Six pre-configured profiles: Quick Host Scan (~5 min), Network Assessment (~30 min), Web Application Scan (~60 min), API Assessment (~45 min), External Footprint (~20 min), and Full Assessment (~90 min).

---

### 13. Can I schedule assessments?

Yes. The Professional tier supports unlimited scheduled assessments. The Free tier supports up to five scheduled assessments.

---

### 14. What are the system requirements?

Linux x86_64 or arm64, 4 GB RAM (8 GB recommended), 10 GB disk, and either Docker Engine 20.10+ or Python 3.9–3.12.

---

### 15. How do I get support?

For bug reports and feature requests, use the GitHub issue tracker at https://github.com/kingusecurity/kingsec/issues. For direct inquiries, email kingusecurity@gmail.com.

---

### 16. Is KingSec free?

The Free tier is fully functional with all six scanners, all six assessment profiles, and unlimited local storage. Paid tiers add RBAC, teams, additional scheduled assessments, custom scanner plugin integration, and priority support. The software has no trial period or time limits on the Free tier.

---

**Version:** 1.1.0  
**Author:** Abdul Mannan  
**Contact:** kingusecurity@gmail.com  
**GitHub:** https://github.com/kingusecurity/kingsec
