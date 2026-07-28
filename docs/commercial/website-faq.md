# KingSec v1.1.0 — Frequently Asked Questions (Website Edition)

---

### 1. What is KingSec?

KingSec is a local-first, AI-augmented attack surface management (ASM) and vulnerability prioritization platform for small and medium businesses. It orchestrates nine security scanners under a single interface, runs on your own infrastructure, and keeps your data private by default.

---

### 2. What does "local-first" mean?

It means all scanning, processing, and data storage happens on your machine. KingSec does not send your scan data, network topology, or findings to any external service. The only exception is optional AI enrichment, which sends only finding metadata to an AI provider of your choice using your own API key.

---

### 3. How is this different from SaaS vulnerability scanners?

SaaS scanners require you to upload your scan targets and findings to a third-party cloud. KingSec runs entirely on your hardware. You control the data, the schedule, and the AI integration. There is no per-asset license fee, no data residency concern, and no internet requirement for core functionality.

---

### 4. Do I need an internet connection?

Core scanning and assessment management work fully offline. You only need internet access to download the Docker image or pip package, and optionally to use AI enrichment (if configured).

---

### 5. Which scanners are included?

Nine scanners are bundled: Nmap, Nuclei, Nikto, FFUF, Gobuster, Trivy, Semgrep, Amass, and OWASP ZAP. All are pre-configured and ready to use.

---

### 6. Can I add my own scanners?

The Enterprise tier supports custom scanner plugins. The scanner framework is plugin-based, so custom scanners can be integrated using the documented plugin interface. For Free and Professional tiers, the nine bundled scanners are available.

---

### 7. How does the AI enrichment work?

You provide your own API key from OpenAI, Anthropic, or a compatible provider. When findings are generated, you can optionally request AI-powered analysis, which includes remediation guidance, severity explanation, and context-aware recommendations. Only finding title, severity, and relevant evidence snippets are sent to the AI provider.

---

### 8. Is my data sent to the AI provider if I don't enable AI?

No. AI enrichment is off by default. No data is sent to any third party unless you explicitly configure an AI provider and enable enrichment.

---

### 9. What authentication options are available?

KingSec supports JWT-based authentication with configurable token expiration. Role-based access control (RBAC) with Admin, Analyst, and Viewer roles is available in the Professional and Enterprise tiers. MFA via TOTP is supported across all tiers.

---

### 10. What reporting formats are supported?

JSON, HTML, PDF, CSV, and Markdown. Reports can be generated on demand or on a schedule. HTML and Markdown templates can be customized.

---

### 11. What are the assessment profiles?

Eight pre-configured profiles: Quick Host Scan (~5 min), Network Assessment (~30 min), Web Application Scan (~60 min), API Assessment (~45 min), Source Code Review (~15 min), Container Assessment (~10 min), External Footprint (~20 min), and Full Assessment (~90 min).

---

### 12. Can I schedule assessments?

Yes. The Professional tier supports unlimited scheduled assessments. The Free tier supports up to five scheduled assessments.

---

### 13. What are the system requirements?

Linux x86_64 or arm64, 4 GB RAM (8 GB recommended), 10 GB disk, and either Docker Engine 20.10+ or Python 3.9–3.12.

---

### 14. How do I get support?

For bug reports and feature requests, use the GitHub issue tracker at https://github.com/kingusecurity/kingsec/issues. For direct inquiries, email kingusecurity@gmail.com.

---

### 15. Is KingSec free?

The Free tier is fully functional with all nine scanners, all eight assessment profiles, and unlimited local storage. Paid tiers add RBAC, teams, additional scheduled assessments, custom plugins, and priority support. The software has no trial period or time limits on the Free tier.

---

**Version:** 1.1.0  
**Author:** Abdul Mannan  
**Contact:** kingusecurity@gmail.com  
**GitHub:** https://github.com/kingusecurity/kingsec
