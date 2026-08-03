# Frequently Asked Questions

**Version:** 1.1.0

## General

### What is KingSec?
KingSec is a local-first, AI-augmented Attack Surface Management (ASM) and Vulnerability Management (VM) platform for small and mid-sized businesses. It runs on your own infrastructure, supports Bring-Your-Own-Key AI enrichment, and provides comprehensive security assessment capabilities through an extensible scanner orchestration framework.

### Who is KingSec for?
IT administrators, security analysts, penetration testers, and managed security service providers (MSSPs) who need a self-hosted vulnerability management solution without per-asset licensing or cloud dependency.

### Is KingSec free?
KingSec is a commercial product. A free tier with limited assessments is available. See the pricing page for full details.

### Does KingSec require an internet connection?
No. KingSec runs entirely on your local machine or network. Scanner tool updates (e.g., Nuclei templates, Trivy vulnerability DB) require internet, but the core platform is fully offline-capable.

### How is KingSec different from cloud-based ASM platforms?
KingSec is local-first and private. Your scan data never leaves your infrastructure. There are no per-asset fees, no data uploads to third-party clouds, and no vendor lock-in.

## Installation

### What are the minimum system requirements?
- 2 CPU cores, 4 GB RAM, 10 GB free disk
- Python 3.11 or later
- Docker (optional, recommended) or pip

### Which scanners are included?
KingSec supports 9 scanners: Nmap, Nuclei, Nikto, FFUF, Gobuster, Trivy, Semgrep, Amass, and OWASP ZAP. Scanners are auto-detected at runtime. Missing scanners are simply skipped.

### Can I run KingSec on Windows?
Yes. KingSec supports Windows, Linux, and macOS. The Docker installation is identical on all platforms. Direct pip installation also works on Windows.

### How do I update KingSec?
```bash
docker pull kingsec:1.1.0
docker stop kingsec
docker rm kingsec
docker run -d --name kingsec ... kingsec:1.1.0
```

## Usage

### How do I create my first assessment?
Register an account, choose an assessment profile (e.g., Quick Host Scan), provide a target, and start the scan. The results appear in the Findings page when complete.

### What is an assessment profile?
A pre-configured scanner selection optimized for specific assessment types. For example, "Web Application Scan" runs Nmap, Gobuster, FFUF, Nuclei, and ZAP against web targets.

### How long do assessments take?
Quick Host Scan: ~5 minutes. Full Assessment: ~90 minutes. Duration depends on target responsiveness, scanner count, and system resources.

### Can I cancel a running assessment?
Yes. Use the Cancel button in the Assessment Detail page or the POST /assessments/{id}/cancel API endpoint.

### How are findings categorized?
Findings use standard severity levels: CRITICAL, HIGH, MEDIUM, LOW, and INFORMATIONAL. Status tracking includes OPEN, IN_PROGRESS, RESOLVED, and FALSE_POSITIVE.

## Reports

### What report formats are available?
JSON, HTML, PDF, CSV, and Markdown. HTML and PDF are best for client delivery. JSON and CSV are ideal for programmatic consumption.

### What is the executive score?
A 0-100 score summarizing overall security posture. 80-100 is Good, 60-79 is Fair, 40-59 is Poor, 0-39 is Critical.

### Can I regenerate a report?
Yes. The Report Center provides a Regenerate button, or use the POST /api/v1/assessments/{id}/report endpoint.

## Security

### How are passwords stored?
Argon2 password hashing with recommended parameters. Argon2 is memory-hard and resistant to GPU-based attacks.

### Does KingSec support multi-factor authentication?
Yes. TOTP-based MFA is supported with recovery codes.

### Is API traffic encrypted?
KingSec supports HTTPS when configured behind a reverse proxy. By default, it binds to 127.0.0.1 (localhost only).

### How are secrets managed?
AI API keys and encryption keys are stored encrypted at rest using Fernet symmetric encryption.

## Troubleshooting

### The scanner health shows 0% — what's wrong?
No scanners are installed or detected. Install at least one scanner binary (e.g., Nmap) and restart KingSec. The scanner discovery runs on startup and periodically.

### I get "401 Unauthorized" on API calls
Your token may be expired. Log in again to obtain a fresh token. Check that the Authorization header uses the format "Bearer {token}".

### The database needs migration — what do I do?
Run `alembic upgrade head` from the project root, or `kingsec-migrate` if installed via pip.

## Support

### How do I get help?
Email kingusecurity@gmail.com. Check INSTALL.md and TROUBLESHOOTING.md for common issues.

### How do I report a bug?
Open an issue on GitHub or email kingusecurity@gmail.com. Include the version number, steps to reproduce, and relevant log output.

### How do I request a feature?
Feature requests are welcome via GitHub issues or email. Check the ROADMAP.md for planned features.
