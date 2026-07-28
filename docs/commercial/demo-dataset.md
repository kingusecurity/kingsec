# KingSec Demo Dataset

**Version:** 1.0  
**Last Updated:** 2026-07-27

## Scenario: Acme Innovations

### Company Profile
- **Name:** Acme Innovations Inc.
- **Industry:** Technology / SaaS
- **Size:** 25 employees
- **Infrastructure:** Small business with web application, internal servers, and cloud-hosted API
- **Goal:** Demonstrate KingSec's ability to assess a realistic small business environment

### Assets

| Asset | Type | Purpose | Target Type |
|-------|------|---------|-------------|
| `web.acmeinnovations.com` | Web server | Public-facing company website and customer portal | URL |
| `api.acmeinnovations.com` | API endpoint | REST API for mobile app backend | URL |
| `mail.acmeinnovations.com` | Mail server | Internal email and communication | Hostname |
| `10.0.1.50` | Internal host | File server and internal tools | IP Address |
| `10.0.1.0/24` | Internal network | Office LAN | Network |

---

## Assessment Workflow

### Step 1: External Footprint Assessment

**Profile:** External Footprint  
**Target:** `acmeinnovations.com` (hostname)

**Purpose:** Discover exposed subdomains and services

**Expected results:**
- Subdomains discovered: web, api, mail, dev, admin
- Open ports on web.acmeinnovations.com: 80, 443, 8080
- Open ports on mail.acmeinnovations.com: 25, 143, 993

**Duration:** ~20 minutes

---

### Step 2: Web Application Scan

**Profile:** Web Application Scan  
**Target:** `https://web.acmeinnovations.com`

**Purpose:** Full web application security assessment

**Expected results:**

| Severity | Count | Example Findings |
|----------|-------|------------------|
| CRITICAL | 1 | SQL injection in login form parameter |
| HIGH | 3 | XSS in search field, missing CSP headers, outdated jQuery library |
| MEDIUM | 5 | Insecure cookies (no HttpOnly flag), missing X-Frame-Options, directory listing enabled on /assets, verbose error messages, missing rate limiting on login |
| LOW | 8 | Informational headers leaking server version, missing security.txt, non-HTTPS redirect on port 80 |

**Duration:** ~60 minutes

---

### Step 3: API Assessment

**Profile:** API Assessment  
**Target:** `https://api.acmeinnovations.com`

**Purpose:** REST API security testing

**Expected results:**

| Severity | Count | Example Findings |
|----------|-------|------------------|
| HIGH | 2 | No authentication on /api/v1/users endpoint, JWT token not validated on /api/v1/admin |
| MEDIUM | 3 | Rate limiting not enforced on /api/v1/login, verbose error messages exposing stack traces, CORS misconfigured allowing any origin |
| LOW | 4 | No API versioning header, missing rate limit headers, no content-type validation, informational comments in API responses |

**Duration:** ~45 minutes

---

### Step 4: Network Assessment

**Profile:** Network Assessment  
**Target:** `10.0.1.0/24`

**Purpose:** Internal network vulnerability scanning

**Expected results:**

| Host | Open Ports | Findings |
|------|------------|----------|
| `10.0.1.1` (Gateway) | — | Default credentials not changed |
| `10.0.1.50` (File Server) | 445, 139, 135 | SMBv1 enabled, null session allowed |
| `10.0.1.100-120` (Workstations) | Various | Missing security patches, outdated software |

**Duration:** ~30 minutes

---

### Step 5: Full Assessment

**Profile:** Full Assessment  
**Target:** `https://web.acmeinnovations.com`

**Purpose:** Maximum coverage assessment

**Expected results:** Combined results from all applicable scanners

**Duration:** ~90 minutes

---

## Report Examples

### Executive Summary (Quick Host Scan)

```
Target: 10.0.1.50
Assessment: Quick Host Scan
Date: 2026-07-27
Executive Score: 62/100 (Fair)

Summary:
The internal file server at 10.0.1.50 shows moderate security
risk. Outdated SMBv1 protocol exposes the host to potential
EternalBlue-style attacks. Default credentials on the gateway
router increase the risk of lateral movement. Immediate attention
recommended for the SMBv1 deprecation.
```

### Findings Summary

| Severity | Count | Top Priority |
|----------|-------|--------------|
| CRITICAL | 0 | — |
| HIGH | 3 | SMBv1 enabled; Default gateway credentials; Missing security patches |
| MEDIUM | 5 | Insecure cookies; Missing security headers; Directory listing; Verbose errors; No rate limiting |
| LOW | 8 | Information leakage; Outdated software banners; Missing security.txt |

---

## Demo Script for Sales

### Setup (5 minutes)
1. Start KingSec: `docker run -d --name kingsec -p 8765:8765 kingsec:1.1.0`
2. Open browser to http://127.0.0.1:8765
3. Register admin account
4. Show Dashboard (will be empty — explain this is a fresh install)

### Assessment (15 minutes)
1. Create assessment with "Quick Host Scan" profile
2. Target: `scanme.nmap.org` (a legal test target)
3. Run the assessment
4. Show live progress panel with scanner status cards
5. Wait for completion

### Review (5 minutes)
1. Open Findings page, show severity breakdown
2. Generate report (HTML format)
3. Open Report Center, preview the report
4. Download the PDF

### Administration (5 minutes)
1. Show Scanner Health page
2. Show Admin Users page
3. Show Audit Log
