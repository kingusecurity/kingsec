# KingSec v1.1.0 Quick Start Guide

Zero to first assessment in under 15 minutes.

Author: Abdul Mannan  
Contact: kingusecurity@gmail.com  
GitHub: https://github.com/kingusecurity/kingsec

---

## Prerequisites

- Docker 24.0+ installed and running
- A modern web browser (Chrome 120+, Firefox 120+, Edge 120+)
- Network connectivity to pull the KingSec Docker image
- At least 4 GB of available RAM

---

## Step 1: Quick Install (Docker)

Open a terminal and run the following commands.

Pull the image:

    docker pull kingusecurity/kingsec:1.1.0

Create data directories:

    mkdir -p /opt/kingsec/data
    mkdir -p /opt/kingsec/logs
    mkdir -p /opt/kingsec/reports

Start KingSec:

    docker run -d \
      --name kingsec \
      --restart unless-stopped \
      -p 127.0.0.1:8765:8765 \
      -v /opt/kingsec/data:/app/data \
      -v /opt/kingsec/logs:/app/logs \
      -v /opt/kingsec/reports:/app/reports \
      kingusecurity/kingsec:1.1.0

Confirm the container is running:

    docker ps --filter name=kingsec

---

## Step 2: Login / Register First Admin

1. Open your browser and navigate to http://127.0.0.1:8765
2. Click the "Register" link below the login form
3. Enter the following details:
   - Username: admin
   - Email: admin@example.com
   - Password: Choose a strong password (minimum 12 characters with uppercase, lowercase, digit, and special character)
4. Click "Register"
5. You are automatically logged in and assigned the ADMIN role

---

## Step 3: Choose an Assessment Profile

1. From the left sidebar, click "Assessments"
2. Click the "New Assessment" button
3. Select a profile from the list:

   - Quick Host Scan: Basic port and service discovery (fastest, ~2 minutes)
   - Network Assessment: Full network sweep with Nmap
   - Web Application Scan: Web vulnerability scanning with Nuclei and Nikto
   - API Assessment: API endpoint discovery and fuzzing
   - Source Code Review: Static analysis with Semgrep
   - Container Assessment: Container image scanning with Trivy
   - External Footprint: External reconnaissance with Amass
   - Full Assessment: All scanners combined (longest runtime)

4. For this quick start, select "Quick Host Scan"

---

## Step 4: Run an Assessment

1. Enter a target. For a quick test, use a local target such as 127.0.0.1 or scanme.nmap.org
2. Review the scan settings (defaults are pre-configured for the chosen profile)
3. Click "Launch Assessment"
4. The assessment status changes to "Running"
5. Live progress is displayed, including discovered hosts and open ports
6. When complete, the status changes to "Completed" (typically 2-5 minutes for Quick Host Scan)

---

## Step 5: View Results

1. Click on the completed assessment in the list
2. The Findings tab displays all discovered issues, organized by severity:

   - Critical: Red badge
   - High: Orange badge
   - Medium: Yellow badge
   - Low: Green badge
   - Info: Gray badge

3. Click any finding to view details including description, remediation advice, and raw scanner output
4. Use filters on the right panel to narrow results by severity, scanner, or status

---

## Step 6: Generate a Report

1. From the assessment detail page, click "Generate Report"
2. Select the report format:

   - JSON: Machine-readable, ideal for SIEM ingestion
   - HTML: Human-readable with charts and severity breakdown
   - PDF: Printable, suitable for stakeholder distribution
   - CSV: Spreadsheet-compatible for further analysis
   - Markdown: Lightweight, version-control friendly

3. Click "Generate"
4. Once generated, click "Download" to save the report
5. The report is also available from the Reports page in the sidebar

---

## Step 7: Next Steps

Now that you have completed your first assessment, explore the following:

- Review the full USER_GUIDE.md for detailed feature walkthroughs
- Set up Multi-Factor Authentication in Settings > Security
- Create additional users and assign roles (see ADMIN_GUIDE.md)
- Configure API keys for automated scanning pipelines
- Install additional scanners (Nuclei, Nmap, Trivy) for deeper assessments
- Schedule recurring assessments in Settings > Schedules
- Connect KingSec to your notification channels (Slack, email, webhook)

---

## Quick Reference

| Task                            | Command / Action                                    |
|---------------------------------|-----------------------------------------------------|
| Start KingSec (Docker)          | docker start kingsec                                |
| Stop KingSec (Docker)           | docker stop kingsec                                 |
| View logs                       | docker logs kingsec -f                              |
| Access web UI                   | http://127.0.0.1:8765                               |
| Health check                    | curl http://127.0.0.1:8765/api/health               |
| Version info                    | curl http://127.0.0.1:8765/api/version              |
| Default admin port              | 127.0.0.1:8765                                      |
| Database location               | /opt/kingsec/data/kingsec.db                        |
| Report output directory         | /opt/kingsec/reports/                               |

---

## Getting Help

- Full documentation: See INSTALL.md, USER_GUIDE.md, and ADMIN_GUIDE.md
- GitHub Issues: https://github.com/kingusecurity/kingsec/issues
- Email support: kingusecurity@gmail.com
