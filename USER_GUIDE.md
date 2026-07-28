# KingSec v1.1.0 User Guide

Author: Abdul Mannan  
Contact: kingusecurity@gmail.com  
GitHub: https://github.com/kingusecurity/kingsec

---

## Introduction to KingSec

KingSec is a local-first, AI-augmented Attack Surface Management (ASM) and Vulnerability Management (VM) platform. It consolidates multiple open-source security scanners into a unified interface, automates assessment workflows, and provides actionable reporting.

### Key Capabilities

- Unified scanning orchestration across 9 pluggable scanners
- Pre-configured assessment profiles for common use cases
- Severity-based finding management with AI-assisted prioritization
- Multi-format report generation (JSON, HTML, PDF, CSV, Markdown)
- Role-based access control with ADMIN, ANALYST, and VIEWER roles
- API-first design for CI/CD pipeline integration
- REST API with React single-page application frontend

### Architecture Overview

KingSec runs as a REST API server bound to 127.0.0.1:8765 by default. The React frontend is served from the same endpoint. All data is stored locally in a SQLite database. Scanners execute on the host machine or via Docker, and results are collected and correlated by the KingSec engine.

---

## Logging In and Authentication

### First-Time Login

1. Navigate to http://127.0.0.1:8765 in your browser
2. Enter your username and password
3. Click "Login"
4. If this is your first time, click "Register" to create an account
5. The first registered user is automatically granted the ADMIN role

### Password Authentication

- Passwords must be at least 12 characters
- Must contain uppercase, lowercase, digit, and special character
- Passwords are hashed using bcrypt before storage
- Session tokens use JWT with a configurable expiry (default: 60 minutes)
- Idle sessions expire after the JWT token lifetime

### Multi-Factor Authentication (MFA / TOTP)

MFA adds a second layer of security using time-based one-time passwords.

**Enabling MFA:**

1. Log in to KingSec
2. Navigate to Settings > Security
3. Click "Enable MFA"
4. Scan the QR code with your authenticator app (Google Authenticator, Authy, or any TOTP-compatible app)
5. Enter the 6-digit code from your authenticator app
6. Click "Verify and Enable"
7. Download or copy the recovery codes shown. Store them securely.

**Logging In with MFA:**

1. Enter your username and password as usual
2. When prompted, enter the 6-digit code from your authenticator app
3. Click "Verify"
4. If you lose access to your authenticator app, use a recovery code

**Disabling MFA:**

1. Navigate to Settings > Security
2. Click "Disable MFA"
3. Enter your current TOTP code or a recovery code
4. Confirm the action

---

## Dashboard Overview

The Dashboard is the home page after login. It provides a high-level summary of your security posture.

### Widgets

- Total Assessments: Count of all assessments run
- Open Findings: Total unresolved findings by severity
- Scanner Status: Health indicators for each installed scanner
- Recent Activity: Chronological log of recent assessments and findings
- Severity Breakdown: Pie chart showing distribution of finding severity levels
- Trends Over Time: Line chart of findings discovered per day

### Interacting with the Dashboard

- Click any severity segment in the pie chart to navigate to filtered findings
- Click an activity entry to open the related assessment
- Hover over trend chart points for daily counts

---

## Creating and Running Assessments

### Assessment Profiles

KingSec includes 8 pre-configured assessment profiles. Each profile enables a specific set of scanners optimized for a particular assessment type.

| Profile                   | Scanners Used                        | Typical Duration |
|---------------------------|--------------------------------------|------------------|
| Quick Host Scan           | Nmap                                 | 2-5 minutes      |
| Network Assessment        | Nmap, Nuclei                         | 10-30 minutes    |
| Web Application Scan      | Nuclei, Nikto, FFUF                  | 15-60 minutes    |
| API Assessment            | FFUF, Nuclei                         | 10-30 minutes    |
| Source Code Review        | Semgrep                              | 5-20 minutes     |
| Container Assessment      | Trivy                                | 5-15 minutes     |
| External Footprint        | Amass, Nmap                          | 20-60 minutes    |
| Full Assessment           | All available scanners               | 30-120 minutes   |

### Creating an Assessment

1. Click "Assessments" in the left sidebar
2. Click "New Assessment"
3. Configure the assessment:

   - Name: A descriptive label (e.g., "Q3 Internal Network Scan")
   - Profile: Select from the 8 profiles
   - Target: IP address, CIDR range, domain name, or URL
   - Scanner Options: (Optional) Override default scanner arguments
   - Schedule: (Optional) Set a recurring schedule

4. Click "Launch Assessment"

### Running and Monitoring

- The assessment detail page shows real-time progress
- Each scanner phase updates as it completes
- Findings appear incrementally as scanners report results
- Use the "Stop" button to abort a running assessment

### Assessment States

- Pending: Queued and waiting for a scanner to become available
- Running: Scanners are actively executing
- Completed: All scanners finished successfully
- Failed: One or more scanners encountered an error
- Stopped: Manually stopped by a user

---

## Viewing Findings and Severity

### Findings List

After an assessment completes, findings are organized in a table:

- Severity: Color-coded badge (Critical, High, Medium, Low, Info)
- Scanner: Which scanner discovered the finding
- Target: The affected host or URL
- Port: The affected port (if applicable)
- CVSS Score: CVSS v3.1 score (if available)
- Status: Open, Acknowledged, In Progress, Remediated, False Positive

### Severity Levels

| Severity | Color  | Description                                    |
|----------|--------|------------------------------------------------|
| Critical | Red    | Remote code execution, authentication bypass   |
| High     | Orange| SQL injection, XSS, privilege escalation        |
| Medium   | Yellow | Information disclosure, misconfigurations       |
| Low      | Green  | Software version disclosure, weak cookie settings|
| Info     | Gray   | Open port, service detection, banner grab       |

### Finding Detail View

Click any finding to open the detail panel, which includes:

- Full description of the vulnerability
- Affected target and port
- CVSS vector string and score
- Proof-of-concept output from the scanner
- Remediation steps and references
- Custom notes (editable by ANALYST and ADMIN roles)
- Status management buttons

### Filtering and Searching

- Filter by severity using the multi-select dropdown
- Filter by scanner using the scanner checkboxes
- Filter by status (Open, Acknowledged, etc.)
- Search by keyword across finding titles and descriptions
- Sort by severity, date, or CVSS score

---

## Generating and Downloading Reports

### Report Generation

1. Navigate to an assessment detail page
2. Click "Generate Report"
3. Choose a format:

   - JSON: Full structured data for programmatic consumption
   - HTML: Interactive report with charts and filtering
   - PDF: Formatted document suitable for distribution
   - CSV: Tabular data for spreadsheets
   - Markdown: Plain text for documentation or version control

4. (Optional) Select severity filters to include only specific levels
5. Click "Generate"

### Downloading Reports

1. Navigate to "Reports" in the left sidebar
2. All generated reports are listed with filename, format, and generation date
3. Click the download icon for the desired report
4. The report is saved to your browser's default download location

### Report Contents

Each report includes:

- Assessment name, profile, and target
- Scanner summary (which scanners ran, duration per scanner)
- Finding count by severity
- Full finding details with descriptions and remediation
- Charts and visualizations (HTML and PDF formats only)
- Generation timestamp and KingSec version

---

## Managing API Keys

API keys allow programmatic access to KingSec for CI/CD integration and automation.

### Creating an API Key

1. Navigate to Settings > API Keys
2. Click "Create API Key"
3. Enter a descriptive name (e.g., "CI/CD Pipeline Key")
4. Select the role permission for this key:

   - ADMIN: Full access to all endpoints
   - ANALYST: Create assessments, view findings, generate reports
   - VIEWER: Read-only access

5. (Optional) Set an expiration date
6. Click "Create"
7. Copy the API key immediately. It is shown only once.

### Using an API Key

Include the key in the Authorization header:

    Authorization: Bearer <your-api-key>

Example using curl:

    curl -H "Authorization: Bearer ks_api_abc123def456" \
      http://127.0.0.1:8765/api/v1/assessments

### Revoking an API Key

1. Navigate to Settings > API Keys
2. Find the key in the list
3. Click "Revoke"
4. Confirm the action
5. The key is immediately invalidated

---

## Profile Management

### Changing Your Password

1. Navigate to Settings > Profile
2. Enter your current password
3. Enter your new password
4. Confirm the new password
5. Click "Update Password"
6. You will be redirected to the login page to authenticate with your new password

### Managing MFA

See the "Multi-Factor Authentication (MFA / TOTP)" section above for setup and teardown instructions.

### Profile Information

- Update your display name and email address from the Profile page
- Changes to email address may require re-verification depending on system settings

---

## Notifications

KingSec can send notifications for assessment completion, new critical findings, and scanner failures.

### Configuring Notification Channels

1. Navigate to Settings > Notifications
2. Choose one or more channels:

   - Email: Requires SMTP configuration by an administrator
   - Slack: Enter a Slack webhook URL
   - Webhook: Enter a custom HTTP endpoint

3. Test the channel by clicking "Send Test"
4. Toggle which events trigger notifications:

   - Assessment completed
   - Critical finding discovered
   - Scanner failure
   - User login from new device
   - API key created or revoked

### Notification Preferences

- Set quiet hours to suppress notifications during off-hours
- Choose notification severity threshold (e.g., only Critical and High)
- Each user can have independent notification preferences

---

## Best Practices

### Assessment Planning

- Schedule Full Assessment profiles during maintenance windows
- Use Quick Host Scan for daily health checks
- Run Web Application Scan after every deployment
- Perform External Footprint assessments monthly
- Document assessment scope and targets in the assessment description

### Finding Management

- Acknowledge findings within 24 hours of discovery
- Assign remediation SLA based on severity:
  - Critical: 24 hours
  - High: 72 hours
  - Medium: 7 days
  - Low: 30 days
- Mark findings as False Positive only after manual verification
- Add notes to findings to document remediation steps taken

### Report Usage

- Share HTML reports with development teams for actionable insights
- Export PDF reports for compliance and audit requirements
- Use JSON format for ingesting findings into SIEM platforms
- Archive CSV reports for historical trend analysis

### Security Hygiene

- Enable MFA on all accounts
- Rotate API keys every 90 days
- Review active sessions in Settings regularly
- Log out when leaving the workstation
- Report suspicious activity to the system administrator
