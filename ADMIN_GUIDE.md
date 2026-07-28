# KingSec v1.1.0 Administrator Guide

Author: Abdul Mannan  
Contact: kingusecurity@gmail.com  
GitHub: https://github.com/kingusecurity/kingsec

---

## User Management

### Creating a New User

1. Log in with an ADMIN account
2. Navigate to Admin > Users
3. Click "Create User"
4. Fill in the following fields:

   - Username: Must be unique, 3-32 alphanumeric characters
   - Email: Valid email address, used for notifications
   - Password: Minimum 12 characters with complexity requirements
   - Role: Select ADMIN, ANALYST, or VIEWER

5. Click "Create"
6. The new user receives a welcome email (if SMTP is configured) with login instructions

### Deactivating a User

1. Navigate to Admin > Users
2. Find the user in the list
3. Click the "Deactivate" button
4. Confirm the action
5. Deactivated users cannot log in. Active sessions are invalidated within 60 seconds.
6. To reactivate, click "Activate" on the same user record

### Assigning Roles

1. Navigate to Admin > Users
2. Click the edit icon next to the target user
3. Select the new role from the dropdown:

   - ADMIN: Full system access, including user management and system settings
   - ANALYST: Create and run assessments, manage findings, generate reports
   - VIEWER: Read-only access to assessments, findings, and reports

4. Click "Save"
5. Role changes take effect immediately on next request

### Bulk User Operations

- Use the checkbox column to select multiple users
- Bulk actions: Activate, Deactivate, Change Role
- For large deployments, use the API for user provisioning automation

---

## Role-Based Access Control (RBAC)

### Role Permissions Matrix

| Feature                       | ADMIN | ANALYST | VIEWER |
|-------------------------------|-------|---------|--------|
| View Dashboard                | Yes   | Yes     | Yes    |
| View Assessments              | Yes   | Yes     | Yes    |
| Create / Run Assessments      | Yes   | Yes     | No     |
| Stop Assessments              | Yes   | Yes     | No     |
| View Findings                 | Yes   | Yes     | Yes    |
| Update Finding Status         | Yes   | Yes     | No     |
| Generate Reports              | Yes   | Yes     | Yes    |
| Manage API Keys (own)         | Yes   | Yes     | Yes    |
| Manage All API Keys           | Yes   | No      | No     |
| User Management               | Yes   | No      | No     |
| System Settings               | Yes   | No      | No     |
| Audit Log                     | Yes   | No      | No     |
| Scanner Health Monitoring     | Yes   | Yes     | No     |

### Best Practices for Role Assignment

- Assign ADMIN to the minimum number of users necessary
- Use ANALYST for day-to-day security operations staff
- Assign VIEWER to auditors, managers, and stakeholders
- Create dedicated service accounts with ANALYST role for CI/CD pipelines
- Review role assignments quarterly

---

## API Key Management for Automation

### Creating an API Key for Service Accounts

1. Navigate to Settings > API Keys
2. Click "Create API Key"
3. Provide a descriptive name (e.g., "Jenkins Pipeline - Production Scan")
4. Select the appropriate role:

   - Use ANALYST for pipeline integration
   - Use ADMIN only when full API access is required

5. Set an expiration date (recommended: 90 days maximum)
6. Click "Create"

### Managing Existing Keys

- View all API keys with creation date, last used timestamp, and expiry
- Revoke compromised keys immediately
- Rotate keys before expiration to avoid pipeline disruption
- The audit log records all API key usage

### Automation Examples

**Launch an assessment via API:**

    curl -X POST \
      -H "Authorization: Bearer ks_api_abc123def456" \
      -H "Content-Type: application/json" \
      -d '{
        "name": "Automated Nightly Scan",
        "profile": "quick_host_scan",
        "target": "10.0.0.0/24"
      }' \
      http://127.0.0.1:8765/api/v1/assessments

**Retrieve findings for a specific assessment:**

    curl -H "Authorization: Bearer ks_api_abc123def456" \
      http://127.0.0.1:8765/api/v1/assessments/<id>/findings

---

## Audit Log

### Accessing the Audit Log

1. Navigate to Admin > Audit Log
2. All significant system events are displayed in reverse chronological order

### Events Captured

- User login and logout (including failed login attempts)
- Account creation, deactivation, and role changes
- Assessment creation, launch, completion, and stop
- Finding status changes (Open, Acknowledged, Remediated, False Positive)
- Report generation and download
- API key creation, usage, and revocation
- System settings changes
- MFA enable and disable events
- Scanner health status changes

### Audit Log Retention

- Default retention: 365 days
- Configure retention period in Settings > System
- Audit logs are exported with system backups
- Use the search bar to filter events by user, action type, or date range

### Exporting the Audit Log

1. Click "Export" in the Audit Log page
2. Choose CSV or JSON format
3. The exported file includes all event fields: timestamp, user, action, target, IP address, user agent, and result

---

## System Settings and Configuration

### Accessing System Settings

Navigate to Admin > System Settings. The following configuration categories are available.

### General Settings

- Instance Name: Displayed in the browser title and email notifications
- Default Assessment Profile: Pre-selected profile when creating new assessments
- Session Timeout: JWT token expiry in minutes (default: 60)
- Max Concurrent Assessments: Limit parallel scans (default: 3)

### Scanner Settings

- Scanner Timeout: Maximum runtime per scanner (default: 1800 seconds)
- Scanner Retry Count: Number of retries on failure (default: 2)
- Custom Scanner Paths: Override scanner binary locations
- Scanner Resource Limits: CPU and memory limits for scanner containers

### Notification Settings

- SMTP Server: Hostname, port, username, password, and TLS settings
- From Address: Sender email for notifications
- Slack Webhook URL: Incoming webhook for Slack notifications
- Webhook Endpoints: Custom HTTP endpoints for event forwarding

### Database Settings

- Backup Schedule: Cron expression for automated backups
- Backup Retention: Number of backup files to retain (default: 30)
- Log Level: DEBUG, INFO, WARNING, ERROR (default: INFO)
- Audit Log Retention Days: How long to keep audit records (default: 365)

---

## Backup and Restore

### Automated Backup Configuration

1. Navigate to Admin > System Settings > Database
2. Enable "Automated Backups"
3. Set the schedule using cron syntax:

   - Daily at midnight: 0 0 * * *
   - Every 6 hours: 0 */6 * * *
   - Weekly on Sunday: 0 0 * * 0

4. Set retention count (number of backup files to keep)
5. Backup files are stored in /opt/kingsec/data/backups/
6. Click "Save"

### Manual Backup

To trigger an immediate backup from the web interface:

1. Navigate to Admin > Backups
2. Click "Create Backup Now"
3. The backup file is created and listed on the page

Alternatively, use the CLI:

    docker exec kingsec kingsec db backup --output /opt/kingsec/backups/manual-$(date +%Y%m%d).sqlite

### Restoring from Backup

1. Navigate to Admin > Backups
2. Select the backup file from the list
3. Click "Restore"
4. Confirm the action

**Warning:** Restoring a backup overwrites all current data. Ensure the KingSec service is not running any assessments during restore.

CLI restore:

    docker exec kingsec kingsec db restore --input /opt/kingsec/backups/<filename>.sqlite

### Backup Verification

Periodically verify backup integrity:

    docker exec kingsec kingsec db check --input /opt/kingsec/backups/<filename>.sqlite

---

## Monitor Scanner Health

### Scanner Health Dashboard

1. Navigate to Settings > Scanner Health
2. Each installed scanner is listed with:

   - Name and version (if detectable)
   - Status: Online, Offline, or Not Installed
   - Last checked timestamp
   - Last successful scan timestamp
   - Error count (last 24 hours)

### Scanner Status Interpretation

| Status        | Meaning                                               |
|---------------|-------------------------------------------------------|
| Online        | Scanner binary found and responsive                   |
| Offline       | Scanner binary found but not responding               |
| Not Installed | Scanner binary not found in system PATH               |

### Troubleshooting Scanner Issues

- Offline scanners: Restart the scanner or check for stuck processes
- Not Installed: Install the scanner and restart KingSec
- High error count: Review scanner logs from the detail page
- Path issues: Set custom scanner paths in System Settings > Scanner Settings

### Health Check Notifications

Configure alerts for scanner health changes:

1. Navigate to Settings > Notifications
2. Enable "Scanner Health Change" event
3. Configure notification channels (Email, Slack, Webhook)

---

## Production Deployment Checklist

### Before Going Live

- [ ] Deploy behind a reverse proxy (Nginx, Caddy, or HAProxy)
- [ ] Configure TLS/SSL certificate (Let's Encrypt or commercial CA)
- [ ] Set strong KINGSEC_SECRET_KEY and KINGSEC_JWT_SECRET environment variables
- [ ] Enable MFA for all ADMIN accounts
- [ ] Configure SMTP for email notifications
- [ ] Set up automated database backups
- [ ] Configure log shipping to a centralized log management system
- [ ] Install all required scanners for your assessment profiles
- [ ] Review and adjust scanner timeout settings for expected target sizes
- [ ] Configure firewall rules to restrict access to port 8765

### Reverse Proxy Configuration (Nginx Example)

    server {
        listen 443 ssl;
        server_name kingsec.example.com;

        ssl_certificate /etc/letsencrypt/live/kingsec.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/kingsec.example.com/privkey.pem;

        location / {
            proxy_pass http://127.0.0.1:8765;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 300s;
            proxy_send_timeout 300s;
        }

        location /api/ws {
            proxy_pass http://127.0.0.1:8765;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }

### Performance Tuning

- Increase max concurrent assessments for larger teams
- Set scanner resource limits to prevent host resource exhaustion
- Use SSD storage for the database volume
- Monitor memory usage during Full Assessment profiles
- Consider horizontal scaling for enterprise deployments

---

## Security Hardening Recommendations

### Network Security

- Bind KingSec to 127.0.0.1 and use a reverse proxy for external access
- Restrict API access to trusted IP ranges using firewall rules
- Enable rate limiting on the reverse proxy
- Use HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- Disable unused ports and services on the host

### Authentication Hardening

- Enforce MFA for all ADMIN accounts
- Set JWT expiry to 15-30 minutes for production environments
- Use long, random secrets for KINGSEC_SECRET_KEY and KINGSEC_JWT_SECRET
- Rotate secrets every 90 days
- Configure account lockout after 5 failed login attempts (Admin > System Settings)

### Data Protection

- Encrypt the database file at rest using filesystem-level encryption (LUKS, BitLocker)
- Use TLS 1.3 for the reverse proxy
- Mask sensitive data in audit logs (passwords, API keys)
- Sanitize scanner output before displaying findings
- Apply the principle of least privilege for all service accounts

### Docker Security

- Run KingSec as a non-root user inside the container
- Use read-only root filesystem for the container
- Limit container capabilities with --cap-drop=ALL
- Scan the KingSec image with Trivy before deployment
- Keep Docker and host OS up to date with security patches

### Ongoing Hardening

- Subscribe to KingSec GitHub releases for security advisories
- Review audit logs weekly for suspicious activity
- Conduct quarterly access reviews
- Update installed scanners to their latest versions
- Perform periodic penetration testing against the KingSec instance

---

## Troubleshooting Common Admin Tasks

### User Cannot Log In

1. Verify the account is active in Admin > Users
2. Check the audit log for failed login attempts
3. Reset the password from Admin > Users > Edit > Reset Password
4. If MFA is enabled and the user lost their device, disable MFA from Admin > Users and request re-setup

### Scanner Continuously Failing

1. Check scanner health in Settings > Scanner Health
2. Verify the scanner binary is installed: which <scanner-name>
3. Check scanner logs from the failure details
4. Increase scanner timeout in System Settings > Scanner Settings
5. Test the scanner manually on the command line
6. Restart KingSec after scanner reinstallation

### Database Migration Errors

1. Check disk space: df -h /opt/kingsec/data
2. Verify file permissions: ls -la /opt/kingsec/data/kingsec.db
3. Run integrity check: docker exec kingsec kingsec db check
4. Restore from the most recent backup
5. Contact support with the migration error log

### Performance Issues During Assessments

1. Reduce max concurrent assessments in System Settings
2. Reduce scanner timeout values
3. Allocate more CPU and RAM to the Docker container
4. Run resource-intensive scans (Full Assessment) during off-hours
5. Monitor host resource usage with htop or Task Manager
6. Consider upgrading host hardware

### Email Notifications Not Working

1. Verify SMTP settings in Admin > System Settings
2. Test SMTP connectivity from the KingSec host: nc -vz <smtp-host> 587
3. Check for TLS/SSL requirements from your email provider
4. Review KingSec logs for SMTP errors: docker logs kingsec
5. Check the spam folder for test emails

### Backup or Restore Failures

1. Ensure the backup directory exists and is writable
2. Check disk space on the backup volume
3. Verify the backup file is not corrupted
4. For restore, ensure no assessments are running
5. For large databases, increase the API timeout setting

### Upgrading KingSec

1. Back up the database before upgrading
2. Pull the new image: docker pull kingusecurity/kingsec:1.1.0
3. Stop the current container: docker stop kingsec
4. Remove the container: docker rm kingsec
5. Start with the new image using the same volume mounts
6. Database migrations run automatically on startup
7. Verify the upgrade: curl http://127.0.0.1:8765/api/version
