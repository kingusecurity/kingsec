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

There is currently no CLI equivalent. KingSec ships only the `kingsec`,
`kingsec-migrate`, and `kingsec-bootstrap` entry points; none of them expose
a `db backup` / `db restore` / `db check` subcommand. Manage backups from
the web interface (Admin > Backups), or take a filesystem-level snapshot of
the database file directly.

### Restoring from Backup

**Current limitation:** the "Restore" action in Admin > Backups (and the
equivalent snapshot / scoped-restore actions) decrypts, decompresses, and
checksum-verifies the selected backup artifact, but it does **not** write
the recovered data back into the live database. Today this action verifies
that a backup is intact and recoverable — it is not yet a data-recovery
operation, and clicking it does not affect the running system's data.

To actually recover data from a backup, stop the KingSec service, replace
the live database file with the (decrypted/decompressed) backup artifact
manually, restart the service, and run `kingsec-migrate` to bring the
schema up to date. Treat this as a manual, operator-driven procedure until
in-application restore is implemented.

### Backup Verification

Backup integrity can be checked using the same "Restore" action described
above: select a backup file in Admin > Backups and click "Restore" — this
performs decrypt/decompress/checksum verification without modifying any
live data (see the limitation above).

---

## Secret and Key Rotation

KingSec relies on two distinct secrets, and they play very different
roles. Rotating them is not the same operation and carries different
risk profiles — read both subsections before rotating either one.

### JWT Signing Secret (`KINGSEC_JWT__SECRET_KEY`)

**What it protects:** this secret signs and verifies every access and
refresh token issued to logged-in users. It does not encrypt any stored
data.

**Why rotate it:** to invalidate all currently-issued tokens at once —
for example, after a suspected leak of the signing secret itself, or as
routine hardening (see "Rotate secrets every 90 days" under Security
Hardening Recommendations, below).

**What happens to existing JWTs/sessions after rotation:** every
previously-issued access and refresh token stops validating immediately.
Every logged-in user is forced to re-authenticate. This is the entire
point of rotating this secret — it is not a side effect, it is the
mechanism. Plan rotation for a low-traffic window and communicate the
forced re-login to users in advance where practical.

**Procedure:**

1. Generate a new secret:

       python -c "import secrets; print(secrets.token_urlsafe(48))"

2. Set `KINGSEC_JWT__SECRET_KEY` to the new value in your deployment's
   environment configuration (`.env` file or orchestrator secret store).
3. Restart the KingSec service so the new value takes effect.
4. Confirm the service started successfully (`GET /api/v1/health` returns
   200) and that a fresh login succeeds.
5. Inform users that all existing sessions have been invalidated.

**What NOT to do:** do not rotate this secret without expecting every
active session to end — there is no partial or gradual rotation path for
JWT signing.

### Fernet Encryption Key (`KINGSEC_SECRETS__ENCRYPTION_KEY`)

**What it protects:** this key encrypts every value stored through
KingSec's internal secret-management subsystem (for example, third-party
integration credentials saved via the Secrets admin API). It is
completely separate from the JWT signing secret and from user account
passwords (which are hashed with Argon2id, not encrypted, and are never
affected by this key).

**Primary and legacy keys:** KingSec supports one *primary* encryption
key plus zero or more *legacy* keys, both sourced from durable
configuration and loaded at process startup:

- `KINGSEC_SECRETS__ENCRYPTION_KEY` — the primary key. All new
  encryption uses this key.
- `KINGSEC_SECRETS__LEGACY_ENCRYPTION_KEYS` — an ordered list of
  retired keys, accepted for **decryption only**. A legacy key is never
  used to encrypt new data. Populate this list when rotating the
  primary key so that data already encrypted under an old key remains
  readable after the restart that switches to the new one.

Key rotation (changing which key is primary) and secret migration
(re-encrypting already-stored ciphertext under the current primary key)
are two separate, operator-controlled steps — see below.

**Key rotation procedure:**

1. Take a full backup first (see Backup and Restore, above) — this is
   mandatory, not optional, for this procedure.
2. Generate a new Fernet key *outside* the running application:

       python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

   KingSec never generates this key for you — it must be supplied
   through configuration.
3. Take the **current** value of `KINGSEC_SECRETS__ENCRYPTION_KEY` and
   add it to `KINGSEC_SECRETS__LEGACY_ENCRYPTION_KEYS`, so it remains
   available for decryption during and after migration.
4. Set `KINGSEC_SECRETS__ENCRYPTION_KEY` to the newly generated key.
5. Restart KingSec. The application now builds its encryption service
   from the new primary key plus the old key(s) listed as legacy —
   existing secrets remain readable immediately after the restart
   because the old key is still part of durable configuration.
6. Call `POST /api/v1/admin/secrets/rotate` to migrate stored secrets.
   This endpoint does **not** generate a key; it decrypts every stored
   secret (using primary or legacy keys, whichever applies) and
   re-encrypts it under the current primary key. Like before, this is a
   safe two-pass procedure — every value is decrypted first, aborting
   cleanly if any value fails to decrypt before anything is mutated —
   so a call either migrates everything or leaves the store untouched.
7. Verify a re-entered/migrated secret can still be retrieved correctly
   before relying on it.

**Legacy-key retirement:** KingSec does not automatically detect or
prevent premature removal of a legacy key. Do not remove a key from
`KINGSEC_SECRETS__LEGACY_ENCRYPTION_KEYS` until you have independently
confirmed no remaining stored ciphertext still depends on it (for
example, by calling `/secrets/rotate` and confirming it reports the
expected number of migrated secrets). If a legacy key is removed while
ciphertext still depends on it, that secret will fail to decrypt.

**What NOT to do:**

- Do not expect `POST /api/v1/admin/secrets/rotate` to generate a key
  for you — key generation and configuration are operator steps that
  must happen first (steps 1–5 above). The endpoint's job is migrating
  already-stored ciphertext onto the current primary key, not producing
  new key material.
- Do not remove a key from `KINGSEC_SECRETS__ENCRYPTION_KEY` or
  `KINGSEC_SECRETS__LEGACY_ENCRYPTION_KEYS` while any stored secret is
  still encrypted under it — doing so makes that secret undecryptable.
- Do not commit any actual secret value (JWT secret, encryption key, or
  a stored secret's plaintext) to Git, to this documentation, or to any
  ticket/support channel. Production credentials must never appear in
  written documentation, source control, or logs.

---

## Rollback and Incident Response

### A. Application Rollback

Consider rolling back to a previously known-good KingSec image when a
newly deployed version is causing errors, crashes, or a serious
regression that cannot be quickly fixed forward.

1. **Identify the previous known-good release.** Check the image tag
   currently running (`docker inspect kingsec --format '{{.Config.Image}}'`)
   and the tag you deployed immediately before it — your deployment
   history or `docker images` on the host is the source of truth.
2. **Pause normal operations where practical.** Avoid starting new
   assessments during the rollback window; let in-flight scans finish or
   accept that they will be interrupted.
3. **Take a database backup before rolling back** (see Backup and
   Restore, above) — a rollback that also needs a database restore is a
   much bigger operation than one that doesn't.
4. **Check database compatibility.** If the version you are rolling back
   *from* ran any database migrations that the version you are rolling
   back *to* does not know about, the older application code may not
   understand the current schema. Do not assume a schema downgrade is
   automatic or safe — see Section B below before touching migrations.
5. **Restore the previous application image:**

       docker stop kingsec
       docker rm kingsec
       docker run -d --name kingsec --env-file .env -p 8765:8765 \
         -v kingsec-data:/home/kingsec/.kingsec kingsec:<previous-tag>

6. **Verify health:** `curl http://127.0.0.1:8765/api/v1/health` should
   return `200`, and the container's own Docker healthcheck should report
   `healthy` (`docker ps` shows the container status).
7. **Check logs** (`docker logs kingsec`) for startup errors, especially
   schema-version mismatches.
8. **Confirm the application is actually serving correctly** — log in,
   load the dashboard, and confirm existing data is visible as expected,
   not just that the health endpoint responds.

### B. Database/Migration Rollback

Database rollback is more sensitive than application rollback because
data loss from a bad downgrade is often irreversible, while a bad
application rollback is fixable by rolling forward again.

- **Never assume an Alembic downgrade is safe by default.** Only run
  `alembic downgrade` when you have specifically verified that the
  target migration's downgrade path was written to preserve the data you
  care about — some migrations (e.g. ones that drop a column or table)
  cannot losslessly reverse themselves even if a `downgrade()` function
  exists.
- **Always take a backup immediately before any destructive migration
  operation** — before running a downgrade, and ideally before running
  a forward migration too, since a bad forward migration is exactly what
  a downgrade or restore would need to recover from.
- **Keep application and database versions compatible.** The safest
  recovery from a bad migration is usually restoring the database backup
  taken immediately before the migration ran, paired with the
  application version that backup was captured under — not attempting a
  live downgrade against a database whose current state may not match
  what the downgrade path expects.
- **Do not blindly run `alembic downgrade` in production** as a
  first-response action. Prefer restoring from backup (Section
  "Restoring from Backup", above) unless you have specifically confirmed
  the downgrade path is safe for your data.

### C. Incident Response

This is an operator runbook for KingSec-specific incidents, not a
general security framework. Adapt the order to the actual situation —
containment sometimes has to happen before full identification is
complete.

1. **Identify.** Determine what actually happened: check the Audit Log
   (Admin > Audit Log) for the relevant time window, review
   `docker logs kingsec`, and confirm which accounts, API keys, or
   secrets are implicated.
2. **Contain.** Deactivate compromised user accounts (Admin > Users >
   Deactivate — invalidates active sessions within 60 seconds) and/or
   revoke compromised API keys (Admin > API Keys) immediately. If the
   host itself may be compromised, isolate it from the network before
   doing further investigation.
3. **Preserve evidence.** Export the relevant Audit Log range (see
   "Exporting the Audit Log", above) and take a database backup before
   making further changes, so the state at time of discovery is not
   lost.
4. **Rotate compromised credentials/secrets.** See "Secret and Key
   Rotation," above, for the JWT signing secret and encryption key
   specifically — note the encryption-key limitation documented there
   if that is the credential in question. For a compromised API key,
   revoke it from Admin > API Keys and issue a new one. For a
   compromised user password, force a reset from Admin > Users > Edit >
   Reset Password.
5. **Assess database impact.** Review the Audit Log for what the
   compromised credential/account actually accessed or modified during
   the exposure window, and cross-check against a backup from before the
   incident if you need to determine what changed.
6. **Recover.** Restore from a pre-incident backup only if you have
   confirmed data was corrupted or improperly modified — otherwise,
   prefer forward remediation (revoke, rotate, reset) over a destructive
   restore.
7. **Verify.** Confirm the previously-compromised credential/account no
   longer has access, that legitimate users can still operate normally,
   and that the health endpoint and core workflows (login, assessment
   creation) function correctly.
8. **Document.** Record what happened, what was affected, what actions
   were taken, and when — this becomes the incident record referenced
   in future audits.
9. **Prevent recurrence.** Identify the root cause (leaked credential,
   weak password, missing MFA, exposed admin endpoint, etc.) and apply
   the corresponding hardening measure from "Security Hardening
   Recommendations," below.

**Example scenarios:**

- **Suspected API-key compromise:** revoke the key immediately (Admin >
  API Keys), review the Audit Log for actions taken under that key
  during the suspected exposure window, issue a replacement key, and
  update any automation that used the old key.
- **JWT-secret compromise:** rotate `KINGSEC_JWT__SECRET_KEY`
  immediately (Section A, above) — this invalidates every active
  session at once, which is the correct containment action for this
  specific credential.
- **Encryption-key compromise:** follow the "only currently safe way to
  change this key" procedure under Secret and Key Rotation, above —
  export, rotate, re-enter. Treat any secret encrypted under the
  compromised key as exposed even after rotation, since rotation does
  not retroactively protect data an attacker already decrypted.
- **Suspected unauthorized administrative access:** deactivate the
  affected admin account, review the Audit Log for every action taken
  under it, and audit which other accounts/roles that admin could have
  modified.
- **Suspected database compromise:** isolate the host, preserve a copy
  of the current database file for forensic review before taking any
  further action, and assess whether encrypted secrets (Section on
  encryption-key compromise, above) or password hashes were exposed.

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
