# KingSec Screenshot Checklist

**Version:** 1.0  
**Last Updated:** 2026-07-27

## General Requirements

- [ ] Resolution: 1920x1080
- [ ] Dark theme enabled
- [ ] Browser chrome hidden
- [ ] No personal or real customer data visible
- [ ] Consistent demo target across all screenshots
- [ ] PNG format, lossless
- [ ] File naming: `kingsec-{page}-{description}.png`
- [ ] Alt text documented for each screenshot

---

## 1. Login Page

- [ ] Login form with username/email and password fields
- [ ] Register link visible
- [ ] "KingSec" branding in header
- [ ] Dark theme styling visible

**Suggested filename:** `kingsec-login.png`

---

## 2. Dashboard

- [ ] Summary stat cards (total scans, findings, scanners, schedules)
- [ ] Severity breakdown chart/bar
- [ ] Recent reports section
- [ ] Quick actions panel
- [ ] Finding trends visualization
- [ ] Navigation sidebar visible

**Suggested filename:** `kingsec-dashboard.png`

---

## 3. Assessments List

- [ ] Assessment table/grid with status badges
- [ ] Filter and search controls
- [ ] Create Assessment button visible
- [ ] Pagination controls
- [ ] At least 3 assessments in different statuses (completed, running, pending)

**Suggested filename:** `kingsec-assessments-list.png`

---

## 4. Create Assessment

- [ ] Profile selection (dropdown or card grid)
- [ ] Target input field
- [ ] Execution plan preview (scanners, duration, warnings)
- [ ] Start button visible
- [ ] Profile descriptions visible

**Suggested filename:** `kingsec-create-assessment.png`

---

## 5. Assessment Detail — Running

- [ ] Progress bar with percentage
- [ ] Current phase indicator
- [ ] Per-scanner status cards
- [ ] Cancel button visible
- [ ] Phase labels visible
- [ ] Auto-refresh indicator (if shown)

**Suggested filename:** `kingsec-assessment-running.png`

---

## 6. Assessment Detail — Completed

- [ ] Completion status (checkmark/success indicator)
- [ ] Finding summary counts
- [ ] Generate Report button
- [ ] Assessment metadata

**Suggested filename:** `kingsec-assessment-completed.png`

---

## 7. Findings Page

- [ ] Filter controls (severity, status, search)
- [ ] Findings table with severity badges
- [ ] Pagination
- [ ] Total count displayed
- [ ] Stat cards at top (total, critical, high, medium)

**Suggested filename:** `kingsec-findings.png`

---

## 8. Report Center

- [ ] Report card grid with executive score rings
- [ ] Search bar
- [ ] Severity filter pills
- [ ] Sort dropdown
- [ ] Pagination
- [ ] At least 4 report cards visible

**Suggested filename:** `kingsec-reports-center.png`

---

## 9. Report Preview (Drawer)

- [ ] Executive score ring (large)
- [ ] Executive summary text
- [ ] Risk severity bars
- [ ] Finding counts
- [ ] Metadata panel
- [ ] Download and Regenerate buttons

**Suggested filename:** `kingsec-report-preview.png`

---

## 10. Administration — Users

- [ ] Users table with roles, status, dates
- [ ] Role badges (ADMIN, ANALYST, VIEWER)
- [ ] Search/filter if available
- [ ] User management actions

**Suggested filename:** `kingsec-admin-users.png`

---

## 11. Administration — Audit Log

- [ ] Audit event table with timestamps
- [ ] Event types visible
- [ ] User identifiers
- [ ] Pagination controls

**Suggested filename:** `kingsec-admin-audit.png`

---

## 12. Scanner Health

- [ ] Health score display
- [ ] Per-scanner status (usable/unusable, version, warnings)
- [ ] Installation instructions or helpful messages for missing scanners
- [ ] At least 3 scanners shown

**Suggested filename:** `kingsec-scanner-health.png`

---

## 13. Settings — Profile

- [ ] User profile information
- [ ] Change password option
- [ ] MFA section (enable/disable status)
- [ ] API keys management if available

**Suggested filename:** `kingsec-settings-profile.png`

---

## 14. Settings — Sessions

- [ ] Active sessions table
- [ ] Session details (created, last active, device info)
- [ ] Revoke button

**Suggested filename:** `kingsec-settings-sessions.png`

---

## 15. API Key Management

- [ ] API keys list
- [ ] Create/revoke/rotate actions
- [ ] Key details (name, scope, status, last used)
- [ ] Pagination if many keys

**Suggested filename:** `kingsec-api-keys.png`

---

## 16. Error States

- [ ] Empty state (no assessments, no findings)
- [ ] Loading state (skeleton screens)
- [ ] Error state (with retry option)
- [ ] 404 page

**Suggested filename:** `kingsec-error-empty.png`, `kingsec-error-loading.png`, `kingsec-error-404.png`

---

## 17. Mobile Views (Optional)

- [ ] Dashboard on tablet (768px)
- [ ] Assessments list on mobile (375px)
- [ ] Report preview on mobile

---

## Screenshot Inventory

| # | File | Status | Notes |
|---|------|--------|-------|
| 1 | `kingsec-login.png` | | |
| 2 | `kingsec-dashboard.png` | | |
| 3 | `kingsec-assessments-list.png` | | |
| 4 | `kingsec-create-assessment.png` | | |
| 5 | `kingsec-assessment-running.png` | | |
| 6 | `kingsec-assessment-completed.png` | | |
| 7 | `kingsec-findings.png` | | |
| 8 | `kingsec-reports-center.png` | | |
| 9 | `kingsec-report-preview.png` | | |
| 10 | `kingsec-admin-users.png` | | |
| 11 | `kingsec-admin-audit.png` | | |
| 12 | `kingsec-scanner-health.png` | | |
| 13 | `kingsec-settings-profile.png` | | |
| 14 | `kingsec-settings-sessions.png` | | |
| 15 | `kingsec-api-keys.png` | | |
| 16 | `kingsec-error-empty.png` | | |
| 17 | `kingsec-error-loading.png` | | |
| 18 | `kingsec-error-404.png` | | |
