# KingSec Frontend Dead-Button Audit — 2026-08

Full inventory of interactive elements across all 45 routed screens, checked
against the standing product principle: "Every visible action must either
work, be disabled, or be hidden. Never dead."

Audit-only — no code changes were made as part of this pass. Scope:
`frontend/src/pages/**` and every shared component/hook/API-client module
those pages import.

Categories:
- **Working** — calls a real API/mutation or navigates to a real, populated route.
- **Dead-A** — trivial to finish: the backend endpoint already exists and works, frontend just isn't calling it.
- **Dead-B** — genuinely incomplete: backend support doesn't exist yet, or the frontend work is a larger effort (form-building, new flow).
- **Dead-C** — candidate for "should this exist in v1 at all."
- **Unsure** — flagged, needs a second opinion rather than a guess.

## Summary

| Category | Count |
|---|---|
| Working | ~308 |
| Dead-A | ~22 |
| Dead-B | ~9 |
| Dead-C | 0 confidently (1 borderline B/C case, see Plugins) |
| Unsure | ~6 |
| **Total elements reviewed** | **~345** |

Counts are approximate — see notes inline where an element's status has a caveat baked into its own row rather than being a clean single-category call. A live, filterable version of this same inventory is also available as a published artifact from the same session; this file is the durable, reviewable copy.

---

## Login (`/login`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Sign-in form submit | `login.mutate(data, {onSuccess: navigate('/dashboard')})` — real `authApi.login` mutation | Working | `pages/LoginPage.tsx:39` | — |
| "Sign in" button | `type="submit"`, disabled while pending | Working | `pages/LoginPage.tsx:71-77` | — |
| "Register" link | `<Link to="/register">` | Working | `pages/LoginPage.tsx:81-83` | — |
| Already-authenticated redirect | `<Navigate to="/dashboard" replace />` | Working | `pages/LoginPage.tsx:28-30` | — |

## Register (`/register`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Registration form submit | `registerMutation.mutate(data, {onSuccess: navigate('/login')})` — real `authApi.register` | Working | `pages/RegisterPage.tsx:40` | — |
| "Create account" button | disabled while pending | Working | `pages/RegisterPage.tsx:90-96` | — |
| "Sign in" link | `<Link to="/login">` | Working | `pages/RegisterPage.tsx:100-102` | — |

## Dashboard (`/dashboard`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| ErrorState "Retry" | `refetchSummary(); refetchJobs()` — real TanStack refetch | Working | `pages/DashboardPage.tsx:29` | — |
| "View all" (Recent Reports header) | `<Link to="/reports">` | Working | `pages/DashboardPage.tsx:91-96` | — |
| Report row "View" link | `<Link to="/assessments/{id}">` | Working | `pages/DashboardPage.tsx:150-157` | — |
| StatCards (display only) | Bound to real `summary`/`jobs` query data, not interactive | Working | `pages/DashboardPage.tsx:44-47` | — |
| QuickActions: "New Assessment" | `<Link to="/assessments/new">` | Working | `components/features/dashboard/QuickActions.tsx:18` | — |
| QuickActions: "View Reports" | `<Link to="/assessments?status=completed">` — navigates fine, but see Assessments-list filter finding below (the `status` param it passes is silently ignored on arrival) | Working | `components/features/dashboard/QuickActions.tsx:18` | Fix is on the receiving page, not here. |
| QuickActions: "Dashboard" | `<Link to="/dashboard">` | Working | `components/features/dashboard/QuickActions.tsx:18` | — |
| QuickActions: "Settings" | `<Link to="/settings">` | Working | `components/features/dashboard/QuickActions.tsx:18` | — |
| Recent-assessment row link | `<Link to="/assessments/{id}">` | Working | `components/features/dashboard/RecentAssessmentsTable.tsx:31-45` | — |
| "View All Assessments" link | `<Link to="/assessments">` | Working | `components/features/dashboard/RecentAssessmentsTable.tsx:47` | — |
| ScannerHealthPanel "Refresh" | `refetch()` from `useScannerHealth` | Working | `components/features/monitoring/ScannerHealthPanel.tsx:398` | — |
| ScannerHealthPanel filter chips (All/Installed/Missing/Warnings) | Real client-side state filter over real scanner data | Working | `components/features/monitoring/ScannerHealthPanel.tsx:411-424` | — |
| ScannerHealthPanel scanner row (click) | `onSelect(scanner_id)` → expands real detail via `useScannerDetail`/`useScannerInstallInfo` | Working | `components/features/monitoring/ScannerHealthPanel.tsx:64-115` | — |
| ScannerHealthPanel "Copy" (recommendation/command) | `navigator.clipboard.writeText(...)` | Working | `components/features/monitoring/ScannerHealthPanel.tsx:129-137` | — |
| ScannerHealthPanel "Copy Install Command" | `navigator.clipboard.writeText(best_command.command)` | Working | `components/features/monitoring/ScannerHealthPanel.tsx:160-167` | — |
| ScannerHealthPanel "Close" (detail panel) | `setSelectedScanner(null)` | Working | `components/features/monitoring/ScannerHealthPanel.tsx:200` | — |
| ScannerHealthPanel website external link | Real `<a href={installInfo.website}>` | Working | `components/features/monitoring/ScannerHealthPanel.tsx:273-279` | — |
| ScannerHealthPanel "Export Markdown" | `window.open('/scanners/{id}/diagnostics?fmt=markdown')` — **confirmed against the backend: no such route exists** (`/deployment/diagnostics*` are the only diagnostics routes; `scanner-health.ts`'s API client has no export function either) | Dead-B | `components/features/monitoring/ScannerHealthPanel.tsx:324-334` | Will 404 or hit the SPA catch-all. Build a real scanner-specific export endpoint, or remove the buttons. |
| ScannerHealthPanel "Export Text" | Same pattern as above, `fmt=text` | Dead-B | `components/features/monitoring/ScannerHealthPanel.tsx:335-345` | Same fix as Export Markdown. |

## Assessments list (`/assessments`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "New Assessment" button | `navigate('/assessments/new')` | Working | `pages/AssessmentsPage.tsx:90-92` | — |
| Target-name row link | `<Link to="/assessments/{id}">` | Working | `pages/AssessmentsPage.tsx:131-133` | — |
| Arrow-icon row link (duplicate target) | Same route as above | Working | `pages/AssessmentsPage.tsx:143-145` | — |
| Pagination | `page` param correctly drives `offset` sent to the query | Working | `pages/AssessmentsPage.tsx:154-158` | — |
| "New Assessment" (empty state) | `window.location.href = '/assessments/new'` — full page reload instead of `navigate()`, used one line away for the identical action | Working | `pages/AssessmentsPage.tsx:167` | Style nit: swap to `navigate()` for consistency. |
| Search box | Updates URL/state correctly; **never reaches the actual query** — the params object sent to `useAssessments` only ever contains `limit`/`offset` | Dead-A | `components/features/assessment/AssessmentFilters.tsx:35-41` | Add `search` to the params object at `AssessmentsPage.tsx:32-35` — same pattern already correct on Reports/Findings pages. |
| Status filter select | Same root cause as Search box | Dead-A | `components/features/assessment/AssessmentFilters.tsx:43-57` | Add `status` to the query params. |
| Sort-by select | Same root cause | Dead-A | `components/features/assessment/AssessmentFilters.tsx:58-69` | Add `sort_by` to the query params. |
| Sort-order select | Same root cause | Dead-A | `components/features/assessment/AssessmentFilters.tsx:70-79` | Add `sort_order` to the query params. |
| "Clear" (filters) | `setSearchParams(new URLSearchParams())` — works, just clearing filters that weren't affecting the query anyway | Working | `components/features/assessment/AssessmentFilters.tsx:81-83` | — |

## Assessment detail (`/assessments/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| ErrorState "Retry" | `refetch` from `useAssessment(id)` | Working | `pages/AssessmentDetailPage.tsx:49` | — |
| "Back to assessments" link | `<Link to="/assessments">` | Working | `pages/AssessmentDetailPage.tsx:56-59` | — |
| "Back to Assessments" (not-found state) | `<Link to="/assessments">` | Working | `pages/AssessmentDetailPage.tsx:149-151` | — |
| "Generate Report" (no report yet) | `reportMutation.mutate(id)` — real `useGenerateReport` | Working | `pages/AssessmentDetailPage.tsx:211-220` | — |
| "Download" (report exists) | Real fetch + blob download via `adminApi.downloadReport` | Working | `pages/AssessmentDetailPage.tsx:265-277` | — |
| "Regenerate" (report exists) | `reportMutation.mutate(id)` | Working | `pages/AssessmentDetailPage.tsx:278-287` | — |
| AssessmentActions: "Start" | `startMutation.mutate(id)` — real `useStartAssessment` | Working | `components/features/assessment/AssessmentActions.tsx:35-37` | — |
| AssessmentActions: "Cancel" | Opens ConfirmDialog → real `useCancelAssessment` on confirm | Working | `components/features/assessment/AssessmentActions.tsx:40-42, 55-64` | — |
| AssessmentActions: "Generate Report" | Real mutation | Working | `components/features/assessment/AssessmentActions.tsx:44-47` | — |
| AssessmentActions: "Delete" | Opens ConfirmDialog → real `useDeleteAssessment` on confirm | Working | `components/features/assessment/AssessmentActions.tsx:49-52, 65-74` | — |
| ExecutionProgressPanel "Cancel" | Opens ConfirmDialog → real `useCancelExecution` | Working | `components/features/execution/ExecutionProgressPanel.tsx:189-196, 258-267` | — |
| ExecutionProgressPanel "Event Log (N)" toggle | Real state toggle, expands real polled events | Working | `components/features/execution/ExecutionProgressPanel.tsx:232-238` | — |
| ExecutionProgressPanel ErrorState retry | `refetch()` from `useExecutionStatus` | Working | `components/features/execution/ExecutionProgressPanel.tsx:145` | — |

## Create assessment (`/assessments/new`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Back to assessments" link | `<Link to="/assessments">` | Working | `pages/CreateAssessmentPage.tsx:27-33` | — |
| Form submit | Real `useCreateAssessment` mutation, navigates to the new assessment on success | Working | `pages/CreateAssessmentPage.tsx:41-45` | — |
| Wizard "Back" | Real local step state | Working | `components/features/assessment/CreateAssessmentForm.tsx:370-372` | — |
| Wizard "Next" / "Review Plan" | Validates fields, triggers real `usePlan()` mutation | Working | `components/features/assessment/CreateAssessmentForm.tsx:376-378` | — |
| "Create Assessment" submit | Triggers the page's real create mutation | Working | `components/features/assessment/CreateAssessmentForm.tsx:380-382` | — |
| Profile card (click) | Real form-state update, resets plan for regeneration | Working | `components/features/assessment/CreateAssessmentForm.tsx:55-90` | — |

## Findings list (`/findings`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Search box | Debounced, correctly feeds `useFindings({search})` — this filter bar IS wired correctly (unlike Assessments list) | Working | `pages/FindingsPage.tsx:85` | — |
| Severity select | Feeds `useFindings({severity})` | Working | `pages/FindingsPage.tsx:89` | — |
| Status select | Feeds `useFindings({status})` | Working | `pages/FindingsPage.tsx:97` | — |
| "Previous" pagination | Real offset state | Working | `pages/FindingsPage.tsx:149` | — |
| "Next" pagination | Real offset state | Working | `pages/FindingsPage.tsx:150` | — |
| Recent-assessment rows | No `onClick`/`href` and no clickable styling — inert but not misleading (no affordance implied) | Working | `pages/FindingsPage.tsx:34-60` | Note only — add real navigation if these were meant to be clickable. |

## Finding detail (`/assessments/:id/findings/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| ErrorState "Retry" | `refetch` from `useFinding` | Working | `pages/FindingDetailPage.tsx:21` | — |
| "Back to assessment" link (top) | `<Link to="/assessments/{id}">` | Working | `pages/FindingDetailPage.tsx:31-37` | — |
| "View {target}" link (related assessment) | `<Link to="/assessments/{id}">` | Working | `pages/FindingDetailPage.tsx:60-66` | — |
| "Back to assessment" (not-found state) | `<Link to="/assessments/{id}">` | Working | `pages/FindingDetailPage.tsx:101-103` | — |
| CVE reference link | Real external MITRE link, data-driven | Working | `components/features/findings/FindingReferences.tsx:41-50` | — |
| CWE reference link | Real external MITRE link, data-driven | Working | `components/features/findings/FindingReferences.tsx:60-69` | — |
| Evidence disclosure (`<details>`) | Native expand/collapse, real evidence content | Working | `components/features/findings/EvidencePanel.tsx:69-80` | — |
| Recommendation details | Shows a real count, but renders only a static placeholder sentence in place of actual content — no button/link to view them either | Dead-B | `components/features/findings/FindingRecommendations.tsx:29-32` | Needs a real recommendations fetch + render — content gap, not a mechanical fix. |

## Reports (`/reports`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Preview" (report card) | Opens real PreviewDrawer with real data | Working | `pages/ReportsPage.tsx:154-160` | — |
| "Download" (report card) | Real fetch+blob download | Working | `pages/ReportsPage.tsx:161-168` | — |
| "Regenerate" (report card) | Real `useRegenerateReport` mutation | Working | `pages/ReportsPage.tsx:169-177` | — |
| "Clear search" (X) | Real state clear | Working | `pages/ReportsPage.tsx:446-452` | — |
| Sort select | Drives real `useReports({order_by, order_dir})` | Working | `pages/ReportsPage.tsx:457-466` | — |
| Severity filter pills | Drives real `useReports({severity})` — this filter bar IS wired correctly | Working | `pages/ReportsPage.tsx:472-485` | — |
| "Clear all filters" (empty state) | Real state reset | Working | `pages/ReportsPage.tsx:510-512` | — |
| "Clear all filters" (results header) | Real state reset | Working | `pages/ReportsPage.tsx:532-534` | — |
| Pagination (Previous/Next) | Real offset state | Working | `pages/ReportsPage.tsx:555-572` | — |
| PreviewDrawer "Download" | Real, same handler as card | Working | `pages/ReportsPage.tsx:335-343` | — |
| PreviewDrawer "Regenerate" | Real, same handler as card | Working | `pages/ReportsPage.tsx:344-353` | — |

## Administration (`/administration`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Tab nav (Overview/Users/Agents/Backups/Plugins/Queue) | Real tab switch, each backed by a real query hook | Working | `pages/AdministrationPage.tsx:29-41` | — |
| Users search | Debounced, real `useAdminUsersSearch` | Working | `pages/AdministrationPage.tsx:219` | — |
| Role filter select | Real query param | Working | `pages/AdministrationPage.tsx:223` | — |
| "Deactivate" (user) | Real `adminApi.deactivateUser` | Working | `pages/AdministrationPage.tsx:262-267` | — |
| "Activate" (user) | Real `adminApi.activateUser` | Working | `pages/AdministrationPage.tsx:269-275` | — |
| "Change Role" | Opens real modal | Working | `pages/AdministrationPage.tsx:277-282` | — |
| "Reset Password" | Opens real modal | Working | `pages/AdministrationPage.tsx:283-288` | — |
| Pagination (Previous/Next) | Real offset state | Working | `pages/AdministrationPage.tsx:304-305` | — |
| Role-change modal Cancel/Save | Real `authApi.assignRole` on save | Working | `pages/AdministrationPage.tsx:318-325` | — |
| Reset-password modal Cancel/Reset | Real `adminApi.resetPassword` | Working | `pages/AdministrationPage.tsx:340-347` | — |
| Agents/Backups/Plugins/Queue tab content | Pure real-data display, no buttons | Working | `pages/AdministrationPage.tsx:355-477` | — |

## Settings — General / Appearance (`/settings`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Theme RadioGroup | Real theme persistence + live toggle | Working | `components/features/settings/AppearanceSection.tsx:17-21` | — |

## Settings — Dashboard preferences (`/settings`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| 6 toggles (landing page, refresh interval, 4 widget-visibility switches) | Save correctly to local storage via the UI store, but **nothing downstream reads any of these fields** — confirmed via repo-wide search; DashboardPage never consults them | Dead-A | `components/features/settings/DashboardPreferencesSection.tsx:31-64` | Wire DashboardPage to read these prefs, or remove the section — the storage plumbing already works. |

## Settings — Notification preferences (`/settings`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| 4 notification-channel toggles | Same pattern — saved, never consumed by any dispatch logic | Dead-A | `components/features/settings/NotificationPreferencesSection.tsx:16-35` | Wire it in, or remove until there's a consumer. |

## Settings — Security / API / About / Integrations / License / Organizations (`/settings`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Terminate session" | Real `settingsApi.deleteSession` | Working | `components/features/settings/SecuritySection.tsx:32-36` | — |
| "Logout all sessions" | Real `settingsApi.deleteAllSessions` | Working | `components/features/settings/SecuritySection.tsx:98-105` | — |
| Sessions ErrorState retry | Real refetch | Working | `components/features/settings/SecuritySection.tsx:83` | — |
| API health ErrorState retry | Real refetch | Working | `components/features/settings/ApiSettingsSection.tsx:23` | — |
| Version string | Hardcoded literal `"1.0.0"`, not sourced from any API — will drift from the real app version | Dead-A | `components/features/settings/AboutSection.tsx:26` | Read from `deploymentApi.getSystemInfo`, already used elsewhere for the same data. |
| "Test Connection" (integration) | Real `integrationsApi.test`, disabled when not configured | Working | `components/features/settings/IntegrationsSection.tsx:55-63` | — |
| "Activate"/"Deactivate" toggle & buttons (License tab) | Real `licensingApi.activate`/`deactivate` via shared hooks | Working | `components/features/settings/LicenseSection.tsx:95-143` | — |
| "New Organization" / "Create" | Real `organizationsApi.create` | Working | `components/features/settings/OrganizationSection.tsx:93-103` | — |
| Org card (click) | Real toggle, correct a11y (`role="button"`, keydown) | Working | `components/features/settings/OrganizationSection.tsx:118-138` | — |
| "Add" (member) | Real `organizationsApi.addMember` | Working | `components/features/settings/OrganizationSection.tsx:165-167` | — |
| "Remove member" icon button | Real `organizationsApi.removeMember`, but no `aria-label` (icon-only) | Working | `components/features/settings/OrganizationSection.tsx:176-178` | Accessibility nit — add a label. |
| "Add" (team) | Real `organizationsApi.createTeam` | Working | `components/features/settings/OrganizationSection.tsx:189-191` | — |

## Audit log (`/audit`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Action/Resource/Result filter selects | Drive real `useAuditLog` query | Working | `components/features/audit/AuditFilters.tsx:58-75` | — |
| "Clear" (filters) | Real state reset | Working | `components/features/audit/AuditFilters.tsx:76-79` | — |
| Table row (click) | Opens real detail drawer | Working | `components/features/audit/AuditTable.tsx:76-84` | — |
| ErrorState retry | Real refetch | Working | `components/features/audit/AuditTable.tsx` | — |
| Drawer close | Real state reset | Working | `pages/AuditLogPage.tsx:75-79` | — |
| Pagination | Real page state | Working | `components/features/audit/AuditTable.tsx:112-116` | — |

## Identity providers (`/identity`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Add Provider"/"Cancel" | Real state toggle | Working | `pages/IdentityProvidersPage.tsx:76-78` | — |
| "Create Provider" | Real `identityApi.createProvider` | Working | `pages/IdentityProvidersPage.tsx:96` | — |
| "Close" (test result) | Real state reset | Working | `pages/IdentityProvidersPage.tsx:106` | — |
| Provider row (click) | `navigate('/identity/{id}')`, real route — but a plain `<div>` with `cursor-pointer`, no `role`/`tabIndex`/keydown | Working | `pages/IdentityProvidersPage.tsx:114` | Accessibility nit — not keyboard-reachable. |
| "Test" (connection) | Real `identityApi.testConnection` | Working | `pages/IdentityProvidersPage.tsx:131` | — |
| "Deactivate"/"Activate" | Real mutations | Working | `pages/IdentityProvidersPage.tsx:133/135` | — |
| "Delete" provider | Real `identityApi.deleteProvider` mutation, fires immediately | Working | `pages/IdentityProvidersPage.tsx:137` | Add a ConfirmDialog before this destructive action. |
| Provider name/issuer text (list view) | No `truncate`/`title` — a long issuer URL can overflow the row; the detail page truncates the same fields correctly | Dead-A | `pages/IdentityProvidersPage.tsx:116-123` | Add the same truncate + title pattern already used on the detail page. |

## Identity provider detail (`/identity/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Back" | `navigate('/identity')` | Working | `pages/IdentityProviderDetailPage.tsx:111` | — |
| "Test Connection" | Real mutation | Working | `pages/IdentityProviderDetailPage.tsx:112-114` | — |
| "Deactivate"/"Activate" | Real mutations | Working | `pages/IdentityProviderDetailPage.tsx:116/118` | — |
| "Delete" | Real mutation, fires immediately, then navigates away | Working | `pages/IdentityProviderDetailPage.tsx:120` | Add a ConfirmDialog. |

## Backup center (`/backup`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Cleanup Expired" | Real `backupApi.cleanupExpired`, but not disabled while pending | Working | `pages/BackupCenterPage.tsx:101` | Add `disabled={cleanup.isPending}` to prevent double-fire. |
| "New Backup"/"Cancel" | Real state toggle | Working | `pages/BackupCenterPage.tsx:102` | — |
| Tab buttons (Backups/Schedules/Recovery/Health) | Real tab state | Working | `pages/BackupCenterPage.tsx:108-117` | — |
| "Create Backup" | Real `createBackup.mutateAsync` | Working | `pages/BackupCenterPage.tsx:131-133` | — |
| Backup card (click) | `navigate('/backup/{id}')`, real route | Working | `pages/BackupCenterPage.tsx:140` | — |
| "Delete" (backup) | Real mutation, fires immediately, no confirm | Working | `pages/BackupCenterPage.tsx:155-157` | Add a ConfirmDialog. |
| "Create" (schedule) | Real `createSchedule.mutateAsync` | Working | `pages/BackupCenterPage.tsx:185` | — |
| "Delete" (schedule) | Real mutation, no confirm | Working | `pages/BackupCenterPage.tsx:199` | Add a ConfirmDialog. |
| "Create Plan" (recovery) | Real `createPlan.mutateAsync` | Working | `pages/BackupCenterPage.tsx:217` | — |
| Recovery plan row (click) | Navigates to `/backup/recovery/{id}` — **confirmed against the router: this route does not exist**, and no recovery-plan detail page component exists at all | Dead-B | `pages/BackupCenterPage.tsx:223` | Genuinely missing page, not a one-line fix — build a detail view, or make the row non-clickable and show details inline. |
| "Test" (recovery plan) | Real `backupApi.testRecovery` | Working | `pages/BackupCenterPage.tsx:234` | — |
| "Delete" (recovery plan) | Real mutation, no confirm | Working | `pages/BackupCenterPage.tsx:235` | Add a ConfirmDialog. |
| Health tab content | Real data from `useBackupHealth()` | Working | `pages/BackupCenterPage.tsx:245-281` | — |

## Backup detail (`/backup/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Back" | `navigate('/backup')` | Working | `pages/BackupDetailPage.tsx:63` | — |
| "Delete" | Real mutation, fires immediately, no confirm | Working | `pages/BackupDetailPage.tsx:64` | Add a ConfirmDialog. |
| "Restore"/"Test Restore" | Real `backupApi.restoreWithScope` | Working | `pages/BackupDetailPage.tsx:127-129` | — |
| "Run Verification" | Real `backupApi.verifyBackupFull` | Working | `pages/BackupDetailPage.tsx:141-143` | — |

## Deployment (`/deployment`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Tabs (System Info/Health & Startup/Upgrade) | Real tab state | Working | `pages/DeploymentPage.tsx:206-211` | — |
| ErrorState retries (System/Health) | Real refetch | Working | `pages/DeploymentPage.tsx:36, 119` | — |
| "Check for Updates" | `disabled`, no `onClick`, no tooltip. `deploymentApi.getUpgradePlan` + `useUpgradePlan` hook already exist, hit a real working backend endpoint, and are simply never imported into this page | Dead-A | `pages/DeploymentPage.tsx:186-188` | Wire to the existing hook; show the plan in a modal. See disabled-button investigation below for why it was left off. |
| "View Changelog" | `disabled`, no handler, no tooltip | Dead-A | `pages/DeploymentPage.tsx:189-191` | Point at the existing, working `/release-audit` route — no new backend work needed. |

## License — standalone route (`/license`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Deactivate License" | Real inline `useMutation` → `licensingApi.deactivate` | Working | `pages/LicensePage.tsx:102-109` | — |
| "Activate" | Real inline `useMutation` → `licensingApi.activate` | Working | `pages/LicensePage.tsx:138-143` | — |
| License-key input | Real controlled state | Working | `pages/LicensePage.tsx:131-137` | — |
| Whole page vs. Settings → License tab | Both activate/deactivate the same license independently, with different mutation wiring for the same feature | Working | `pages/LicensePage.tsx` vs `components/features/settings/LicenseSection.tsx` | Not dead, but redundant — consolidate to one implementation. |

## Diagnostics (`/diagnostics`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Refresh Diagnostics" | Real `refetch()` | Working | `pages/DiagnosticsPage.tsx:121-123` | — |
| "Download Bundle" | `disabled`, no `onClick`, no tooltip. `deploymentApi.downloadDiagnostics` already exists and calls a real, working backend endpoint (built and verified this session) | Dead-A | `pages/DiagnosticsPage.tsx:124-126` | Wire to the existing blob-download pattern already used on Reports/AssessmentDetail's "Download" buttons. See disabled-button investigation below. |
| Scanner install/detection status | This page has **no per-scanner installed/optional/missing breakdown at all** — just one aggregate health badge. The real three-state UI lives in `ScannerHealthPanel.tsx` (Dashboard, Live Activity), not here | Unsure | `pages/DiagnosticsPage.tsx` (whole page) | Not necessarily this page's job — flagging since the audit explicitly asked about scanner-status clarity. Consider linking to it. |

## Release audit (`/release-audit`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Tabs (Release History/Telemetry) | Real tab state | Working | `pages/ReleaseAuditPage.tsx:201-205` | — |
| ErrorState retries (both tabs) | Real refetch | Working | `pages/ReleaseAuditPage.tsx:26, 138` | — |

## Playbooks list (`/playbooks`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Filter tabs (All/Enabled/Disabled) | Real client-side filter | Working | `pages/PlaybooksPage.tsx:94-100` | — |
| "+ New Playbook" | Real `createPb.mutate`, but collects the name via native `window.prompt()` instead of a form | Working | `pages/PlaybooksPage.tsx:103-110` | Works, but reads as unfinished — replace with the app's own modal/form pattern. |
| Playbook row (click) | `navigate('/playbooks/{id}')`, real detail page | Working | `pages/PlaybooksPage.tsx:121` | — |
| "Disable"/"Enable" (row) | Real `disablePb.mutate`/`enablePb.mutate` | Working | `pages/PlaybooksPage.tsx:138/140` | — |
| "Run" (row) | Real `executePb.mutate` | Working | `pages/PlaybooksPage.tsx:142` | — |
| "Delete" (row) | Real `deletePb.mutate`, confirmed via native `window.confirm()` instead of the app's ConfirmDialog | Working | `pages/PlaybooksPage.tsx:143` | Swap to ConfirmDialog for visual consistency. |

## Playbook detail (`/playbooks/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Edit"/"Cancel" toggle | Toggles local `editing` state that is **never read anywhere else** in the component — no form appears, nothing changes visibly except the button's own label | Dead-B | `pages/PlaybookDetailPage.tsx:64` | Build a real edit form; a working update mutation (`useUpdatePlaybook`) already exists and is never called. |
| "Disable"/"Enable" (header) | Real mutations | Working | `pages/PlaybookDetailPage.tsx:66/68` | — |
| "Run Now" | Real `executePb.mutate` | Working | `pages/PlaybookDetailPage.tsx:70` | — |

## Playbook execution history (`/playbooks/history`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Status filter buttons | Real server-side filter via `useExecutions({status})` | Working | `pages/ExecutionHistoryPage.tsx:77-84` | — |
| Pagination | Real offset param | Working | `pages/ExecutionHistoryPage.tsx:138-142` | — |

## Schedules (`/schedules`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| ErrorState "Try again" | Real refetch from `useSchedules()` | Working | `pages/SchedulesPage.tsx:16` | — |
| Entire create/edit/delete/pause/resume surface | **Does not exist.** No `api/schedules.ts` file; the only hooks are GET-only. Empty state tells users to "Create recurring assessment schedules" with no button anywhere to do it. The backend already has a full, working lifecycle (create/update/delete/pause/resume/enable/disable — confirmed directly against the backend this session) | Dead-B | `pages/SchedulesPage.tsx` (whole page) | Backend is fully ready — this is a bounded frontend build: an `api/schedules.ts` client plus create/edit forms and row actions. |
| Power/PowerOff status icons | Look like enable/disable toggles; have no `onClick` at all — purely decorative | Dead-A | `pages/SchedulesPage.tsx:49-53` | Wire to the enable/disable endpoints once the API client exists, or restyle so they don't read as controls. |

## Plugins (`/plugins`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Scan Directory" | Real `scanPlugins.mutate` | Working | `pages/PluginsSdkPage.tsx:41-43` | — |
| Tabs (Installed/Marketplace) | Real tab state | Working | `pages/PluginsSdkPage.tsx:51-58` | — |
| Type filter chips | Real server-side filter on both tabs | Working | `pages/PluginsSdkPage.tsx:64-73` | — |
| "Unload"/"Load" (installed plugin) | Real `unloadPlugin.mutate`/`loadPlugin.mutate` | Working | `pages/PluginsSdkPage.tsx:106/108` | — |
| Entire Marketplace tab | No install/configure/detail action on any card — the only thing in the action slot is a static license-string label. Backing endpoints (`getMarketplacePlugin`, `getPermissions`) and their hooks exist and are never called from anywhere in the app | Dead-B | `pages/PluginsSdkPage.tsx:117-152` | Directly matches the source assessment's "little visible customer value." Needs a real install/consent flow — or a product call on whether this tab belongs in v1 at all (flagged as borderline B/C). |

## Live activity (`/monitor`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| ActivityTimeline "Refresh" + ErrorState retry | Real `useLiveActivity`, polls every 5s | Working | `components/features/monitoring/ActivityTimeline.tsx:60,73` | — |
| WorkerStatusPanel "Refresh" + retry | Real `useWorkerStatus` | Working | `components/features/monitoring/WorkerStatusPanel.tsx:43,56` | — |
| QueueStatusPanel "Refresh" | Real `useQueueStatus` | Working | `components/features/monitoring/QueueStatusPanel.tsx:56` | — |
| ScannerHealthPanel (shared component, same as Dashboard) | Refresh/filter/select/copy/close/export all present | Working (10) / Dead-B (2) | `components/features/monitoring/ScannerHealthPanel.tsx` | Export Markdown/Text buttons are the same confirmed-dead links as on Dashboard — one shared component, one fix covers both screens. |

## Security operations (`/monitoring`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Tabs (Overview/Recent Events/Open Alerts/Trends) | Real tab state, all real query-backed content | Working | `pages/SecurityOperationsPage.tsx:83-89` | — |
| Recent-alert row (click) | `navigate('/monitoring/alerts/{id}')`, real detail page, keyboard-accessible | Working | `pages/SecurityOperationsPage.tsx:114-121` | — |
| Open-alert row (click) | Same pattern | Working | `pages/SecurityOperationsPage.tsx:192-199` | — |

## Alerts (`/monitoring/alerts`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Severity filter select | Real query param | Working | `pages/AlertsPage.tsx:42-52` | — |
| Status filter select | Real query param | Working | `pages/AlertsPage.tsx:53-63` | — |
| Alert title (click) | Real navigation | Working | `pages/AlertsPage.tsx:112-118` | — |
| "Acknowledge" | Real `useAcknowledgeAlert` | Working | `pages/AlertsPage.tsx:128` | — |
| "Resolve" | Real `useResolveAlert` | Working | `pages/AlertsPage.tsx:132` | — |
| "Dismiss" | Real `useDismissAlert` | Working | `pages/AlertsPage.tsx:133` | — |

## Alert detail (`/monitoring/alerts/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Back to Alerts" (x2) | Real navigation | Working | `pages/AlertDetailPage.tsx:38,47` | — |
| "Acknowledge"/"Resolve"/"Dismiss" | Real mutations, same hooks as Alerts list | Working | `pages/AlertDetailPage.tsx:65,69,70` | — |

## Monitoring rules (`/monitoring/rules`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Show disabled rules" checkbox | Real query param toggle | Working | `pages/MonitoringRulesPage.tsx:28-34` | — |
| "Seed Default Rules" (x2) | Real `useSeedRules` | Working | `pages/MonitoringRulesPage.tsx:36-38,94` | — |
| "Disable"/"Enable" (rule) | Real mutations | Working | `pages/MonitoringRulesPage.tsx:74-80` | — |
| "Delete" (rule) | Real `useDeleteRule`, fires immediately, no confirm | Working | `pages/MonitoringRulesPage.tsx:82-84` | Add a ConfirmDialog before this destructive action. |
| Create/Edit rule | No such UI exists anywhere on the page, despite `useCreateRule`/`useUpdateRule` and their backend calls already being fully implemented and query-invalidated — just never rendered | Dead-A | `pages/MonitoringRulesPage.tsx` (whole page) | Add a create/edit form; the mutation plumbing is already done and tested. |

## Monitoring timeline (`/monitoring/timeline`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Tabs (Events/Alerts) | Real tab state | Working | `pages/MonitoringTimelinePage.tsx:32-36` | — |
| Alert row (click) | Real navigation | Working | `pages/MonitoringTimelinePage.tsx:74-80` | — |

## Notifications (`/notifications`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "All notifications" header label | Static text, not a control — sits where a mark-all-read/filter/settings control would be expected | Unsure | `pages/NotificationsPage.tsx:13-16` | Not misleading alone, but see the row below for what's actually missing. |
| "Refresh" | Real `refetch()` | Working | `components/features/monitoring/NotificationList.tsx:52` | — |
| "Mark as read" (per item) | Real `useMarkNotificationRead` → `notificationsApi.markRead` | Working | `components/features/monitoring/NotificationItem.tsx:75-81` | — |
| "Delete" (per item) | Real `useDeleteNotification` → `notificationsApi.delete` | Working | `components/features/monitoring/NotificationItem.tsx:84-90` | — |
| Mark-all-read / filters / settings / pagination | None of these exist anywhere on the page. The backend notifications API itself only supports list/get/markRead/delete — no bulk-read or filter endpoint to build against | Dead-B | `pages/NotificationsPage.tsx` (whole page) | Genuine backend gap, not just a frontend wiring job — would need new bulk-read/filter endpoints first. |
| Header bell — fake unread indicator | `onClick` navigates correctly, but renders a **hardcoded, always-visible red dot** with no data binding. A fully-built replacement (`NotificationBadge.tsx`, computes a real unread count) exists and is unused outside its own test file | Dead-A | `components/layout/Header.tsx:61-68` | Swap the static dot for the existing `NotificationBadge` component. Very likely the direct cause of "Notifications feels inactive." |

## AI Assistant (`/ai`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Health" button | Real `refetchHealth()` | Working | `pages/AIAssistantPage.tsx:74-76` | — |
| Suggested-question chips | Real `chatMutation.mutateAsync` | Working | `pages/AIAssistantPage.tsx:114-121` | — |
| "Send" | Real POST to `/ai/chat` (not mocked), traced end-to-end | Working | `pages/AIAssistantPage.tsx:162-169` | — |
| Enter-to-send | Same real send path | Working | `pages/AIAssistantPage.tsx:55-60` | — |

## AI Copilot (`/copilot`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "+ New Investigation" | Real `useCreateConversation` | Working | `pages/AICopilotPage.tsx:275-277` | — |
| Conversation list item (click) | Real `useConversation(id)` | Working | `pages/AICopilotPage.tsx:282-297` | — |
| Chat/Evidence/Notes tab buttons | Real local tab state | Working | `pages/AICopilotPage.tsx:313-333` | — |
| "Export MD"/"Export JSON" | Real authenticated fetch + blob download | Working | `pages/AICopilotPage.tsx:337-342` | — |
| Prompt-template quick buttons | Real `useAskCopilot` mutation | Working | `pages/AICopilotPage.tsx:369-384` | — |
| "Templates" toggle | Real state toggle | Working | `pages/AICopilotPage.tsx:396-403` | — |
| "Send" (main input) + Enter-to-send | Real POST to `/copilot/ask`, traced end-to-end | Working | `pages/AICopilotPage.tsx:415-417,408-409` | — |
| Template chip / "Clear" (template) | Real state | Working | `pages/AICopilotPage.tsx:423-443` | — |
| Suggested-question chips (post-answer) | Populate input; intentional two-step (user still presses Send) | Working | `pages/AICopilotPage.tsx:463-472` | — |
| "+ Add Note" / Cancel / Save Note | Real `createNote.mutate` | Working | `pages/AICopilotPage.tsx:556,124,126` | — |
| Pin/Unpin note | Real `pinNote.mutate`/`unpinNote.mutate` | Working | `pages/AICopilotPage.tsx:581` | — |
| Edit note (open/cancel/save) | Real `updateNote.mutate` | Working | `pages/AICopilotPage.tsx:588,613,614` | — |
| "Delete" note | Real `deleteNote.mutate`, fires immediately, no confirm | Working | `pages/AICopilotPage.tsx:595` | Add a ConfirmDialog. |
| Copy code block | Real clipboard write | Working | `components/features/copilot/MarkdownBlock.tsx:36-40` | — |

## Threat intelligence dashboard (`/threat-intelligence`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| ErrorState retry | Real refetch | Working | `pages/ThreatIntelligenceDashboard.tsx:26` | — |
| Trending/critical CVE links | Real navigation to CVE detail | Working | `pages/ThreatIntelligenceDashboard.tsx:85,108` | — |

## CVE explorer (`/threat-intelligence/cves`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Search" | Real `useCves(filter)` | Working | `pages/CveExplorerPage.tsx:54` | — |
| "Sync CVE" | Real `useSyncCve` | Working | `pages/CveExplorerPage.tsx:64-66` | — |
| Severity filter / "KEV Only" toggle | Real query params | Working | `pages/CveExplorerPage.tsx:74-88` | — |
| CVE code link | Real navigation | Working | `pages/CveExplorerPage.tsx:100-105` | — |
| "Delete" (per CVE) | Real `useDeleteCve`, fires immediately, no confirm | Working | `pages/CveExplorerPage.tsx:122-127` | Add a ConfirmDialog. |
| Pagination | Real state | Working | `pages/CveExplorerPage.tsx:141-145` | — |

## CVE detail (`/threat-intelligence/cves/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Re-sync" | Real `useSyncCve` | Working | `pages/CveDetailPage.tsx:32-34` | — |
| Reference links | Real external links | Working | `pages/CveDetailPage.tsx:71` | — |

## KEV view (`/threat-intelligence/kev`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Search input | Real `useKevEntries` refetch | Working | `pages/KevViewPage.tsx:31` | — |
| "Ransomware Campaign Only" checkbox | Real query param | Working | `pages/KevViewPage.tsx:35` | — |
| CVE code link | Real navigation | Working | `pages/KevViewPage.tsx:51` | — |
| Pagination | Real state | Working | `pages/KevViewPage.tsx:78` | — |

## Threat timeline (`/threat-intelligence/timeline`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Days select (7/30/90) | Real `useTITimeline(days)` refetch | Working | `pages/ThreatTimelinePage.tsx:17-25` | — |
| CVE code link | Real navigation | Working | `pages/ThreatTimelinePage.tsx:42` | — |

## Workers (`/workers`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Register Worker"/"Cancel" | Real state toggle | Working | `pages/WorkersPage.tsx:46-48` | — |
| "Register" (form) | Real `useRegisterWorker` | Working | `pages/WorkersPage.tsx:66` | — |
| Register form fields (5 inputs) | Real onChange handlers, but use `className="input"` — a CSS class that **does not exist anywhere in the project** — fields render completely unstyled | Dead-A | `pages/WorkersPage.tsx:55-59` | Swap to the shared Input component / existing styling used everywhere else. |
| Worker card (click) | Real navigation | Working | `pages/WorkersPage.tsx:72` | — |
| "Remove" worker | Real `useDeleteWorker`, fires immediately, no confirm (contrast with detail page, which does confirm the same action) | Working | `pages/WorkersPage.tsx:89-91` | Add a ConfirmDialog for consistency with WorkerDetailPage. |

## Worker detail (`/workers/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Back" | Real navigation | Working | `pages/WorkerDetailPage.tsx:41` | — |
| "Remove Worker" | Opens real ConfirmDialog → real `useDeleteWorker` | Working | `pages/WorkerDetailPage.tsx:42,90-99` | — |

## Queue (`/queue`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Queue/Dead Letter tabs | Real tab state, real counts | Working | `pages/QueuePage.tsx:53-54` | — |
| State filter buttons | Real `useQueue(stateFilter)` | Working | `pages/QueuePage.tsx:62-66` | — |
| Queue entry card (click) | Real navigation | Working | `pages/QueuePage.tsx:72` | — |
| "Retry" (failed jobs) | Real `useRetryJob` | Working | `pages/QueuePage.tsx:86` | — |
| "Cancel" | Opens real ConfirmDialog → `useCancelJob` | Working | `pages/QueuePage.tsx:89,121-130` | — |
| "Requeue" (dead-letter) | Real `useRequeueDeadLetter` | Working | `pages/QueuePage.tsx:113` | — |
| Job ID / error message text | No `truncate`/`break-all` on long IDs or error strings sitting in a flex row — overflow risk on narrow viewports | Dead-A | `pages/QueuePage.tsx:75,82,107` | Add truncate/break-all, same pattern used correctly elsewhere in the app. |

## Job detail (`/queue/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Back" | Real navigation | Working | `pages/JobDetailPage.tsx:39` | — |
| "Retry" | Real `useRetryJob` | Working | `pages/JobDetailPage.tsx:40` | — |
| "Cancel" | Real `useCancelJob`, no confirm (QueuePage's own cancel action does confirm the same operation) | Working | `pages/JobDetailPage.tsx:41` | Add a ConfirmDialog for consistency. |

## Compliance dashboard (`/compliance`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| ErrorState retry | Real `useFrameworks` refetch | Working | `pages/ComplianceDashboardPage.tsx:59` | — |
| Tabs (Overview/Frameworks/Gap Analysis/Reports) | Real tab switch mechanism | Working | `pages/ComplianceDashboardPage.tsx:69-72` | — |
| Framework select | Real `useFrameworkControls` | Working | `pages/ComplianceDashboardPage.tsx:122-133` | — |
| "Frameworks" tile | Computed live from `frameworks?.length` | Working | `pages/ComplianceDashboardPage.tsx:82` | — |
| "Supported: 8" tile | Hardcoded literal, currently accurate (8 frameworks really are defined on the backend) but not computed — see detailed investigation below | Dead-A | `pages/ComplianceDashboardPage.tsx:90` | Compute from `frameworks?.length` like the tile next to it, so the two can't silently diverge. |
| "Mapping: Auto" tile | Hardcoded literal, accurately describes the real keyword-based backend mapper — see detailed investigation below | Dead-A | `pages/ComplianceDashboardPage.tsx:99` | Fine as static copy; restyle so it doesn't look like a live KPI next to ones that are. |
| "Reports: 3" tile | Hardcoded literal, accurately matches the 3 real backend report types — see detailed investigation below | Dead-A | `pages/ComplianceDashboardPage.tsx:108` | Same as above — restyle as a caption, not a stat tile. |
| Coverage chart "--%" | Shows "--%" for every framework, but with an honest caption ("Connect findings to see coverage") explaining why | Working | `pages/ComplianceDashboardPage.tsx:33-34` | Correctly self-explains as a placeholder — the model example of "disabled with a reason" in this whole audit. |
| Gap Analysis tab | Pure instructional text, no controls. Backing `analyzeGaps` endpoint exists, never called | Dead-B | `pages/ComplianceDashboardPage.tsx:175-189` | Needs a real gap-analysis flow built, not a wiring fix. |
| Reports tab | Pure descriptive cards, no controls. Backing `generateReport` endpoint exists, never called | Dead-B | `pages/ComplianceDashboardPage.tsx:192-214` | Needs a real generate/preview/download flow built. |

## Asset inventory (`/assets`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Asset card (click) | Real navigation | Working | `pages/AssetInventoryPage.tsx:49,52` | — |
| ErrorState retry | Real refetch | Working | `pages/AssetInventoryPage.tsx:115` | — |
| Search box | Debounced, real query | Working | `pages/AssetInventoryPage.tsx:151-156` | — |
| Type/Criticality filter selects | Real query params | Working | `pages/AssetInventoryPage.tsx:157-177` | — |
| Pagination | Real offset param | Working | `pages/AssetInventoryPage.tsx:192` | — |

## Asset detail (`/assets/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Back to Inventory" (x2) | Real navigation | Working | `pages/AssetDetailPage.tsx:43,64` | — |
| Tabs (Overview/Details/Tags/Technologies/Relationships/History) | Real tab state, all real query-backed content | Working | `pages/AssetDetailPage.tsx:90-95` | — |
| "Add Tag" | Real `assetsApi.addTag` | Working | `pages/AssetDetailPage.tsx:177` | — |
| Remove-tag (×) | Real `assetsApi.removeTag` | Working | `pages/AssetDetailPage.tsx:184` | — |
| "Recalculate Risk" / "Change Criticality" | No such buttons exist anywhere on the page, despite `useRecalculateRisk`/`useUpdateCriticality` already being fully implemented against real backend endpoints | Dead-A | `pages/AssetDetailPage.tsx` (whole page) | Add the two missing buttons — hooks and API are already done. |
| 8 "Details" rows (Cloud Provider, Container Runtime, etc.) | Wired to literal `null` constants, then filtered out — can never render under any data | Dead-A | `pages/AssetDetailPage.tsx:141-146` | Delete the dead rows, or replace with real field lookups. |

## Attack surface (`/attack-surface`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Exposure card (click) | Real navigation | Working | `pages/AttackSurfacePage.tsx:24,27` | — |
| Search box | Real query, but no debounce — fires on every keystroke | Dead-A | `pages/AttackSurfacePage.tsx:116-121` | Add the same `useDebouncedValue` used on Asset Inventory. |
| Severity/Status filter selects | Real query params | Working | `pages/AttackSurfacePage.tsx:122-142` | — |
| Pagination | **Does not exist**, despite the API supporting `limit`/`offset` and a total count being displayed — results beyond the first page are unreachable | Dead-A | `pages/AttackSurfacePage.tsx` (whole page) | Add the same Pagination component already used on Asset Inventory. |
| Summary error/retry state | Only destructures `data`/`isLoading` — a failed summary fetch silently shows all-zero stats with no retry | Dead-A | `pages/AttackSurfacePage.tsx:65` | Add the isError/retry pattern already used on Asset Inventory's equivalent fetch. |

## Attack surface detail (`/attack-surface/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Back to Attack Surface" (x2) | Real navigation | Working | `pages/AttackSurfaceDetailPage.tsx:42,62` | — |
| "Mitigate" | Real mutation fires correctly, but its success handler invalidates the wrong query key — this page's own `['exposure', id]` never gets refreshed, so the button can look like it did nothing until you navigate away and back | Dead-A | `pages/AttackSurfaceDetailPage.tsx:86-88` | One-line fix: add the specific exposure id to the invalidation key in `useMitigateExposure`. |
| Tabs (Overview/Details/Remediation/History) | Real tab state | Working | `pages/AttackSurfaceDetailPage.tsx:95-98` | — |
| "Save Remediation" | Real `useUpdateRemediation`, correctly invalidates its own query | Working | `pages/AttackSurfaceDetailPage.tsx:194-196` | — |
| Evidence / header-value text | No truncate/break-all/wrap — the URL field on the same page correctly uses `break-all`, these don't | Dead-A | `pages/AttackSurfaceDetailPage.tsx:150-155` | Apply the same break-all pattern already used for the URL field, two rows away. |

---

## Deep-dive: Compliance dashboard hardcoded stats

See the full write-up in the accompanying investigation notes. Short version:
"Supported: 8", "Mapping: Auto / keyword-based", and "Reports: 3" are all
literal constants — but all three are currently **true, accurate facts about
the platform's capabilities**, not fabricated example data or a fictional
compliance score. None of them describe a customer's specific environment, so
the risk of a customer mistaking them for their own live compliance posture is
low. The real problem is presentational: they sit in KPI-styled tiles
identical to the one genuinely live metric next to them ("Frameworks"),
inviting the assumption that all four are computed the same way. Full detail
in the deliverable summary.

## Deep-dive: the three disabled-despite-working-backend buttons

Investigated via git log/blame, code comments, TODO search, feature-flag
search, CHANGELOG.md/ROADMAP.md, and license feature-gating. **No reason was
found for any of the three.** All three were introduced already-disabled in
the original feature commit (`1fe86f8`, "phase32: add deployment, licensing,
diagnostics and release infrastructure") with no comment or rationale. A
later commit (`22eceb1`) fixed the real backend wiring for the rest of these
same pages and files, but did not touch these three buttons at all — they
were simply never revisited. No feature-flag system exists anywhere in this
codebase. No TODO/FIXME near any of the three. No related entry in
CHANGELOG.md or ROADMAP.md. No permission/license gate applies beyond the
page-level admin RoleGuard, which doesn't explain button-level disabling.
Full detail in the deliverable summary — reported as "unknown, no evidence
found" per the task's instruction not to assume.
