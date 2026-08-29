# KingSec Frontend Dead-Button Audit — Filtered to Actionable Rows — 2026-08

Filtered export of `dead-button-audit-2026-08.md` (the full ~345-row audit)
down to only the rows categorized **Dead-A**, **Dead-B**, or **Unsure** — the
~308 **Working** rows have been dropped. Pure extraction: no re-audit, no new
analysis, no fixes. Screens with zero non-Working rows are omitted entirely;
everything else keeps its original wording, file:line references, and
recommendation exactly as written in the source file.

The full, unfiltered audit remains at `dead-button-audit-2026-08.md` — this
file is an additional export, not a replacement.

Categories:
- **Dead-A** — trivial to finish: the backend endpoint already exists and works, frontend just isn't calling it.
- **Dead-B** — genuinely incomplete: backend support doesn't exist yet, or the frontend work is a larger effort (form-building, new flow).
- **Unsure** — flagged, needs a second opinion rather than a guess.

## Summary

| Category | Count in this filtered file |
|---|---|
| Dead-A | 26 |
| Dead-B | 10 |
| Unsure | 2 |
| Mixed working/dead-B (ScannerHealthPanel, Live Activity instance) | 1 |
| **Total rows in this file** | **39** |

Note: the source file's own summary line rounds these to "~22 Dead-A / ~9
Dead-B / ~6 Unsure." A literal count of rows tagged exactly `Dead-A`,
`Dead-B`, or `Unsure` in that file gives the figures above instead (26 / 10 /
2) — Dead-A and Dead-B are close to the source's rounded estimate, Unsure is
not. Reported as found, per this task's pure-extraction scope — the source
file's summary line was left as-is, not corrected.

---

## Dashboard (`/dashboard`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| ScannerHealthPanel "Export Markdown" | `window.open('/scanners/{id}/diagnostics?fmt=markdown')` — **confirmed against the backend: no such route exists** (`/deployment/diagnostics*` are the only diagnostics routes; `scanner-health.ts`'s API client has no export function either) | Dead-B | `components/features/monitoring/ScannerHealthPanel.tsx:324-334` | Will 404 or hit the SPA catch-all. Build a real scanner-specific export endpoint, or remove the buttons. |
| ScannerHealthPanel "Export Text" | Same pattern as above, `fmt=text` | Dead-B | `components/features/monitoring/ScannerHealthPanel.tsx:335-345` | Same fix as Export Markdown. |

## Assessments list (`/assessments`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Search box | Updates URL/state correctly; **never reaches the actual query** — the params object sent to `useAssessments` only ever contains `limit`/`offset` | Dead-A | `components/features/assessment/AssessmentFilters.tsx:35-41` | Add `search` to the params object at `AssessmentsPage.tsx:32-35` — same pattern already correct on Reports/Findings pages. |
| Status filter select | Same root cause as Search box | Dead-A | `components/features/assessment/AssessmentFilters.tsx:43-57` | Add `status` to the query params. |
| Sort-by select | Same root cause | Dead-A | `components/features/assessment/AssessmentFilters.tsx:58-69` | Add `sort_by` to the query params. |
| Sort-order select | Same root cause | Dead-A | `components/features/assessment/AssessmentFilters.tsx:70-79` | Add `sort_order` to the query params. |

## Finding detail (`/assessments/:id/findings/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Recommendation details | Shows a real count, but renders only a static placeholder sentence in place of actual content — no button/link to view them either | Dead-B | `components/features/findings/FindingRecommendations.tsx:29-32` | Needs a real recommendations fetch + render — content gap, not a mechanical fix. |

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
| Version string | Hardcoded literal `"1.0.0"`, not sourced from any API — will drift from the real app version | Dead-A | `components/features/settings/AboutSection.tsx:26` | Read from `deploymentApi.getSystemInfo`, already used elsewhere for the same data. |

## Identity providers (`/identity`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Provider name/issuer text (list view) | No `truncate`/`title` — a long issuer URL can overflow the row; the detail page truncates the same fields correctly | Dead-A | `pages/IdentityProvidersPage.tsx:116-123` | Add the same truncate + title pattern already used on the detail page. |

## Backup center (`/backup`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Recovery plan row (click) | Navigates to `/backup/recovery/{id}` — **confirmed against the router: this route does not exist**, and no recovery-plan detail page component exists at all | Dead-B | `pages/BackupCenterPage.tsx:223` | Genuinely missing page, not a one-line fix — build a detail view, or make the row non-clickable and show details inline. |

## Deployment (`/deployment`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Check for Updates" | `disabled`, no `onClick`, no tooltip. `deploymentApi.getUpgradePlan` + `useUpgradePlan` hook already exist, hit a real working backend endpoint, and are simply never imported into this page | Dead-A | `pages/DeploymentPage.tsx:186-188` | Wire to the existing hook; show the plan in a modal. See disabled-button investigation below for why it was left off. |
| "View Changelog" | `disabled`, no handler, no tooltip | Dead-A | `pages/DeploymentPage.tsx:189-191` | Point at the existing, working `/release-audit` route — no new backend work needed. |

## Diagnostics (`/diagnostics`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Download Bundle" | `disabled`, no `onClick`, no tooltip. `deploymentApi.downloadDiagnostics` already exists and calls a real, working backend endpoint (built and verified this session) | Dead-A | `pages/DiagnosticsPage.tsx:124-126` | Wire to the existing blob-download pattern already used on Reports/AssessmentDetail's "Download" buttons. See disabled-button investigation below. |
| Scanner install/detection status | This page has **no per-scanner installed/optional/missing breakdown at all** — just one aggregate health badge. The real three-state UI lives in `ScannerHealthPanel.tsx` (Dashboard, Live Activity), not here | Unsure | `pages/DiagnosticsPage.tsx` (whole page) | Not necessarily this page's job — flagging since the audit explicitly asked about scanner-status clarity. Consider linking to it. |

## Playbook detail (`/playbooks/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Edit"/"Cancel" toggle | Toggles local `editing` state that is **never read anywhere else** in the component — no form appears, nothing changes visibly except the button's own label | Dead-B | `pages/PlaybookDetailPage.tsx:64` | Build a real edit form; a working update mutation (`useUpdatePlaybook`) already exists and is never called. |

## Schedules (`/schedules`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Entire create/edit/delete/pause/resume surface | **Does not exist.** No `api/schedules.ts` file; the only hooks are GET-only. Empty state tells users to "Create recurring assessment schedules" with no button anywhere to do it. The backend already has a full, working lifecycle (create/update/delete/pause/resume/enable/disable — confirmed directly against the backend this session) | Dead-B | `pages/SchedulesPage.tsx` (whole page) | Backend is fully ready — this is a bounded frontend build: an `api/schedules.ts` client plus create/edit forms and row actions. |
| Power/PowerOff status icons | Look like enable/disable toggles; have no `onClick` at all — purely decorative | Dead-A | `pages/SchedulesPage.tsx:49-53` | Wire to the enable/disable endpoints once the API client exists, or restyle so they don't read as controls. |

## Plugins (`/plugins`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Entire Marketplace tab | No install/configure/detail action on any card — the only thing in the action slot is a static license-string label. Backing endpoints (`getMarketplacePlugin`, `getPermissions`) and their hooks exist and are never called from anywhere in the app | Dead-B | `pages/PluginsSdkPage.tsx:117-152` | Directly matches the source assessment's "little visible customer value." Needs a real install/consent flow — or a product call on whether this tab belongs in v1 at all (flagged as borderline B/C). |

## Live activity (`/monitor`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| ScannerHealthPanel (shared component, same as Dashboard) | Refresh/filter/select/copy/close/export all present | Working (10) / Dead-B (2) | `components/features/monitoring/ScannerHealthPanel.tsx` | Export Markdown/Text buttons are the same confirmed-dead links as on Dashboard — one shared component, one fix covers both screens. |

## Monitoring rules (`/monitoring/rules`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Create/Edit rule | No such UI exists anywhere on the page, despite `useCreateRule`/`useUpdateRule` and their backend calls already being fully implemented and query-invalidated — just never rendered | Dead-A | `pages/MonitoringRulesPage.tsx` (whole page) | Add a create/edit form; the mutation plumbing is already done and tested. |

## Notifications (`/notifications`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "All notifications" header label | Static text, not a control — sits where a mark-all-read/filter/settings control would be expected | Unsure | `pages/NotificationsPage.tsx:13-16` | Not misleading alone, but see the row below for what's actually missing. |
| Mark-all-read / filters / settings / pagination | None of these exist anywhere on the page. The backend notifications API itself only supports list/get/markRead/delete — no bulk-read or filter endpoint to build against | Dead-B | `pages/NotificationsPage.tsx` (whole page) | Genuine backend gap, not just a frontend wiring job — would need new bulk-read/filter endpoints first. |
| Header bell — fake unread indicator | `onClick` navigates correctly, but renders a **hardcoded, always-visible red dot** with no data binding. A fully-built replacement (`NotificationBadge.tsx`, computes a real unread count) exists and is unused outside its own test file | Dead-A | `components/layout/Header.tsx:61-68` | Swap the static dot for the existing `NotificationBadge` component. Very likely the direct cause of "Notifications feels inactive." |

## Workers (`/workers`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Register form fields (5 inputs) | Real onChange handlers, but use `className="input"` — a CSS class that **does not exist anywhere in the project** — fields render completely unstyled | Dead-A | `pages/WorkersPage.tsx:55-59` | Swap to the shared Input component / existing styling used everywhere else. |

## Queue (`/queue`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Job ID / error message text | No `truncate`/`break-all` on long IDs or error strings sitting in a flex row — overflow risk on narrow viewports | Dead-A | `pages/QueuePage.tsx:75,82,107` | Add truncate/break-all, same pattern used correctly elsewhere in the app. |

## Compliance dashboard (`/compliance`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Supported: 8" tile | Hardcoded literal, currently accurate (8 frameworks really are defined on the backend) but not computed — see detailed investigation below | Dead-A | `pages/ComplianceDashboardPage.tsx:90` | Compute from `frameworks?.length` like the tile next to it, so the two can't silently diverge. |
| "Mapping: Auto" tile | Hardcoded literal, accurately describes the real keyword-based backend mapper — see detailed investigation below | Dead-A | `pages/ComplianceDashboardPage.tsx:99` | Fine as static copy; restyle so it doesn't look like a live KPI next to ones that are. |
| "Reports: 3" tile | Hardcoded literal, accurately matches the 3 real backend report types — see detailed investigation below | Dead-A | `pages/ComplianceDashboardPage.tsx:108` | Same as above — restyle as a caption, not a stat tile. |
| Gap Analysis tab | Pure instructional text, no controls. Backing `analyzeGaps` endpoint exists, never called | Dead-B | `pages/ComplianceDashboardPage.tsx:175-189` | Needs a real gap-analysis flow built, not a wiring fix. |
| Reports tab | Pure descriptive cards, no controls. Backing `generateReport` endpoint exists, never called | Dead-B | `pages/ComplianceDashboardPage.tsx:192-214` | Needs a real generate/preview/download flow built. |

## Asset detail (`/assets/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Recalculate Risk" / "Change Criticality" | No such buttons exist anywhere on the page, despite `useRecalculateRisk`/`useUpdateCriticality` already being fully implemented against real backend endpoints | Dead-A | `pages/AssetDetailPage.tsx` (whole page) | Add the two missing buttons — hooks and API are already done. |
| 8 "Details" rows (Cloud Provider, Container Runtime, etc.) | Wired to literal `null` constants, then filtered out — can never render under any data | Dead-A | `pages/AssetDetailPage.tsx:141-146` | Delete the dead rows, or replace with real field lookups. |

## Attack surface (`/attack-surface`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| Search box | Real query, but no debounce — fires on every keystroke | Dead-A | `pages/AttackSurfacePage.tsx:116-121` | Add the same `useDebouncedValue` used on Asset Inventory. |
| Pagination | **Does not exist**, despite the API supporting `limit`/`offset` and a total count being displayed — results beyond the first page are unreachable | Dead-A | `pages/AttackSurfacePage.tsx` (whole page) | Add the same Pagination component already used on Asset Inventory. |
| Summary error/retry state | Only destructures `data`/`isLoading` — a failed summary fetch silently shows all-zero stats with no retry | Dead-A | `pages/AttackSurfacePage.tsx:65` | Add the isError/retry pattern already used on Asset Inventory's equivalent fetch. |

## Attack surface detail (`/attack-surface/:id`)

| Element | Current Behavior | Category | File:Line | Recommendation |
|---|---|---|---|---|
| "Mitigate" | Real mutation fires correctly, but its success handler invalidates the wrong query key — this page's own `['exposure', id]` never gets refreshed, so the button can look like it did nothing until you navigate away and back | Dead-A | `pages/AttackSurfaceDetailPage.tsx:86-88` | One-line fix: add the specific exposure id to the invalidation key in `useMitigateExposure`. |
| Evidence / header-value text | No truncate/break-all/wrap — the URL field on the same page correctly uses `break-all`, these don't | Dead-A | `pages/AttackSurfaceDetailPage.tsx:150-155` | Apply the same break-all pattern already used for the URL field, two rows away. |
