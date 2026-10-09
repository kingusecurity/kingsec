import { useMemo } from 'react'
import { useLocation } from 'react-router-dom'

const labelMap: Record<string, string> = {
  dashboard: 'Dashboard',
  assessments: 'Assessments',
  new: 'New Assessment',
  settings: 'Settings',
  reports: 'Reports',
  findings: 'Findings',
  schedules: 'Schedules',
  monitor: 'Monitor',
  monitoring: 'Security Operations',
  notifications: 'Notifications',
  audit: 'Audit Log',
  administration: 'Administration',
  admin: 'Administration',
  users: 'Users',
  roles: 'Roles & Permissions',
  grants: 'Authorization Grants',
  assets: 'Assets',
  'attack-surface': 'Attack Surface',
  compliance: 'Compliance',
  'threat-intelligence': 'Threat Intelligence',
  cves: 'CVEs',
  kev: 'Known Exploited Vulnerabilities',
  playbooks: 'Playbooks',
  history: 'Execution History',
  plugins: 'Plugins',
  workers: 'Workers',
  queue: 'Job Queue',
  identity: 'Identity Providers',
  backup: 'Backup',
  recovery: 'Recovery Plans',
  deployment: 'Deployment',
  license: 'License',
  diagnostics: 'Diagnostics',
  'release-audit': 'Release Audit',
}

const detailLabelMap: Record<string, string> = {
  assessments: 'Assessment',
  assets: 'Asset',
  'attack-surface': 'Exposure',
  alerts: 'Alert',
  cves: 'CVE',
  playbooks: 'Playbook',
  workers: 'Worker',
  queue: 'Job',
  identity: 'Identity Provider',
  backup: 'Backup',
}

export interface BreadcrumbItem {
  label: string
  href: string
  isCurrent: boolean
}

export function buildBreadcrumbs(pathname: string): BreadcrumbItem[] {
  const normalizedPath = pathname.length > 1 ? pathname.replace(/\/$/, '') : pathname
  const segments = normalizedPath.split('/').filter(Boolean)
  if (segments.length === 0) {
    return [{ label: 'Dashboard', href: '/dashboard', isCurrent: true }]
  }

  // There is no route at /assessments/:id/findings. Do not create a
  // breadcrumb link to that dead end; link back to the owning assessment.
  if (
    segments.length === 4
    && segments[0] === 'assessments'
    && segments[2] === 'findings'
  ) {
    const assessmentHref = `/assessments/${segments[1]}`
    return [
      { label: 'Assessments', href: '/assessments', isCurrent: false },
      { label: 'Assessment', href: assessmentHref, isCurrent: false },
      { label: 'Finding', href: normalizedPath, isCurrent: true },
    ]
  }

  // Recovery-plan detail is nested for routing purposes, but /backup/recovery
  // is not a page. Keep the only navigable ancestor in the trail.
  if (
    segments.length === 3
    && segments[0] === 'backup'
    && segments[1] === 'recovery'
  ) {
    return [
      { label: 'Backup', href: '/backup', isCurrent: false },
      { label: 'Recovery Plan', href: normalizedPath, isCurrent: true },
    ]
  }

  const items: BreadcrumbItem[] = []
  let accumulated = ''

  for (const [index, segment] of segments.entries()) {
    accumulated += `/${segment}`
    const mappedLabel = labelMap[segment.toLowerCase()]
    const isUnmappedDetail = !mappedLabel && index === segments.length - 1 && index > 0
    const label = mappedLabel
      ?? (isUnmappedDetail
        ? detailLabelMap[segments[index - 1]?.toLowerCase() ?? ''] ?? 'Details'
        : segment.charAt(0).toUpperCase() + segment.slice(1))

    items.push({
      label,
      href: accumulated,
      isCurrent: accumulated === normalizedPath,
    })
  }

  return items
}

export function useBreadcrumbs(): BreadcrumbItem[] {
  const { pathname } = useLocation()

  return useMemo(() => buildBreadcrumbs(pathname), [pathname])
}
