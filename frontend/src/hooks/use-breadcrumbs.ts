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
  notifications: 'Notifications',
  audit: 'Audit Log',
}

export interface BreadcrumbItem {
  label: string
  href: string
  isCurrent: boolean
}

export function useBreadcrumbs(): BreadcrumbItem[] {
  const { pathname } = useLocation()

  return useMemo(() => {
    const segments = pathname.split('/').filter(Boolean)
    if (segments.length === 0) {
      return [{ label: 'Dashboard', href: '/dashboard', isCurrent: true }]
    }

    const items: BreadcrumbItem[] = []
    let accumulated = ''

    for (const segment of segments) {
      accumulated += `/${segment}`

      const label =
        labelMap[segment.toLowerCase()] ??
        (segment.length === 36 && segment.includes('-') ? 'Details' : segment.charAt(0).toUpperCase() + segment.slice(1))

      items.push({
        label,
        href: accumulated,
        isCurrent: accumulated === pathname,
      })
    }

    return items
  }, [pathname])
}
