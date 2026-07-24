import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Select } from '@/components/ui/Select'
import { Toggle } from '@/components/ui/Toggle'
import { useUIStore } from '@/store/ui'

const defaultPageOptions = [
  { value: 'dashboard', label: 'Dashboard' },
  { value: 'assessments', label: 'Assessments' },
  { value: 'findings', label: 'Findings' },
  { value: 'monitor', label: 'Monitor' },
]

const refreshOptions = [
  { value: '15', label: '15 seconds' },
  { value: '30', label: '30 seconds' },
  { value: '60', label: '1 minute' },
  { value: '300', label: '5 minutes' },
]

export function DashboardPreferencesSection() {
  const prefs = useUIStore((s) => s.dashboardPreferences)
  const setPrefs = useUIStore((s) => s.setDashboardPreferences)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Dashboard Preferences</CardTitle>
        <CardDescription>Configure your dashboard experience</CardDescription>
      </CardHeader>
      <div className="p-5 space-y-6">
        <Select
          label="Default Landing Page"
          value={prefs.defaultPage}
          onChange={(e) => setPrefs({ defaultPage: e.target.value })}
          options={defaultPageOptions}
        />
        <Select
          label="Dashboard Refresh Interval"
          value={String(prefs.refreshInterval)}
          onChange={(e) => setPrefs({ refreshInterval: Number(e.target.value) })}
          options={refreshOptions}
        />
        <div className="space-y-3">
          <p className="text-sm font-medium text-text-primary">Visible Widgets</p>
          <Toggle
            label="Show Quick Actions"
            checked={prefs.showQuickActions}
            onChange={(e) => setPrefs({ showQuickActions: e.target.checked })}
          />
          <Toggle
            label="Show Recent Assessments"
            checked={prefs.showRecentAssessments}
            onChange={(e) => setPrefs({ showRecentAssessments: e.target.checked })}
          />
          <Toggle
            label="Show System Status"
            checked={prefs.showSystemStatus}
            onChange={(e) => setPrefs({ showSystemStatus: e.target.checked })}
          />
          <Toggle
            label="Show Job Status"
            checked={prefs.showJobStatus}
            onChange={(e) => setPrefs({ showJobStatus: e.target.checked })}
          />
        </div>
      </div>
    </Card>
  )
}
