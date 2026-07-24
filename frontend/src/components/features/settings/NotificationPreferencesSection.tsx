import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Toggle } from '@/components/ui/Toggle'
import { useUIStore } from '@/store/ui'

export function NotificationPreferencesSection() {
  const prefs = useUIStore((s) => s.notificationPreferences)
  const setPrefs = useUIStore((s) => s.setNotificationPreferences)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Notification Preferences</CardTitle>
        <CardDescription>Choose which notifications you want to receive</CardDescription>
      </CardHeader>
      <div className="p-5 space-y-4">
        <Toggle
          label="Assessment Notifications"
          checked={prefs.assessmentNotifications}
          onChange={(e) => setPrefs({ assessmentNotifications: e.target.checked })}
        />
        <Toggle
          label="Report Notifications"
          checked={prefs.reportNotifications}
          onChange={(e) => setPrefs({ reportNotifications: e.target.checked })}
        />
        <Toggle
          label="System Notifications"
          checked={prefs.systemNotifications}
          onChange={(e) => setPrefs({ systemNotifications: e.target.checked })}
        />
        <Toggle
          label="Email Notifications"
          checked={prefs.emailNotifications}
          onChange={(e) => setPrefs({ emailNotifications: e.target.checked })}
        />
      </div>
    </Card>
  )
}
