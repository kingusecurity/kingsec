import { useCallback } from "react"
import { useNotificationSettings } from "../hooks/use-local-settings"
import { SettingsSection } from "../components/settings-section"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Card, CardContent } from "@/shared/ui/card"
import { Label } from "@/shared/ui/label"

interface ToggleProps {
  id: string
  label: string
  description: string
  checked: boolean
  onChange: (checked: boolean) => void
}

function Toggle({ id, label, description, checked, onChange }: ToggleProps): React.ReactElement {
  return (
    <div className="flex items-center justify-between">
      <div className="space-y-0.5">
        <Label htmlFor={id}>{label}</Label>
        <p className="text-xs text-[hsl(var(--muted-fg))]">{description}</p>
      </div>
      <input
        id={id}
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="size-4 rounded border-[hsl(var(--border))] accent-[hsl(var(--primary))]"
      />
    </div>
  )
}

export function NotificationSettingsPage(): React.ReactElement {
  const { settings, update } = useNotificationSettings()

  return (
    <ErrorBoundary>
      <SettingsSection
        title="Notifications"
        description="Configure how you receive notifications."
      >
        <Card>
          <CardContent className="p-6 space-y-6">
            <div className="space-y-4">
              <h4 className="text-sm font-medium text-[hsl(var(--fg))]">Channels</h4>
              <Toggle
                id="browser"
                label="Browser Notifications"
                description="Receive push notifications in your browser."
                checked={settings.browser_notifications}
                onChange={(v) => update({ browser_notifications: v })}
              />
              <Toggle
                id="sse"
                label="SSE Notifications"
                description="Receive real-time notifications via Server-Sent Events."
                checked={settings.sse_notifications}
                onChange={(v) => update({ sse_notifications: v })}
              />
              <Toggle
                id="email"
                label="Email Notifications"
                description="Receive notifications via email."
                checked={settings.email_notifications}
                onChange={(v) => update({ email_notifications: v })}
              />
            </div>

            <div className="border-t border-[hsl(var(--border))] pt-4 space-y-4">
              <h4 className="text-sm font-medium text-[hsl(var(--fg))]">Events</h4>
              <Toggle
                id="report-generated"
                label="Report Generated"
                description="Notify when a report is generated."
                checked={settings.report_generated}
                onChange={(v) => update({ report_generated: v })}
              />
              <Toggle
                id="scan-completed"
                label="Scan Completed"
                description="Notify when a scan completes."
                checked={settings.scan_completed}
                onChange={(v) => update({ scan_completed: v })}
              />
              <Toggle
                id="scan-failed"
                label="Scan Failed"
                description="Notify when a scan fails."
                checked={settings.scan_failed}
                onChange={(v) => update({ scan_failed: v })}
              />
              <Toggle
                id="security-alerts"
                label="Security Alerts"
                description="Notify on security events."
                checked={settings.security_alerts}
                onChange={(v) => update({ security_alerts: v })}
              />
            </div>
          </CardContent>
        </Card>
      </SettingsSection>
    </ErrorBoundary>
  )
}
