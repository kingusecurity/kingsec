import { useCallback } from "react"
import { useThemeStore, THEMES, type ThemeName } from "@/shared/lib/theme-store"
import { useAppearanceSettings } from "../hooks/use-local-settings"
import { SettingsSection } from "../components/settings-section"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Card, CardContent } from "@/shared/ui/card"
import { Label } from "@/shared/ui/label"
import { Select } from "@/shared/ui/select"

export function AppearanceSettingsPage(): React.ReactElement {
  const { settings, update } = useAppearanceSettings()
  const setTheme = useThemeStore((s) => s.setTheme)

  const handleThemeChange = useCallback(
    (value: string) => {
      const theme = value as ThemeName
      setTheme(theme)
      update({ theme })
    },
    [setTheme, update],
  )

  const handleCompactModeChange = useCallback(
    (checked: boolean) => {
      update({ compact_mode: checked })
    },
    [update],
  )

  const handleSidebarCollapsedChange = useCallback(
    (checked: boolean) => {
      update({ sidebar_collapsed: checked })
    },
    [update],
  )

  return (
    <ErrorBoundary>
      <SettingsSection
        title="Appearance"
        description="Customize the look and feel of KingSec."
      >
        <Card>
          <CardContent className="p-6 space-y-6">
            <div className="space-y-2">
              <Label htmlFor="theme">Theme</Label>
              <Select id="theme" value={settings.theme} onChange={(e) => handleThemeChange(e.target.value)}>
                {THEMES.map((t) => (
                  <option key={t.name} value={t.name}>{t.label}</option>
                ))}
              </Select>
              <p className="text-xs text-[hsl(var(--muted-fg))]">
                Select a color theme for the application.
              </p>
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="compact">Compact Mode</Label>
                <p className="text-xs text-[hsl(var(--muted-fg))]">
                  Reduce spacing and padding throughout the UI.
                </p>
              </div>
              <input
                id="compact"
                type="checkbox"
                checked={settings.compact_mode}
                onChange={(e) => handleCompactModeChange(e.target.checked)}
                className="size-4 rounded border-[hsl(var(--border))] accent-[hsl(var(--primary))]"
              />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="sidebar">Sidebar Collapsed by Default</Label>
                <p className="text-xs text-[hsl(var(--muted-fg))]">
                  Start with the sidebar in collapsed state.
                </p>
              </div>
              <input
                id="sidebar"
                type="checkbox"
                checked={settings.sidebar_collapsed}
                onChange={(e) => handleSidebarCollapsedChange(e.target.checked)}
                className="size-4 rounded border-[hsl(var(--border))] accent-[hsl(var(--primary))]"
              />
            </div>
          </CardContent>
        </Card>
      </SettingsSection>
    </ErrorBoundary>
  )
}
