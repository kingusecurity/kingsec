import { useCallback } from "react"
import { create } from "zustand"
import { persist } from "zustand/middleware"
import type { AppearanceSettings, NotificationSettings, ScannerSettings } from "../types"

interface LocalSettingsState {
  appearance: AppearanceSettings
  notifications: NotificationSettings
  scanner: ScannerSettings
  updateAppearance: (settings: Partial<AppearanceSettings>) => void
  updateNotifications: (settings: Partial<NotificationSettings>) => void
  updateScanner: (settings: Partial<ScannerSettings>) => void
}

export const useLocalSettings = create<LocalSettingsState>()(
  persist(
    (set) => ({
      appearance: {
        theme: "dark",
        compact_mode: false,
        sidebar_collapsed: false,
      },
      notifications: {
        browser_notifications: false,
        sse_notifications: true,
        email_notifications: false,
        report_generated: true,
        scan_completed: true,
        scan_failed: true,
        security_alerts: true,
      },
      scanner: {
        default_scan_profile: "full",
        timeout_seconds: 300,
        concurrent_jobs: 3,
        auto_generate_report: true,
        auto_delete_reports: false,
      },
      updateAppearance: (settings) =>
        set((state) => ({
          appearance: { ...state.appearance, ...settings },
        })),
      updateNotifications: (settings) =>
        set((state) => ({
          notifications: { ...state.notifications, ...settings },
        })),
      updateScanner: (settings) =>
        set((state) => ({
          scanner: { ...state.scanner, ...settings },
        })),
    }),
    {
      name: "kingsec-settings",
    },
  ),
)

export function useAppearanceSettings() {
  const appearance = useLocalSettings((s) => s.appearance)
  const updateAppearance = useLocalSettings((s) => s.updateAppearance)
  return { settings: appearance, update: updateAppearance }
}

export function useNotificationSettings() {
  const notifications = useLocalSettings((s) => s.notifications)
  const updateNotifications = useLocalSettings((s) => s.updateNotifications)
  return { settings: notifications, update: updateNotifications }
}

export function useScannerSettings() {
  const scanner = useLocalSettings((s) => s.scanner)
  const updateScanner = useLocalSettings((s) => s.updateScanner)
  return { settings: scanner, update: updateScanner }
}
