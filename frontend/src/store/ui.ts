import { create } from 'zustand'

interface DashboardPreferences {
  defaultPage: string
  refreshInterval: number
  showQuickActions: boolean
  showRecentAssessments: boolean
  showSystemStatus: boolean
  showJobStatus: boolean
}

interface NotificationPreferences {
  assessmentNotifications: boolean
  reportNotifications: boolean
  systemNotifications: boolean
  emailNotifications: boolean
}

interface UIState {
  sidebarCollapsed: boolean
  sidebarMobileOpen: boolean
  toggleSidebar: () => void
  setSidebarCollapsed: (collapsed: boolean) => void
  setSidebarMobileOpen: (open: boolean) => void
  closeMobileSidebar: () => void
  dashboardPreferences: DashboardPreferences
  setDashboardPreferences: (prefs: Partial<DashboardPreferences>) => void
  notificationPreferences: NotificationPreferences
  setNotificationPreferences: (prefs: Partial<NotificationPreferences>) => void
}

const defaultDashboardPreferences: DashboardPreferences = {
  defaultPage: 'dashboard',
  refreshInterval: 30,
  showQuickActions: true,
  showRecentAssessments: true,
  showSystemStatus: true,
  showJobStatus: true,
}

const defaultNotificationPreferences: NotificationPreferences = {
  assessmentNotifications: true,
  reportNotifications: true,
  systemNotifications: true,
  emailNotifications: false,
}

function loadPrefs<T>(key: string, defaults: T): T {
  try {
    const stored = localStorage.getItem(key)
    if (stored) return JSON.parse(stored) as T
  } catch {}
  return defaults
}

function savePrefs<T>(key: string, prefs: T) {
  try {
    localStorage.setItem(key, JSON.stringify(prefs))
  } catch {}
}

export const useUIStore = create<UIState>((set) => ({
  sidebarCollapsed: false,
  sidebarMobileOpen: false,
  dashboardPreferences: loadPrefs('kingsec-dashboard-prefs', defaultDashboardPreferences),
  notificationPreferences: loadPrefs('kingsec-notification-prefs', defaultNotificationPreferences),

  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
  setSidebarMobileOpen: (open) => set({ sidebarMobileOpen: open }),
  closeMobileSidebar: () => set({ sidebarMobileOpen: false }),

  setDashboardPreferences: (prefs) =>
    set((s) => {
      const updated = { ...s.dashboardPreferences, ...prefs }
      savePrefs('kingsec-dashboard-prefs', updated)
      return { dashboardPreferences: updated }
    }),

  setNotificationPreferences: (prefs) =>
    set((s) => {
      const updated = { ...s.notificationPreferences, ...prefs }
      savePrefs('kingsec-notification-prefs', updated)
      return { notificationPreferences: updated }
    }),
}))
