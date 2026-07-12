import { useState, useCallback, lazy, Suspense, useMemo } from "react"
import { NavLink, useLocation } from "react-router-dom"
import {
  User,
  Palette,
  Shield,
  Bell,
  ScanSearch,
  Key,
  Settings,
  ArrowLeft,
} from "lucide-react"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Button } from "@/shared/ui/button"
import { cn } from "@/shared/lib/utils"
import { ROUTES } from "@/shared/lib/constants"
import type { SettingsSection } from "../types"

const ProfileSettingsPage = lazy(() => import("./profile-settings-page").then(m => ({ default: m.ProfileSettingsPage })))
const AppearanceSettingsPage = lazy(() => import("./appearance-settings-page").then(m => ({ default: m.AppearanceSettingsPage })))
const SecuritySettingsPage = lazy(() => import("./security-settings-page").then(m => ({ default: m.SecuritySettingsPage })))
const NotificationSettingsPage = lazy(() => import("./notification-settings-page").then(m => ({ default: m.NotificationSettingsPage })))
const ScannerSettingsPage = lazy(() => import("./scanner-settings-page").then(m => ({ default: m.ScannerSettingsPage })))
const ApiKeysSettingsPage = lazy(() => import("./api-keys-settings-page").then(m => ({ default: m.ApiKeysSettingsPage })))
const AdvancedSettingsPage = lazy(() => import("./advanced-settings-page").then(m => ({ default: m.AdvancedSettingsPage })))

const SETTINGS_NAV: Array<{ id: SettingsSection; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { id: "profile", label: "Profile", icon: User },
  { id: "appearance", label: "Appearance", icon: Palette },
  { id: "security", label: "Security", icon: Shield },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "scanner", label: "Scanner", icon: ScanSearch },
  { id: "api-keys", label: "API Keys", icon: Key },
  { id: "advanced", label: "Advanced", icon: Settings },
]

function SettingsPageFallback(): React.ReactElement {
  return (
    <div className="space-y-3 p-4">
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="skeleton h-10 rounded-lg" />
      ))}
    </div>
  )
}

export function SettingsPage(): React.ReactElement {
  const location = useLocation()
  const activeSection = useMemo(() => {
    const path = location.pathname
    const segment = path.split("/settings/")[1]
    return (segment as SettingsSection) || "profile"
  }, [location.pathname])

  const renderContent = useCallback(() => {
    switch (activeSection) {
      case "profile": return <ProfileSettingsPage />
      case "appearance": return <AppearanceSettingsPage />
      case "security": return <SecuritySettingsPage />
      case "notifications": return <NotificationSettingsPage />
      case "scanner": return <ScannerSettingsPage />
      case "api-keys": return <ApiKeysSettingsPage />
      case "advanced": return <AdvancedSettingsPage />
      default: return <ProfileSettingsPage />
    }
  }, [activeSection])

  return (
    <ErrorBoundary>
      <div className="p-6">
        <div className="mb-6 flex items-center gap-4">
          <Button variant="ghost" size="sm" onClick={() => window.history.back()}>
            <ArrowLeft className="mr-2 size-4" />
            Back
          </Button>
          <div>
            <h1 className="text-2xl font-bold text-[hsl(var(--fg))]">Settings</h1>
            <p className="text-sm text-[hsl(var(--muted-fg))]">Configure your KingSec instance.</p>
          </div>
        </div>

        <div className="flex gap-6">
          {/* Sidebar */}
          <nav className="w-48 shrink-0 space-y-1" aria-label="Settings navigation">
            {SETTINGS_NAV.map((item) => (
              <NavLink
                key={item.id}
                to={`/settings/${item.id}`}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                    isActive
                      ? "bg-[hsl(var(--primary))]/10 text-[hsl(var(--primary))]"
                      : "text-[hsl(var(--muted-fg))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--fg))]",
                  )
                }
              >
                <item.icon className="size-4 shrink-0" />
                {item.label}
              </NavLink>
            ))}
          </nav>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <Suspense fallback={<SettingsPageFallback />}>
              {renderContent()}
            </Suspense>
          </div>
        </div>
      </div>
    </ErrorBoundary>
  )
}
