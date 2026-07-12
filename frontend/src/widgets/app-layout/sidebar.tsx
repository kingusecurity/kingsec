import { useState, useEffect, useCallback, useRef } from "react"
import { NavLink } from "react-router-dom"
import {
  LayoutDashboard, BarChart3, ScanSearch, Shield, FileText,
  Users, ScrollText, Settings, User, LogOut,
  ChevronLeft, ChevronRight, Menu, X,
} from "lucide-react"
import { useAuth } from "@/features/auth/hooks/use-auth"
import { ROUTES, ROLE_HIERARCHY } from "@/shared/lib/constants"
import { cn } from "@/shared/lib/utils"
import { Button } from "@/shared/ui/button"

const NAV_ITEMS = [
  { to: ROUTES.DASHBOARD, icon: LayoutDashboard, label: "Dashboard", roles: ["VIEWER", "ANALYST", "ADMIN"] },
  { to: ROUTES.ANALYTICS, icon: BarChart3, label: "Analytics", roles: ["VIEWER", "ANALYST", "ADMIN"] },
  { to: ROUTES.ASSESSMENTS, icon: ScanSearch, label: "Assessments", roles: ["VIEWER", "ANALYST", "ADMIN"] },
  { to: ROUTES.REPORTS, icon: FileText, label: "Reports", roles: ["VIEWER", "ANALYST", "ADMIN"] },
  { to: ROUTES.USERS, icon: Users, label: "Users", roles: ["ADMIN"] },
  { to: ROUTES.AUDIT, icon: ScrollText, label: "Audit Log", roles: ["ADMIN"] },
  { to: ROUTES.SETTINGS, icon: Settings, label: "Settings", roles: ["VIEWER", "ANALYST", "ADMIN"] },
] as const

interface MobileSidebarProps {
  open: boolean
  onClose: () => void
}

function MobileSidebar({ open, onClose }: MobileSidebarProps): React.ReactElement | null {
  const { user, logout } = useAuth()
  const overlayRef = useRef<HTMLDivElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const previousFocus = useRef<HTMLElement | null>(null)

  const filteredNav = NAV_ITEMS.filter((item) => {
    if (!user) return false
    return ROLE_HIERARCHY[user.role] >= ROLE_HIERARCHY[item.roles[item.roles.length - 1] as keyof typeof ROLE_HIERARCHY]
  })

  useEffect(() => {
    if (open) {
      previousFocus.current = document.activeElement as HTMLElement
      panelRef.current?.focus()
      document.body.style.overflow = "hidden"
    } else {
      document.body.style.overflow = ""
      previousFocus.current?.focus()
    }
    return () => { document.body.style.overflow = "" }
  }, [open])

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Escape") onClose()
    if (e.key === "Tab" && panelRef.current) {
      const focusable = panelRef.current.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )
      if (focusable.length === 0) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
  }, [onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
      <div
        ref={overlayRef}
        className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        ref={panelRef}
        tabIndex={-1}
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex w-72 flex-col bg-[hsl(var(--sidebar))] shadow-xl transition-transform duration-200",
          "data-[state=open]:translate-x-0 data-[state=closed]:-translate-x-full",
        )}
        onKeyDown={handleKeyDown}
        data-state={open ? "open" : "closed"}
      >
        <div className="flex h-14 items-center justify-between border-b border-[hsl(var(--border))] px-4">
          <div className="flex items-center gap-2">
            <Shield className="size-6 text-[hsl(var(--primary))]" aria-hidden="true" />
            <span className="text-lg font-bold text-[hsl(var(--fg))]">KingSec</span>
          </div>
          <Button variant="ghost" size="icon" className="size-8" onClick={onClose} aria-label="Close menu">
            <X className="size-4" />
          </Button>
        </div>

        <nav className="flex-1 space-y-1 p-2" aria-label="Main navigation">
          {filteredNav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={onClose}
              className={({ isActive }) => cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-[hsl(var(--primary))]/10 text-[hsl(var(--primary))]"
                  : "text-[hsl(var(--sidebar-fg))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--accent-fg))]",
              )}
            >
              <item.icon className="size-5 shrink-0" aria-hidden="true" />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-[hsl(var(--border))] p-2">
          <NavLink
            to={ROUTES.PROFILE}
            onClick={onClose}
            className={({ isActive }) => cn(
              "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
              isActive
                ? "bg-[hsl(var(--primary))]/10 text-[hsl(var(--primary))]"
                : "text-[hsl(var(--sidebar-fg))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--accent-fg))]",
            )}
          >
            <User className="size-5 shrink-0" aria-hidden="true" />
            <span>{user?.username ?? "User"}</span>
          </NavLink>
          <button
            onClick={() => { logout(); onClose() }}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-[hsl(var(--sidebar-fg))] transition-colors hover:bg-[hsl(var(--destructive))]/10 hover:text-[hsl(var(--destructive))]"
          >
            <LogOut className="size-5 shrink-0" aria-hidden="true" />
            <span>Logout</span>
          </button>
        </div>
      </div>
    </div>
  )
}

interface SidebarProps {
  onMobileMenuToggle?: () => void
}

export function Sidebar({ onMobileMenuToggle }: SidebarProps): React.ReactElement {
  const { user, logout } = useAuth()
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  const handleMobileOpen = useCallback(() => setMobileOpen(true), [])
  const handleMobileClose = useCallback(() => setMobileOpen(false), [])

  useEffect(() => {
    if (onMobileMenuToggle) {
      // Expose mobile open to parent
      ;(onMobileMenuToggle as unknown as { current: () => void }).current = handleMobileOpen
    }
  }, [onMobileMenuToggle, handleMobileOpen])

  const filteredNav = NAV_ITEMS.filter((item) => {
    if (!user) return false
    return ROLE_HIERARCHY[user.role] >= ROLE_HIERARCHY[item.roles[item.roles.length - 1] as keyof typeof ROLE_HIERARCHY]
  })

  return (
    <>
      {/* Desktop sidebar */}
      <aside
        className={cn(
          "hidden h-screen flex-col border-r border-[hsl(var(--border))] bg-[hsl(var(--sidebar))] transition-all duration-200 lg:flex",
          collapsed ? "w-16" : "w-64",
        )}
        aria-label="Sidebar"
      >
        <div className="flex h-14 items-center justify-between border-b border-[hsl(var(--border))] px-4">
          {!collapsed && (
            <div className="flex items-center gap-2">
              <Shield className="size-6 text-[hsl(var(--primary))]" aria-hidden="true" />
              <span className="text-lg font-bold text-[hsl(var(--fg))]">KingSec</span>
            </div>
          )}
          <Button
            variant="ghost"
            size="icon"
            className="size-8"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <ChevronRight className="size-4" /> : <ChevronLeft className="size-4" />}
          </Button>
        </div>

        <nav className="flex-1 space-y-1 p-2" aria-label="Main navigation">
          {filteredNav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-[hsl(var(--primary))]/10 text-[hsl(var(--primary))]"
                  : "text-[hsl(var(--sidebar-fg))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--accent-fg))]",
              )}
              title={collapsed ? item.label : undefined}
            >
              <item.icon className="size-5 shrink-0" aria-hidden="true" />
              {!collapsed && <span>{item.label}</span>}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-[hsl(var(--border))] p-2">
          <NavLink
            to={ROUTES.PROFILE}
            className={({ isActive }) => cn(
              "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
              isActive
                ? "bg-[hsl(var(--primary))]/10 text-[hsl(var(--primary))]"
                : "text-[hsl(var(--sidebar-fg))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--accent-fg))]",
            )}
            title={collapsed ? user?.username ?? "User" : undefined}
          >
            <User className="size-5 shrink-0" aria-hidden="true" />
            {!collapsed && <span>{user?.username ?? "User"}</span>}
          </NavLink>
          <button
            onClick={logout}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-[hsl(var(--sidebar-fg))] transition-colors hover:bg-[hsl(var(--destructive))]/10 hover:text-[hsl(var(--destructive))]"
            title={collapsed ? "Logout" : undefined}
          >
            <LogOut className="size-5 shrink-0" aria-hidden="true" />
            {!collapsed && <span>Logout</span>}
          </button>
        </div>
      </aside>

      {/* Mobile hamburger button (rendered in header via AppLayout) */}
      <button
        className="fixed left-4 top-3.5 z-50 flex size-10 items-center justify-center rounded-lg text-[hsl(var(--fg))] transition-colors hover:bg-[hsl(var(--accent))] lg:hidden"
        onClick={handleMobileOpen}
        aria-label="Open menu"
      >
        <Menu className="size-5" />
      </button>

      {/* Mobile sidebar drawer */}
      <MobileSidebar open={mobileOpen} onClose={handleMobileClose} />
    </>
  )
}
