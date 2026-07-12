import { NavLink } from "react-router-dom"
import {
  LayoutDashboard,
  BarChart3,
  ScanSearch,
  Shield,
  FileText,
  Users,
  ScrollText,
  Settings,
  User,
  LogOut,
  ChevronLeft,
  ChevronRight,
} from "lucide-react"
import { useState } from "react"
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

export function Sidebar(): React.ReactElement {
  const { user, logout } = useAuth()
  const [collapsed, setCollapsed] = useState(false)

  const filteredNav = NAV_ITEMS.filter((item) => {
    if (!user) return false
    return ROLE_HIERARCHY[user.role] >= ROLE_HIERARCHY[item.roles[item.roles.length - 1] as keyof typeof ROLE_HIERARCHY]
  })

  return (
    <aside
      className={cn(
        "flex h-screen flex-col border-r border-[hsl(var(--border))] bg-[hsl(var(--sidebar))] transition-all duration-200",
        collapsed ? "w-16" : "w-64",
      )}
    >
      {/* Logo */}
      <div className="flex h-14 items-center justify-between border-b border-[hsl(var(--border))] px-4">
        {!collapsed && (
          <div className="flex items-center gap-2">
            <Shield className="size-6 text-[hsl(var(--primary))]" />
            <span className="text-lg font-bold text-[hsl(var(--fg))]">KingSec</span>
          </div>
        )}
        <Button variant="ghost" size="icon" className="size-8" onClick={() => setCollapsed(!collapsed)}>
          {collapsed ? <ChevronRight className="size-4" /> : <ChevronLeft className="size-4" />}
        </Button>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-1 p-2">
        {filteredNav.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-[hsl(var(--primary))]/10 text-[hsl(var(--primary))]"
                  : "text-[hsl(var(--sidebar-fg))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--accent-fg))]",
              )
            }
          >
            <item.icon className="size-5 shrink-0" />
            {!collapsed && <span>{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* User */}
      <div className="border-t border-[hsl(var(--border))] p-2">
        <NavLink
          to={ROUTES.PROFILE}
          className={({ isActive }) =>
            cn(
              "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
              isActive
                ? "bg-[hsl(var(--primary))]/10 text-[hsl(var(--primary))]"
                : "text-[hsl(var(--sidebar-fg))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--accent-fg))]",
            )
          }
        >
          <User className="size-5 shrink-0" />
          {!collapsed && <span>{user?.username ?? "User"}</span>}
        </NavLink>
        <button
          onClick={logout}
          className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-[hsl(var(--sidebar-fg))] transition-colors hover:bg-[hsl(var(--destructive))]/10 hover:text-[hsl(var(--destructive))]"
        >
          <LogOut className="size-5 shrink-0" />
          {!collapsed && <span>Logout</span>}
        </button>
      </div>
    </aside>
  )
}
