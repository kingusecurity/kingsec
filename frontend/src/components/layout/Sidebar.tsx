import { useEffect, useRef } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  ShieldCheck,
  FileText,
  Settings,
  LogOut,
  Shield,
  ChevronLeft,
  ChevronRight,
  X,
  Search,
  CalendarCheck,
  Radio,
  Bell,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/store/auth'
import { useUIStore } from '@/store/ui'
import { useLogout } from '@/hooks/use-auth'

interface NavItem {
  to: string
  label: string
  icon: React.ComponentType<{ className?: string }>
  roles: string[]
}

const navItems: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, roles: ['viewer', 'analyst', 'admin'] },
  { to: '/assessments', label: 'Assessments', icon: ShieldCheck, roles: ['viewer', 'analyst', 'admin'] },
  { to: '/findings', label: 'Findings', icon: Search, roles: ['viewer', 'analyst', 'admin'] },
  { to: '/reports', label: 'Reports', icon: FileText, roles: ['analyst', 'admin'] },
  { to: '/schedules', label: 'Schedules', icon: CalendarCheck, roles: ['viewer', 'analyst', 'admin'] },
  { to: '/monitor', label: 'Monitor', icon: Radio, roles: ['viewer', 'analyst', 'admin'] },
  { to: '/notifications', label: 'Notifications', icon: Bell, roles: ['viewer', 'analyst', 'admin'] },
  { to: '/settings', label: 'Settings', icon: Settings, roles: ['viewer', 'analyst', 'admin'] },
]

export function Sidebar() {
  const user = useAuthStore((s) => s.user)
  const logout = useLogout()
  const navigate = useNavigate()
  const { sidebarCollapsed, sidebarMobileOpen, toggleSidebar, closeMobileSidebar } = useUIStore()
  const sidebarRef = useRef<HTMLDivElement>(null)

  const userRole = user?.role?.toLowerCase() ?? 'viewer'

  const visibleItems = navItems.filter((item) =>
    item.roles.some((r) => r === userRole),
  )

  const handleLogout = () => {
    logout()
    navigate('/login', { replace: true })
  }

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && sidebarMobileOpen) {
        closeMobileSidebar()
      }
    }
    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [sidebarMobileOpen, closeMobileSidebar])

  useEffect(() => {
    if (!sidebarMobileOpen) return
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = '' }
  }, [sidebarMobileOpen])

  const handleNavClick = () => {
    if (sidebarMobileOpen) closeMobileSidebar()
  }

  const sidebarContent = (
    <>
      <div className={cn(
        'flex h-14 items-center border-b border-border',
        sidebarCollapsed ? 'justify-center px-0' : 'gap-2 px-5',
      )}>
        <Shield className="h-6 w-6 shrink-0 text-emerald-500" />
        {!sidebarCollapsed && <span className="text-lg font-semibold text-text-primary">KingSec</span>}
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-2 py-3" aria-label="Main navigation">
        {visibleItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            onClick={handleNavClick}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface',
                isActive
                  ? 'bg-accent/10 text-accent font-medium'
                  : 'text-text-muted hover:bg-surface-tertiary hover:text-text-primary',
                sidebarCollapsed && 'justify-center px-2',
              )
            }
            title={sidebarCollapsed ? item.label : undefined}
          >
            <item.icon className="h-4 w-4 shrink-0" />
            {!sidebarCollapsed && <span>{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      <div className={cn(
        'border-t border-border py-3',
        sidebarCollapsed ? 'space-y-2 px-2' : 'space-y-1 px-3',
      )}>
        {!sidebarCollapsed && user && (
          <div className="mb-2 px-3 text-xs text-text-muted">
            <p className="truncate font-medium text-text-secondary">{user.username}</p>
            <span className="inline-block mt-0.5 rounded bg-accent/10 px-1.5 py-0.5 text-xs text-accent">
              {user.role}
            </span>
          </div>
        )}

        <button
          onClick={toggleSidebar}
          className={cn(
            'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-text-muted transition-colors',
            'hover:bg-surface-tertiary hover:text-text-primary',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
            sidebarCollapsed && 'justify-center px-2',
          )}
          aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {sidebarCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          {!sidebarCollapsed && <span>Collapse</span>}
        </button>

        <button
          onClick={handleLogout}
          className={cn(
            'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-text-muted transition-colors',
            'hover:bg-surface-tertiary hover:text-red-400',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
            sidebarCollapsed && 'justify-center px-2',
          )}
          aria-label="Sign out"
          title="Sign out"
        >
          <LogOut className="h-4 w-4 shrink-0" />
          {!sidebarCollapsed && <span>Sign Out</span>}
        </button>
      </div>
    </>
  )

  return (
    <>
      <aside
        ref={sidebarRef}
        className={cn(
          'hidden lg:flex flex-col border-r border-border bg-surface-secondary transition-all duration-200',
          sidebarCollapsed ? 'w-16' : 'w-64',
        )}
      >
        {sidebarContent}
      </aside>

      {sidebarMobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div
            className="absolute inset-0 bg-black/60"
            onClick={closeMobileSidebar}
            aria-hidden="true"
          />
          <div className="absolute inset-y-0 left-0 flex w-72 flex-col border-r border-border bg-surface-secondary shadow-theme-lg">
            <div className="flex h-14 items-center justify-between border-b border-border px-5">
              <div className="flex items-center gap-2">
                <Shield className="h-6 w-6 text-emerald-500" />
                <span className="text-lg font-semibold text-text-primary">KingSec</span>
              </div>
              <button
                onClick={closeMobileSidebar}
                className="rounded p-1 text-text-muted hover:text-text-primary"
                aria-label="Close navigation menu"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto px-2 py-3">
              {visibleItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  onClick={handleNavClick}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                      isActive
                        ? 'bg-accent/10 text-accent font-medium'
                        : 'text-text-muted hover:bg-surface-tertiary hover:text-text-primary',
                    )
                  }
                >
                  <item.icon className="h-4 w-4" />
                  <span>{item.label}</span>
                </NavLink>
              ))}
            </div>
            <div className="border-t border-border px-3 py-4 space-y-2">
              {user && (
                <div className="px-3 text-xs text-text-muted">
                  <p className="truncate font-medium text-text-secondary">{user.username}</p>
                  <span className="inline-block mt-0.5 rounded bg-accent/10 px-1.5 py-0.5 text-xs text-accent">
                    {user.role}
                  </span>
                </div>
              )}
              <button
                onClick={handleLogout}
                className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-text-muted transition-colors hover:bg-surface-tertiary hover:text-red-400"
              >
                <LogOut className="h-4 w-4" />
                <span>Sign Out</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
