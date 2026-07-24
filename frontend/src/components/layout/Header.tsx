import { useNavigate } from 'react-router-dom'
import { Bell, Search, Menu, User, Settings, BookOpen, LogOut } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Input, Badge } from '@/components/ui'
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator } from '@/components/ui/DropdownMenu'
import { Breadcrumb, BreadcrumbItem, BreadcrumbSeparator } from '@/components/ui/Breadcrumb'
import { useAuthStore } from '@/store/auth'
import { useUIStore } from '@/store/ui'
import { useLogout } from '@/hooks/use-auth'
import { useBreadcrumbs } from '@/hooks/use-breadcrumbs'

export function Header() {
  const user = useAuthStore((s) => s.user)
  const logout = useLogout()
  const navigate = useNavigate()
  const setSidebarMobileOpen = useUIStore((s) => s.setSidebarMobileOpen)
  const breadcrumbs = useBreadcrumbs()

  const handleLogout = () => {
    logout()
    navigate('/login', { replace: true })
  }

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-4 border-b border-border bg-surface-secondary/95 backdrop-blur-sm px-4 sm:px-6">
      <button
        onClick={() => setSidebarMobileOpen(true)}
        className="rounded-lg p-1.5 text-text-muted hover:bg-surface-tertiary hover:text-text-primary lg:hidden"
        aria-label="Open navigation menu"
      >
        <Menu className="h-5 w-5" />
      </button>

      <div className="hidden min-w-0 sm:block">
        <Breadcrumb>
          {breadcrumbs.map((item, index) => (
            <span key={item.href} className="inline-flex items-center gap-1.5">
              {index > 0 && <BreadcrumbSeparator />}
              <BreadcrumbItem
                href={item.isCurrent ? undefined : item.href}
                isCurrent={item.isCurrent}
              >
                {item.label}
              </BreadcrumbItem>
            </span>
          ))}
        </Breadcrumb>
      </div>

      <div className="flex-1" />

      <div className="hidden sm:block w-64">
        <Input
          placeholder="Search..."
          prefix={<Search className="h-4 w-4" />}
          aria-label="Global search"
        />
      </div>

      <button
        className="relative rounded-lg p-1.5 text-text-muted hover:bg-surface-tertiary hover:text-text-primary transition-colors"
        aria-label="Notifications"
      >
        <Bell className="h-5 w-5" />
        <span className="absolute right-1 top-1 h-2 w-2 rounded-full bg-red-500" aria-hidden="true" />
      </button>

      <div className="flex items-center gap-2">
        <div className="hidden sm:flex h-8 w-8 items-center justify-center rounded-full bg-accent/10 text-xs font-semibold text-accent">
          {user?.username?.charAt(0).toUpperCase() ?? '?'}
        </div>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              className={cn(
                'flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm text-text-secondary transition-colors',
                'hover:bg-surface-tertiary hover:text-text-primary',
              )}
              aria-label="User menu"
            >
              <span className="hidden sm:inline text-sm font-medium">{user?.username}</span>
              {user?.role && (
                <Badge variant="info" size="sm">{user.role}</Badge>
              )}
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="min-w-[180px]">
            <DropdownMenuItem onClick={() => navigate('/settings')}>
              <User className="h-4 w-4" />
              Profile
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => navigate('/settings')}>
              <Settings className="h-4 w-4" />
              Settings
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => window.open('https://kingsec.readme.io', '_blank', 'noopener,noreferrer')}>
              <BookOpen className="h-4 w-4" />
              Documentation
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={handleLogout} danger>
              <LogOut className="h-4 w-4" />
              Sign Out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
