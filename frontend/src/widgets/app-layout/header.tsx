import { useAuth } from "@/features/auth/hooks/use-auth"
import { ThemeSwitcher } from "@/widgets/theme-switcher/theme-switcher"
import { Badge } from "@/shared/ui/badge"
import { NotificationBell } from "@/features/notifications"

export function Header(): React.ReactElement {
  const { user } = useAuth()

  return (
    <header className="flex h-14 items-center justify-between border-b border-[hsl(var(--border))] bg-[hsl(var(--bg))] px-6">
      <div />
      <div className="flex items-center gap-3">
        <ThemeSwitcher variant="pills" />
        <NotificationBell />
        {user && (
          <Badge variant={user.role === "ADMIN" ? "default" : "secondary"}>
            {user.role}
          </Badge>
        )}
      </div>
    </header>
  )
}
