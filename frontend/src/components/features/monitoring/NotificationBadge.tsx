import { Bell } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useNotifications } from '@/hooks/use-notifications'

interface NotificationBadgeProps {
  onClick?: () => void
  className?: string
}

export function NotificationBadge({ onClick, className }: NotificationBadgeProps) {
  const { data } = useNotifications({ limit: 1, read: false })
  const unreadCount = data?.total ?? 0

  return (
    <button
      onClick={onClick}
      className={cn(
        'relative rounded-lg p-2 text-text-muted transition-colors hover:bg-surface-tertiary hover:text-text-primary',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface',
        className,
      )}
      aria-label={unreadCount > 0 ? unreadCount + ' unread notifications' : 'No unread notifications'}
    >
      <Bell className="h-5 w-5" />
      {unreadCount > 0 && (
        <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-bold text-white">
          {unreadCount > 99 ? '99+' : unreadCount}
        </span>
      )}
    </button>
  )
}
