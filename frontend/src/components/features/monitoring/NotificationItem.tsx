import { AlertCircle, AlertTriangle, CheckCircle2, Info, Trash2, MailOpen } from 'lucide-react'
import { cn } from '@/lib/utils'
import { formatRelativeTime } from '@/lib/utils'
import type { Notification } from '@/api/notifications'
import { Badge } from '@/components/ui/Badge'

const iconMap: Record<string, React.ComponentType<{ className?: string }>> = {
  critical: AlertCircle,
  high: AlertTriangle,
  medium: AlertTriangle,
  low: Info,
  info: Info,
  success: CheckCircle2,
}

const badgeVariantMap: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  success: 'success',
}

interface NotificationItemProps {
  notification: Notification
  onMarkRead?: (id: string) => void
  onDelete?: (id: string) => void
  onNavigate?: (id: string) => void
}

export function NotificationItem({ notification, onMarkRead, onDelete, onNavigate }: NotificationItemProps) {
  const Icon = iconMap[notification.severity] ?? Info
  const badgeVariant = badgeVariantMap[notification.severity] ?? 'info'

  return (
    <div
      className={cn(
        'group flex items-start gap-3 rounded-lg border p-4 transition-colors',
        notification.read
          ? 'border-border bg-surface-secondary'
          : 'border-accent/20 bg-accent/[0.03]',
      )}
      role="listitem"
      aria-label={notification.title}
    >
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-surface-tertiary">
        <Icon className="h-4 w-4 text-text-muted" />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className={cn('text-sm', notification.read ? 'text-text-primary' : 'font-medium text-text-primary')}>
              {notification.title}
            </p>
            {notification.message && (
              <p className="mt-0.5 text-xs text-text-secondary line-clamp-2">{notification.message}</p>
            )}
          </div>
          <Badge variant={badgeVariant} size="sm">
            {notification.severity}
          </Badge>
        </div>

        <div className="mt-2 flex items-center gap-3 text-xs text-text-muted">
          <span>{formatRelativeTime(notification.created_at)}</span>
          {notification.assessment_id && (
            <button
              onClick={() => onNavigate?.(notification.assessment_id!)}
              className="hover:text-accent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded"
            >
              View assessment
            </button>
          )}
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
        {!notification.read && onMarkRead && (
          <button
            onClick={() => onMarkRead(notification.id)}
            className="rounded p-1.5 text-text-muted hover:text-accent hover:bg-surface-tertiary transition-colors"
            aria-label="Mark as read"
          >
            <MailOpen className="h-4 w-4" />
          </button>
        )}
        {onDelete && (
          <button
            onClick={() => onDelete(notification.id)}
            className="rounded p-1.5 text-text-muted hover:text-red-400 hover:bg-surface-tertiary transition-colors"
            aria-label="Delete notification"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  )
}
