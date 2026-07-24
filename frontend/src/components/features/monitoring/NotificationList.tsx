import { Mail, RefreshCw } from 'lucide-react'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import { useNotifications, useMarkNotificationRead, useDeleteNotification } from '@/hooks/use-notifications'
import { NotificationItem } from './NotificationItem'

interface NotificationListProps {
  limit?: number
}

export function NotificationList({ limit = 20 }: NotificationListProps) {
  const { data, isLoading, error, refetch } = useNotifications({ limit })
  const markRead = useMarkNotificationRead()
  const deleteNotification = useDeleteNotification()

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Spinner size="lg" />
      </div>
    )
  }

  if (error) {
    return (
      <ErrorState
        title="Failed to load notifications"
        message={(error as Error).message}
        onRetry={() => refetch()}
      />
    )
  }

  const notifications = data?.notifications ?? []

  if (notifications.length === 0) {
    return (
      <EmptyState
        icon={<Mail className="h-8 w-8" />}
        title="No notifications"
        description="You're all caught up"
      />
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm text-text-secondary">{data?.total ?? 0} total</p>
        <Button variant="ghost" size="xs" onClick={() => refetch()} iconLeft={<RefreshCw className="h-3 w-3" />}>
          Refresh
        </Button>
      </div>
      <div className="space-y-2" role="list" aria-label="Notifications">
        {notifications.map((n) => (
          <NotificationItem
            key={n.id}
            notification={n}
            onMarkRead={markRead.mutate}
            onDelete={deleteNotification.mutate}
          />
        ))}
      </div>
    </div>
  )
}
