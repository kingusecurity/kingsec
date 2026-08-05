import { useState } from 'react'
import { Mail, RefreshCw } from 'lucide-react'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import {
  useNotifications,
  useMarkNotificationRead,
  useMarkAllNotificationsRead,
  useDeleteNotification,
} from '@/hooks/use-notifications'
import { NotificationItem } from './NotificationItem'

const CHANNELS = ['email', 'webhook', 'slack', 'discord', 'microsoft_teams', 'in_app']
const PRIORITIES = ['low', 'medium', 'high', 'critical']
const STATUSES = ['pending', 'sent', 'failed', 'read']

const selectClassName = 'flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm'

interface NotificationListProps {
  limit?: number
}

export function NotificationList({ limit = 20 }: NotificationListProps) {
  const [offset, setOffset] = useState(0)
  const [readFilter, setReadFilter] = useState('')
  const [channelFilter, setChannelFilter] = useState('')
  const [priorityFilter, setPriorityFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  let readParam: boolean | undefined
  if (readFilter === 'unread') readParam = false
  else if (readFilter === 'read') readParam = true

  const { data, isLoading, error, refetch } = useNotifications({
    limit,
    offset,
    read: readParam,
    channel: channelFilter || undefined,
    priority: priorityFilter || undefined,
    status: statusFilter || undefined,
  })
  const { data: unreadData } = useNotifications({ limit: 1, read: false })
  const markRead = useMarkNotificationRead()
  const markAllRead = useMarkAllNotificationsRead()
  const deleteNotification = useDeleteNotification()

  const hasUnread = (unreadData?.total ?? 0) > 0

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
  const total = data?.total ?? 0
  const hasFilters = !!(readFilter || channelFilter || priorityFilter || statusFilter)

  const resetFilters = () => {
    setReadFilter('')
    setChannelFilter('')
    setPriorityFilter('')
    setStatusFilter('')
    setOffset(0)
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={readFilter}
          onChange={(e) => { setReadFilter(e.target.value); setOffset(0) }}
          className={selectClassName}
          aria-label="Filter by read status"
        >
          <option value="">All</option>
          <option value="unread">Unread</option>
          <option value="read">Read</option>
        </select>
        <select
          value={channelFilter}
          onChange={(e) => { setChannelFilter(e.target.value); setOffset(0) }}
          className={selectClassName}
          aria-label="Filter by channel"
        >
          <option value="">All channels</option>
          {CHANNELS.map((c) => (
            <option key={c} value={c}>{c.replace(/_/g, ' ')}</option>
          ))}
        </select>
        <select
          value={priorityFilter}
          onChange={(e) => { setPriorityFilter(e.target.value); setOffset(0) }}
          className={selectClassName}
          aria-label="Filter by priority"
        >
          <option value="">All priorities</option>
          {PRIORITIES.map((p) => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setOffset(0) }}
          className={selectClassName}
          aria-label="Filter by status"
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        {hasFilters && (
          <Button variant="ghost" size="xs" onClick={resetFilters}>Clear filters</Button>
        )}
      </div>

      {notifications.length === 0 ? (
        <EmptyState
          icon={<Mail className="h-8 w-8" />}
          title="No notifications"
          description={hasFilters ? 'No notifications match these filters' : "You're all caught up"}
        />
      ) : (
        <>
          <div className="flex items-center justify-between">
            <p className="text-sm text-text-secondary">{total} total</p>
            <div className="flex items-center gap-2">
              {hasUnread && (
                <Button
                  variant="ghost"
                  size="xs"
                  onClick={() => markAllRead.mutate()}
                  disabled={markAllRead.isPending}
                >
                  {markAllRead.isPending ? 'Marking...' : 'Mark all as read'}
                </Button>
              )}
              <Button variant="ghost" size="xs" onClick={() => refetch()} iconLeft={<RefreshCw className="h-3 w-3" />}>
                Refresh
              </Button>
            </div>
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
          {total > limit && (
            <div className="flex items-center justify-between pt-2">
              <Button
                variant="outline"
                size="xs"
                onClick={() => setOffset(Math.max(0, offset - limit))}
                disabled={offset === 0}
              >
                Previous
              </Button>
              <p className="text-xs text-text-muted">
                {offset + 1}-{Math.min(offset + limit, total)} of {total}
              </p>
              <Button
                variant="outline"
                size="xs"
                onClick={() => setOffset(offset + limit)}
                disabled={offset + limit >= total}
              >
                Next
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
