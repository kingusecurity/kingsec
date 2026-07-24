import { Activity, RefreshCw } from 'lucide-react'
import { cn } from '@/lib/utils'
import { formatRelativeTime } from '@/lib/utils'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { Button } from '@/components/ui/Button'
import { useLiveActivity } from '@/hooks/use-activity'
import type { ActivityEvent } from '@/api/activity'

const severityDotColors: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-gray-500',
}

interface ActivityTimelineProps {
  limit?: number
  showTitle?: boolean
  className?: string
}

function TimelineItem({ event }: { event: ActivityEvent }) {
  const dotColor = severityDotColors[event.severity] ?? 'bg-gray-500'

  return (
    <div className="relative flex gap-4 pb-6 last:pb-0">
      <div className="flex flex-col items-center">
        <div className={cn('h-2.5 w-2.5 rounded-full ring-2 ring-surface-secondary', dotColor)} />
        <div className="mt-1 w-px flex-1 bg-border" />
      </div>
      <div className="min-w-0 flex-1 -mt-0.5">
        <p className="text-sm text-text-primary">{event.message}</p>
        <div className="mt-1 flex items-center gap-2 text-xs text-text-muted">
          <span>{formatRelativeTime(event.created_at)}</span>
          {event.user && <span>by {event.user}</span>}
          {event.assessment_id && (
            <span className="rounded bg-surface-tertiary px-1.5 py-0.5 font-mono text-[10px]">
              {event.assessment_id.slice(0, 8)}...
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

export function ActivityTimeline({ limit = 20, showTitle = true, className }: ActivityTimelineProps) {
  const { data, isLoading, error, refetch } = useLiveActivity({ limit })

  const activity = data?.activity ?? []

  if (error) {
    return (
      <ErrorState
        title="Failed to load activity"
        message={(error as Error).message}
        onRetry={() => refetch()}
      />
    )
  }

  return (
    <div className={cn('space-y-4', className)}>
      {showTitle && (
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-text-muted" />
            <h3 className="text-sm font-semibold text-text-primary">Live Activity</h3>
          </div>
          <Button variant="ghost" size="xs" onClick={() => refetch()} iconLeft={<RefreshCw className="h-3 w-3" />}>
            Refresh
          </Button>
        </div>
      )}

      {isLoading ? (
        <div className="space-y-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex gap-4">
              <Skeleton className="h-2.5 w-2.5 rounded-full" />
              <div className="flex-1 space-y-2">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-3 w-1/3" />
              </div>
            </div>
          ))}
        </div>
      ) : activity.length === 0 ? (
        <EmptyState
          icon={<Activity className="h-8 w-8" />}
          title="No recent activity"
          description="Activity will appear here as scans run"
        />
      ) : (
        <div className="pl-1">
          {activity.map((event: ActivityEvent) => (
            <TimelineItem key={event.id} event={event} />
          ))}
        </div>
      )}
    </div>
  )
}
