import { RefreshCw } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { Button } from '@/components/ui/Button'
import { useQueueStatus } from '@/hooks/use-activity'

interface QueueStatusPanelProps {
  className?: string
}

function ProgressBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0

  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 rounded-full bg-surface-tertiary overflow-hidden">
        <div
          className={cn('h-full rounded-full transition-all duration-500', color)}
          style={{ width: pct + '%' }}
        />
      </div>
      <span className="text-sm font-medium text-text-primary w-8 text-right">{value}</span>
    </div>
  )
}

export function QueueStatusPanel({ className }: QueueStatusPanelProps) {
  const { data, isLoading, error, refetch } = useQueueStatus()

  if (error) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle>Queue Status</CardTitle>
        </CardHeader>
        <ErrorState
          title="Failed to load queue status"
          message={(error as Error).message}
          onRetry={() => refetch()}
        />
      </Card>
    )
  }

  const total = data
    ? data.pending + data.running + data.completed + data.failed
    : 0

  return (
    <Card className={className}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Queue Status</CardTitle>
          <Button variant="ghost" size="xs" onClick={() => refetch()} iconLeft={<RefreshCw className="h-3 w-3" />}>
            Refresh
          </Button>
        </div>
      </CardHeader>

      <div className="p-5 space-y-4">
        {isLoading ? (
          <div className="space-y-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3">
                <Skeleton className="h-4 w-16" />
                <Skeleton className="flex-1 h-2 rounded-full" />
                <Skeleton className="h-4 w-8" />
              </div>
            ))}
          </div>
        ) : (
          <>
            <div className="flex items-center justify-between border-b border-border pb-3">
              <span className="text-sm text-text-secondary">Total Jobs</span>
              <span className="text-lg font-semibold text-text-primary">{total}</span>
            </div>
            <div className="space-y-3">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-text-secondary">Pending</span>
                </div>
                <ProgressBar value={data?.pending ?? 0} max={total || 1} color="bg-yellow-500" />
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-text-secondary">Running</span>
                </div>
                <ProgressBar value={data?.running ?? 0} max={total || 1} color="bg-blue-500" />
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-text-secondary">Completed</span>
                </div>
                <ProgressBar value={data?.completed ?? 0} max={total || 1} color="bg-emerald-500" />
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-text-secondary">Failed</span>
                </div>
                <ProgressBar value={data?.failed ?? 0} max={total || 1} color="bg-red-500" />
              </div>
            </div>
          </>
        )}
      </div>
    </Card>
  )
}
