import { HardDrive, RefreshCw, Wifi, WifiOff, AlertTriangle } from 'lucide-react'
import { cn } from '@/lib/utils'
import { formatRelativeTime } from '@/lib/utils'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { Button } from '@/components/ui/Button'
import { useWorkerStatus } from '@/hooks/use-activity'
import type { WorkerInfo } from '@/api/activity'

const statusVariant: Record<string, 'success' | 'warning' | 'danger' | 'neutral'> = {
  healthy: 'success',
  degraded: 'warning',
  down: 'danger',
  offline: 'neutral',
}

const statusIcon: Record<string, React.ComponentType<{ className?: string }>> = {
  healthy: Wifi,
  degraded: AlertTriangle,
  down: WifiOff,
  offline: WifiOff,
}

interface WorkerStatusPanelProps {
  className?: string
}

export function WorkerStatusPanel({ className }: WorkerStatusPanelProps) {
  const { data, isLoading, error, refetch } = useWorkerStatus()

  if (error) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle>Worker Status</CardTitle>
        </CardHeader>
        <ErrorState
          title="Failed to load worker status"
          message={(error as Error).message}
          onRetry={() => refetch()}
        />
      </Card>
    )
  }

  const workers = data?.workers ?? []

  return (
    <Card className={className}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Worker Status</CardTitle>
          <Button variant="ghost" size="xs" onClick={() => refetch()} iconLeft={<RefreshCw className="h-3 w-3" />}>
            Refresh
          </Button>
        </div>
      </CardHeader>

      <div className="p-5 space-y-3">
        {isLoading ? (
          Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 rounded-lg bg-surface-tertiary/50 p-3">
              <Skeleton className="h-8 w-8 rounded-lg" />
              <div className="flex-1 space-y-1.5">
                <Skeleton className="h-4 w-1/2" />
                <Skeleton className="h-3 w-1/3" />
              </div>
            </div>
          ))
        ) : workers.length === 0 ? (
          <EmptyState
            icon={<HardDrive className="h-8 w-8" />}
            title="No workers"
            description="No workers are currently registered"
          />
        ) : (
          workers.map((worker: WorkerInfo) => {
            const Icon = statusIcon[worker.status] ?? Wifi
            const variant = statusVariant[worker.status] ?? 'neutral'

            return (
              <div
                key={worker.id}
                className="flex items-center gap-3 rounded-lg bg-surface-tertiary/50 p-3 transition-colors hover:bg-surface-tertiary"
              >
                <div className={cn(
                  'flex h-8 w-8 items-center justify-center rounded-lg',
                  worker.status === 'healthy' ? 'bg-emerald-900/30 text-emerald-400' :
                  worker.status === 'degraded' ? 'bg-yellow-900/30 text-yellow-400' :
                  'bg-red-900/30 text-red-400',
                )}>
                  <Icon className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-text-primary truncate">{worker.name}</p>
                    <Badge variant={variant} size="sm">{worker.status}</Badge>
                  </div>
                  <div className="mt-0.5 flex items-center gap-3 text-xs text-text-muted">
                    {worker.task && <span>Task: {worker.task}</span>}
                    <span>CPU: {worker.cpu}%</span>
                    <span>MEM: {worker.memory}%</span>
                  </div>
                  <p className="text-[10px] text-text-muted mt-0.5">
                    Last seen: {formatRelativeTime(worker.last_seen)}
                  </p>
                </div>
              </div>
            )
          })
        )}
      </div>
    </Card>
  )
}
