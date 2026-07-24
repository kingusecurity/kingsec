import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { Server, HardDrive } from 'lucide-react'
import type { SystemStatus } from '@/types/api'

interface SystemStatusCardProps {
  scanners?: SystemStatus['scanners']
  workers?: SystemStatus['workers']
  lastUpdated?: string
  loading?: boolean
}

export function SystemStatusCard({ scanners, workers, lastUpdated, loading }: SystemStatusCardProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>System Status</CardTitle>
      </CardHeader>
      <div className="px-5 pb-5 space-y-4">
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
          </div>
        ) : (
          <>
            <div className="flex items-start gap-3 rounded-lg bg-surface-tertiary/50 p-3">
              <Server className="h-5 w-5 text-text-muted mt-0.5" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-text-primary">Scanners</p>
                <p className="text-xs text-text-muted mt-0.5">Active scanners monitoring targets</p>
                {scanners && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    <Badge variant="success" size="sm">{scanners.healthy} Healthy</Badge>
                    {scanners.degraded > 0 && <Badge variant="warning" size="sm">{scanners.degraded} Degraded</Badge>}
                    {scanners.down > 0 && <Badge variant="critical" size="sm">{scanners.down} Down</Badge>}
                  </div>
                )}
              </div>
            </div>
            <div className="flex items-start gap-3 rounded-lg bg-surface-tertiary/50 p-3">
              <HardDrive className="h-5 w-5 text-text-muted mt-0.5" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-text-primary">Workers</p>
                <p className="text-xs text-text-muted mt-0.5">Processing assessment jobs</p>
                {workers && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    <Badge variant="info" size="sm">{workers.active} Active</Badge>
                    <Badge variant="neutral" size="sm">{workers.idle} Idle</Badge>
                  </div>
                )}
              </div>
            </div>
            {lastUpdated && (
              <p className="text-xs text-text-muted text-right">Updated {lastUpdated}</p>
            )}
          </>
        )}
      </div>
    </Card>
  )
}
