import { Radio, Activity, Server, ListOrdered } from 'lucide-react'
import { PageContainer, PageHeader, StatGrid } from '@/components/layout/PageContainer'
import { StatCard } from '@/components/features/dashboard/StatCard'
import { Panel } from '@/components/layout/PageContainer'
import { ActivityTimeline } from '@/components/features/monitoring/ActivityTimeline'
import { WorkerStatusPanel } from '@/components/features/monitoring/WorkerStatusPanel'
import { QueueStatusPanel } from '@/components/features/monitoring/QueueStatusPanel'
import { ScannerHealthPanel } from '@/components/features/monitoring/ScannerHealthPanel'
import { useLiveActivity, useWorkerStatus, useQueueStatus } from '@/hooks/use-activity'

export function LiveActivityPage() {
  const { isLoading: _activityLoading } = useLiveActivity()
  const { data: workers, isLoading: workersLoading } = useWorkerStatus()
  const { data: queue, isLoading: queueLoading } = useQueueStatus()

  return (
    <PageContainer>
      <PageHeader
        title="Live Monitoring"
        description="Real-time system activity and status"
        actions={
          <div className="flex items-center gap-2 text-sm text-text-muted">
            <Radio className="h-4 w-4 text-emerald-500" />
            <span>Auto-refreshing every 15s</span>
          </div>
        }
      />

      <StatGrid columns={3}>
        <StatCard
          icon={Activity}
          label="Running Jobs"
          value={queue?.running ?? 0}
          variant="warning"
          loading={queueLoading}
          description="Currently executing"
        />
        <StatCard
          icon={ListOrdered}
          label="Pending"
          value={queue?.pending ?? 0}
          loading={queueLoading}
          description="Waiting in queue"
        />
        <StatCard
          icon={Server}
          label="Workers"
          value={workers?.workers?.length ?? 0}
          variant="success"
          loading={workersLoading}
          description="Available workers"
        />
      </StatGrid>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Panel title="Activity Timeline">
            <div className="p-5">
              <ActivityTimeline showTitle={false} />
            </div>
          </Panel>
        </div>
        <div className="space-y-6">
          <ScannerHealthPanel />
          <WorkerStatusPanel />
          <QueueStatusPanel />
        </div>
      </div>
    </PageContainer>
  )
}
