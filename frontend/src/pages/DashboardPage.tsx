import { Shield, AlertTriangle, Activity, TrendingUp, Server, HardDrive } from 'lucide-react'
import { PageContainer, PageHeader, StatGrid } from '@/components/layout/PageContainer'
import { StatCard } from '@/components/features/dashboard/StatCard'
import { RecentAssessmentsTable } from '@/components/features/dashboard/RecentAssessmentsTable'
import { QuickActions } from '@/components/features/dashboard/QuickActions'
import { DashboardSkeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { useDashboardSummary, useDashboardJobs, useDashboardScanners, useDashboardWorkers } from '@/hooks/use-dashboard'
import { useAssessments } from '@/hooks/use-assessments'

export function DashboardPage() {
  const { data: summary, isLoading: summaryLoading, error: summaryError, refetch: refetchSummary } = useDashboardSummary()
  const { data: jobs, isLoading: jobsLoading, error: jobsError, refetch: refetchJobs } = useDashboardJobs()
  const { data: assessments, isLoading: assessmentsLoading } = useAssessments({ limit: 5, sort_by: 'created_at', sort_order: 'desc' })
  const { data: scanners, isLoading: scannersLoading } = useDashboardScanners()
  const { data: workers, isLoading: workersLoading } = useDashboardWorkers()

  if (summaryError || jobsError) {
    return (
      <PageContainer>
        <PageHeader title="Dashboard" description="Security assessment overview" />
        <ErrorState
          title="Failed to load dashboard"
          message={(summaryError as Error)?.message || (jobsError as Error)?.message}
          onRetry={() => { refetchSummary(); refetchJobs() }}
        />
      </PageContainer>
    )
  }

  if (summaryLoading || jobsLoading) {
    return <DashboardSkeleton />
  }

  return (
    <PageContainer>
      <PageHeader title="Dashboard" description="Security assessment overview" />

      <StatGrid columns={4}>
        <StatCard icon={Shield} label="Total Scans" value={summary?.total_scans ?? 0} loading={summaryLoading} />
        <StatCard icon={AlertTriangle} label="Critical" value={summary?.critical ?? 0} variant="danger" loading={summaryLoading} />
        <StatCard icon={Activity} label="Running" value={jobs?.running ?? 0} variant="warning" loading={jobsLoading} />
        <StatCard icon={TrendingUp} label="Completed" value={jobs?.completed ?? 0} variant="success" loading={jobsLoading} />
      </StatGrid>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-border bg-surface-secondary">
          <div className="flex items-center justify-between border-b border-border px-5 py-4">
            <h3 className="text-sm font-semibold text-text-primary">Recent Assessments</h3>
          </div>
          <RecentAssessmentsTable assessments={assessments?.items} loading={assessmentsLoading} />
        </div>

        <div className="rounded-xl border border-border bg-surface-secondary">
          <div className="flex items-center justify-between border-b border-border px-5 py-4">
            <h3 className="text-sm font-semibold text-text-primary">Quick Actions</h3>
          </div>
          <div className="p-5">
            <QuickActions />
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 rounded-xl border border-border bg-surface-secondary">
          <div className="flex items-center justify-between border-b border-border px-5 py-4">
            <h3 className="text-sm font-semibold text-text-primary">System Status</h3>
          </div>
          <div className="p-5">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="flex items-start gap-3 rounded-lg bg-surface-tertiary/50 p-4">
                <Server className="h-5 w-5 text-text-muted mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-text-primary">Scanners</p>
                  <p className="text-sm text-text-secondary mt-1">
                    {scannersLoading ? '...' : `${scanners?.scanners?.length ?? 0} configured`}
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3 rounded-lg bg-surface-tertiary/50 p-4">
                <HardDrive className="h-5 w-5 text-text-muted mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-text-primary">Workers</p>
                  <p className="text-sm text-text-secondary mt-1">
                    {workersLoading ? '...' : `${workers?.workers?.length ?? 0} available`}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="rounded-xl border border-border bg-surface-secondary">
          <div className="flex items-center justify-between border-b border-border px-5 py-4">
            <h3 className="text-sm font-semibold text-text-primary">Job Status</h3>
          </div>
          <div className="p-5 space-y-4">
            <JobRow label="Pending" value={jobs?.pending ?? 0} />
            <JobRow label="Running" value={jobs?.running ?? 0} />
            <JobRow label="Completed" value={jobs?.completed ?? 0} />
            <JobRow label="Failed" value={jobs?.failed ?? 0} />
          </div>
        </div>
      </div>
    </PageContainer>
  )
}

function JobRow({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-text-secondary">{label}</span>
      <span className="text-sm font-semibold text-text-primary">{value}</span>
    </div>
  )
}
