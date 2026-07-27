import { Shield, AlertTriangle, Activity, TrendingUp, FileText, Eye, ArrowRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import { PageContainer, PageHeader, StatGrid } from '@/components/layout/PageContainer'
import { StatCard } from '@/components/features/dashboard/StatCard'
import { RecentAssessmentsTable } from '@/components/features/dashboard/RecentAssessmentsTable'
import { QuickActions } from '@/components/features/dashboard/QuickActions'
import { DashboardSkeleton, Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { useDashboardSummary, useDashboardJobs } from '@/hooks/use-dashboard'
import { useAssessments } from '@/hooks/use-assessments'
import { useReports } from '@/hooks/use-reports'
import { formatRelativeTime } from '@/lib/utils'
import type { ReportListEntry } from '@/types/api'

export function DashboardPage() {
  const { data: summary, isLoading: summaryLoading, error: summaryError, refetch: refetchSummary } = useDashboardSummary()
  const { data: jobs, isLoading: jobsLoading, error: jobsError, refetch: refetchJobs } = useDashboardJobs()
  const { data: assessments, isLoading: assessmentsLoading } = useAssessments({ limit: 5 })

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
        <StatCard icon={AlertTriangle} label="Critical" value={summary?.critical_findings ?? 0} variant="danger" loading={summaryLoading} />
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

      <RecentReportsSection />
    </PageContainer>
  )
}

const scoreColors: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10',
  HIGH: 'text-orange-400 bg-orange-500/10',
  MEDIUM: 'text-yellow-400 bg-yellow-500/10',
  LOW: 'text-blue-400 bg-blue-500/10',
}

function RecentReportsSection() {
  const { data, isLoading } = useReports({ limit: 5, order_by: 'generated_at', order_dir: 'desc' })

  return (
    <div className="rounded-xl border border-border bg-surface-secondary">
      <div className="flex items-center justify-between border-b border-border px-5 py-4">
        <h3 className="text-sm font-semibold text-text-primary">Recent Reports</h3>
        <Link
          to="/reports"
          className="inline-flex items-center gap-1 text-xs text-text-muted hover:text-text-primary transition-colors"
        >
          View all <ArrowRight className="h-3 w-3" />
        </Link>
      </div>
      {isLoading ? (
        <div className="space-y-3 p-4">
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-4 w-1/2" />
          <Skeleton className="h-4 w-2/3" />
        </div>
      ) : !data?.items.length ? (
        <p className="text-sm text-text-muted py-4 text-center">No reports generated yet.</p>
      ) : (
        <div className="divide-y divide-border">
          {data.items.map((r) => (
            <RecentReportRow key={r.assessment_id} report={r} />
          ))}
        </div>
      )}
    </div>
  )
}

function RecentReportRow({ report }: { report: ReportListEntry }) {
  const score = report.executive_score ?? 0
  const severityLabel = report.verdict_highest_severity ?? ''

  return (
    <div className="flex items-center justify-between px-5 py-3 transition-colors hover:bg-surface-tertiary/50">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <FileText className="h-4 w-4 shrink-0 text-text-muted" />
          <p className="text-sm font-medium text-text-primary truncate">{report.target}</p>
        </div>
        <div className="flex items-center gap-2 mt-1">
          <span className="text-xs text-text-muted">{formatRelativeTime(report.generated_at)}</span>
          {severityLabel && (
            <span className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-medium ${scoreColors[severityLabel] || 'text-text-muted bg-surface-tertiary'}`}>
              {severityLabel}
            </span>
          )}
          <span className={`text-xs font-medium ${score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-yellow-400' : score >= 40 ? 'text-orange-400' : 'text-red-400'}`}>
            Score: {Math.round(score)}
          </span>
        </div>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <Link
          to={`/assessments/${report.assessment_id}`}
          className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-xs text-text-muted hover:text-text-primary hover:bg-surface-tertiary transition-colors"
          aria-label={`View assessment for ${report.target}`}
        >
          <Eye className="h-3 w-3" />
          View
        </Link>
      </div>
    </div>
  )
}
