import { memo, useMemo } from 'react'
import { Shield, AlertTriangle, Activity, TrendingUp, FileText, Eye, ArrowRight, ShieldCheck } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import { PageContainer, PageHeader, StatGrid } from '@/components/layout/PageContainer'
import { StatCard } from '@/components/features/dashboard/StatCard'
import { RecentAssessmentsTable } from '@/components/features/dashboard/RecentAssessmentsTable'
import { QuickActions } from '@/components/features/dashboard/QuickActions'
import { ScannerHealthPanel } from '@/components/features/monitoring/ScannerHealthPanel'
import { DashboardSkeleton, Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { useDashboardSummary, useDashboardJobs } from '@/hooks/use-dashboard'
import { useAssessments } from '@/hooks/use-assessments'
import { useReports } from '@/hooks/use-reports'
import { useAuthStore } from '@/store/auth'
import { formatRelativeTime } from '@/lib/utils'
import type { ReportListEntry } from '@/types/api'

export function DashboardPage() {
  const navigate = useNavigate()
  const role = useAuthStore((s) => s.user?.role.toLowerCase())
  const canCreate = role === 'analyst' || role === 'admin'
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

  // A genuinely empty account (never created a single assessment), not a
  // styling choice - total_scans counts every assessment ever created,
  // regardless of status.
  const isFirstRun = (summary?.total_scans ?? 0) === 0

  return (
    <PageContainer>
      <PageHeader title="Dashboard" description="Security assessment overview" />

      {isFirstRun ? (
        <div className="rounded-xl border border-border bg-surface-secondary">
          <EmptyState
            icon={<Shield className="h-8 w-8" />}
            title="No assessments yet"
            description={canCreate ? 'Run your first security assessment to see findings and reports here.' : 'An analyst or administrator can create an assessment. Findings and reports will appear here afterward.'}
            action={canCreate ? { label: 'New Assessment', onClick: () => navigate('/assessments/new') } : undefined}
          />
          <p className="pb-6 text-center text-sm text-text-muted">
            <a href="#scanner-health" className="inline-flex items-center gap-1 text-accent hover:underline">
              <ShieldCheck className="h-3.5 w-3.5" />
              Check which scanners are ready before you start
            </a>
          </p>
        </div>
      ) : (
        <StatGrid columns={4}>
          <StatCard icon={Shield} label="Total Scans" value={summary?.total_scans ?? 0} loading={summaryLoading} />
          <StatCard icon={AlertTriangle} label="Critical" value={summary?.critical_findings ?? 0} variant="danger" loading={summaryLoading} />
          <StatCard icon={Activity} label="Running" value={jobs?.running ?? 0} variant="warning" loading={jobsLoading} />
          <StatCard icon={TrendingUp} label="Completed" value={jobs?.completed ?? 0} variant="success" loading={jobsLoading} />
        </StatGrid>
      )}

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
            <QuickActions suggestFirst={isFirstRun} />
          </div>
        </div>
      </div>

      <div id="scanner-health">
        <ScannerHealthPanel />
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

const RecentReportsSection = memo(function RecentReportsSection() {
  const { data, isLoading, isError } = useReports({ limit: 5, order_by: 'generated_at', order_dir: 'desc' })

  const reportItems = useMemo(() => data?.items ?? [], [data?.items])

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
      ) : isError ? (
        <p className="text-sm text-red-400 py-4 text-center">Failed to load reports.</p>
      ) : !reportItems.length ? (
        <p className="text-sm text-text-muted py-4 text-center">No reports generated yet.</p>
      ) : (
        <div className="divide-y divide-border">
          {reportItems.map((r) => (
            <RecentReportRow key={r.assessment_id} report={r} />
          ))}
        </div>
      )}
    </div>
  )
})

const RecentReportRow = memo(function RecentReportRow({ report }: { report: ReportListEntry }) {
  const score = report.executive_score ?? 0
  const severityLabel = report.verdict_highest_severity ?? ''

  const scoreClass = useMemo(() => {
    if (score >= 80) return 'text-emerald-400'
    if (score >= 60) return 'text-yellow-400'
    if (score >= 40) return 'text-orange-400'
    return 'text-red-400'
  }, [score])

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
          <span className={`text-xs font-medium ${scoreClass}`}>
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
})
