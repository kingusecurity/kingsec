import { useParams, Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { PageContainer } from '@/components/layout/PageContainer'
import { CardSkeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { ReportDownloadCard } from '@/components/features/reports/ReportDownloadCard'
import { ReportMetadataCard } from '@/components/features/reports/ReportMetadataCard'
import { FindingsSummaryTable } from '@/components/features/assessment/FindingsSummaryTable'
import { useReport } from '@/hooks/use-reports'
import { useGenerateReport } from '@/hooks/use-assessments'
import { formatDate } from '@/lib/utils'

export function ReportDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: assessment, isLoading, error, refetch } = useReport(id ?? '')
  const reportMutation = useGenerateReport()

  if (error) {
    return (
      <PageContainer>
        <ErrorState title="Failed to load report" message={(error as Error).message} onRetry={refetch} />
      </PageContainer>
    )
  }

  if (isLoading) {
    return (
      <PageContainer>
        <div className="flex items-center gap-2 mb-4">
          <div className="h-4 w-24 animate-pulse rounded bg-surface-tertiary" />
        </div>
        <div className="grid gap-6 lg:grid-cols-3">
          <div className="lg:col-span-2"><CardSkeleton /></div>
          <div><CardSkeleton /></div>
        </div>
        <CardSkeleton />
      </PageContainer>
    )
  }

  if (!assessment) {
    return (
      <PageContainer>
        <div className="flex flex-col items-center gap-4 py-16 text-center">
          <h2 className="text-lg font-semibold text-text-primary">Report not found</h2>
          <p className="text-sm text-text-secondary">The requested report could not be found.</p>
          <Link to="/reports" className="text-sm text-accent hover:text-emerald-400">Back to Reports</Link>
        </div>
      </PageContainer>
    )
  }

  return (
    <PageContainer>
      <Link to="/reports" className="inline-flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary transition-colors">
        <ArrowLeft className="h-4 w-4" />
        Back to reports
      </Link>

      <h1 className="text-2xl font-bold text-text-primary">{assessment.target}</h1>
      <p className="text-sm text-text-muted">Created {formatDate(assessment.created_at)}</p>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-6">
          <ReportMetadataCard
            target={assessment.target}
            createdAt={assessment.created_at}
            loading={isLoading}
          />

          <div className="rounded-xl border border-border bg-surface-secondary p-5">
            <h3 className="text-sm font-semibold text-text-primary mb-4">Findings ({assessment.findings.length})</h3>
            <FindingsSummaryTable findings={assessment.findings} />
          </div>
        </div>

        <div>
          <ReportDownloadCard
            assessmentId={assessment.assessment_id}
            loading={isLoading}
            onRegenerate={() => reportMutation.mutate(assessment.assessment_id)}
            regenerateLoading={reportMutation.isPending}
          />
        </div>
      </div>
    </PageContainer>
  )
}
