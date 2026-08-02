import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, FileText, Download, RotateCw } from 'lucide-react'
import { PageContainer } from '@/components/layout/PageContainer'
import { Card, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { AssessmentStatusBadge } from '@/components/features/assessment/AssessmentStatusBadge'
import { AssessmentActions } from '@/components/features/assessment/AssessmentActions'
import { AssessmentTimeline } from '@/components/features/assessment/AssessmentTimeline'
import { FindingsSummaryTable } from '@/components/features/assessment/FindingsSummaryTable'
import { ExecutionProgressPanel } from '@/components/features/execution/ExecutionProgressPanel'
import { useAssessment, useStartAssessment, useCancelAssessment, useDeleteAssessment, useGenerateReport } from '@/hooks/use-assessments'
import { useReportDetail } from '@/hooks/use-reports'
import { adminApi } from '@/api/admin'
import { ApiError } from '@/api/client'
import { formatDate, cn } from '@/lib/utils'

export function AssessmentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: assessment, isLoading, error, refetch } = useAssessment(id ?? '')
  const startMutation = useStartAssessment()
  const cancelMutation = useCancelAssessment()
  const deleteMutation = useDeleteAssessment()
  const reportMutation = useGenerateReport()

  const isRunning = assessment?.status?.toLowerCase() === 'running'
  const isPending = assessment?.status?.toLowerCase() === 'pending'
  const isDraft = assessment?.status?.toLowerCase() === 'draft'
  const isCompleted = assessment?.status?.toLowerCase() === 'completed'

  function stepStatus(active: boolean, done: boolean): 'completed' | 'current' | 'upcoming' {
    if (done) return 'completed'
    if (active) return 'current'
    return 'upcoming'
  }

  const timelineSteps = [
    { label: 'Draft', status: stepStatus(isDraft, true), timestamp: assessment?.created_at },
    { label: 'Authorized', status: stepStatus(false, !!assessment?.is_authorized) },
    { label: 'Running', status: stepStatus(isRunning, isCompleted) },
    { label: 'Completed', status: stepStatus(false, isCompleted) },
  ]

  if (error) {
    return (
      <PageContainer>
        <ErrorState title="Failed to load assessment" message={(error as Error).message} onRetry={refetch} />
      </PageContainer>
    )
  }

  return (
    <PageContainer>
      <Link to="/assessments" className="inline-flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary transition-colors">
        <ArrowLeft className="h-4 w-4" />
        Back to assessments
      </Link>

      {isLoading ? (
        <Card>
          <CardHeader>
            <Skeleton className="h-8 w-64" />
            <Skeleton className="h-4 w-32" />
          </CardHeader>
        </Card>
      ) : assessment ? (
        <>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <h1 className="text-2xl font-bold text-text-primary">{assessment.target}</h1>
              <div className="flex items-center gap-3 mt-2">
                <AssessmentStatusBadge status={assessment.status} />
                <span className="text-sm text-text-muted">Created {formatDate(assessment.created_at)}</span>
              </div>
            </div>
            <AssessmentActions
              status={assessment.status}
              onStart={() => startMutation.mutate(assessment.assessment_id)}
              onCancel={() => cancelMutation.mutate(assessment.assessment_id)}
              onDelete={() => deleteMutation.mutate(assessment.assessment_id)}
              onGenerateReport={() => reportMutation.mutate(assessment.assessment_id)}
              startLoading={startMutation.isPending}
              cancelLoading={cancelMutation.isPending}
              deleteLoading={deleteMutation.isPending}
              reportLoading={reportMutation.isPending}
            />
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            <Card>
              <CardHeader>
                <CardTitle>Details</CardTitle>
              </CardHeader>
              <div className="px-5 pb-5 space-y-3">
                <DetailRow label="Assessment ID" value={assessment.assessment_id} />
                <DetailRow label="Status" value={<AssessmentStatusBadge status={assessment.status} />} />
                <DetailRow label="Authorized" value={assessment.is_authorized ? 'Yes' : 'No'} />
                <DetailRow label="Created" value={formatDate(assessment.created_at)} />
              </div>
            </Card>

            <div className="rounded-xl border border-border bg-surface-secondary p-5">
              <h3 className="text-sm font-semibold text-text-primary mb-4">Timeline</h3>
              <AssessmentTimeline steps={timelineSteps} />
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Report</CardTitle>
              </CardHeader>
              <div className="px-5 pb-5 space-y-3">
                {isCompleted ? (
                  <AssessmentReportSection
                    assessmentId={assessment.assessment_id}
                    reportMutation={reportMutation}
                  />
                ) : isRunning || isPending ? (
                  <p className="text-sm text-text-muted">Report will be available after completion.</p>
                ) : (
                  <p className="text-sm text-text-muted">Start the assessment to generate a report.</p>
                )}
              </div>
            </Card>
          </div>

          {(isRunning || isPending) && (
            <ExecutionProgressPanel assessmentId={assessment.assessment_id} />
          )}

          <Card>
            <CardHeader>
              <CardTitle>Findings ({assessment.findings.length})</CardTitle>
              <CardDescription>Security issues discovered during assessment</CardDescription>
            </CardHeader>
            <div className="px-5 pb-5">
              <FindingsSummaryTable findings={assessment.findings} />
            </div>
          </Card>
        </>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Assessment not found</CardTitle>
            <CardDescription>The requested assessment could not be found.</CardDescription>
          </CardHeader>
          <CardFooter>
            <Link to="/assessments" className="inline-flex items-center justify-center rounded-lg bg-accent text-white px-4 py-2 text-sm font-medium hover:bg-emerald-400 transition-colors">
              Back to Assessments
            </Link>
          </CardFooter>
        </Card>
      )}
    </PageContainer>
  )
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between items-center">
      <span className="text-sm text-text-secondary">{label}</span>
      <span className="text-sm text-text-primary font-medium">{value}</span>
    </div>
  )
}

const SEVERITY_BADGES: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10',
  HIGH: 'text-orange-400 bg-orange-500/10',
  MEDIUM: 'text-yellow-400 bg-yellow-500/10',
  LOW: 'text-blue-400 bg-blue-500/10',
  INFORMATIONAL: 'text-gray-400 bg-gray-500/10',
}

function scoreColor(score: number): string {
  if (score >= 80) return 'text-emerald-400'
  if (score >= 60) return 'text-yellow-400'
  if (score >= 40) return 'text-orange-400'
  return 'text-red-400'
}

function scoreBgColor(score: number): string {
  if (score >= 80) return 'bg-emerald-900/20 border-emerald-800/40'
  if (score >= 60) return 'bg-yellow-900/20 border-yellow-800/40'
  if (score >= 40) return 'bg-orange-900/20 border-orange-800/40'
  return 'bg-red-900/20 border-red-800/40'
}

function AssessmentReportSection({
  assessmentId,
  reportMutation,
}: {
  assessmentId: string
  reportMutation: { mutate: (id: string) => void; isPending: boolean }
}) {
  const { data: report, isLoading, error } = useReportDetail(assessmentId)
  const reportNotFound = error && (error as ApiError).status === 404

  if (isLoading) {
    return (
      <div className="space-y-2">
        <Skeleton className="h-16 w-full rounded-lg" />
        <Skeleton className="h-9 w-full rounded-lg" />
      </div>
    )
  }

  if (reportNotFound || !report) {
    return (
      <Button
        variant="outline"
        size="sm"
        className="w-full"
        onClick={() => reportMutation.mutate(assessmentId)}
        loading={reportMutation.isPending}
        iconLeft={<FileText className="h-4 w-4" />}
      >
        Generate Report
      </Button>
    )
  }

  const score = report.executive_score ?? 0

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 rounded-lg border border-border bg-surface-tertiary/50 p-3">
        <div className={cn('flex h-12 w-12 shrink-0 items-center justify-center rounded-lg border-2', scoreBgColor(score))}>
          <span className={cn('text-sm font-bold', scoreColor(score))}>
            {Math.round(score)}
          </span>
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-xs text-text-muted">Executive Score</p>
          <p className="text-sm font-medium text-text-primary truncate">{report.target}</p>
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        {report.critical_count > 0 && (
          <span className={cn('inline-block rounded px-1.5 py-0.5 text-[10px] font-medium', SEVERITY_BADGES.CRITICAL)}>
            {report.critical_count} Critical
          </span>
        )}
        {report.high_count > 0 && (
          <span className={cn('inline-block rounded px-1.5 py-0.5 text-[10px] font-medium', SEVERITY_BADGES.HIGH)}>
            {report.high_count} High
          </span>
        )}
        {report.medium_count > 0 && (
          <span className={cn('inline-block rounded px-1.5 py-0.5 text-[10px] font-medium', SEVERITY_BADGES.MEDIUM)}>
            {report.medium_count} Medium
          </span>
        )}
        {report.low_count > 0 && (
          <span className={cn('inline-block rounded px-1.5 py-0.5 text-[10px] font-medium', SEVERITY_BADGES.LOW)}>
            {report.low_count} Low
          </span>
        )}
      </div>
      <p className="text-xs text-text-secondary truncate" title={report.verdict_headline}>
        {report.verdict_headline}
      </p>
      <div className="flex gap-2">
        <Button
          variant="outline"
          size="xs"
          className="flex-1"
          onClick={() => {
            adminApi.downloadReport(assessmentId).catch((err) => {
              console.error('Failed to download report', err)
            })
          }}
          iconLeft={<Download className="h-3.5 w-3.5" />}
        >
          Download
        </Button>
        <Button
          variant="outline"
          size="xs"
          className="flex-1"
          onClick={() => reportMutation.mutate(assessmentId)}
          loading={reportMutation.isPending}
          iconLeft={<RotateCw className="h-3.5 w-3.5" />}
        >
          Regenerate
        </Button>
      </div>
    </div>
  )
}
