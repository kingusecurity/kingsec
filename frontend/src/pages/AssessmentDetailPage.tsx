import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, FileText } from 'lucide-react'
import { PageContainer } from '@/components/layout/PageContainer'
import { Card, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { AssessmentStatusBadge } from '@/components/features/assessment/AssessmentStatusBadge'
import { AssessmentActions } from '@/components/features/assessment/AssessmentActions'
import { AssessmentTimeline } from '@/components/features/assessment/AssessmentTimeline'
import { FindingsSummaryTable } from '@/components/features/assessment/FindingsSummaryTable'
import { useAssessment, useStartAssessment, useCancelAssessment, useDeleteAssessment, useGenerateReport } from '@/hooks/use-assessments'
import { formatDate } from '@/lib/utils'

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
                  <>
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full"
                      onClick={() => reportMutation.mutate(assessment.assessment_id)}
                      loading={reportMutation.isPending}
                      iconLeft={<FileText className="h-4 w-4" />}
                    >
                      Generate Report
                    </Button>
                  </>
                ) : isRunning || isPending ? (
                  <p className="text-sm text-text-muted">Report will be available after completion.</p>
                ) : (
                  <p className="text-sm text-text-muted">Start the assessment to generate a report.</p>
                )}
              </div>
            </Card>
          </div>

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
