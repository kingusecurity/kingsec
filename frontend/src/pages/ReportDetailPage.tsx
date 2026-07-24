import { useParams, Link, useNavigate } from 'react-router-dom'
import { ArrowLeft, Download, Printer, ExternalLink, Trash2 } from 'lucide-react'
import { PageContainer } from '@/components/layout/PageContainer'
import { CardSkeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { Button } from '@/components/ui/Button'
import { ReportDownloadCard } from '@/components/features/reports/ReportDownloadCard'
import { ReportMetadataCard } from '@/components/features/reports/ReportMetadataCard'
import { ReportSummary } from '@/components/features/reports/ReportSummary'
import { FindingsSummaryTable } from '@/components/features/assessment/FindingsSummaryTable'
import { useReport, useDeleteReport, useDownloadReport } from '@/hooks/use-reports'
import { useGenerateReport, useFindings } from '@/hooks/use-assessments'
import { formatDate } from '@/lib/utils'

export function ReportDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data: report, isLoading, error, refetch } = useReport(id ?? '')
  const { data: assessmentFindings } = useFindings(id ?? '')
  const reportMutation = useGenerateReport()
  const deleteReport = useDeleteReport()
  const downloadReport = useDownloadReport()

  const handleDownload = () => {
    if (!id) return
    const url = downloadReport.getDownloadUrl(id)
    window.open(url, '_blank')
  }

  const handlePrint = () => {
    window.print()
  }

  const handleDelete = () => {
    if (!id) return
    deleteReport.mutate(id, {
      onSuccess: () => navigate('/reports', { replace: true }),
    })
  }

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

  if (!report) {
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

  const findings = assessmentFindings?.findings ?? []

  return (
    <PageContainer>
      <div className="flex items-center justify-between">
        <Link to="/reports" className="inline-flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary transition-colors">
          <ArrowLeft className="h-4 w-4" />
          Back to reports
        </Link>
        <div className="flex items-center gap-2 print:hidden">
          <Button variant="outline" size="sm" onClick={handlePrint} iconLeft={<Printer className="h-4 w-4" />}>
            Print
          </Button>
          <Button variant="outline" size="sm" onClick={handleDownload} iconLeft={<Download className="h-4 w-4" />}>
            Download
          </Button>
          <Button variant="ghost" size="sm" onClick={handleDelete} iconLeft={<Trash2 className="h-4 w-4" />} className="text-text-muted hover:text-red-400">
            Delete
          </Button>
        </div>
      </div>

      <h1 className="text-2xl font-bold text-text-primary">{report.target}</h1>
      <p className="text-sm text-text-muted">Generated {report.generated_at ? formatDate(report.generated_at) : 'N/A'}</p>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-6">
          <ReportMetadataCard
            target={report.target}
            createdAt={report.created_at}
            report={{
              assessment_id: report.assessment_id,
              verdict: report.verdict ?? '',
              action_required: (report.highest_severity ?? '') === 'critical' || (report.highest_severity ?? '') === 'high',
              highest_severity: report.highest_severity ?? null,
              total_findings: report.total_findings,
              severity_counts: report.severity_counts,
              artifact_media_type: '',
              artifact_filename: report.artifact_filename ?? '',
              artifact_bytes: report.artifact_bytes ?? 0,
            }}
            loading={isLoading}
          />

          <ReportSummary
            severityCounts={report.severity_counts}
            totalFindings={report.total_findings}
            highestSeverity={report.highest_severity}
            executiveSummary={report.executive_summary}
            recommendations={report.recommendations}
          />

          <div className="rounded-xl border border-border bg-surface-secondary p-5">
            <h3 className="text-sm font-semibold text-text-primary mb-4">Findings ({findings.length})</h3>
            <FindingsSummaryTable findings={findings} />
          </div>
        </div>

        <div className="space-y-4">
          <ReportDownloadCard
            assessmentId={report.assessment_id}
            report={{
              assessment_id: report.assessment_id,
              verdict: report.verdict ?? '',
              action_required: (report.highest_severity ?? '') === 'critical' || (report.highest_severity ?? '') === 'high',
              highest_severity: report.highest_severity ?? null,
              total_findings: report.total_findings,
              severity_counts: report.severity_counts,
              artifact_media_type: '',
              artifact_filename: report.artifact_filename ?? '',
              artifact_bytes: report.artifact_bytes ?? 0,
            }}
            loading={isLoading}
            onRegenerate={() => reportMutation.mutate(report.assessment_id)}
            regenerateLoading={reportMutation.isPending}
          />

          <div className="rounded-xl border border-border bg-surface-secondary p-5">
            <h3 className="text-sm font-semibold text-text-primary mb-3">Quick Actions</h3>
            <div className="space-y-2">
              <Button variant="outline" size="sm" fullWidth onClick={handleDownload} iconLeft={<Download className="h-4 w-4" />}>
                Download PDF
              </Button>
              <Link
                to={`/assessments/${report.assessment_id}`}
                className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-border-light px-4 py-2 text-sm font-medium text-text-primary hover:bg-surface-tertiary transition-colors"
              >
                <ExternalLink className="h-4 w-4" />
                View Assessment
              </Link>
            </div>
          </div>
        </div>
      </div>
    </PageContainer>
  )
}
