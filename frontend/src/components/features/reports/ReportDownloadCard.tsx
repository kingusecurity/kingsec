import { Download, FileText } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { assessmentsApi } from '@/api/assessments'
import type { GenerateReportResponse } from '@/types/api'

const verdictVariant: Record<string, 'success' | 'warning' | 'critical' | 'neutral'> = {
  safe: 'success',
  minor: 'warning',
  moderate: 'warning',
  critical: 'critical',
  unknown: 'neutral',
}

interface ReportDownloadCardProps {
  assessmentId: string
  report?: GenerateReportResponse
  loading?: boolean
  onRegenerate?: () => void
  regenerateLoading?: boolean
}

export function ReportDownloadCard({
  assessmentId,
  report,
  loading,
  onRegenerate,
  regenerateLoading,
}: ReportDownloadCardProps) {
  const downloadUrl = report?.artifact_filename
    ? assessmentsApi.getReportDownloadUrl(assessmentId, report.artifact_filename)
    : null

  return (
    <Card>
      <CardHeader>
        <CardTitle>Report</CardTitle>
        <CardDescription>Assessment report and download</CardDescription>
      </CardHeader>
      <div className="px-5 pb-5 space-y-4">
        {loading ? (
          <div className="space-y-2">
            <div className="h-4 w-24 animate-pulse rounded bg-surface-tertiary" />
            <div className="h-8 w-full animate-pulse rounded bg-surface-tertiary" />
          </div>
        ) : report ? (
          <>
            <div className="flex items-center justify-between rounded-lg bg-surface-tertiary/50 p-3">
              <div className="flex items-center gap-3">
                <FileText className="h-5 w-5 text-text-muted" />
                <div>
                  <p className="text-sm font-medium text-text-primary">{report.artifact_filename}</p>
                  <p className="text-xs text-text-muted">{(report.artifact_bytes / 1024).toFixed(1)} KB</p>
                </div>
              </div>
              <Badge variant={verdictVariant[report.verdict?.toLowerCase()] ?? 'neutral'}>{report.verdict}</Badge>
            </div>
            {downloadUrl && (
              <Button
                variant="primary"
                className="w-full"
                onClick={() => window.open(downloadUrl, '_blank')}
                iconLeft={<Download className="h-4 w-4" />}
              >
                Download Report
              </Button>
            )}
            {onRegenerate && (
              <Button
                variant="outline"
                className="w-full"
                onClick={onRegenerate}
                loading={regenerateLoading}
                iconLeft={<FileText className="h-4 w-4" />}
              >
                Regenerate Report
              </Button>
            )}
          </>
        ) : (
          <div className="flex flex-col items-center gap-3 py-4 text-center">
            <FileText className="h-8 w-8 text-text-muted" />
            <p className="text-sm text-text-muted">No report generated yet.</p>
            {onRegenerate && (
              <Button onClick={onRegenerate} loading={regenerateLoading} size="sm">
                Generate Report
              </Button>
            )}
          </div>
        )}
      </div>
    </Card>
  )
}
