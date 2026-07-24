import { Link } from 'react-router-dom'
import { ArrowRight, Download, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { AssessmentStatusBadge } from '@/components/features/assessment/AssessmentStatusBadge'
import { formatDate } from '@/lib/utils'
import { assessmentsApi } from '@/api/assessments'
import type { AssessmentSummary } from '@/types/api'

interface ReportTableProps {
  reports?: AssessmentSummary[]
  loading?: boolean
  onDownload?: (assessmentId: string) => void
  onDelete?: (assessmentId: string) => void
}

export function ReportTable({ reports, loading, onDownload, onDelete }: ReportTableProps) {
  if (loading) {
    return (
      <div className="space-y-3 p-4">
        <div className="h-4 w-3/4 animate-pulse rounded bg-surface-tertiary" />
        <div className="h-4 w-1/2 animate-pulse rounded bg-surface-tertiary" />
        <div className="h-4 w-2/3 animate-pulse rounded bg-surface-tertiary" />
      </div>
    )
  }

  if (!reports || reports.length === 0) {
    return <p className="py-8 text-center text-sm text-text-muted">No reports found.</p>
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-surface-tertiary">
            <th className="px-5 py-3 text-left font-medium text-text-secondary">Target</th>
            <th className="px-5 py-3 text-left font-medium text-text-secondary">Status</th>
            <th className="px-5 py-3 text-right font-medium text-text-secondary">Findings</th>
            <th className="px-5 py-3 text-left font-medium text-text-secondary">Date</th>
            <th className="px-5 py-3 w-24" />
          </tr>
        </thead>
        <tbody>
          {reports.map((r) => (
            <tr key={r.assessment_id} className="border-b border-border transition-colors hover:bg-surface-tertiary/50">
              <td className="px-5 py-3">
                <Link to={`/reports/${r.assessment_id}`} className="font-medium text-accent hover:text-emerald-400">
                  {r.target}
                </Link>
              </td>
              <td className="px-5 py-3">
                <AssessmentStatusBadge status={r.status} />
              </td>
              <td className="px-5 py-3 text-right text-text-secondary">{r.findings_count}</td>
              <td className="px-5 py-3 text-text-secondary whitespace-nowrap">{formatDate(r.created_at)}</td>
              <td className="px-5 py-3">
                <div className="flex items-center gap-1">
                  {onDownload ? (
                    <Button
                      variant="ghost"
                      size="xs"
                      onClick={() => onDownload(r.assessment_id)}
                      aria-label={`Download report for ${r.target}`}
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                  ) : (
                    <Button
                      variant="ghost"
                      size="xs"
                      onClick={() => window.open(assessmentsApi.getReportDownloadUrl(r.assessment_id, `report-${r.assessment_id}.pdf`), '_blank')}
                      aria-label={`Download report for ${r.target}`}
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                  )}
                  <Link
                    to={`/reports/${r.assessment_id}`}
                    className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-text-muted hover:text-text-primary hover:bg-surface-tertiary"
                    aria-label={`View report for ${r.target}`}
                  >
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                  {onDelete && (
                    <Button
                      variant="ghost"
                      size="xs"
                      onClick={() => onDelete(r.assessment_id)}
                      aria-label={`Delete report for ${r.target}`}
                      className="text-text-muted hover:text-red-400"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
