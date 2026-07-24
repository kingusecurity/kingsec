import { AssessmentSeverityBadge } from '@/components/features/assessment/AssessmentSeverityBadge'
import { AssessmentStatusBadge } from '@/components/features/assessment/AssessmentStatusBadge'
import type { FindingResponse } from '@/types/api'

interface FindingsTableProps {
  findings: FindingResponse[]
  loading?: boolean
}

export function FindingsTable({ findings, loading }: FindingsTableProps) {
  if (loading) {
    return (
      <div className="space-y-3 p-4">
        <div className="h-4 w-full animate-pulse rounded bg-surface-tertiary" />
        <div className="h-4 w-3/4 animate-pulse rounded bg-surface-tertiary" />
        <div className="h-4 w-2/3 animate-pulse rounded bg-surface-tertiary" />
      </div>
    )
  }

  if (!findings || findings.length === 0) {
    return <p className="py-8 text-center text-sm text-text-muted">No findings found.</p>
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-surface-tertiary">
            <th className="px-5 py-3 text-left font-medium text-text-secondary">Title</th>
            <th className="px-5 py-3 text-left font-medium text-text-secondary">Severity</th>
            <th className="px-5 py-3 text-left font-medium text-text-secondary">Status</th>
            <th className="px-5 py-3 text-right font-medium text-text-secondary">Evidence</th>
            <th className="px-5 py-3 text-right font-medium text-text-secondary">Recommendations</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.finding_id} className="border-b border-border transition-colors hover:bg-surface-tertiary/50">
              <td className="px-5 py-3 font-medium text-text-primary">{f.title}</td>
              <td className="px-5 py-3">
                <AssessmentSeverityBadge severity={f.severity} />
              </td>
              <td className="px-5 py-3">
                <AssessmentStatusBadge status={f.status} />
              </td>
              <td className="px-5 py-3 text-right text-text-secondary">{f.evidence_count}</td>
              <td className="px-5 py-3 text-right text-text-secondary">{f.recommendation_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
