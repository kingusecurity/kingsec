import { AssessmentSeverityBadge } from './AssessmentSeverityBadge'
import type { FindingResponse } from '@/types/api'

interface FindingsSummaryTableProps {
  findings: FindingResponse[]
}

export function FindingsSummaryTable({ findings }: FindingsSummaryTableProps) {
  if (findings.length === 0) {
    return <p className="text-sm text-text-muted py-4 text-center">No findings found.</p>
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-surface-tertiary">
            <th scope="col" className="px-4 py-3 text-left font-medium text-text-secondary">Title</th>
            <th scope="col" className="px-4 py-3 text-left font-medium text-text-secondary">Severity</th>
            <th scope="col" className="px-4 py-3 text-left font-medium text-text-secondary">Status</th>
            <th scope="col" className="px-4 py-3 text-right font-medium text-text-secondary">Evidence</th>
            <th scope="col" className="px-4 py-3 text-right font-medium text-text-secondary">Recommendations</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr key={finding.finding_id} className="border-b border-border transition-colors hover:bg-surface-tertiary/50">
              <td className="px-4 py-3 text-text-primary">{finding.title}</td>
              <td className="px-4 py-3">
                <AssessmentSeverityBadge severity={finding.severity} />
              </td>
              <td className="px-4 py-3 text-text-secondary">{finding.status}</td>
              <td className="px-4 py-3 text-right text-text-secondary">{finding.evidence_count}</td>
              <td className="px-4 py-3 text-right text-text-secondary">{finding.recommendation_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
