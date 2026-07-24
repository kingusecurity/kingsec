import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { AssessmentSeverityBadge } from '@/components/features/assessment/AssessmentSeverityBadge'
import { AssessmentStatusBadge } from '@/components/features/assessment/AssessmentStatusBadge'
import type { FindingResponse } from '@/types/api'

interface FindingDetailCardProps {
  finding: FindingResponse & { assessment_id?: string; target?: string }
  loading?: boolean
}

export function FindingDetailCard({ finding, loading }: FindingDetailCardProps) {
  if (loading) {
    return (
      <Card>
        <CardHeader>
          <div className="h-6 w-3/4 animate-pulse rounded bg-surface-tertiary" />
          <div className="h-4 w-1/2 animate-pulse rounded bg-surface-tertiary" />
        </CardHeader>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle>{finding.title}</CardTitle>
            {finding.target && <CardDescription>Asset: {finding.target}</CardDescription>}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <AssessmentSeverityBadge severity={finding.severity} />
            <AssessmentStatusBadge status={finding.status} />
          </div>
        </div>
      </CardHeader>
      <div className="px-5 pb-5 space-y-3">
        <div className="flex items-center gap-6 text-sm">
          <div>
            <span className="text-text-secondary">Evidence Items</span>
            <p className="font-medium text-text-primary">{finding.evidence_count}</p>
          </div>
          <div>
            <span className="text-text-secondary">Recommendations</span>
            <p className="font-medium text-text-primary">{finding.recommendation_count}</p>
          </div>
        </div>
        <p className="text-xs text-text-muted">Finding ID: {finding.finding_id}</p>
      </div>
    </Card>
  )
}
