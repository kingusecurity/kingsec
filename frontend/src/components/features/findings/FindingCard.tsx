import { Link } from 'react-router-dom'
import { Shield, ArrowRight } from 'lucide-react'
import { Card } from '@/components/ui/Card'
import { AssessmentSeverityBadge } from '@/components/features/assessment/AssessmentSeverityBadge'
import { AssessmentStatusBadge } from '@/components/features/assessment/AssessmentStatusBadge'
import type { FindingDetail } from '@/types/api'

interface FindingCardProps {
  finding: FindingDetail
  assessmentId?: string
  loading?: boolean
}

export function FindingCard({ finding, assessmentId, loading }: FindingCardProps) {
  if (loading) {
    return (
      <Card>
        <div className="p-5 space-y-3">
          <div className="h-5 w-3/4 animate-pulse rounded bg-surface-tertiary" />
          <div className="h-4 w-1/2 animate-pulse rounded bg-surface-tertiary" />
        </div>
      </Card>
    )
  }

  const detailPath = assessmentId
    ? `/assessments/${assessmentId}/findings/${finding.finding_id}`
    : `/findings/${finding.finding_id}`

  return (
    <Card className="hover:border-border-light transition-colors">
      <div className="p-5 space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-tertiary">
              <Shield className="h-4 w-4 text-text-muted" />
            </div>
            <div className="min-w-0">
              <Link
                to={detailPath}
                className="text-sm font-medium text-text-primary hover:text-accent transition-colors truncate block"
              >
                {finding.title}
              </Link>
              {finding.asset && (
                <p className="text-xs text-text-muted mt-0.5">{finding.asset}</p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <AssessmentSeverityBadge severity={finding.severity} />
            <AssessmentStatusBadge status={finding.status} />
          </div>
        </div>

        {finding.description && (
          <p className="text-xs text-text-secondary line-clamp-2">{finding.description}</p>
        )}

        <div className="flex items-center gap-4 text-xs text-text-secondary">
          {finding.cve && finding.cve.length > 0 && (
            <span>CVE: {finding.cve.length}</span>
          )}
          {finding.cvss_score !== undefined && (
            <span>CVSS: {finding.cvss_score.toFixed(1)}</span>
          )}
          {finding.port && (
            <span>Port: {finding.port}/{finding.protocol ?? 'tcp'}</span>
          )}
          {finding.scanner && (
            <span>Scanner: {finding.scanner}</span>
          )}
        </div>

        <div className="flex items-center justify-between pt-1">
          <Link
            to={detailPath}
            className="inline-flex items-center gap-1 text-xs text-accent hover:text-emerald-400 transition-colors"
          >
            View details
            <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
      </div>
    </Card>
  )
}
