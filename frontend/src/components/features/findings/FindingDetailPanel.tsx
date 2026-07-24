import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { AssessmentSeverityBadge } from '@/components/features/assessment/AssessmentSeverityBadge'
import { AssessmentStatusBadge } from '@/components/features/assessment/AssessmentStatusBadge'
import type { FindingDetail } from '@/types/api'

interface FindingDetailPanelProps {
  finding?: FindingDetail
  loading?: boolean
}

export function FindingDetailPanel({ finding, loading }: FindingDetailPanelProps) {
  if (loading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-3/4" />
          <Skeleton className="h-4 w-1/2" />
        </CardHeader>
        <div className="px-5 pb-5 space-y-3">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-2/3" />
        </div>
      </Card>
    )
  }

  if (!finding) return null

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
      <div className="px-5 pb-5 space-y-4">
        {finding.description && (
          <div>
            <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-1">Description</p>
            <p className="text-sm text-text-secondary leading-relaxed">{finding.description}</p>
          </div>
        )}

        {finding.remediation && (
          <div>
            <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-1">Remediation</p>
            <p className="text-sm text-text-secondary leading-relaxed">{finding.remediation}</p>
          </div>
        )}

        <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 pt-2 border-t border-border">
          {finding.scanner && (
            <div>
              <p className="text-xs text-text-muted">Scanner</p>
              <p className="text-sm font-medium text-text-primary">{finding.scanner}</p>
            </div>
          )}
          {finding.asset && (
            <div>
              <p className="text-xs text-text-muted">Asset</p>
              <p className="text-sm font-medium text-text-primary">{finding.asset}</p>
            </div>
          )}
          {finding.port && (
            <div>
              <p className="text-xs text-text-muted">Port</p>
              <p className="text-sm font-medium text-text-primary">{finding.port}/{finding.protocol ?? 'tcp'}</p>
            </div>
          )}
          {finding.cvss_score !== undefined && (
            <div>
              <p className="text-xs text-text-muted">CVSS Score</p>
              <p className="text-sm font-medium text-text-primary">{finding.cvss_score.toFixed(1)}</p>
            </div>
          )}
          {finding.cvss_vector && (
            <div className="col-span-2">
              <p className="text-xs text-text-muted">CVSS Vector</p>
              <code className="text-xs text-text-secondary break-all">{finding.cvss_vector}</code>
            </div>
          )}
          {finding.evidence && finding.evidence.length > 0 && (
            <div className="col-span-full">
              <p className="text-xs text-text-muted">Evidence Items</p>
              <p className="text-sm font-medium text-text-primary">{finding.evidence.length}</p>
            </div>
          )}
          {finding.references && finding.references.length > 0 && (
            <div className="col-span-full">
              <p className="text-xs text-text-muted">References</p>
              <p className="text-sm font-medium text-text-primary">{finding.references.length}</p>
            </div>
          )}
        </div>

        <div className="text-xs text-text-muted pt-1">
          Finding ID: {finding.finding_id}
          {finding.assessment_id && <> &middot; Assessment: {finding.assessment_id}</>}
        </div>
      </div>
    </Card>
  )
}
