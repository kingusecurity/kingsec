import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Progress } from '@/components/ui/Progress'
import { formatDate } from '@/lib/utils'
import type { GenerateReportResponse } from '@/types/api'

const severityVariant: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info' | 'neutral'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
}

interface ReportMetadataCardProps {
  target: string
  createdAt: string
  report?: GenerateReportResponse
  loading?: boolean
}

export function ReportMetadataCard({ target, createdAt, report, loading }: ReportMetadataCardProps) {
  const total = report?.total_findings ?? 0

  return (
    <Card>
      <CardHeader>
        <CardTitle>Report Summary</CardTitle>
        <CardDescription>{target}</CardDescription>
      </CardHeader>
      <div className="px-5 pb-5 space-y-4">
        {loading ? (
          <div className="space-y-2">
            <div className="h-4 w-full animate-pulse rounded bg-surface-tertiary" />
            <div className="h-4 w-3/4 animate-pulse rounded bg-surface-tertiary" />
          </div>
        ) : (
          <>
            <div className="flex items-center justify-between">
              <span className="text-sm text-text-secondary">Created</span>
              <span className="text-sm text-text-primary">{formatDate(createdAt)}</span>
            </div>
            {report && (
              <>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-text-secondary">Verdict</span>
                  <Badge variant={severityVariant[report.verdict?.toLowerCase()] ?? 'neutral'}>{report.verdict}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-text-secondary">Action Required</span>
                  <span className={`text-sm font-medium ${report.action_required ? 'text-red-400' : 'text-emerald-400'}`}>
                    {report.action_required ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-text-secondary">Highest Severity</span>
                  {report.highest_severity ? (
                    <Badge variant={severityVariant[report.highest_severity.toLowerCase()] ?? 'neutral'}>
                      {report.highest_severity}
                    </Badge>
                  ) : (
                    <span className="text-sm text-text-muted">None</span>
                  )}
                </div>
                <div className="pt-2 border-t border-border">
                  <p className="text-sm font-medium text-text-primary mb-3">Severity Distribution ({total} total)</p>
                  <div className="space-y-2">
                    {report.severity_counts.map((sc) => (
                      <SeverityBar
                        key={sc.severity}
                        label={sc.severity}
                        count={sc.count}
                        total={total}
                      />
                    ))}
                  </div>
                </div>
              </>
            )}
          </>
        )}
      </div>
    </Card>
  )
}

function SeverityBar({
  label,
  count,
  total,
}: {
  label: string
  count: number
  total: number
}) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0
  const variant = severityVariant[label.toLowerCase()] ?? 'neutral'
  return (
    <div className="flex items-center gap-3">
      <Badge variant={variant} size="sm" className="w-20 capitalize">{label}</Badge>
      <div className="flex-1">
        <Progress value={pct} />
      </div>
      <span className="text-xs text-text-secondary w-12 text-right">{count}</span>
    </div>
  )
}
