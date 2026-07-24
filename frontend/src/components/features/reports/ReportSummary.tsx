import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Progress } from '@/components/ui/Progress'
import { Skeleton } from '@/components/ui/Skeleton'

const severityVariant: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info' | 'neutral'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
}

interface SeverityCount {
  severity: string
  count: number
}

interface ReportSummaryProps {
  severityCounts?: SeverityCount[]
  totalFindings?: number
  highestSeverity?: string | null
  executiveSummary?: string
  recommendations?: string[]
  loading?: boolean
}

export function ReportSummary({
  severityCounts,
  totalFindings,
  highestSeverity,
  executiveSummary,
  recommendations,
  loading,
}: ReportSummaryProps) {
  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-48 rounded-xl" />
        <Skeleton className="h-32 rounded-xl" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {(severityCounts && severityCounts.length > 0) || highestSeverity ? (
        <Card>
          <CardHeader>
            <CardTitle>Severity Breakdown</CardTitle>
          </CardHeader>
          <div className="px-5 pb-5 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-text-secondary">Highest Severity</span>
              {highestSeverity ? (
                <Badge variant={severityVariant[highestSeverity.toLowerCase()] ?? 'neutral'}>
                  {highestSeverity}
                </Badge>
              ) : (
                <span className="text-sm text-text-muted">None</span>
              )}
            </div>
            <div className="pt-2 border-t border-border">
              <p className="text-sm font-medium text-text-primary mb-3">
                Distribution ({totalFindings ?? 0} total)
              </p>
              <div className="space-y-2">
                {severityCounts?.map((sc) => {
                  const pct = totalFindings && totalFindings > 0 ? Math.round((sc.count / totalFindings) * 100) : 0
                  return (
                    <div key={sc.severity} className="flex items-center gap-3">
                      <Badge variant={severityVariant[sc.severity.toLowerCase()] ?? 'neutral'} size="sm" className="w-20 capitalize">
                        {sc.severity}
                      </Badge>
                      <div className="flex-1">
                        <Progress value={pct} />
                      </div>
                      <span className="text-xs text-text-secondary w-12 text-right">{sc.count}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </Card>
      ) : null}

      {executiveSummary ? (
        <Card>
          <CardHeader>
            <CardTitle>Executive Summary</CardTitle>
          </CardHeader>
          <div className="px-5 pb-5">
            <p className="text-sm text-text-secondary leading-relaxed">{executiveSummary}</p>
          </div>
        </Card>
      ) : null}

      {recommendations && recommendations.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Recommendations</CardTitle>
          </CardHeader>
          <div className="px-5 pb-5">
            <ul className="space-y-2">
              {recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-text-secondary">
                  <span className="text-accent mt-0.5 shrink-0">•</span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        </Card>
      ) : null}
    </div>
  )
}
