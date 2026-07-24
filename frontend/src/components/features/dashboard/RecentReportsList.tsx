import { Link } from 'react-router-dom'
import { Skeleton } from '@/components/ui/Skeleton'
import { Badge } from '@/components/ui/Badge'
import { FileText, ArrowRight } from 'lucide-react'
import { formatRelativeTime } from '@/lib/utils'
import type { RecentReportItem } from '@/types/api'

interface RecentReportsListProps {
  reports?: RecentReportItem[]
  loading?: boolean
}

const verdictVariant: Record<string, 'success' | 'warning' | 'critical' | 'neutral'> = {
  safe: 'success',
  minor: 'warning',
  moderate: 'warning',
  critical: 'critical',
  unknown: 'neutral',
}

export function RecentReportsList({ reports, loading }: RecentReportsListProps) {
  if (loading) {
    return (
      <div className="space-y-3 p-4">
        <Skeleton className="h-4 w-3/4" />
        <Skeleton className="h-4 w-1/2" />
        <Skeleton className="h-4 w-2/3" />
      </div>
    )
  }

  if (!reports || reports.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 py-6 text-center">
        <FileText className="h-8 w-8 text-text-muted" />
        <p className="text-sm text-text-muted">No reports generated yet.</p>
      </div>
    )
  }

  return (
    <div className="divide-y divide-border">
      {reports.slice(0, 5).map((r) => (
        <Link
          key={r.assessment_id}
          to={`/assessments/${r.assessment_id}`}
          className="flex items-center justify-between px-5 py-3 transition-colors hover:bg-surface-tertiary/50"
        >
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-text-primary truncate">{r.target}</p>
            <p className="text-xs text-text-muted mt-0.5">{formatRelativeTime(r.generated_at)}</p>
          </div>
          <div className="flex items-center gap-3">
            <Badge variant={verdictVariant[r.verdict?.toLowerCase()] ?? 'neutral'} size="sm">
              {r.verdict}
            </Badge>
            <ArrowRight className="h-4 w-4 text-text-muted" />
          </div>
        </Link>
      ))}
    </div>
  )
}
