import { Link } from 'react-router-dom'
import { AssessmentStatusBadge } from '@/components/features/assessment/AssessmentStatusBadge'
import { Skeleton } from '@/components/ui/Skeleton'
import { ArrowRight } from 'lucide-react'
import { formatRelativeTime } from '@/lib/utils'
import type { RecentAssessmentItem } from '@/types/api'

interface RecentAssessmentsTableProps {
  assessments?: RecentAssessmentItem[]
  loading?: boolean
}

export function RecentAssessmentsTable({ assessments, loading }: RecentAssessmentsTableProps) {
  if (loading) {
    return (
      <div className="space-y-3 p-4">
        <Skeleton className="h-4 w-3/4" />
        <Skeleton className="h-4 w-1/2" />
        <Skeleton className="h-4 w-2/3" />
      </div>
    )
  }

  if (!assessments || assessments.length === 0) {
    return <p className="text-sm text-text-muted py-4 text-center">No recent assessments.</p>
  }

  return (
    <div className="divide-y divide-border">
      {assessments.slice(0, 5).map((a) => (
        <Link
          key={a.assessment_id}
          to={`/assessments/${a.assessment_id}`}
          className="flex items-center justify-between px-5 py-3 transition-colors hover:bg-surface-tertiary/50"
        >
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-text-primary truncate">{a.target}</p>
            <p className="text-xs text-text-muted mt-0.5">{formatRelativeTime(a.created_at)}</p>
          </div>
          <div className="flex items-center gap-3">
            <AssessmentStatusBadge status={a.status} />
            <ArrowRight className="h-4 w-4 text-text-muted" />
          </div>
        </Link>
      ))}
      <div className="px-5 py-3">
        <Link to="/assessments" className="inline-flex items-center justify-center rounded-lg text-sm font-medium text-text-secondary hover:text-text-primary hover:bg-surface-tertiary transition-colors w-full py-2">
          View All Assessments
        </Link>
      </div>
    </div>
  )
}
