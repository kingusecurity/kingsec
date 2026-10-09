import { memo } from 'react'
import { Badge } from '@/components/ui/Badge'

const statusVariantMap: Record<string, 'success' | 'warning' | 'neutral' | 'critical' | 'info'> = {
  completed: 'success',
  completed_with_gaps: 'warning',
  authorized: 'info',
  running: 'info',
  pending: 'warning',
  failed: 'critical',
  cancelled: 'neutral',
  draft: 'neutral',
}

interface AssessmentStatusBadgeProps {
  status: string
}

export const AssessmentStatusBadge = memo(function AssessmentStatusBadge({ status }: AssessmentStatusBadgeProps) {
  const normalizedStatus = status.toLowerCase()
  const variant = statusVariantMap[normalizedStatus] ?? 'neutral'
  return <Badge variant={variant}>{normalizedStatus.replace(/_/g, ' ')}</Badge>
})
