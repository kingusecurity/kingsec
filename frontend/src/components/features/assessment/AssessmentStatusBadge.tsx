import { memo } from 'react'
import { Badge } from '@/components/ui/Badge'

const statusVariantMap: Record<string, 'success' | 'warning' | 'neutral' | 'critical' | 'info'> = {
  completed: 'success',
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
  const variant = statusVariantMap[status.toLowerCase()] ?? 'neutral'
  return <Badge variant={variant}>{status}</Badge>
})
