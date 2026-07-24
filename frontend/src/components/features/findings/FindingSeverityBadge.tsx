import { Badge } from '@/components/ui/Badge'

const severityVariantMap: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  informational: 'info',
}

interface FindingSeverityBadgeProps {
  severity: string
}

export function FindingSeverityBadge({ severity }: FindingSeverityBadgeProps) {
  const variant = severityVariantMap[severity.toLowerCase()] ?? 'info'
  return <Badge variant={variant}>{severity}</Badge>
}
