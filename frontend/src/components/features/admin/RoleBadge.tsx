import { memo } from 'react'
import { Badge } from '@/components/ui/Badge'

const roleVariant: Record<string, 'critical' | 'warning' | 'info' | 'neutral'> = {
  admin: 'critical',
  analyst: 'warning',
  viewer: 'info',
}

interface RoleBadgeProps {
  role: string
}

export const RoleBadge = memo(function RoleBadge({ role }: RoleBadgeProps) {
  return (
    <Badge variant={roleVariant[role.toLowerCase()] ?? 'neutral'} size="sm">
      {role}
    </Badge>
  )
})
