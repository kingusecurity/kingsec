import { Badge } from '@/components/ui/Badge'

interface UserStatusBadgeProps {
  isActive: boolean
}

export function UserStatusBadge({ isActive }: UserStatusBadgeProps) {
  return (
    <Badge variant={isActive ? 'success' : 'neutral'} size="sm">
      {isActive ? 'Active' : 'Inactive'}
    </Badge>
  )
}
