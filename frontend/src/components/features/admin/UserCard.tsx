import { Card } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { UserStatusBadge } from './UserStatusBadge'
import { RoleBadge } from './RoleBadge'
import type { AdminUser } from '@/api/admin'

interface UserCardProps {
  user: AdminUser | undefined
  isLoading: boolean
}

export function UserCard({ user, isLoading }: UserCardProps) {
  if (isLoading) {
    return (
      <Card>
        <div className="p-5 space-y-3">
          <Skeleton className="h-6 w-48" />
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-4 w-24" />
        </div>
      </Card>
    )
  }

  if (!user) return null

  return (
    <Card>
      <div className="p-5 space-y-4">
        <div className="flex items-center gap-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-accent/10 text-lg font-semibold text-accent">
            {user.username.charAt(0).toUpperCase()}
          </div>
          <div>
            <h3 className="text-lg font-semibold text-text-primary">{user.username}</h3>
            <p className="text-sm text-text-secondary">{user.email}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <UserStatusBadge isActive={user.is_active} />
          <RoleBadge role={user.role} />
        </div>
      </div>
    </Card>
  )
}
