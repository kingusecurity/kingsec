import { useAuthStore } from '@/store/auth'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { formatDate } from '@/lib/utils'

export function GeneralSection() {
  const user = useAuthStore((s) => s.user)

  return (
    <Card>
      <CardHeader>
        <CardTitle>General</CardTitle>
        <CardDescription>Your account information</CardDescription>
      </CardHeader>
      <div className="p-5 space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <p className="text-xs text-text-muted">Username</p>
            <p className="text-sm font-medium text-text-primary">{user?.username ?? '-'}</p>
          </div>
          <div>
            <p className="text-xs text-text-muted">Email</p>
            <p className="text-sm font-medium text-text-primary">{user?.email || '-'}</p>
          </div>
          <div>
            <p className="text-xs text-text-muted">Role</p>
            <Badge variant="info" size="sm">{user?.role ?? '-'}</Badge>
          </div>
          <div>
            <p className="text-xs text-text-muted">Account Status</p>
            <Badge variant={user?.is_active ? 'success' : 'warning'} size="sm">
              {user?.is_active ? 'Active' : 'Inactive'}
            </Badge>
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <p className="text-xs text-text-muted">Member Since</p>
            <p className="text-sm font-medium text-text-primary">
              {user?.created_at ? formatDate(user.created_at) : '-'}
            </p>
          </div>
          <div>
            <p className="text-xs text-text-muted">Last Login</p>
            <p className="text-sm font-medium text-text-primary">
              {user?.last_login_at ? formatDate(user.last_login_at) : 'N/A'}
            </p>
          </div>
        </div>
      </div>
    </Card>
  )
}
