import { Shield, CheckCircle } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import type { RolePermission } from '@/api/admin'

interface RolePermissionsPanelProps {
  roles: RolePermission[] | undefined
  isLoading: boolean
  error: Error | null
  onRetry: () => void
}

export function RolePermissionsPanel({ roles, isLoading, error, onRetry }: RolePermissionsPanelProps) {
  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Roles & Permissions</CardTitle>
          <CardDescription>System roles and their access permissions</CardDescription>
        </CardHeader>
        <div className="p-5">
          <ErrorState title="Failed to load roles" message={error.message} onRetry={onRetry} />
        </div>
      </Card>
    )
  }

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Roles & Permissions</CardTitle>
          <CardDescription>System roles and their access permissions</CardDescription>
        </CardHeader>
        <div className="p-5 space-y-4">
          <Skeleton className="h-24 w-full rounded-lg" />
          <Skeleton className="h-24 w-full rounded-lg" />
          <Skeleton className="h-24 w-full rounded-lg" />
        </div>
      </Card>
    )
  }

  if (!roles || roles.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Roles & Permissions</CardTitle>
          <CardDescription>System roles and their access permissions</CardDescription>
        </CardHeader>
        <div className="p-5">
          <p className="text-sm text-text-secondary">No roles configured.</p>
        </div>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      {roles.map((role) => (
        <Card key={role.role}>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-accent" />
              <CardTitle className="capitalize">{role.role}</CardTitle>
            </div>
            {role.description && (
              <CardDescription>{role.description}</CardDescription>
            )}
          </CardHeader>
          <div className="px-5 pb-5 space-y-4">
            <div>
              <p className="text-sm font-medium text-text-primary mb-2">Permissions</p>
              <div className="flex flex-wrap gap-2">
                {role.permissions.map((perm) => (
                  <div key={perm} className="flex items-center gap-1.5 rounded-md bg-surface-tertiary/50 px-2.5 py-1">
                    <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
                    <span className="text-xs text-text-secondary">{perm}</span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <p className="text-sm font-medium text-text-primary mb-2">Accessible Modules</p>
              <div className="flex flex-wrap gap-2">
                {role.accessible_modules.map((mod) => (
                  <Badge key={mod} variant="info" size="sm">
                    {mod}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
        </Card>
      ))}
    </div>
  )
}
