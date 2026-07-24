import { Shield, LogOut } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { useSessions, useDeleteSession, useDeleteAllSessions, useMfaStatus } from '@/hooks/use-settings'
import { useAuthStore } from '@/store/auth'
import { formatRelativeTime } from '@/lib/utils'
import type { SessionInfo } from '@/api/settings'

function SessionRow({ session, onDelete }: { session: SessionInfo; onDelete: (id: string) => void }) {
  return (
    <div className="flex items-center justify-between rounded-lg bg-surface-tertiary/50 p-3">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <p className="text-sm font-medium text-text-primary truncate">
            {session.user_agent || 'Unknown'}
          </p>
          {session.is_current && <Badge variant="success" size="sm">Current</Badge>}
        </div>
        <p className="text-xs text-text-muted mt-0.5">
          IP: {session.ip_address || 'Unknown'} &middot; Last active: {formatRelativeTime(session.last_active_at)}
        </p>
      </div>
      {!session.is_current && (
        <Button
          variant="ghost"
          size="xs"
          onClick={() => onDelete(session.id)}
          aria-label="Terminate session"
        >
          <LogOut className="h-3 w-3" />
        </Button>
      )}
    </div>
  )
}

export function SecuritySection() {
  const user = useAuthStore((s) => s.user)
  const { data: sessions, isLoading: sessionsLoading, error: sessionsError, refetch: refetchSessions } = useSessions()
  const { data: mfaStatus, isLoading: mfaLoading } = useMfaStatus()
  const deleteSession = useDeleteSession()
  const deleteAll = useDeleteAllSessions()

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Account Security</CardTitle>
          <CardDescription>Manage your account security settings</CardDescription>
        </CardHeader>
        <div className="p-5 space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <p className="text-xs text-text-muted">User ID</p>
              <p className="text-sm font-medium text-text-primary font-mono">{user?.user_id ?? '-'}</p>
            </div>
            <div>
              <p className="text-xs text-text-muted">Multi-Factor Authentication</p>
              {mfaLoading ? (
                <Skeleton className="h-5 w-20 mt-0.5" />
              ) : (
                <Badge variant={mfaStatus?.enabled ? 'success' : 'neutral'} size="sm">
                  {mfaStatus?.enabled ? 'Enabled' : 'Disabled'}
                </Badge>
              )}
            </div>
          </div>
        </div>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Active Sessions</CardTitle>
          <CardDescription>Manage your active sessions</CardDescription>
        </CardHeader>
        <div className="p-5">
          {sessionsError ? (
            <ErrorState message={(sessionsError as Error).message} onRetry={() => refetchSessions()} />
          ) : sessionsLoading ? (
            <div className="space-y-3">
              {Array.from({ length: 2 }).map((_, i) => (
                <Skeleton key={i} className="h-16 w-full rounded-lg" />
              ))}
            </div>
          ) : !sessions || sessions.length === 0 ? (
            <EmptyState icon={<Shield className="h-8 w-8" />} title="No active sessions" />
          ) : (
            <div className="space-y-3">
              {sessions.map((s: SessionInfo) => (
                <SessionRow key={s.id} session={s} onDelete={(id) => deleteSession.mutate(id)} />
              ))}
              {sessions.length > 1 && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => deleteAll.mutate()}
                  iconLeft={<LogOut className="h-4 w-4" />}
                >
                  Logout all sessions
                </Button>
              )}
            </div>
          )}
        </div>
      </Card>
    </div>
  )
}
