import { Badge } from '@/components/ui/Badge'
import { Drawer } from '@/components/ui/Drawer'
import { Skeleton } from '@/components/ui/Skeleton'
import { formatDate } from '@/lib/utils'
import { useAuditEntry } from '@/hooks/use-audit'
import type { AuditEntry } from '@/api/audit'

const severityVariant: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'warning'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  success: 'success',
}

interface AuditDetailDrawerProps {
  entry: AuditEntry | null
  open: boolean
  onClose: () => void
}

export function AuditDetailDrawer({ entry, open, onClose }: AuditDetailDrawerProps) {
  const { data: detail, isLoading } = useAuditEntry(entry?.id ?? '')

  const auditData = detail ?? entry

  return (
    <Drawer open={open} onClose={onClose} title="Audit Entry Details">
      {isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-5 w-1/2" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-4 w-1/2" />
        </div>
      ) : auditData ? (
        <div className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <p className="text-xs text-text-muted">User</p>
              <p className="text-sm font-medium text-text-primary">{auditData.username}</p>
            </div>
            <div>
              <p className="text-xs text-text-muted">User ID</p>
              <p className="text-sm font-mono text-text-primary">{auditData.user_id}</p>
            </div>
            <div>
              <p className="text-xs text-text-muted">Action</p>
              <code className="text-sm font-mono text-text-primary">{auditData.action}</code>
            </div>
            <div>
              <p className="text-xs text-text-muted">Severity</p>
              <Badge variant={severityVariant[auditData.severity] ?? 'neutral'} size="sm">
                {auditData.severity}
              </Badge>
            </div>
            <div>
              <p className="text-xs text-text-muted">Resource Type</p>
              <p className="text-sm font-medium text-text-primary">{auditData.resource_type}</p>
            </div>
            <div>
              <p className="text-xs text-text-muted">Resource ID</p>
              <p className="text-sm font-mono text-text-primary">{auditData.resource_id ?? 'N/A'}</p>
            </div>
            <div>
              <p className="text-xs text-text-muted">Status</p>
              <Badge variant={auditData.success ? 'success' : 'critical'} size="sm">
                {auditData.success ? 'Success' : 'Failed'}
              </Badge>
            </div>
            <div>
              <p className="text-xs text-text-muted">IP Address</p>
              <p className="text-sm font-medium text-text-primary">{auditData.ip_address ?? 'N/A'}</p>
            </div>
          </div>
          <div>
            <p className="text-xs text-text-muted">Timestamp</p>
            <p className="text-sm font-medium text-text-primary">{formatDate(auditData.created_at)}</p>
          </div>
          {auditData.details && (
            <div>
              <p className="text-xs text-text-muted mb-1">Details</p>
              <div className="rounded-lg bg-surface-tertiary p-3">
                <p className="text-sm text-text-primary whitespace-pre-wrap">{auditData.details}</p>
              </div>
            </div>
          )}
        </div>
      ) : null}
    </Drawer>
  )
}
