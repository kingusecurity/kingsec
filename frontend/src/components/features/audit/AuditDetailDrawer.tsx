import { Badge } from '@/components/ui/Badge'
import { Drawer } from '@/components/ui/Drawer'
import { formatDate } from '@/lib/utils'
import type { AuditEntry } from '@/api/audit'

interface AuditDetailDrawerProps {
  entry: AuditEntry | null
  open: boolean
  onClose: () => void
}

export function AuditDetailDrawer({ entry, open, onClose }: AuditDetailDrawerProps) {
  return (
    <Drawer open={open} onClose={onClose} title="Audit Entry Details">
      {entry ? (
        <div className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <p className="text-xs text-text-muted">User</p>
              <p className="text-sm font-medium text-text-primary">{entry.username}</p>
            </div>
            <div>
              <p className="text-xs text-text-muted">User ID</p>
              <p className="text-sm font-mono text-text-primary">{entry.user_id}</p>
            </div>
            <div>
              <p className="text-xs text-text-muted">Action</p>
              <code className="text-sm font-mono text-text-primary">{entry.action}</code>
            </div>
            <div>
              <p className="text-xs text-text-muted">Resource Type</p>
              <p className="text-sm font-medium text-text-primary">{entry.resource_type}</p>
            </div>
            <div>
              <p className="text-xs text-text-muted">Resource ID</p>
              <p className="text-sm font-mono text-text-primary">{entry.resource_id ?? 'N/A'}</p>
            </div>
            <div>
              <p className="text-xs text-text-muted">Status</p>
              <Badge variant={entry.success ? 'success' : 'critical'} size="sm">
                {entry.success ? 'Success' : 'Failed'}
              </Badge>
            </div>
            <div>
              <p className="text-xs text-text-muted">IP Address</p>
              <p className="text-sm font-medium text-text-primary">{entry.ip_address ?? 'N/A'}</p>
            </div>
          </div>
          <div>
            <p className="text-xs text-text-muted">Timestamp</p>
            <p className="text-sm font-medium text-text-primary">{formatDate(entry.timestamp)}</p>
          </div>
          {entry.reason && (
            <div>
              <p className="text-xs text-text-muted mb-1">Reason</p>
              <div className="rounded-lg bg-surface-tertiary p-3">
                <p className="text-sm text-text-primary whitespace-pre-wrap">{entry.reason}</p>
              </div>
            </div>
          )}
          {entry.correlation_id && (
            <div>
              <p className="text-xs text-text-muted">Correlation ID</p>
              <p className="text-sm font-mono text-text-primary">{entry.correlation_id}</p>
            </div>
          )}
        </div>
      ) : null}
    </Drawer>
  )
}
