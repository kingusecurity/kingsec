import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Pagination } from '@/components/ui/Pagination'
import { formatDate } from '@/lib/utils'
import type { AuditEntry } from '@/api/audit'

const severityVariant: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'warning'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  success: 'success',
}

interface AuditTableProps {
  entries: AuditEntry[] | undefined
  isLoading: boolean
  error: Error | null
  onRetry: () => void
  currentPage: number
  totalPages: number
  onPageChange: (page: number) => void
  onSelect: (entry: AuditEntry) => void
}

export function AuditTable({
  entries,
  isLoading,
  error,
  onRetry,
  currentPage,
  totalPages,
  onPageChange,
  onSelect,
}: AuditTableProps) {
  if (error) {
    return <ErrorState title="Failed to load audit log" message={error.message} onRetry={onRetry} />
  }

  if (isLoading) {
    return (
      <div className="space-y-3">
        <div className="flex gap-4 border-b border-border pb-3">
          <Skeleton className="h-4 w-1/5" />
          <Skeleton className="h-4 w-1/5" />
          <Skeleton className="h-4 w-1/6" />
          <Skeleton className="h-4 w-1/6" />
          <Skeleton className="h-4 w-1/6" />
        </div>
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="flex gap-4 py-3">
            <Skeleton className="h-4 w-1/5" />
            <Skeleton className="h-4 w-1/5" />
            <Skeleton className="h-4 w-1/6" />
            <Skeleton className="h-4 w-1/6" />
            <Skeleton className="h-4 w-1/6" />
          </div>
        ))}
      </div>
    )
  }

  if (!entries || entries.length === 0) {
    return <EmptyState title="No audit entries" description="No audit log entries match your criteria" />
  }

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm" role="table">
          <thead>
            <tr className="border-b border-border text-left">
              <th className="pb-3 text-xs font-medium text-text-muted uppercase tracking-wider px-2">User</th>
              <th className="pb-3 text-xs font-medium text-text-muted uppercase tracking-wider px-2">Action</th>
              <th className="pb-3 text-xs font-medium text-text-muted uppercase tracking-wider px-2">Resource</th>
              <th className="pb-3 text-xs font-medium text-text-muted uppercase tracking-wider px-2">Severity</th>
              <th className="pb-3 text-xs font-medium text-text-muted uppercase tracking-wider px-2">Status</th>
              <th className="pb-3 text-xs font-medium text-text-muted uppercase tracking-wider px-2">Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr
                key={entry.id}
                className="border-b border-border/50 hover:bg-surface-tertiary/50 cursor-pointer transition-colors"
                onClick={() => onSelect(entry)}
                tabIndex={0}
                role="row"
                onKeyDown={(e) => { if (e.key === 'Enter') onSelect(entry) }}
                aria-label={`Audit entry: ${entry.action} on ${entry.resource_type}`}
              >
                <td className="py-3 px-2 text-text-primary">{entry.username}</td>
                <td className="py-3 px-2">
                  <code className="rounded bg-surface-tertiary px-1.5 py-0.5 text-xs font-mono text-text-primary">
                    {entry.action}
                  </code>
                </td>
                <td className="py-3 px-2 text-text-secondary">
                  {entry.resource_type}
                  {entry.resource_id && (
                    <span className="font-mono text-text-muted text-[10px] ml-1">
                      #{entry.resource_id.slice(0, 8)}
                    </span>
                  )}
                </td>
                <td className="py-3 px-2">
                  <Badge variant={severityVariant[entry.severity] ?? 'neutral'} size="sm">
                    {entry.severity}
                  </Badge>
                </td>
                <td className="py-3 px-2">
                  <Badge variant={entry.success ? 'success' : 'critical'} size="sm">
                    {entry.success ? 'Success' : 'Failed'}
                  </Badge>
                </td>
                <td className="py-3 px-2 text-text-secondary text-xs whitespace-nowrap">
                  {formatDate(entry.created_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {totalPages > 1 && (
        <div className="flex justify-center pt-4">
          <Pagination currentPage={currentPage} totalPages={totalPages} onPageChange={onPageChange} />
        </div>
      )}
    </div>
  )
}
