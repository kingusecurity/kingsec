import { useState, useCallback } from 'react'
import { PageContainer, PageHeader, Panel } from '@/components/layout/PageContainer'
import { AuditFilters } from '@/components/features/audit/AuditFilters'
import { AuditTable } from '@/components/features/audit/AuditTable'
import { AuditDetailDrawer } from '@/components/features/audit/AuditDetailDrawer'
import { useAuditLog } from '@/hooks/use-audit'
import type { AuditEntry } from '@/api/audit'

const PAGE_SIZE = 20

export function AuditLogPage() {
  const [search, setSearch] = useState('')
  const [action, setAction] = useState('')
  const [resourceType, setResourceType] = useState('')
  const [severity, setSeverity] = useState('')
  const [success, setSuccess] = useState('')
  const [page, setPage] = useState(0)
  const [selectedEntry, setSelectedEntry] = useState<AuditEntry | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)

  const params = {
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
    search: search || undefined,
    action: action || undefined,
    resource_type: resourceType || undefined,
    severity: severity || undefined,
    success: success ? success === 'true' : undefined,
  }

  const { data, isLoading, error, refetch } = useAuditLog(params)

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0

  const hasFilters = !!(search || action || resourceType || severity || success)

  const handleClear = useCallback(() => {
    setSearch('')
    setAction('')
    setResourceType('')
    setSeverity('')
    setSuccess('')
    setPage(0)
  }, [])

  const handleSelect = useCallback((entry: AuditEntry) => {
    setSelectedEntry(entry)
    setDrawerOpen(true)
  }, [])

  return (
    <PageContainer>
      <PageHeader
        title="Audit Log"
        description="View and search security audit events"
      />
      <Panel title="Audit Events">
        <div className="p-5 space-y-4">
          <AuditFilters
            search={search}
            action={action}
            resourceType={resourceType}
            severity={severity}
            success={success}
            onSearchChange={(v) => { setSearch(v); setPage(0) }}
            onActionChange={(v) => { setAction(v); setPage(0) }}
            onResourceTypeChange={(v) => { setResourceType(v); setPage(0) }}
            onSeverityChange={(v) => { setSeverity(v); setPage(0) }}
            onSuccessChange={(v) => { setSuccess(v); setPage(0) }}
            onClear={handleClear}
            hasFilters={hasFilters}
          />
          <AuditTable
            entries={data?.items}
            isLoading={isLoading}
            error={error as Error | null}
            onRetry={() => refetch()}
            currentPage={page + 1}
            totalPages={totalPages}
            onPageChange={(p) => setPage(p - 1)}
            onSelect={handleSelect}
          />
        </div>
      </Panel>
      <AuditDetailDrawer
        entry={selectedEntry}
        open={drawerOpen}
        onClose={() => { setDrawerOpen(false); setSelectedEntry(null) }}
      />
    </PageContainer>
  )
}
