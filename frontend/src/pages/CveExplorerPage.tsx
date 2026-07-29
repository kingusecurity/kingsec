import { useState } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import { useCves, useSyncCve, useDeleteCve } from '@/hooks/use-threat-intelligence'
import type { CveFilter } from '@/api/threat-intelligence'

export function CveExplorerPage() {
  const [filter, setFilter] = useState<CveFilter>({ page: 1, page_size: 20, sort_by: '-threat_score' })
  const [searchInput, setSearchInput] = useState('')
  const [syncCode, setSyncCode] = useState('')
  const { data, isLoading } = useCves(filter)
  const syncCve = useSyncCve()
  const deleteCve = useDeleteCve()

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.ceil(total / (filter.page_size ?? 20))

  const handleSearch = () => {
    setFilter((f) => ({ ...f, search: searchInput || undefined, page: 1 }))
  }

  const handleSync = () => {
    if (syncCode.trim()) {
      syncCve.mutate(syncCode.trim())
      setSyncCode('')
    }
  }

  const severityBadge = (s: string) => {
    if (s === 'CRITICAL') return <Badge variant="danger">{s}</Badge>
    if (s === 'HIGH') return <Badge variant="warning">{s}</Badge>
    if (s === 'MEDIUM') return <Badge variant="neutral">{s}</Badge>
    return <Badge variant="neutral">{s}</Badge>
  }

  return (
    <PageContainer>
      <PageHeader title="CVE Explorer" description="Browse, search, and enrich CVEs from threat intelligence sources" />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <input
          type="text"
          placeholder="Search CVEs..."
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
          className="rounded border border-border-primary bg-bg-secondary px-3 py-1.5 text-sm text-text-primary"
        />
        <Button onClick={handleSearch} variant="outline" className="text-xs">Search</Button>

        <div className="ml-auto flex items-center gap-2">
          <input
            type="text"
            placeholder="CVE-XXXX-XXXXX"
            value={syncCode}
            onChange={(e) => setSyncCode(e.target.value)}
            className="rounded border border-border-primary bg-bg-secondary px-3 py-1.5 text-sm text-text-primary"
          />
          <Button onClick={handleSync} variant="primary" className="text-xs" disabled={syncCve.isPending}>
            {syncCve.isPending ? 'Syncing...' : 'Sync CVE'}
          </Button>
        </div>
      </div>

      {/* Severity filter */}
      <div className="mb-4 flex flex-wrap items-center gap-2 text-xs">
        <span className="text-text-muted">Severity:</span>
        {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
          <button
            key={s}
            onClick={() => setFilter((f) => ({ ...f, severity: s || undefined, page: 1 }))}
            className={`rounded px-2 py-1 ${(filter.severity ?? '') === s ? 'bg-accent-primary text-white' : 'bg-bg-secondary text-text-muted'}`}
          >
            {s || 'All'}
          </button>
        ))}
        <span className="ml-2 text-text-muted">KEV:</span>
        <button
          onClick={() => setFilter((f) => ({ ...f, is_kev: f.is_kev ? undefined : true, page: 1 }))}
          className={`rounded px-2 py-1 ${filter.is_kev ? 'bg-red-500 text-white' : 'bg-bg-secondary text-text-muted'}`}
        >
          KEV Only
        </button>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-8"><Spinner /></div>
      ) : items.length > 0 ? (
        <div className="space-y-2">
          {items.map((cve) => (
            <Card key={cve.id}>
              <div className="flex items-start justify-between px-5 py-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <a
                      href={`/threat-intelligence/cves/${cve.id}`}
                      className="text-sm font-medium text-accent-primary hover:underline"
                    >
                      {cve.cve_code}
                    </a>
                    {severityBadge(cve.severity)}
                    {cve.is_kev && <Badge variant="danger">KEV</Badge>}
                    <span className="text-xs text-text-muted">
                      {cve.exploit_maturity.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-text-muted line-clamp-2">{cve.description}</p>
                  {cve.affected_products.length > 0 && (
                    <p className="mt-1 text-xs text-text-muted">
                      {cve.affected_products.map((p) => `${p.vendor}/${p.product} ${p.version}`).join(', ')}
                    </p>
                  )}
                </div>
                <div className="ml-4 flex flex-col items-end gap-1">
                  <span className="text-lg font-bold text-text-primary">{cve.threat_score.toFixed(1)}</span>
                  <span className="text-xs text-text-muted">CVSS: {cve.cvss_data.base_score.toFixed(1)}</span>
                  <button
                    onClick={() => deleteCve.mutate(cve.id)}
                    className="text-xs text-red-500 hover:underline"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      ) : (
        <p className="py-8 text-center text-sm text-text-muted">No CVEs found. Sync a CVE to get started.</p>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="mt-4 flex items-center justify-center gap-2 text-sm">
          <button
            onClick={() => setFilter((f) => ({ ...f, page: Math.max(1, (f.page ?? 1) - 1) }))}
            disabled={(filter.page ?? 1) <= 1}
            className="rounded bg-bg-secondary px-3 py-1 text-text-muted disabled:opacity-50"
          >
            Previous
          </button>
          <span className="text-text-muted">
            Page {filter.page ?? 1} of {totalPages} ({total} total)
          </span>
          <button
            onClick={() => setFilter((f) => ({ ...f, page: Math.min(totalPages, (f.page ?? 1) + 1) }))}
            disabled={(filter.page ?? 1) >= totalPages}
            className="rounded bg-bg-secondary px-3 py-1 text-text-muted disabled:opacity-50"
          >
            Next
          </button>
        </div>
      )}
    </PageContainer>
  )
}
