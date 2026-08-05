import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { Input } from '@/components/ui/Input'
import { Pagination } from '@/components/ui/Pagination'
import { useAttackSurfaceSummary, useExposures } from '@/hooks/use-attack-surface'
import type { ExposureListItem } from '@/api/attack-surface'

const PAGE_SIZE = 24

function useDebouncedValue(value: string, delay: number): string {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return debounced
}

const severityColors: Record<string, string> = {
  critical: 'border-red-500 text-red-500',
  high: 'border-orange-500 text-orange-500',
  medium: 'border-yellow-500 text-yellow-500',
  low: 'border-green-500 text-green-500',
  info: 'border-blue-500 text-blue-500',
}

function ExposureCard({ item }: { item: ExposureListItem }) {
  const nav = useNavigate()
  return (
    <div
      className="cursor-pointer rounded-lg border border-border bg-surface-primary transition-shadow hover:shadow-md"
      onClick={() => nav(`/attack-surface/${item.id}`)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && nav(`/attack-surface/${item.id}`)}
    >
      <div className="flex items-start gap-3 px-5 py-4">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-text-primary">
            {item.title || item.exposure_type.replace(/_/g, ' ')}
          </p>
          <p className="text-xs text-text-muted">
            {item.exposure_type.replace(/_/g, ' ')}
            {item.hostname && ` · ${item.hostname}`}
            {item.ip_address && !item.hostname && ` · ${item.ip_address}`}
          </p>
          {item.remediation && (
            <p className="mt-1 text-xs text-text-muted line-clamp-1">{item.remediation}</p>
          )}
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <Badge variant="neutral" className={`border ${severityColors[item.severity] || ''}`}>
            {item.severity}
          </Badge>
          {item.risk_score > 0 && (
            <span className="text-xs font-medium text-text-muted">
              Risk: {item.risk_score.toFixed(0)}
            </span>
          )}
          <Badge variant="neutral" className="text-xs text-text-muted">
            {item.status}
          </Badge>
        </div>
      </div>
    </div>
  )
}

export function AttackSurfacePage() {
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [page, setPage] = useState(1)
  const debouncedSearch = useDebouncedValue(search, 300)
  const { data: summary, isLoading: summaryLoading, isError, error, refetch } = useAttackSurfaceSummary()
  const { data: listData, isLoading: listLoading } = useExposures({
    search: debouncedSearch || undefined,
    severity: sevFilter || undefined,
    status: statusFilter || undefined,
    limit: PAGE_SIZE,
    offset: (page - 1) * PAGE_SIZE,
  })

  useEffect(() => { setPage(1) }, [debouncedSearch, sevFilter, statusFilter])

  const exposures = listData?.items ?? []
  const total = listData?.total ?? 0
  const totalPages = listData ? Math.ceil(listData.total / (listData.limit || PAGE_SIZE)) : 0

  return (
    <PageContainer>
      <PageHeader
        title="Attack Surface"
        description="Discover and manage exposures across your infrastructure"
      />

      {isError ? (
        <ErrorState
          title="Failed to load attack surface summary"
          message={(error as Error)?.message}
          onRetry={() => refetch()}
        />
      ) : summaryLoading ? (
        <div className="flex justify-center py-12">
          <Spinner size="lg" />
        </div>
      ) : (
        <div className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader><CardTitle className="text-sm text-text-secondary">Total Exposures</CardTitle></CardHeader>
              <div className="px-5 pb-5">
                <p className="text-2xl font-bold">{summary?.total_exposures ?? 0}</p>
              </div>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm text-text-secondary">Critical</CardTitle></CardHeader>
              <div className="px-5 pb-5">
                <p className="text-2xl font-bold text-red-500">{summary?.critical_count ?? 0}</p>
              </div>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm text-text-secondary">High Risk</CardTitle></CardHeader>
              <div className="px-5 pb-5">
                <p className="text-2xl font-bold text-orange-500">{summary?.high_count ?? 0}</p>
              </div>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm text-text-secondary">Assets Affected</CardTitle></CardHeader>
              <div className="px-5 pb-5">
                <p className="text-2xl font-bold">{summary?.total_assets_affected ?? 0}</p>
              </div>
            </Card>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Input
              placeholder="Search exposures..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-64"
            />
            <select
              value={sevFilter}
              onChange={(e) => setSevFilter(e.target.value)}
              className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
            >
              <option value="">All Statuses</option>
              <option value="active">Active</option>
              <option value="mitigated">Mitigated</option>
            </select>
            <p className="text-sm text-text-muted">{total} exposure{total !== 1 ? 's' : ''}</p>
          </div>

          {listLoading ? (
            <div className="flex justify-center py-8">
              <Spinner />
            </div>
          ) : exposures.length > 0 ? (
            <>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {exposures.map((e) => <ExposureCard key={e.id} item={e} />)}
              </div>
              {totalPages > 1 && (
                <div className="flex justify-center pt-2">
                  <Pagination currentPage={page} totalPages={totalPages} onPageChange={setPage} />
                </div>
              )}
            </>
          ) : (
            <div className="py-12 text-center text-text-muted">
              <p className="text-lg font-medium">No exposures found</p>
              <p className="mt-1 text-sm">Exposures are discovered automatically during scans.</p>
            </div>
          )}
        </div>
      )}
    </PageContainer>
  )
}
