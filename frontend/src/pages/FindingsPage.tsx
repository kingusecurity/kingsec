import { useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Pagination } from '@/components/ui/Pagination'
import { TableSkeleton } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { AssessmentStatusBadge } from '@/components/features/assessment/AssessmentStatusBadge'
import { FindingFilters } from '@/components/features/findings/FindingFilters'
import { useFindingsList } from '@/hooks/use-findings'
import { formatRelativeTime } from '@/lib/utils'
import type { AssessmentListParams } from '@/types/api'

const PAGE_SIZE = 20

export function FindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams()

  const search = searchParams.get('search') ?? ''
  const severityFilter = searchParams.get('severity') ?? ''
  const statusFilter = searchParams.get('status') ?? ''
  const page = parseInt(searchParams.get('page') ?? '1', 10)
  const offset = (page - 1) * PAGE_SIZE

  const params: AssessmentListParams = {
    limit: PAGE_SIZE,
    offset,
    search: search || undefined,
    sort_by: 'created_at',
    sort_order: 'desc',
  }

  const { data, isLoading, error, refetch } = useFindingsList(params)

  const updateParams = useCallback((updates: Record<string, string>) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      for (const [key, value] of Object.entries(updates)) {
        if (value) next.set(key, value)
        else next.delete(key)
      }
      return next
    })
  }, [setSearchParams])

  const handleSearchChange = useCallback((value: string) => {
    updateParams({ search: value, page: '1' })
  }, [updateParams])

  const handleSeverityFilterChange = useCallback((value: string) => {
    updateParams({ severity: value, page: '1' })
  }, [updateParams])

  const handleStatusFilterChange = useCallback((value: string) => {
    updateParams({ status: value, page: '1' })
  }, [updateParams])

  const handleClear = useCallback(() => {
    setSearchParams(new URLSearchParams())
  }, [setSearchParams])

  const hasFilters = !!(search || severityFilter || statusFilter)
  const totalPages = data ? Math.ceil(data.total / data.limit) : 0

  if (error) {
    return (
      <PageContainer>
        <PageHeader title="Findings" />
        <ErrorState title="Failed to load findings" message={(error as Error).message} onRetry={refetch} />
      </PageContainer>
    )
  }

  return (
    <PageContainer>
      <PageHeader title="Findings" description="Security findings across assessments" />

      <FindingFilters
        search={search}
        onSearchChange={handleSearchChange}
        severityFilter={severityFilter}
        onSeverityFilterChange={handleSeverityFilterChange}
        statusFilter={statusFilter}
        onStatusFilterChange={handleStatusFilterChange}
        onClear={handleClear}
        hasFilters={hasFilters}
      />

      {isLoading ? (
        <div className="rounded-xl border border-border bg-surface-secondary p-5">
          <TableSkeleton rows={8} />
        </div>
      ) : data && data.items.length > 0 ? (
        <div className="rounded-xl border border-border bg-surface-secondary overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-surface-tertiary">
                  <th className="px-5 py-3 text-left font-medium text-text-secondary">Target</th>
                  <th className="px-5 py-3 text-left font-medium text-text-secondary">Status</th>
                  <th className="px-5 py-3 text-right font-medium text-text-secondary">Findings</th>
                  <th className="px-5 py-3 text-left font-medium text-text-secondary">Created</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((item) => (
                  <tr key={item.assessment_id} className="border-b border-border transition-colors hover:bg-surface-tertiary/50">
                    <td className="px-5 py-3 font-medium text-text-primary">{item.target}</td>
                    <td className="px-5 py-3">
                      <AssessmentStatusBadge status={item.status} />
                    </td>
                    <td className="px-5 py-3 text-right text-text-secondary">{item.findings_count}</td>
                    <td className="px-5 py-3 text-text-secondary whitespace-nowrap">{formatRelativeTime(item.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {totalPages > 1 && (
            <div className="flex justify-center border-t border-border px-5 py-4">
              <Pagination
                currentPage={page}
                totalPages={totalPages}
                onPageChange={(p) => updateParams({ page: String(p) })}
              />
            </div>
          )}
        </div>
      ) : (
        <div className="rounded-xl border border-border bg-surface-secondary">
          <EmptyState
            title="No findings found"
            description={hasFilters ? 'Try adjusting your filters.' : 'Run an assessment to generate findings.'}
          />
        </div>
      )}
    </PageContainer>
  )
}
