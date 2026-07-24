import { useCallback } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Pagination } from '@/components/ui/Pagination'
import { TableSkeleton } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { AssessmentSeverityBadge } from '@/components/features/assessment/AssessmentSeverityBadge'
import { AssessmentStatusBadge } from '@/components/features/assessment/AssessmentStatusBadge'
import { FindingFilters } from '@/components/features/findings/FindingFilters'
import { useFindingsList } from '@/hooks/use-findings'
import type { FindingsListParams } from '@/types/api'

const PAGE_SIZE = 20

export function FindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams()

  const search = searchParams.get('search') ?? ''
  const severityFilter = searchParams.get('severity') ?? ''
  const statusFilter = searchParams.get('status') ?? ''
  const assessmentFilter = searchParams.get('assessment_id') ?? ''
  const sortBy = searchParams.get('sort_by') ?? 'severity'
  const sortOrder = searchParams.get('sort_order') ?? 'desc'
  const page = parseInt(searchParams.get('page') ?? '1', 10)
  const offset = (page - 1) * PAGE_SIZE

  const params: FindingsListParams = {
    limit: PAGE_SIZE,
    offset,
    search: search || undefined,
    severity: severityFilter || undefined,
    status: statusFilter || undefined,
    assessment_id: assessmentFilter || undefined,
    sort_by: sortBy,
    sort_order: sortOrder as FindingsListParams['sort_order'],
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

  const hasFilters = !!(search || severityFilter || statusFilter || assessmentFilter || sortBy !== 'severity')
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
                  <th className="px-5 py-3 text-left font-medium text-text-secondary">Title</th>
                  <th className="px-5 py-3 text-left font-medium text-text-secondary">Severity</th>
                  <th className="px-5 py-3 text-left font-medium text-text-secondary">Status</th>
                  <th className="px-5 py-3 text-left font-medium text-text-secondary">Asset</th>
                  <th className="px-5 py-3 text-left font-medium text-text-secondary">Assessment</th>
                  <th className="px-5 py-3 w-10" />
                </tr>
              </thead>
              <tbody>
                {data.items.map((item) => {
                  const detailPath = item.assessment_id
                    ? `/assessments/${item.assessment_id}/findings/${item.finding_id}`
                    : `/findings/${item.finding_id}`
                  return (
                    <tr key={item.finding_id} className="border-b border-border transition-colors hover:bg-surface-tertiary/50">
                      <td className="px-5 py-3">
                        <Link to={detailPath} className="font-medium text-text-primary hover:text-accent transition-colors">
                          {item.title}
                        </Link>
                      </td>
                      <td className="px-5 py-3">
                        <AssessmentSeverityBadge severity={item.severity} />
                      </td>
                      <td className="px-5 py-3">
                        <AssessmentStatusBadge status={item.status} />
                      </td>
                      <td className="px-5 py-3 text-text-secondary">
                        {item.asset ?? '—'}
                      </td>
                      <td className="px-5 py-3">
                        {item.assessment_id ? (
                          <Link to={`/assessments/${item.assessment_id}`} className="text-accent hover:text-emerald-400 text-xs">
                            {item.target ?? item.assessment_id.slice(0, 8)}
                          </Link>
                        ) : (
                          <span className="text-text-muted">—</span>
                        )}
                      </td>
                      <td className="px-5 py-3">
                        <Link
                          to={detailPath}
                          className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-text-muted hover:text-text-primary hover:bg-surface-tertiary"
                          aria-label={`View finding: ${item.title}`}
                        >
                          <ArrowRight className="h-4 w-4" />
                        </Link>
                      </td>
                    </tr>
                  )
                })}
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
