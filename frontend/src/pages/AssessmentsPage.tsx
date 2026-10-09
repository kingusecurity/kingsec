import { useCallback, useEffect } from 'react'
import { Link, useSearchParams, useNavigate } from 'react-router-dom'
import { Plus, ArrowRight } from 'lucide-react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Button } from '@/components/ui/Button'
import { Pagination } from '@/components/ui/Pagination'
import { TableSkeleton } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Alert } from '@/components/ui/Alert'
import { AssessmentStatusBadge } from '@/components/features/assessment/AssessmentStatusBadge'
import { AssessmentFilters } from '@/components/features/assessment/AssessmentFilters'
import { useAssessments } from '@/hooks/use-assessments'
import { useAuthStore } from '@/store/auth'
import { formatRelativeTime } from '@/lib/utils'
import type { AssessmentListParams, AssessmentSortField } from '@/types/api'

const PAGE_SIZE = 20
const VALID_STATUS_FILTERS = new Set([
  'draft',
  'authorized',
  'running',
  'completed',
  'completed_with_gaps',
  'failed',
  'cancelled',
])

export function AssessmentsPage() {
  const navigate = useNavigate()
  const user = useAuthStore((s) => s.user)
  const canCreate = user && ['analyst', 'admin'].includes(user.role.toLowerCase())
  const [searchParams, setSearchParams] = useSearchParams()

  const search = (searchParams.get('search') ?? '').slice(0, 256)
  const requestedStatus = searchParams.get('status') ?? ''
  const statusFilter = VALID_STATUS_FILTERS.has(requestedStatus) ? requestedStatus : ''
  const requestedSort = searchParams.get('sort_by') ?? 'created_at'
  const sortBy = (['created_at', 'status', 'target', 'findings_count'].includes(requestedSort)
    ? requestedSort : 'created_at') as AssessmentSortField
  const sortOrder = searchParams.get('sort_order') === 'asc' ? 'asc' : 'desc'
  const page = Math.max(1, parseInt(searchParams.get('page') ?? '1', 10) || 1)
  const offset = (page - 1) * PAGE_SIZE

  const params: AssessmentListParams = {
    limit: PAGE_SIZE,
    offset,
    search: search || undefined,
    status: statusFilter || undefined,
    order_by: sortBy,
    order_dir: sortOrder,
  }

  const { data, isLoading, error, refetch } = useAssessments(params)

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

  const handleStatusFilterChange = useCallback((value: string) => {
    updateParams({ status: value, page: '1' })
  }, [updateParams])

  const handleSortByChange = useCallback((value: string) => {
    updateParams({ sort_by: value, page: '1' })
  }, [updateParams])

  const handleSortOrderChange = useCallback((value: string) => {
    updateParams({ sort_order: value, page: '1' })
  }, [updateParams])

  const handleClear = useCallback(() => {
    setSearchParams(new URLSearchParams())
  }, [setSearchParams])

  const hasFilters = !!(search || statusFilter || sortBy !== 'created_at' || sortOrder !== 'desc')

  const totalPages = data ? Math.ceil(data.total / data.limit) : 0
  const hasUnreadablePage = !!data
    && data.items.length === 0
    && data.total > 0
    && data.unreadable_ids.length > 0

  useEffect(() => {
    if (!data) return

    const lastPage = Math.max(1, totalPages)
    if (page > lastPage) {
      updateParams({ page: String(lastPage) })
    }
  }, [data, page, totalPages, updateParams])

  if (error) {
    return (
      <PageContainer>
        <PageHeader title="Assessments" />
        <ErrorState title="Failed to load assessments" message={(error as Error).message} onRetry={refetch} />
      </PageContainer>
    )
  }

  return (
    <PageContainer>
      <PageHeader
        title="Assessments"
        description="Manage and monitor security assessments"
        actions={
          canCreate ? (
            <Button onClick={() => navigate('/assessments/new')} iconLeft={<Plus className="h-4 w-4" />}>
              New Assessment
            </Button>
          ) : undefined
        }
      />

      <AssessmentFilters
        search={search}
        onSearchChange={handleSearchChange}
        statusFilter={statusFilter}
        onStatusFilterChange={handleStatusFilterChange}
        sortBy={sortBy}
        onSortByChange={handleSortByChange}
        sortOrder={sortOrder}
        onSortOrderChange={handleSortOrderChange}
        onClear={handleClear}
        hasFilters={hasFilters}
      />

      {data && data.unreadable_ids.length > 0 && (
        <Alert variant="warning" title="Some assessments could not be displayed">
          <p>
            {data.unreadable_ids.length} assessment {data.unreadable_ids.length === 1 ? 'record was' : 'records were'}
            {' '}omitted because {data.unreadable_ids.length === 1 ? 'it could' : 'they could'} not be read. Contact an
            {' '}administrator for help.
          </p>
          <p className="break-all font-mono text-xs" aria-label="Unreadable assessment IDs">
            {data.unreadable_ids.join(', ')}
          </p>
        </Alert>
      )}

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
                  <th scope="col" className="px-5 py-3 text-left font-medium text-text-secondary">Target</th>
                  <th scope="col" className="px-5 py-3 text-left font-medium text-text-secondary">Status</th>
                  <th scope="col" className="px-5 py-3 text-left font-medium text-text-secondary">Findings</th>
                  <th scope="col" className="px-5 py-3 text-left font-medium text-text-secondary">Created</th>
                  <th scope="col" className="px-5 py-3 w-10" />
                </tr>
              </thead>
              <tbody>
                {data.items.map((item) => (
                  <tr key={item.assessment_id} className="border-b border-border transition-colors hover:bg-surface-tertiary/50">
                    <td className="px-5 py-3">
                      <Link to={`/assessments/${item.assessment_id}`} className="text-accent hover:text-emerald-400 font-medium">
                        {item.target}
                      </Link>
                    </td>
                    <td className="px-5 py-3">
                      <AssessmentStatusBadge status={item.status} />
                    </td>
                    <td className="px-5 py-3 text-text-secondary">{item.findings_count}</td>
                    <td className="px-5 py-3 text-text-secondary whitespace-nowrap">
                      {formatRelativeTime(item.created_at)}
                    </td>
                    <td className="px-5 py-3">
                      <Link to={`/assessments/${item.assessment_id}`} className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-text-muted hover:text-text-primary hover:bg-surface-tertiary">
                        <ArrowRight className="h-4 w-4" />
                      </Link>
                    </td>
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
            title={hasUnreadablePage ? 'Assessment records unavailable' : 'No assessments found'}
            description={
              hasUnreadablePage
                ? 'The assessment records on this page could not be read. Review the warning above, retry, or contact an administrator.'
                : hasFilters
                ? 'Try adjusting your search or filters.'
                : canCreate
                  ? 'Create your first assessment to get started.'
                  : 'An analyst or administrator can create an assessment. It will appear here once created.'
            }
            action={!hasUnreadablePage && !hasFilters && canCreate ? { label: 'New Assessment', onClick: () => navigate('/assessments/new') } : undefined}
          />
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
      )}
    </PageContainer>
  )
}
