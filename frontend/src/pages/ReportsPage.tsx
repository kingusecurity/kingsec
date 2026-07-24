import { useState, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Pagination } from '@/components/ui/Pagination'
import { TableSkeleton } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { ReportTable } from '@/components/features/reports/ReportTable'
import { ReportFilters } from '@/components/features/reports/ReportFilters'
import { useReports, useDeleteReport, useDownloadReport } from '@/hooks/use-reports'
import type { ReportListParams } from '@/types/api'

const PAGE_SIZE = 20

export function ReportsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)
  const deleteReport = useDeleteReport()
  const downloadReport = useDownloadReport()

  const search = searchParams.get('search') ?? ''
  const severityFilter = searchParams.get('severity') ?? ''
  const sortBy = searchParams.get('sort_by') ?? 'created_at'
  const sortOrder = searchParams.get('sort_order') ?? 'desc'
  const page = parseInt(searchParams.get('page') ?? '1', 10)
  const offset = (page - 1) * PAGE_SIZE

  const params: ReportListParams = {
    limit: PAGE_SIZE,
    offset,
    search: search || undefined,
    severity: severityFilter || undefined,
    sort_by: sortBy,
    sort_order: sortOrder as ReportListParams['sort_order'],
  }

  const { data, isLoading, error, refetch } = useReports(params)

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

  const handleSortByChange = useCallback((value: string) => {
    updateParams({ sort_by: value, page: '1' })
  }, [updateParams])

  const handleSortOrderChange = useCallback((value: string) => {
    updateParams({ sort_order: value, page: '1' })
  }, [updateParams])

  const handleClear = useCallback(() => {
    setSearchParams(new URLSearchParams())
  }, [setSearchParams])

  const handleDelete = useCallback((id: string) => {
    setDeleteTarget(id)
  }, [])

  const handleConfirmDelete = useCallback(() => {
    if (deleteTarget) {
      deleteReport.mutate(deleteTarget)
      setDeleteTarget(null)
    }
  }, [deleteTarget, deleteReport])

  const handleDownload = useCallback((id: string) => {
    const url = downloadReport.getDownloadUrl(id)
    window.open(url, '_blank')
  }, [downloadReport])

  const hasFilters = !!(search || severityFilter)
  const totalPages = data ? Math.ceil(data.total / data.limit) : 0

  if (error) {
    return (
      <PageContainer>
        <PageHeader title="Reports" />
        <ErrorState title="Failed to load reports" message={(error as Error).message} onRetry={refetch} />
      </PageContainer>
    )
  }

  return (
    <PageContainer>
      <PageHeader title="Reports" description="Completed assessment reports" />

      <ReportFilters
        search={search}
        onSearchChange={handleSearchChange}
        sortBy={sortBy}
        onSortByChange={handleSortByChange}
        sortOrder={sortOrder}
        onSortOrderChange={handleSortOrderChange}
        onClear={handleClear}
        hasFilters={hasFilters}
      />

      {isLoading ? (
        <div className="rounded-xl border border-border bg-surface-secondary p-5">
          <TableSkeleton rows={8} />
        </div>
      ) : data && data.items.length > 0 ? (
        <div className="rounded-xl border border-border bg-surface-secondary overflow-hidden">
          <ReportTable
            reports={data.items.map((r) => ({
              assessment_id: r.assessment_id,
              target: r.target,
              status: r.status,
              findings_count: r.total_findings,
              is_authorized: true,
              created_at: r.created_at,
            }))}
            onDownload={(id) => handleDownload(id)}
            onDelete={(id) => handleDelete(id)}
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
      ) : (
        <div className="rounded-xl border border-border bg-surface-secondary">
          <EmptyState
            title="No reports found"
            description={hasFilters ? 'Try adjusting your search.' : 'Complete an assessment to generate a report.'}
          />
        </div>
      )}

      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleConfirmDelete}
        title="Delete Report"
        message="Are you sure you want to delete this report? This action cannot be undone."
        confirmLabel="Delete"
        variant="danger"
        loading={deleteReport.isPending}
      />
    </PageContainer>
  )
}
