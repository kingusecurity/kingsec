import { useState, useCallback, useEffect, useMemo } from "react"
import { useSearchParams } from "react-router-dom"
import { RefreshCw, Search, ScanSearch } from "lucide-react"
import type { SortingState, Updater } from "@tanstack/react-table"
import { useAssessments } from "../hooks/use-assessments"
import { AssessmentTable } from "../components/assessment-table"
import { CreateAssessmentDialog } from "../components/assessment-create-dialog"
import { PageHeader } from "@/shared/components/page-header"
import { EmptyState } from "@/shared/components/empty-state"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Button } from "@/shared/ui/button"
import { Input } from "@/shared/ui/input"
import { Select } from "@/shared/ui/select"
import { getApiError } from "@/shared/api/error-handler"
import { useDebounce } from "@/shared/hooks/use-debounce"

const PAGE_SIZE = 20

const STATUS_OPTIONS = [
  { value: "", label: "All Statuses" },
  { value: "CREATED", label: "Created" },
  { value: "RUNNING", label: "Running" },
  { value: "COMPLETED", label: "Completed" },
  { value: "FAILED", label: "Failed" },
  { value: "CANCELLED", label: "Cancelled" },
] as const

function parseSorting(sp: URLSearchParams): SortingState {
  const sortParam = sp.get("sort")
  if (!sortParam) return [{ id: "created_at", desc: true }]
  const [id, dir] = sortParam.split(":")
  return [{ id: id ?? "created_at", desc: dir === "desc" }]
}

function sortingToParam(sorting: SortingState): string | null {
  if (sorting.length === 0) return null
  const s = sorting[0]
  return `${s.id}:${s.desc ? "desc" : "asc"}`
}

export function AssessmentListPage(): React.ReactElement {
  const [searchParams, setSearchParams] = useSearchParams()

  const page = Math.max(1, parseInt(searchParams.get("page") ?? "1", 10))
  const search = searchParams.get("q") ?? ""
  const statusFilter = searchParams.get("status") ?? ""
  const sorting = useMemo(() => parseSorting(searchParams), [searchParams])

  const [localSearch, setLocalSearch] = useState(search)
  const debouncedSearch = useDebounce(localSearch, 300)

  const offset = (page - 1) * PAGE_SIZE

  const { data, isLoading, error, refetch, isFetching } = useAssessments({
    limit: PAGE_SIZE,
    offset,
  })

  // Sync debounced search to URL
  useEffect(() => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      if (debouncedSearch) {
        next.set("q", debouncedSearch)
      } else {
        next.delete("q")
      }
      next.delete("page")
      return next
    })
  }, [debouncedSearch, setSearchParams])

  const handleStatusFilter = useCallback(
    (value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev)
        if (value) next.set("status", value)
        else next.delete("status")
        next.delete("page")
        return next
      })
    },
    [setSearchParams],
  )

  const handleSortingChange = useCallback(
    (updater: Updater<SortingState>) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev)
        const resolved = typeof updater === "function" ? updater(sorting) : updater
        const param = sortingToParam(resolved)
        if (param) next.set("sort", param)
        else next.delete("sort")
        return next
      })
    },
    [setSearchParams, sorting],
  )

  const handlePageChange = useCallback(
    (newPage: number) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev)
        if (newPage > 1) next.set("page", String(newPage))
        else next.delete("page")
        return next
      })
    },
    [setSearchParams],
  )

  const filteredItems = useMemo(() => {
    return (data?.items ?? []).filter((item) => {
      if (statusFilter && item.status !== statusFilter) return false
      if (debouncedSearch) {
        const q = debouncedSearch.toLowerCase()
        return item.target.toLowerCase().includes(q) || item.assessment_id.toLowerCase().includes(q)
      }
      return true
    })
  }, [data?.items, statusFilter, debouncedSearch])

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE))

  if (error) {
    const apiErr = getApiError(error)
    return (
      <div className="p-6">
        <PageHeader title="Assessments" description="Manage your attack surface assessments." actions={<CreateAssessmentDialog />} />
        <div className="mt-6 flex flex-col items-center gap-4 rounded-xl border border-[hsl(var(--border))] py-16" role="alert">
          <p className="text-sm text-[hsl(var(--destructive))]">{apiErr.detail}</p>
          {apiErr.status === 401 ? (
            <p className="text-xs text-[hsl(var(--fg-secondary))]">Please log in again.</p>
          ) : (
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 size-4" />
              Retry
            </Button>
          )}
        </div>
      </div>
    )
  }

  return (
    <ErrorBoundary>
      <div className="p-6">
        <PageHeader
          title="Assessments"
          description="Manage your attack surface assessments."
          actions={<CreateAssessmentDialog />}
        />

        {/* Toolbar */}
        <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-1 items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-[hsl(var(--muted-fg))]" aria-hidden="true" />
              <Input
                placeholder="Search by target or ID..."
                value={localSearch}
                onChange={(e) => setLocalSearch(e.target.value)}
                className="pl-9"
                aria-label="Search assessments"
              />
            </div>
            <Select
              value={statusFilter}
              onChange={(e) => handleStatusFilter(e.target.value)}
              className="w-40"
              aria-label="Filter by status"
            >
              {STATUS_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching} aria-label="Refresh assessments">
            <RefreshCw className={`mr-2 size-4 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>

        {/* Table */}
        <div className="mt-4">
          {isLoading ? (
            <AssessmentTable data={[]} isLoading={true} sorting={sorting} onSortingChange={handleSortingChange} />
          ) : filteredItems.length === 0 ? (
            <EmptyState
              icon={<ScanSearch className="size-12" />}
              title="No assessments found"
              description={search || statusFilter ? "Try adjusting your search or filters." : "Create your first assessment to get started."}
              action={!search && !statusFilter ? <CreateAssessmentDialog /> : undefined}
            />
          ) : (
            <AssessmentTable data={filteredItems} isLoading={false} sorting={sorting} onSortingChange={handleSortingChange} />
          )}
        </div>

        {/* Pagination */}
        {data && data.total > PAGE_SIZE && (
          <div className="mt-4 flex items-center justify-between">
            <p className="text-sm text-[hsl(var(--fg-secondary))]" aria-live="polite">
              Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, data.total)} of {data.total}
            </p>
            <nav className="flex items-center gap-2" aria-label="Pagination">
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1}
                onClick={() => handlePageChange(page - 1)}
                aria-label="Previous page"
              >
                Previous
              </Button>
              <span className="text-sm text-[hsl(var(--fg-secondary))]" aria-current="page">
                Page {page} of {totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages}
                onClick={() => handlePageChange(page + 1)}
                aria-label="Next page"
              >
                Next
              </Button>
            </nav>
          </div>
        )}
      </div>
    </ErrorBoundary>
  )
}
