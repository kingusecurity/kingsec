import { useState, useCallback, useEffect } from "react"
import { useSearchParams } from "react-router-dom"
import { RefreshCw, Search, ScanSearch } from "lucide-react"
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

const STATUS_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "", label: "All Statuses" },
  { value: "CREATED", label: "Created" },
  { value: "RUNNING", label: "Running" },
  { value: "COMPLETED", label: "Completed" },
  { value: "FAILED", label: "Failed" },
  { value: "CANCELLED", label: "Cancelled" },
]

export function AssessmentListPage(): React.ReactElement {
  const [searchParams, setSearchParams] = useSearchParams()

  const page = Math.max(1, parseInt(searchParams.get("page") ?? "1", 10))
  const search = searchParams.get("q") ?? ""
  const statusFilter = searchParams.get("status") ?? ""

  const [localSearch, setLocalSearch] = useState(search)
  const debouncedSearch = useDebounce(localSearch, 300)

  const offset = (page - 1) * PAGE_SIZE

  const { data, isLoading, error, refetch, isFetching } = useAssessments({
    limit: PAGE_SIZE,
    offset,
  })

  // Sync debounced search to URL params
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
        if (value) {
          next.set("status", value)
        } else {
          next.delete("status")
        }
        next.delete("page")
        return next
      })
    },
    [setSearchParams],
  )

  const handlePageChange = useCallback(
    (newPage: number) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev)
        if (newPage > 1) {
          next.set("page", String(newPage))
        } else {
          next.delete("page")
        }
        return next
      })
    },
    [setSearchParams],
  )

  // Client-side filtering (API doesn't support server-side search/filter)
  const filteredItems = (data?.items ?? []).filter((item) => {
    if (statusFilter && item.status !== statusFilter) return false
    if (debouncedSearch) {
      const q = debouncedSearch.toLowerCase()
      return item.target.toLowerCase().includes(q) || item.assessment_id.toLowerCase().includes(q)
    }
    return true
  })

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE))

  if (error) {
    const apiErr = getApiError(error)
    return (
      <div className="p-6">
        <PageHeader title="Assessments" description="Manage your attack surface assessments." actions={<CreateAssessmentDialog />} />
        <div className="mt-6 flex flex-col items-center gap-4 rounded-xl border border-[hsl(var(--border))] py-16">
          <p className="text-sm text-[hsl(var(--destructive))]">{apiErr.detail}</p>
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="mr-2 size-4" />
            Retry
          </Button>
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
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-[hsl(var(--muted-fg))]" />
              <Input
                placeholder="Search by target or ID..."
                value={localSearch}
                onChange={(e) => setLocalSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={statusFilter} onChange={(e) => handleStatusFilter(e.target.value)} className="w-40">
              {STATUS_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`mr-2 size-4 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>

        {/* Table */}
        <div className="mt-4">
          {isLoading ? (
            <AssessmentTable data={[]} isLoading={true} />
          ) : filteredItems.length === 0 ? (
            <EmptyState
              icon={<ScanSearch className="size-12" />}
              title="No assessments found"
              description={search || statusFilter ? "Try adjusting your search or filters." : "Create your first assessment to get started."}
              action={!search && !statusFilter ? <CreateAssessmentDialog /> : undefined}
            />
          ) : (
            <AssessmentTable data={filteredItems} isLoading={false} />
          )}
        </div>

        {/* Pagination */}
        {data && data.total > PAGE_SIZE && (
          <div className="mt-4 flex items-center justify-between">
            <p className="text-sm text-[hsl(var(--fg-secondary))]">
              Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, data.total)} of {data.total}
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1}
                onClick={() => handlePageChange(page - 1)}
              >
                Previous
              </Button>
              <span className="text-sm text-[hsl(var(--fg-secondary))]">
                Page {page} of {totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages}
                onClick={() => handlePageChange(page + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </div>
    </ErrorBoundary>
  )
}
