import { memo, useCallback } from "react"
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  type ColumnDef,
  type SortingState,
  type Updater,
} from "@tanstack/react-table"
import { useNavigate } from "react-router-dom"
import { ArrowUpDown, ArrowUp, ArrowDown } from "lucide-react"
import { formatRelative } from "@/shared/lib/utils"
import { ROUTES } from "@/shared/lib/constants"
import { AssessmentStatusBadge } from "./assessment-status-badge"
import { Button } from "@/shared/ui/button"
import type { AssessmentSummary } from "../types"

interface SortIndicatorProps {
  sorted: false | "asc" | "desc"
}

function SortIndicator({ sorted }: SortIndicatorProps): React.ReactElement {
  if (sorted === "asc") return <ArrowUp className="ml-1 size-3" />
  if (sorted === "desc") return <ArrowDown className="ml-1 size-3" />
  return <ArrowUpDown className="ml-1 size-3 opacity-50" />
}

function createColumns(sortable: boolean): ColumnDef<AssessmentSummary>[] {
  return [
    {
      accessorKey: "target",
      header: ({ column }) => (
        <Button
          variant="ghost"
          size="sm"
          className="-ml-2 h-8 data-[state=open]:bg-accent"
          onClick={column.getToggleSortingHandler()}
          aria-label={`Sort by target ${column.getIsSorted() === "asc" ? "descending" : "ascending"}`}
        >
          Target
          {sortable && <SortIndicator sorted={column.getIsSorted()} />}
        </Button>
      ),
      cell: ({ row }) => (
        <span className="font-medium text-[hsl(var(--fg))]">{row.original.target}</span>
      ),
    },
    {
      accessorKey: "status",
      header: ({ column }) => (
        <Button
          variant="ghost"
          size="sm"
          className="-ml-2 h-8"
          onClick={column.getToggleSortingHandler()}
          aria-label={`Sort by status ${column.getIsSorted() === "asc" ? "descending" : "ascending"}`}
        >
          Status
          {sortable && <SortIndicator sorted={column.getIsSorted()} />}
        </Button>
      ),
      cell: ({ row }) => <AssessmentStatusBadge status={row.original.status} />,
    },
    {
      accessorKey: "findings_count",
      header: "Findings",
      cell: ({ row }) => (
        <span className="text-[hsl(var(--fg-secondary))]">{row.original.findings_count}</span>
      ),
    },
    {
      accessorKey: "is_authorized",
      header: "Authorized",
      cell: ({ row }) => (
        <span className={row.original.is_authorized ? "text-[hsl(var(--success))]" : "text-[hsl(var(--destructive))]"}>
          {row.original.is_authorized ? "Yes" : "No"}
        </span>
      ),
    },
    {
      accessorKey: "created_at",
      header: ({ column }) => (
        <Button
          variant="ghost"
          size="sm"
          className="-ml-2 h-8"
          onClick={column.getToggleSortingHandler()}
          aria-label={`Sort by created ${column.getIsSorted() === "asc" ? "descending" : "ascending"}`}
        >
          Created
          {sortable && <SortIndicator sorted={column.getIsSorted()} />}
        </Button>
      ),
      cell: ({ row }) => (
        <span className="text-[hsl(var(--fg-secondary))]">{formatRelative(row.original.created_at)}</span>
      ),
    },
  ]
}

interface AssessmentTableDesktopProps {
  data: AssessmentSummary[]
  sorting: SortingState
  onSortingChange: (updater: Updater<SortingState>) => void
  onRowClick: (id: string) => void
}

const AssessmentTableDesktop = memo(function AssessmentTableDesktop({
  data,
  sorting,
  onSortingChange,
  onRowClick,
}: AssessmentTableDesktopProps): React.ReactElement {
  const columns = createColumns(true)
  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    manualSorting: false,
  })

  return (
    <div className="hidden rounded-xl border border-[hsl(var(--border))] md:block">
      <div className="overflow-x-auto">
        <table className="w-full text-sm" role="table" aria-label="Assessments">
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-[hsl(var(--border))] bg-[hsl(var(--muted))]/50">
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    scope="col"
                    className="px-4 py-3 text-left font-medium text-[hsl(var(--muted-fg))]"
                  >
                    {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.length === 0 ? null : (
              table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  tabIndex={0}
                  role="row"
                  className="cursor-pointer border-b border-[hsl(var(--border))] transition-colors hover:bg-[hsl(var(--accent))]/50 focus:bg-[hsl(var(--accent))]/50 focus:outline-none"
                  onClick={() => onRowClick(row.original.assessment_id)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault()
                      onRowClick(row.original.assessment_id)
                    }
                  }}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-4 py-3">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
})

interface AssessmentCardMobileProps {
  items: AssessmentSummary[]
  onRowClick: (id: string) => void
}

const AssessmentCardMobile = memo(function AssessmentCardMobile({
  items,
  onRowClick,
}: AssessmentCardMobileProps): React.ReactElement {
  if (items.length === 0) return <></>

  return (
    <div className="space-y-3 md:hidden">
      {items.map((item) => (
        <button
          key={item.assessment_id}
          onClick={() => onRowClick(item.assessment_id)}
          className="w-full rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4 text-left transition-colors hover:bg-[hsl(var(--accent))]/50 focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
          aria-label={`Assessment ${item.target}, status ${item.status}`}
        >
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <p className="font-medium text-[hsl(var(--fg))]">{item.target}</p>
              <p className="text-xs text-[hsl(var(--fg-secondary))]">
                {item.findings_count} findings · {formatRelative(item.created_at)}
              </p>
            </div>
            <AssessmentStatusBadge status={item.status} />
          </div>
        </button>
      ))}
    </div>
  )
})

interface AssessmentTableSkeletonProps {
  rows?: number
}

export function AssessmentTableSkeleton({ rows = 5 }: AssessmentTableSkeletonProps): React.ReactElement {
  return (
    <>
      <div className="hidden rounded-xl border border-[hsl(var(--border))] md:block">
        <div className="p-4">
          <div className="space-y-3">
            {Array.from({ length: rows }).map((_, i) => (
              <div key={i} className="flex gap-4">
                <div className="skeleton h-10 flex-1 rounded-md" />
                <div className="skeleton h-10 w-24 rounded-md" />
                <div className="skeleton h-10 w-16 rounded-md" />
                <div className="skeleton h-10 w-20 rounded-md" />
                <div className="skeleton h-10 w-24 rounded-md" />
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="space-y-3 md:hidden">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="skeleton h-24 rounded-xl" />
        ))}
      </div>
    </>
  )
}

interface AssessmentTableProps {
  data: AssessmentSummary[]
  isLoading: boolean
  sorting: SortingState
  onSortingChange: (updater: Updater<SortingState>) => void
}

export function AssessmentTable({ data, isLoading, sorting, onSortingChange }: AssessmentTableProps): React.ReactElement {
  const navigate = useNavigate()
  const handleRowClick = useCallback(
    (id: string) => navigate(`${ROUTES.ASSESSMENTS}/${id}`),
    [navigate],
  )

  if (isLoading) {
    return <AssessmentTableSkeleton />
  }

  return (
    <>
      <AssessmentTableDesktop data={data} sorting={sorting} onSortingChange={onSortingChange} onRowClick={handleRowClick} />
      <AssessmentCardMobile items={data} onRowClick={handleRowClick} />
    </>
  )
}
