import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
} from "@tanstack/react-table"
import { useNavigate } from "react-router-dom"
import { formatRelative } from "@/shared/lib/utils"
import { ROUTES } from "@/shared/lib/constants"
import { AssessmentStatusBadge } from "./assessment-status-badge"
import type { AssessmentSummary } from "../types"

const columns: ColumnDef<AssessmentSummary>[] = [
  {
    accessorKey: "target",
    header: "Target",
    cell: ({ row }) => (
      <span className="font-medium text-[hsl(var(--fg))]">{row.original.target}</span>
    ),
  },
  {
    accessorKey: "status",
    header: "Status",
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
    header: "Created",
    cell: ({ row }) => (
      <span className="text-[hsl(var(--fg-secondary))]">{formatRelative(row.original.created_at)}</span>
    ),
  },
]

interface AssessmentTableProps {
  data: AssessmentSummary[]
  isLoading: boolean
}

export function AssessmentTable({ data, isLoading }: AssessmentTableProps): React.ReactElement {
  const navigate = useNavigate()

  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    manualSorting: true,
  })

  if (isLoading) {
    return (
      <div className="rounded-xl border border-[hsl(var(--border))]">
        <div className="p-4">
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
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
    )
  }

  return (
    <div className="rounded-xl border border-[hsl(var(--border))]">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-[hsl(var(--border))] bg-[hsl(var(--muted))]/50">
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className="px-4 py-3 text-left font-medium text-[hsl(var(--muted-fg))]"
                  >
                    {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-4 py-12 text-center text-[hsl(var(--fg-secondary))]">
                  No assessments found.
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  className="cursor-pointer border-b border-[hsl(var(--border))] transition-colors hover:bg-[hsl(var(--accent))]/50"
                  onClick={() => navigate(`${ROUTES.ASSESSMENTS}/${row.original.assessment_id}`)}
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
}
